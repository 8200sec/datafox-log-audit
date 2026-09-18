// Copyright 2026 DataFox Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

import type { AuditEvent } from "@/schemas/audit-event";
import { RESULT_VALUES, SEVERITY_VALUES, SOURCE_TYPE_VALUES } from "@/schemas/audit-event";
import type { Severity, Result, SourceType } from "@/schemas/audit-event";
import type { NormalizeResult, ParsedEvent, ParseFailure, RawLogInput } from "./types";

const SEVERITY_ALIASES: Record<string, Severity> = {
  info: "info",
  informational: "info",
  notice: "info",
  debug: "info",
  trace: "info",
  low: "low",
  minor: "low",
  medium: "medium",
  moderate: "medium",
  warning: "medium",
  warn: "medium",
  high: "high",
  error: "high",
  major: "high",
  alert: "high",
  critical: "critical",
  fatal: "critical",
  emergency: "critical",
  emerg: "critical",
  severe: "critical",
};

const RESULT_ALIASES: Record<string, Result> = {
  success: "success",
  ok: "success",
  allowed: "success",
  passed: "success",
  accept: "success",
  accepted: "success",
  permit: "success",
  permitted: "success",
  failure: "failure",
  fail: "failure",
  failed: "failure",
  deny: "failure",
  denied: "failure",
  error: "failure",
  reject: "failure",
  rejected: "failure",
  block: "failure",
  blocked: "failure",
};

const SOURCE_TYPE_ALIASES: Record<string, SourceType> = {
  os: "os",
  linux: "os",
  windows: "os",
  unix: "os",
  firewall: "firewall",
  fw: "firewall",
  ids: "firewall",
  ips: "firewall",
  router: "router",
  switch: "router",
  network: "network",
  database: "database",
  db: "database",
  web: "web",
  webserver: "web",
  http: "web",
  application: "application",
  app: "application",
};

const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^[0-9a-fA-F:]+$/;

/** Deterministic djb2 event id — stable for the same tenant+source+raw+time. */
function generateEventId(tenant: string, source: string | undefined, raw: string, ts: number): string {
  const material = `${tenant}:${source ?? ""}:${raw}:${ts}`;
  let hash = 5381;
  for (let i = 0; i < material.length; i++) hash = ((hash << 5) + hash) ^ material.charCodeAt(i);
  return `evt-${ts}-${(hash >>> 0).toString(16).padStart(8, "0")}`;
}

function toPort(value: number | string | undefined): number | undefined {
  if (value === undefined) return undefined;
  const n = typeof value === "string" ? Number(value) : value;
  if (!Number.isInteger(n) || n < 0 || n > 65535) return undefined;
  return n;
}

/**
 * Turns a parser's `ParsedEvent` into a validated `AuditEvent`. Lenient for
 * optional fields (bad IP/port are dropped; severity/result/source_type are
 * coerced to the standard enums) but strict about the two invariants that make
 * an event usable: `raw_log` must be present and `_timestamp` must be valid.
 * `tenant_id` always comes from the trusted input context, never the raw log.
 */
export class Normalizer {
  constructor(private readonly now: () => number = Date.now) {}

  normalizeSeverity(raw: string | undefined): Severity {
    return raw ? (SEVERITY_ALIASES[raw.toLowerCase()] ?? "info") : "info";
  }

  normalizeResult(raw: string | undefined): Result {
    return raw ? (RESULT_ALIASES[raw.toLowerCase()] ?? "unknown") : "unknown";
  }

  normalizeSourceType(raw: string | undefined): SourceType {
    return raw ? (SOURCE_TYPE_ALIASES[raw.toLowerCase()] ?? "other") : "other";
  }

  normalizeIp(raw: string | undefined): string | undefined {
    if (!raw) return undefined;
    return IPV4_RE.test(raw) || IPV6_RE.test(raw) ? raw : undefined;
  }

  normalizePort(raw: number | string | undefined): number | undefined {
    return toPort(raw);
  }

  normalize(parsed: ParsedEvent, input: RawLogInput): NormalizeResult {
    if (!parsed.raw_log) {
      return { status: "failure", failure: this.failure(input, parsed, "normalize", "MISSING_REQUIRED_FIELD", "raw_log is empty") };
    }
    const _timestamp = parsed._timestamp ?? input.received_at;
    if (Number.isNaN(_timestamp) || _timestamp < 0) {
      return { status: "failure", failure: this.failure(input, parsed, "normalize", "INVALID_TIMESTAMP", `invalid timestamp ${parsed._timestamp}`) };
    }

    const event: AuditEvent = {
      _timestamp,
      event_id: generateEventId(input.tenant.tenant_id, parsed.source_name ?? input.source_name, parsed.raw_log, _timestamp),
      tenant_id: input.tenant.tenant_id,
      source_type: this.normalizeSourceType(parsed.source_type ?? input.source_type),
      source_name: parsed.source_name ?? input.source_name,
      collector_id: input.collector_id,
      vendor: parsed.vendor,
      product: parsed.product,
      product_version: parsed.product_version,
      hostname: parsed.hostname,
      asset_id: parsed.asset_id,
      src_ip: this.normalizeIp(parsed.src_ip),
      src_port: this.normalizePort(parsed.src_port),
      dst_ip: this.normalizeIp(parsed.dst_ip),
      dst_port: this.normalizePort(parsed.dst_port),
      username: parsed.username,
      category: parsed.category,
      event_type: parsed.event_type,
      action: parsed.action,
      result: this.normalizeResult(parsed.result),
      severity: this.normalizeSeverity(parsed.severity),
      message: parsed.message,
      raw_log: parsed.raw_log,
      parser_id: parsed.parser_id,
      parser_version: parsed.parser_version,
      ingest_timestamp: this.now(),
      event_attributes: parsed.attributes,
    };
    return { status: "ok", event };
  }

  private failure(input: RawLogInput, parsed: ParsedEvent, stage: ParseFailure["failure_stage"], code: ParseFailure["failure_code"], message: string): ParseFailure {
    return {
      _timestamp: parsed._timestamp ?? input.received_at,
      raw_log: parsed.raw_log || input.raw_log,
      source_type: parsed.source_type ?? input.source_type,
      source_name: parsed.source_name ?? input.source_name,
      collector_id: input.collector_id,
      parser_id: parsed.parser_id,
      parser_version: parsed.parser_version,
      failure_stage: stage,
      failure_code: code,
      failure_message: message,
    };
  }
}

// Keep the enum tokens imported so consumers can reach them through this module
// without a second import path.
export { SEVERITY_VALUES, RESULT_VALUES, SOURCE_TYPE_VALUES };
