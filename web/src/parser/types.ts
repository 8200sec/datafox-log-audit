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

/**
 * Trusted server-side tenant context. `tenant_id` comes from the authenticated
 * ingest context — the raw log is NEVER a source of tenant identity.
 */
export interface TenantContext {
  tenant_id: string;
}

/** Optional transport metadata captured by the collector / ingest edge. */
export interface TransportMetadata {
  protocol?: string;
  remote_ip?: string;
  remote_port?: number;
}

/** What the parser pipeline receives for one log line. */
export interface RawLogInput {
  raw_log: string;
  /** Epoch ms — when the collector/edge received the line. */
  received_at: number;
  /** Optional source hints; detection/parse may refine these. */
  source_type?: string;
  source_name?: string;
  collector_id?: string;
  tenant: TenantContext;
  transport?: TransportMetadata;
}

/**
 * Intermediate representation a parser emits. Field values are UNNORMALIZED —
 * the Normalizer owns severity/result/source_type/ip/port/timestamp coercion.
 * `raw_log` MUST byte-for-byte equal the input (invariant).
 */
export interface ParsedEvent {
  parser_id: string;
  parser_version: string;
  raw_log: string;
  /** Epoch ms, or undefined when the source has no timestamp (→ received_at). */
  _timestamp?: number;
  severity?: string;
  result?: string;
  source_type?: string;
  source_name?: string;
  vendor?: string;
  product?: string;
  product_version?: string;
  hostname?: string;
  asset_id?: string;
  src_ip?: string;
  src_port?: number | string;
  dst_ip?: string;
  dst_port?: number | string;
  username?: string;
  category?: string;
  event_type?: string;
  action?: string;
  message?: string;
  /** Vendor-specific fields — land in AuditEvent.event_attributes. */
  attributes?: Record<string, unknown>;
}

export const FAILURE_CODES = [
  "UNSUPPORTED_FORMAT",
  "MISSING_REQUIRED_FIELD",
  "INVALID_TIMESTAMP",
  "INVALID_IP",
  "INVALID_ENUM",
  "PARSER_EXCEPTION",
  "NORMALIZATION_FAILED",
] as const;
export type FailureCode = (typeof FAILURE_CODES)[number];

/** Which phase of the pipeline the failure happened in. */
export type FailureStage = "detect" | "parse" | "normalize";

/** Structured failure — a log that could not become an AuditEvent, never dropped. */
export interface ParseFailure {
  _timestamp: number;
  raw_log: string;
  source_type?: string;
  source_name?: string;
  collector_id?: string;
  parser_id?: string;
  parser_version?: string;
  failure_stage: FailureStage;
  failure_code: FailureCode;
  failure_message: string;
}

/** Result of the normalize step — either a valid event or a structured failure. */
export type NormalizeResult =
  | { status: "ok"; event: AuditEvent }
  | { status: "failure"; failure: ParseFailure };

/** Result of dispatching one raw log through the registry + normalizer. */
export type DispatchResult =
  | { status: "ok"; event: AuditEvent }
  | { status: "failure"; failure: ParseFailure };
