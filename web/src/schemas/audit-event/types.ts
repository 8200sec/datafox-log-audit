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

import type { Result, Severity, SourceType } from "./enums";

/**
 * A single normalized audit event (AuditEvent v1). One instance per source log
 * line. Timestamps are epoch milliseconds.
 *
 * Vendor-specific fields must NOT be added here — they belong in
 * `event_attributes` (see docs/audit-event-schema.md § Extension fields).
 */
export interface AuditEvent {
  /** Event time. When the source has no timestamp, the parser falls back to ingest time. */
  _timestamp: number;
  /** Unique, stable event id (see docs/audit-event-schema.md § event_id). */
  event_id: string;
  /** Multi-tenant id. Assigned server-side — never trusted from the client. */
  tenant_id: string;
  /** High-level source category (os / firewall / router / database / …). */
  source_type: SourceType;
  /** Identifier of the specific source (host, device, app instance). */
  source_name?: string;
  /** Collector / agent that forwarded the event. */
  collector_id?: string;
  vendor?: string;
  product?: string;
  product_version?: string;
  hostname?: string;
  asset_id?: string;
  src_ip?: string;
  src_port?: number;
  dst_ip?: string;
  dst_port?: number;
  username?: string;
  /** Broad event category (authentication, network, system, …). */
  category?: string;
  /** Specific event type, e.g. `login_failed`. Open — set by the parser. */
  event_type?: string;
  /** The action the event records, e.g. `deny`, `login`, `update`. */
  action?: string;
  result?: Result;
  severity: Severity;
  /** Human-readable summary of the event. */
  message?: string;
  /** The original, unmodified log line. Always retained. */
  raw_log: string;
  parser_id?: string;
  parser_version?: string;
  /** Server-assigned ingestion time (epoch ms). */
  ingest_timestamp: number;
  /** Vendor-specific extension fields. Flat or namespaced keys. */
  event_attributes?: Record<string, unknown>;
}

/**
 * A raw log line that the pipeline could not parse (target stream
 * `audit_parse_failures`). Retained so a future parser version can reprocess it.
 */
export interface AuditParseFailure {
  _timestamp: number;
  tenant_id: string;
  /** Source category when determinable before parsing; otherwise omitted. */
  source_type?: string;
  source_name?: string;
  raw_log: string;
  parser_id?: string;
  parser_version?: string;
  /** Why parsing failed (no matching parser, schema error, …). */
  error_message: string;
  ingest_timestamp: number;
}
