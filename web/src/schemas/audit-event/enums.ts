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

/// Standard enumerations for the AuditEvent v1 data model. Each value is a
/// stable wire-level token — never reorder or rename without a schema bump.

/** Event severity, normalized across every source (see docs/audit-event-schema.md). */
export const SEVERITY_VALUES = ["info", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITY_VALUES)[number];

/** Normalized outcome of the action an event records. */
export const RESULT_VALUES = ["success", "failure", "unknown"] as const;
export type Result = (typeof RESULT_VALUES)[number];

/**
 * High-level category of the emitting source. Covers the intended first-class
 * domains (Linux/Windows → `os`, firewall, router, database, web, application)
 * without enumerating vendors — a new device family is a new token here, never
 * a vendor-specific field on the event.
 */
export const SOURCE_TYPE_VALUES = [
  "os",
  "firewall",
  "router",
  "database",
  "web",
  "application",
  "network",
  "other",
] as const;
export type SourceType = (typeof SOURCE_TYPE_VALUES)[number];

/** Target OpenObserve stream names for the audit pipeline. */
export const AUDIT_STREAM_NAMES = {
  /** Parsed, normalized audit events (one per source log line). */
  AUDIT_EVENTS: "audit_events",
  /** Raw logs that failed to parse — retained for reprocessing, never dropped. */
  AUDIT_PARSE_FAILURES: "audit_parse_failures",
} as const;
