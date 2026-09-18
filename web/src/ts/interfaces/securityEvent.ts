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

export type SecurityEventSeverity = "critical" | "high" | "medium" | "low" | "info";

export type SecurityEventStatus = "open" | "acknowledged" | "resolved" | "closed";

export type SecurityEventCategory =
  | "authentication"
  | "privilege"
  | "network"
  | "malware"
  | "policy"
  | "data_access"
  | "system"
  | "other";

export type SecurityEventActionType = "acknowledge" | "resolve" | "close";

/** Current state of one security event, mirrored from the W3-08 backend. */
export interface SecurityEvent {
  event_id: string;
  tenant_id: string;
  rule_id: string;
  rule_version: string;
  title: string;
  description?: string;
  category: SecurityEventCategory;
  event_type: string;
  severity: SecurityEventSeverity;
  status: SecurityEventStatus;
  first_seen: number;
  last_seen: number;
  event_count: number;
  src_ip?: string;
  dst_ip?: string;
  username?: string;
  asset_id?: string;
  related_event_ids?: string[];
  evidence: Record<string, unknown>;
  created_at: number;
  updated_at: number;
}

/** One workflow audit record (append-only history). */
export interface SecurityEventAction {
  id: string;
  tenant_id: string;
  security_event_id: string;
  action: SecurityEventActionType;
  from_status: SecurityEventStatus;
  to_status: SecurityEventStatus;
  actor_id: string;
  comment?: string | null;
  created_at: number;
}

/** List endpoint query params (all optional). */
export interface SecurityEventFilter {
  status?: SecurityEventStatus;
  severity?: SecurityEventSeverity;
  rule_id?: string;
  event_type?: string;
  src_ip?: string;
  username?: string;
  last_seen_from?: number;
  last_seen_to?: number;
  limit?: number;
  offset?: number;
  sort?: "desc" | "asc";
}

export interface SecurityEventListResponse {
  items: SecurityEvent[];
  total: number;
  limit: number;
  offset: number;
}

/** Summary counts for the four header tiles. */
export interface SecurityEventSummary {
  total: number;
  open: number;
  acknowledged: number;
  highOrCritical: number;
}
