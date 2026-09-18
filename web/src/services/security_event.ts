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

import axios from "axios";

import http from "./http";

import type {
  SecurityEvent,
  SecurityEventAction,
  SecurityEventActionType,
  SecurityEventFilter,
  SecurityEventListResponse,
  SecurityEventSummary,
} from "@/ts/interfaces";

/** Build a querystring from the non-empty filter fields. */
function toQuery(filter: SecurityEventFilter): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filter)) {
    if (value === undefined || value === null || value === "") continue;
    params.set(key, String(value));
  }
  const qs = params.toString();
  return qs ? `?${qs}` : "";
}

/** List security events with server-side filters + pagination. */
export async function listSecurityEvents(
  org: string,
  filter: SecurityEventFilter,
): Promise<SecurityEventListResponse> {
  const res = await http().get(`/api/${org}/security-events${toQuery(filter)}`);
  return res.data as SecurityEventListResponse;
}

/** Fetch one security event by id. */
export async function getSecurityEvent(org: string, eventId: string): Promise<SecurityEvent> {
  const res = await http().get(`/api/${org}/security-events/${eventId}`);
  return res.data as SecurityEvent;
}

/** Fetch the workflow audit trail for one security event. */
export async function listSecurityEventActions(
  org: string,
  eventId: string,
): Promise<SecurityEventAction[]> {
  const res = await http().get(`/api/${org}/security-events/${eventId}/actions`);
  return res.data as SecurityEventAction[];
}

/**
 * Apply a workflow transition (acknowledge / resolve / close). The backend is
 * the state-machine authority: an illegal transition rejects with 409.
 */
export async function transitionSecurityEvent(
  org: string,
  eventId: string,
  action: SecurityEventActionType,
  comment?: string,
): Promise<SecurityEvent> {
  const res = await http().post(`/api/${org}/security-events/${eventId}/${action}`, {
    comment: comment || null,
  });
  return res.data as SecurityEvent;
}

/** True when an axios error is a 409 (concurrent/illegal status transition). */
export function isConflictError(error: unknown): boolean {
  return axios.isAxiosError(error) && error.response?.status === 409;
}

/**
 * Summary counts for the header tiles, derived from the list endpoint's `total`
 * — no dedicated summary service. Each bucket is a `limit=1` list call.
 */
export async function fetchSecurityEventSummary(org: string): Promise<SecurityEventSummary> {
  const [total, open, acknowledged, high, critical] = await Promise.all([
    listSecurityEvents(org, { limit: 1 }),
    listSecurityEvents(org, { status: "open", limit: 1 }),
    listSecurityEvents(org, { status: "acknowledged", limit: 1 }),
    listSecurityEvents(org, { severity: "high", limit: 1 }),
    listSecurityEvents(org, { severity: "critical", limit: 1 }),
  ]);
  return {
    total: total.total,
    open: open.total,
    acknowledged: acknowledged.total,
    highOrCritical: high.total + critical.total,
  };
}
