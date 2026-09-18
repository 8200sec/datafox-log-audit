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

import type { AuditEvent, AuditParseFailure } from "./types";

const T = 1735689600000; // 2026-01-01T00:00:00Z

/** Full example — a firewall deny event with vendor extensions in `event_attributes`. */
export const auditEventFirewallDenyFixture: AuditEvent = {
  _timestamp: T,
  event_id: "evt-01J2A1B2C3D4E5F6G7H8J9K0",
  tenant_id: "tenant-datafox-demo",
  source_type: "firewall",
  source_name: "edge-fw-01",
  collector_id: "collector-syslog-3",
  vendor: "Cisco",
  product: "ASA",
  product_version: "9.18.4",
  hostname: "edge-fw-01",
  asset_id: "asset-1001",
  src_ip: "10.20.0.5",
  src_port: 52314,
  dst_ip: "172.16.0.10",
  dst_port: 443,
  username: "jdoe",
  category: "network",
  event_type: "connection_denied",
  action: "deny",
  result: "failure",
  severity: "high",
  message: "Connection denied by access-list",
  raw_log: 'Jan  1 08:00:00 edge-fw-01 %ASA-4-106023: Deny tcp src outside:10.20.0.5/52314 dst inside:172.16.0.10/443 by access-group "outside-in"',
  parser_id: "cisco-asa",
  parser_version: "1.2.0",
  ingest_timestamp: T + 1200,
  event_attributes: {
    "cisco.asa.message_id": "106023",
    "cisco.asa.access_group": "outside-in",
    "cisco.asa.interface": "outside",
  },
};

/** Minimal example — only the required fields, nothing vendor-specific. */
export const auditEventMinimalFixture: AuditEvent = {
  _timestamp: T,
  event_id: "evt-min-00000000000000000001",
  tenant_id: "tenant-datafox-demo",
  source_type: "application",
  severity: "info",
  raw_log: "application started",
  ingest_timestamp: T + 1,
};

/** Example parse failure — an unrecognized line retained for reprocessing. */
export const auditParseFailureFixture: AuditParseFailure = {
  _timestamp: T,
  tenant_id: "tenant-datafox-demo",
  source_name: "unknown-device",
  raw_log: "\u001b[31mgarbage line with no known format\u001b[0m",
  error_message: "No parser matched the source",
  ingest_timestamp: T + 500,
};
