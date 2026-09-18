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

import { z } from "zod";
import { RESULT_VALUES, SEVERITY_VALUES, SOURCE_TYPE_VALUES } from "./enums";

const port = z.number().int().min(0).max(65535);

export const AuditEventSchema = z.object({
  _timestamp: z.number(),
  event_id: z.string().min(1),
  tenant_id: z.string().min(1),
  source_type: z.enum(SOURCE_TYPE_VALUES),
  source_name: z.string().optional(),
  collector_id: z.string().optional(),
  vendor: z.string().optional(),
  product: z.string().optional(),
  product_version: z.string().optional(),
  hostname: z.string().optional(),
  asset_id: z.string().optional(),
  src_ip: z.string().optional(),
  src_port: port.optional(),
  dst_ip: z.string().optional(),
  dst_port: port.optional(),
  username: z.string().optional(),
  category: z.string().optional(),
  event_type: z.string().optional(),
  action: z.string().optional(),
  result: z.enum(RESULT_VALUES).optional(),
  severity: z.enum(SEVERITY_VALUES),
  message: z.string().optional(),
  raw_log: z.string().min(1),
  parser_id: z.string().optional(),
  parser_version: z.string().optional(),
  ingest_timestamp: z.number(),
  event_attributes: z.record(z.string(), z.unknown()).optional(),
});

export const AuditParseFailureSchema = z.object({
  _timestamp: z.number(),
  tenant_id: z.string().min(1),
  source_type: z.string().optional(),
  source_name: z.string().optional(),
  raw_log: z.string().min(1),
  parser_id: z.string().optional(),
  parser_version: z.string().optional(),
  error_message: z.string().min(1),
  ingest_timestamp: z.number(),
});

export type AuditEventInput = z.infer<typeof AuditEventSchema>;
export type AuditParseFailureInput = z.infer<typeof AuditParseFailureSchema>;
