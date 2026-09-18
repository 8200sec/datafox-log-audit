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

import type { Parser } from "./parser";
import type { ParsedEvent, RawLogInput } from "./types";

/**
 * Generic fallback for logs no dedicated parser claims. Never drops a log: it
 * preserves `raw_log` and the source hints, and leaves the rest at the
 * documented defaults (severity=info, result=unknown) for the Normalizer.
 */
export const FallbackParser: Parser = {
  id: "fallback",
  name: "Generic Fallback",
  version: "1.0.0",
  priority: -100,
  supportedSourceTypes: [],
  detect: () => true,
  parse: (input: RawLogInput): ParsedEvent => ({
    parser_id: "fallback",
    parser_version: "1.0.0",
    raw_log: input.raw_log,
    source_type: input.source_type,
    source_name: input.source_name,
    severity: "info",
    result: "unknown",
    message: "Unrecognized log format",
  }),
};

/**
 * Minimal parser used only to exercise the framework. Emits unnormalized
 * aliases (`warning` → medium, `ok` → success) so tests can assert the
 * Normalizer coerces them.
 */
export const DummyParser: Parser = {
  id: "dummy",
  name: "Dummy Test Parser",
  version: "1.0.0",
  priority: 100,
  supportedSourceTypes: ["test"],
  detect: (input: RawLogInput) =>
    input.source_type === "test" || input.raw_log.includes("DUMMY"),
  parse: (input: RawLogInput): ParsedEvent => ({
    parser_id: "dummy",
    parser_version: "1.0.0",
    raw_log: input.raw_log,
    _timestamp: input.received_at,
    source_type: "application",
    source_name: "dummy-source",
    hostname: "dummy-host",
    src_ip: "10.0.0.7",
    src_port: 1234,
    dst_ip: "10.0.0.8",
    dst_port: 443,
    username: "alice",
    category: "test",
    event_type: "dummy_event",
    action: "test",
    severity: "warning",
    result: "ok",
    message: "parsed by dummy",
    attributes: { "dummy.marker": true },
  }),
};
