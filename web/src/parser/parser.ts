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

import type { ParsedEvent, RawLogInput } from "./types";

/**
 * Contract every parser implements. `detect` and `parse` are deliberately
 * separate: `detect` is a cheap "can I handle this?" check; `parse` does the
 * full extraction and may throw — the dispatcher turns throws into a
 * PARSER_EXCEPTION failure rather than losing the log.
 *
 * Parsers must NOT mutate `input.raw_log` — they return a new `ParsedEvent`.
 */
export interface Parser {
  id: string;
  name: string;
  /** Semver. Bump the major on a breaking output change (see audit-event-schema.md §8). */
  version: string;
  /** Higher is tried first. */
  priority: number;
  /** Source types this parser claims; empty = any. Used as a detect hint. */
  supportedSourceTypes: string[];
  detect(input: RawLogInput): boolean;
  parse(input: RawLogInput): ParsedEvent;
}
