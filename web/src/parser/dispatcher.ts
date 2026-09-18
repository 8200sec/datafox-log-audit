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

import type { Normalizer } from "./normalizer";
import type { Parser } from "./parser";
import type { ParserRegistry } from "./registry";
import type { DispatchResult, ParseFailure, RawLogInput } from "./types";

/**
 * Orchestrates detect → parse → normalize for one raw log. Never throws: a
 * parser exception, a normalization failure, or a total miss all resolve to a
 * structured `ParseFailure` — a log is never silently dropped.
 */
export class Dispatcher {
  constructor(
    private readonly registry: ParserRegistry,
    private readonly normalizer: Normalizer,
  ) {}

  dispatch(input: RawLogInput): DispatchResult {
    const matched = this.safeDetect(input);

    for (const parser of matched) {
      try {
        const parsed = parser.parse(input);
        return this.normalizer.normalize(parsed, input);
      } catch (err) {
        // A matched parser threw — fall through to the next match; the last
        // throw is reported as PARSER_EXCEPTION so nothing is lost.
        if (parser === matched[matched.length - 1]) {
          return {
            status: "failure",
            failure: this.failure(input, parser, "parse", "PARSER_EXCEPTION", errMessage(err)),
          };
        }
      }
    }

    const fallback = this.registry.getFallback();
    if (fallback) {
      try {
        return this.normalizer.normalize(fallback.parse(input), input);
      } catch (err) {
        return {
          status: "failure",
          failure: this.failure(input, fallback, "parse", "PARSER_EXCEPTION", errMessage(err)),
        };
      }
    }

    return {
      status: "failure",
      failure: this.failure(input, undefined, "detect", "UNSUPPORTED_FORMAT", "no parser matched and no fallback configured"),
    };
  }

  private safeDetect(input: RawLogInput): Parser[] {
    try {
      return this.registry.detect(input);
    } catch {
      return [];
    }
  }

  private failure(
    input: RawLogInput,
    parser: Parser | undefined,
    stage: ParseFailure["failure_stage"],
    code: ParseFailure["failure_code"],
    message: string,
  ): ParseFailure {
    return {
      _timestamp: input.received_at,
      raw_log: input.raw_log,
      source_type: input.source_type,
      source_name: input.source_name,
      collector_id: input.collector_id,
      parser_id: parser?.id,
      parser_version: parser?.version,
      failure_stage: stage,
      failure_code: code,
      failure_message: message,
    };
  }
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
