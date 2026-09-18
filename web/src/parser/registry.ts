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
import type { RawLogInput } from "./types";

/**
 * Ordered, self-describing parser lookup. New parsers register themselves — the
 * dispatcher never grows a vendor switch. Priority decides order; `detect`
 * decides a match; a fallback parser catches everything else.
 */
export class ParserRegistry {
  private parsers: Parser[] = [];
  private fallback: Parser | null = null;

  /** Add a parser. Duplicate `id` throws (id is the stable wire identity). */
  register(parser: Parser): void {
    if (this.parsers.some((p) => p.id === parser.id)) {
      throw new Error(`parser id already registered: ${parser.id}`);
    }
    this.parsers.push(parser);
  }

  /** Set the parser used when nothing matches. */
  setFallback(parser: Parser): void {
    this.fallback = parser;
  }

  lookup(id: string): Parser | undefined {
    return this.parsers.find((p) => p.id === id);
  }

  getFallback(): Parser | null {
    return this.fallback;
  }

  /** All registered parsers, highest priority first (stable for equal priority). */
  list(): Parser[] {
    return [...this.parsers].sort((a, b) => b.priority - a.priority);
  }

  /** Parsers whose `detect` accepts the input, in priority order. */
  detect(input: RawLogInput): Parser[] {
    return this.list().filter((p) => p.detect(input));
  }
}
