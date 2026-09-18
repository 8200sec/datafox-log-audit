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

import { describe, it, expect } from "vitest";
import {
  ParserRegistry,
  Normalizer,
  Dispatcher,
  FallbackParser,
  DummyParser,
  type Parser,
  type ParsedEvent,
  type RawLogInput,
} from "./index";

const FIXED_NOW = 1735689600999;
const normalizer = new Normalizer(() => FIXED_NOW);

const makeInput = (over: Partial<RawLogInput> = {}): RawLogInput => ({
  raw_log: "DUMMY test log line",
  received_at: 1735689600000,
  source_type: "test",
  source_name: "src-1",
  collector_id: "collector-1",
  tenant: { tenant_id: "tenant-trusted" },
  ...over,
});

const makeRegistry = (): ParserRegistry => {
  const r = new ParserRegistry();
  r.register(DummyParser);
  r.setFallback(FallbackParser);
  return r;
};

const makeDispatcher = (registry: ParserRegistry) => new Dispatcher(registry, normalizer);

describe("ParserRegistry", () => {
  it("1. registers and looks up a parser", () => {
    const r = new ParserRegistry();
    r.register(DummyParser);
    expect(r.lookup("dummy")).toBe(DummyParser);
    expect(r.lookup("missing")).toBeUndefined();
  });

  it("rejects a duplicate parser id", () => {
    const r = new ParserRegistry();
    r.register(DummyParser);
    expect(() => r.register(DummyParser)).toThrow(/already registered/);
  });

  it("2. orders parsers by priority (higher first)", () => {
    const low: Parser = { ...DummyParser, id: "low", priority: 1 };
    const high: Parser = { ...DummyParser, id: "high", priority: 10 };
    const mid: Parser = { ...DummyParser, id: "mid", priority: 5 };
    const r = new ParserRegistry();
    r.register(low);
    r.register(high);
    r.register(mid);
    expect(r.list().map((p) => p.id)).toEqual(["high", "mid", "low"]);
  });

  it("3. detect returns only matching parsers", () => {
    const r = new ParserRegistry();
    r.register(DummyParser);
    expect(r.detect(makeInput()).map((p) => p.id)).toEqual(["dummy"]);
    expect(r.detect(makeInput({ source_type: "firewall", raw_log: "something else" }))).toEqual([]);
  });
});

describe("Dispatcher", () => {
  it("4. parses and normalizes a matching log", () => {
    const result = makeDispatcher(makeRegistry()).dispatch(makeInput());
    expect(result.status).toBe("ok");
    if (result.status === "ok") {
      expect(result.event.severity).toBe("medium"); // "warning" → medium
      expect(result.event.result).toBe("success"); // "ok" → success
      expect(result.event.source_type).toBe("application");
      expect(result.event.username).toBe("alice");
    }
  });

  it("5. falls back when no parser matches", () => {
    const input = makeInput({ source_type: "unknown", raw_log: "no parser knows me" });
    const result = makeDispatcher(makeRegistry()).dispatch(input);
    expect(result.status).toBe("ok");
    if (result.status === "ok") {
      expect(result.event.parser_id).toBe("fallback");
    }
  });

  it("6. fallback preserves the minimum viable event", () => {
    const input = makeInput({ source_type: "unknown", raw_log: "garbage" });
    const result = makeDispatcher(makeRegistry()).dispatch(input);
    expect(result.status).toBe("ok");
    if (result.status === "ok") {
      expect(result.event.severity).toBe("info");
      expect(result.event.result).toBe("unknown");
      expect(result.event.raw_log).toBe("garbage");
      expect(result.event.event_id).toBeTruthy();
    }
  });

  it("7. turns a parser exception into a structured failure (no throw, no loss)", () => {
    const throwing: Parser = {
      id: "throwing",
      name: "Throwing",
      version: "1.0.0",
      priority: 1000,
      supportedSourceTypes: ["test"],
      detect: () => true,
      parse: () => {
        throw new Error("boom");
      },
    };
    const r = new ParserRegistry();
    r.register(throwing);
    r.setFallback(FallbackParser);
    const result = makeDispatcher(r).dispatch(makeInput());
    expect(result.status).toBe("failure");
    if (result.status === "failure") {
      expect(result.failure.failure_code).toBe("PARSER_EXCEPTION");
      expect(result.failure.failure_message).toContain("boom");
      expect(result.failure.raw_log).toBe(makeInput().raw_log);
    }
  });

  it("8. reports a normalization failure as INVALID_TIMESTAMP", () => {
    const badTs: Parser = {
      id: "bad-ts",
      name: "BadTs",
      version: "1.0.0",
      priority: 1000,
      supportedSourceTypes: ["test"],
      detect: () => true,
      parse: (): ParsedEvent => ({
        parser_id: "bad-ts",
        parser_version: "1.0.0",
        raw_log: "DUMMY x",
        _timestamp: Number.NaN,
        severity: "info",
      }),
    };
    const r = new ParserRegistry();
    r.register(badTs);
    r.setFallback(FallbackParser);
    const result = makeDispatcher(r).dispatch(makeInput());
    expect(result.status).toBe("failure");
    if (result.status === "failure") {
      expect(result.failure.failure_code).toBe("INVALID_TIMESTAMP");
    }
  });

  it("9. preserves raw_log byte-for-byte", () => {
    const raw = "odd \u0000 bytes \u2713 and 中文 and \r\n newline";
    const result = makeDispatcher(makeRegistry()).dispatch(makeInput({ raw_log: raw }));
    expect(result.status).toBe("ok");
    if (result.status === "ok") {
      expect(result.event.raw_log).toBe(raw);
    }
  });

  it("12. tenant_id always comes from trusted context, never the raw log", () => {
    const evil: Parser = {
      id: "evil",
      name: "Evil",
      version: "1.0.0",
      priority: 1000,
      supportedSourceTypes: ["test"],
      detect: () => true,
      parse: (input): ParsedEvent => ({
        parser_id: "evil",
        parser_version: "1.0.0",
        raw_log: input.raw_log,
        attributes: { tenant_id: "tenant-EVIL" },
      }),
    };
    const r = new ParserRegistry();
    r.register(evil);
    r.setFallback(FallbackParser);
    const result = makeDispatcher(r).dispatch(makeInput());
    expect(result.status).toBe("ok");
    if (result.status === "ok") {
      expect(result.event.tenant_id).toBe("tenant-trusted");
      // The smuggled value lands in attributes, not on the trusted tenant field.
      expect(result.event.event_attributes?.tenant_id).toBe("tenant-EVIL");
    }
  });

  it("13. writes parser_id and parser_version onto the event", () => {
    const result = makeDispatcher(makeRegistry()).dispatch(makeInput());
    expect(result.status).toBe("ok");
    if (result.status === "ok") {
      expect(result.event.parser_id).toBe("dummy");
      expect(result.event.parser_version).toBe("1.0.0");
    }
  });

  it("14. never crashes on malformed input", () => {
    const dispatcher = makeDispatcher(makeRegistry());
    const bad = makeInput({ raw_log: "\u0000\u0001\u0002 binary garbage", source_type: "other" });
    const result = dispatcher.dispatch(bad);
    expect(["ok", "failure"]).toContain(result.status);
  });
});

describe("Normalizer", () => {
  it("10. normalizes severity to the five-token enum", () => {
    expect(normalizer.normalizeSeverity("warning")).toBe("medium");
    expect(normalizer.normalizeSeverity("fatal")).toBe("critical");
    expect(normalizer.normalizeSeverity("error")).toBe("high");
    expect(normalizer.normalizeSeverity(undefined)).toBe("info");
    expect(normalizer.normalizeSeverity("gibberish")).toBe("info");
  });

  it("11. normalizes result to success/failure/unknown", () => {
    expect(normalizer.normalizeResult("ok")).toBe("success");
    expect(normalizer.normalizeResult("deny")).toBe("failure");
    expect(normalizer.normalizeResult(undefined)).toBe("unknown");
    expect(normalizer.normalizeResult("gibberish")).toBe("unknown");
  });
});
