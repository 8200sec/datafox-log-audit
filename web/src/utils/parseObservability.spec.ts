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

import { describe, expect, it } from "vitest";

import {
  classifyParser,
  computeObservabilityStats,
  formatPercent,
  histogramIntervalForRange,
  rangeToMillis,
  safeRatio,
  type FailureCodeCount,
  type ParserCount,
  type SourceCount,
} from "./parseObservability";

const parser = (parser_id: string, cnt: number): ParserCount => ({ parser_id, cnt });
const source = (source_name: string, cnt: number): SourceCount => ({ source_name, cnt });
const failure = (failure_code: string, cnt: number): FailureCodeCount => ({
  failure_code,
  cnt,
});

function sample() {
  return computeObservabilityStats({
    parserCounts: [
      parser("linux-auth", 30),
      parser("generic-syslog", 40),
      parser("generic-json", 10),
      parser("fallback", 20),
    ],
    fallbackSources: [source("edge01", 15), source("edge02", 5)],
    failureCodes: [failure("INVALID_TIMESTAMP", 4), failure("PARSER_EXCEPTION", 1)],
    failureSources: [source("edge02", 5)],
  });
}

describe("classifyParser", () => {
  it("maps known parser ids to their class", () => {
    expect(classifyParser("linux-auth")).toBe("specialized");
    expect(classifyParser("generic-json")).toBe("generic");
    expect(classifyParser("generic-syslog")).toBe("generic");
    expect(classifyParser("fallback")).toBe("fallback");
  });

  it("defaults unknown parser ids to generic", () => {
    expect(classifyParser("dummy")).toBe("generic");
    expect(classifyParser("cisco-asa")).toBe("generic");
  });
});

describe("safeRatio", () => {
  it("returns the fraction for a non-zero denominator", () => {
    expect(safeRatio(30, 100)).toBe(0.3);
  });

  it("returns 0 on a zero denominator instead of NaN/Infinity", () => {
    expect(safeRatio(0, 0)).toBe(0);
    expect(safeRatio(5, 0)).toBe(0);
  });
});

describe("computeObservabilityStats", () => {
  it("computes specialized/generic/fallback counts from parser ids", () => {
    const s = sample();
    expect(s.specialized_count).toBe(30);
    expect(s.generic_count).toBe(50);
    expect(s.fallback_count).toBe(20);
  });

  it("classifies historical events by parser_id even without parser_quality", () => {
    // A parser_count row carries only parser_id — mirroring historical events
    // ingested before parser_quality was written. Classification must still work.
    const s = computeObservabilityStats({
      parserCounts: [parser("linux-auth", 5), parser("fallback", 2)],
      fallbackSources: [],
      failureCodes: [],
      failureSources: [],
    });
    expect(s.specialized_count).toBe(5);
    expect(s.fallback_count).toBe(2);
    expect(s.total_ingested).toBe(7);
  });

  it("derives total_ingested from the per-parser counts", () => {
    expect(sample().total_ingested).toBe(100);
  });

  it("computes ratios against total_ingested", () => {
    const s = sample();
    expect(s.specialized_ratio).toBeCloseTo(0.3);
    expect(s.generic_ratio).toBeCloseTo(0.5);
    expect(s.fallback_ratio).toBeCloseTo(0.2);
  });

  it("computes parse_failure_ratio with failures in the denominator", () => {
    const s = sample();
    expect(s.parse_failure_count).toBe(5);
    expect(s.parse_failure_ratio).toBeCloseTo(5 / 105);
  });

  it("keeps parser usage sorted by count desc with percentages", () => {
    const usage = sample().parser_usage;
    expect(usage[0]).toEqual({ parser_id: "generic-syslog", count: 40, percentage: 0.4 });
    expect(usage.map((u) => u.count)).toEqual([40, 30, 20, 10]);
  });

  it("sorts failure reasons by count desc", () => {
    expect(sample().failure_reasons).toEqual([
      { name: "INVALID_TIMESTAMP", count: 4 },
      { name: "PARSER_EXCEPTION", count: 1 },
    ]);
  });

  it("sorts fallback and failure sources by count desc", () => {
    expect(sample().fallback_sources).toEqual([
      { name: "edge01", count: 15 },
      { name: "edge02", count: 5 },
    ]);
    expect(sample().failure_sources).toEqual([{ name: "edge02", count: 5 }]);
  });

  it("treats a null source_name as a dash placeholder", () => {
    const s = computeObservabilityStats({
      parserCounts: [parser("fallback", 1)],
      fallbackSources: [{ source_name: null as unknown as string, cnt: 1 }],
      failureCodes: [],
      failureSources: [],
    });
    expect(s.fallback_sources[0].name).toBe("-");
  });

  it("returns all zeros for empty input", () => {
    const s = computeObservabilityStats({
      parserCounts: [],
      fallbackSources: [],
      failureCodes: [],
      failureSources: [],
    });
    expect(s.total_ingested).toBe(0);
    expect(s.specialized_ratio).toBe(0);
    expect(s.generic_ratio).toBe(0);
    expect(s.fallback_ratio).toBe(0);
    expect(s.parse_failure_ratio).toBe(0);
    expect(s.parser_usage).toEqual([]);
  });

  it("does not mix fallback into parse failures", () => {
    // fallback events are successes (audit_events); only the failure stream
    // counts as failures. Verify the two totals stay independent.
    const s = sample();
    expect(s.fallback_count).toBe(20);
    expect(s.parse_failure_count).toBe(5);
    expect(s.fallback_count + s.parse_failure_count).toBe(25);
  });
});

describe("rangeToMillis", () => {
  it("maps presets to millisecond spans", () => {
    expect(rangeToMillis("15m")).toBe(15 * 60 * 1000);
    expect(rangeToMillis("1h")).toBe(60 * 60 * 1000);
    expect(rangeToMillis("24h")).toBe(24 * 60 * 60 * 1000);
    expect(rangeToMillis("7d")).toBe(7 * 24 * 60 * 60 * 1000);
  });
});

describe("histogramIntervalForRange", () => {
  it("maps presets to histogram bucket intervals", () => {
    expect(histogramIntervalForRange("15m")).toBe("1 minute");
    expect(histogramIntervalForRange("1h")).toBe("5 minute");
    expect(histogramIntervalForRange("24h")).toBe("1 hour");
    expect(histogramIntervalForRange("7d")).toBe("1 day");
  });
});

describe("formatPercent", () => {
  it("rounds to a whole percent", () => {
    expect(formatPercent(0.125)).toBe("13%");
    expect(formatPercent(0)).toBe("0%");
    expect(formatPercent(1)).toBe("100%");
  });
});
