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

// Pure ratio/aggregation math for the Parse Status page. Kept free of Vue/http
// so the denominator rules and zero-denominator handling are unit-testable.

export const PARSER_QUALITIES = ["specialized", "generic", "fallback"] as const;
export type ParserQuality = (typeof PARSER_QUALITIES)[number];

export const TIME_RANGES = ["15m", "1h", "24h", "7d"] as const;
export type TimeRange = (typeof TIME_RANGES)[number];

/** One `GROUP BY parser_id` row from the audit_events stream. */
export interface ParserCount {
  parser_id: string;
  cnt: number;
}

/** One `GROUP BY source_name` row. */
export interface SourceCount {
  source_name: string;
  cnt: number;
}

/** One `GROUP BY failure_code` row from the audit_parse_failures stream. */
export interface FailureCodeCount {
  failure_code: string;
  cnt: number;
}

export interface ParserUsageRow {
  parser_id: string;
  count: number;
  percentage: number;
}

export interface NamedCount {
  name: string;
  count: number;
}

export interface ObservabilityStats {
  total_ingested: number;
  specialized_count: number;
  specialized_ratio: number;
  generic_count: number;
  generic_ratio: number;
  fallback_count: number;
  fallback_ratio: number;
  parse_failure_count: number;
  parse_failure_ratio: number;
  parser_usage: ParserUsageRow[];
  failure_reasons: NamedCount[];
  fallback_sources: NamedCount[];
  failure_sources: NamedCount[];
}

/** Ratio with a zero-denominator guard — 0 / 0 is 0, not NaN. */
export function safeRatio(numerator: number, denominator: number): number {
  if (denominator <= 0) return 0;
  return numerator / denominator;
}

/**
 * Query-side parser classification — mirrors the Rust `classify_parser` in
 * `src/audit_parser/src/observability.rs`. `parser_id` is a top-level field that
 * exists on every event (including historical ones ingested before
 * `parser_quality` was written), so mapping here keeps classification correct
 * without backfilling historical audit_events.
 */
export function classifyParser(parserId: string): ParserQuality {
  switch (parserId) {
    case "linux-auth":
      return "specialized";
    case "generic-json":
    case "generic-syslog":
      return "generic";
    case "fallback":
      return "fallback";
    default:
      return "generic";
  }
}

/**
 * Reduce raw aggregation rows into the summary stats. `total_ingested` is the
 * sum of the per-parser counts (parser_id is always present on an event), so it
 * never double-counts and never drifts from the per-parser breakdown. Failure
 * counts come from the failure stream only — a failure is never in audit_events.
 */
export function computeObservabilityStats(input: {
  parserCounts: ParserCount[];
  fallbackSources: SourceCount[];
  failureCodes: FailureCodeCount[];
  failureSources: SourceCount[];
}): ObservabilityStats {
  const totalIngested = input.parserCounts.reduce((sum, p) => sum + p.cnt, 0);

  const qualityCount = (q: ParserQuality): number =>
    input.parserCounts
      .filter((p) => classifyParser(p.parser_id) === q)
      .reduce((sum, p) => sum + p.cnt, 0);
  const specialized = qualityCount("specialized");
  const generic = qualityCount("generic");
  const fallback = qualityCount("fallback");

  const parseFailureCount = input.failureCodes.reduce((sum, f) => sum + f.cnt, 0);

  return {
    total_ingested: totalIngested,
    specialized_count: specialized,
    specialized_ratio: safeRatio(specialized, totalIngested),
    generic_count: generic,
    generic_ratio: safeRatio(generic, totalIngested),
    fallback_count: fallback,
    fallback_ratio: safeRatio(fallback, totalIngested),
    parse_failure_count: parseFailureCount,
    // Failures are a separate stream, so the denominator is successes + failures.
    parse_failure_ratio: safeRatio(parseFailureCount, totalIngested + parseFailureCount),
    parser_usage: input.parserCounts
      .map((p) => ({
        parser_id: p.parser_id,
        count: p.cnt,
        percentage: safeRatio(p.cnt, totalIngested),
      }))
      .sort((a, b) => b.count - a.count),
    failure_reasons: input.failureCodes
      .map((f) => ({ name: f.failure_code, count: f.cnt }))
      .sort((a, b) => b.count - a.count),
    fallback_sources: input.fallbackSources
      .map((s) => ({ name: s.source_name ?? "-", count: s.cnt }))
      .sort((a, b) => b.count - a.count),
    failure_sources: input.failureSources
      .map((s) => ({ name: s.source_name ?? "-", count: s.cnt }))
      .sort((a, b) => b.count - a.count),
  };
}

/** Millisecond span for a preset time range. */
export function rangeToMillis(range: TimeRange): number {
  switch (range) {
    case "15m":
      return 15 * 60 * 1000;
    case "1h":
      return 60 * 60 * 1000;
    case "24h":
      return 24 * 60 * 60 * 1000;
    case "7d":
      return 7 * 24 * 60 * 60 * 1000;
  }
}

/** OpenObserve histogram bucket interval for a preset range (≈12–15 buckets). */
export function histogramIntervalForRange(range: TimeRange): string {
  switch (range) {
    case "15m":
      return "1 minute";
    case "1h":
      return "5 minute";
    case "24h":
      return "1 hour";
    case "7d":
      return "1 day";
  }
}

/** Format a 0..1 ratio as a whole-percent string, e.g. 0.125 → "13%". */
export function formatPercent(ratio: number): string {
  return `${Math.round(ratio * 100)}%`;
}
