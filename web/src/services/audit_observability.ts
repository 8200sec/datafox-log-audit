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

import http from "./http";

import {
  computeObservabilityStats,
  histogramIntervalForRange,
  rangeToMillis,
  type FailureCodeCount,
  type ObservabilityStats,
  type ParserCount,
  type SourceCount,
  type TimeRange,
} from "@/utils/parseObservability";

/** A raw failure record from the audit_parse_failures stream (µs timestamp). */
export interface FailureRecord {
  _timestamp: number;
  raw_log: string;
  source_name?: string;
  parser_id?: string;
  parser_version?: string;
  failure_stage: string;
  failure_code: string;
  failure_message: string;
}

export interface ObservabilityResult {
  stats: ObservabilityStats;
  failures: FailureRecord[];
  ingestionTrend: number[];
  failureTrend: number[];
}

interface SearchResponse {
  hits: any[];
}

/** Run one SQL aggregation and return its hit rows, or [] on any error (a
 *  missing stream — no failures yet — is an empty result, not a page error). */
async function runAggregation(
  org: string,
  sql: string,
  startTime: number,
  endTime: number,
  size: number,
): Promise<any[]> {
  try {
    const res = await http().post(`/api/${org}/_search?type=logs`, {
      query: { sql, start_time: startTime, end_time: endTime, size },
    });
    const data = res.data as SearchResponse;
    return data.hits ?? [];
  } catch {
    return [];
  }
}

/** Load the full observability payload for one org over a time range. */
export async function fetchObservability(
  org: string,
  range: TimeRange,
): Promise<ObservabilityResult> {
  const nowMs = Date.now();
  const startTime = (nowMs - rangeToMillis(range)) * 1000; // µs
  const endTime = nowMs * 1000;
  const interval = histogramIntervalForRange(range);

  const [parserHits, fallbackHits, failureCodeHits, failureSourceHits, failureRows, ingestTrendHits, failTrendHits] =
    await Promise.all([
      runAggregation(
        org,
        'SELECT parser_id, count(*) as cnt FROM "audit_events" GROUP BY parser_id',
        startTime,
        endTime,
        50,
      ),
      runAggregation(
        org,
        'SELECT source_name, count(*) as cnt FROM "audit_events" WHERE parser_id = \'fallback\' GROUP BY source_name',
        startTime,
        endTime,
        50,
      ),
      runAggregation(
        org,
        'SELECT failure_code, count(*) as cnt FROM "audit_parse_failures" GROUP BY failure_code',
        startTime,
        endTime,
        50,
      ),
      runAggregation(
        org,
        'SELECT source_name, count(*) as cnt FROM "audit_parse_failures" GROUP BY source_name',
        startTime,
        endTime,
        50,
      ),
      runAggregation(
        org,
        'SELECT * FROM "audit_parse_failures" ORDER BY _timestamp DESC LIMIT 100',
        startTime,
        endTime,
        100,
      ),
      runAggregation(
        org,
        `SELECT histogram(_timestamp, '${interval}') AS zo_sql_key, count(*) AS zo_sql_num FROM "audit_events" GROUP BY zo_sql_key ORDER BY zo_sql_key`,
        startTime,
        endTime,
        100,
      ),
      runAggregation(
        org,
        `SELECT histogram(_timestamp, '${interval}') AS zo_sql_key, count(*) AS zo_sql_num FROM "audit_parse_failures" GROUP BY zo_sql_key ORDER BY zo_sql_key`,
        startTime,
        endTime,
        100,
      ),
    ]);

  const stats = computeObservabilityStats({
    parserCounts: parserHits as ParserCount[],
    fallbackSources: fallbackHits as SourceCount[],
    failureCodes: failureCodeHits as FailureCodeCount[],
    failureSources: failureSourceHits as SourceCount[],
  });

  return {
    stats,
    failures: failureRows as FailureRecord[],
    ingestionTrend: ingestTrendHits.map((h) => h.zo_sql_num as number),
    failureTrend: failTrendHits.map((h) => h.zo_sql_num as number),
  };
}
