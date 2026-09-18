<!-- Copyright 2026 DataFox Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
-->

<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useStore } from "vuex";

import OButton from "@/lib/core/Button/OButton.vue";
import OButtonGroup from "@/lib/core/Button/OButtonGroup.vue";
import OEmptyState from "@/lib/core/EmptyState/OEmptyState.vue";
import OPageLayout from "@/lib/core/PageLayout/OPageLayout.vue";
import OSparkline from "@/lib/data/Sparkline/OSparkline.vue";
import type { OTableColumnDef } from "@/lib/core/Table/OTable.types";
import OTable from "@/lib/core/Table/OTable.vue";
import OStatStrip from "@/lib/data/StatStrip/OStatStrip.vue";
import type { StatItem } from "@/lib/data/StatStrip/OStatStrip.types";
import { fetchObservability, type FailureRecord } from "@/services/audit_observability";
import { raw, useI18nTyped } from "@/types/i18n";
import { formatTimestamp } from "@/utils/date";
import {
  formatPercent,
  TIME_RANGES,
  type ObservabilityStats,
  type TimeRange,
} from "@/utils/parseObservability";

const store = useStore();
const { t } = useI18nTyped();

const org = computed(() => store.state.selectedOrganization.identifier);
const range = ref<TimeRange>("1h");
const loading = ref(false);
const error = ref<string | null>(null);
const stats = ref<ObservabilityStats | null>(null);
const failures = ref<FailureRecord[]>([]);
const ingestionTrend = ref<number[]>([]);
const failureTrend = ref<number[]>([]);

async function load(): Promise<void> {
  if (!org.value) return;
  loading.value = true;
  error.value = null;
  try {
    const result = await fetchObservability(org.value, range.value);
    stats.value = result.stats;
    failures.value = result.failures;
    ingestionTrend.value = result.ingestionTrend;
    failureTrend.value = result.failureTrend;
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e);
  } finally {
    loading.value = false;
  }
}

function setRange(next: TimeRange): void {
  if (range.value === next) return;
  range.value = next;
  void load();
}

onMounted(() => {
  void load();
});

const hasData = computed(
  () =>
    (stats.value?.total_ingested ?? 0) > 0 ||
    (stats.value?.parse_failure_count ?? 0) > 0 ||
    failures.value.length > 0,
);

const summaryStats = computed<StatItem[]>(() => {
  const s = stats.value;
  return [
    {
      key: "total",
      label: t("parseStatus.totalIngested"),
      value: s?.total_ingested ?? 0,
      icon: "description",
      tone: "primary",
      dataTest: "parse-status-stat-total",
    },
    {
      key: "specialized",
      label: t("parseStatus.specializedRatio"),
      value: formatPercent(s?.specialized_ratio ?? 0),
      sub: t("parseStatus.logsCount", { count: s?.specialized_count ?? 0 }, s?.specialized_count ?? 0),
      icon: "auto-awesome",
      tone: "success",
      dataTest: "parse-status-stat-specialized",
    },
    {
      key: "generic",
      label: t("parseStatus.genericRatio"),
      value: formatPercent(s?.generic_ratio ?? 0),
      sub: t("parseStatus.logsCount", { count: s?.generic_count ?? 0 }, s?.generic_count ?? 0),
      icon: "function",
      tone: "info",
      dataTest: "parse-status-stat-generic",
    },
    {
      key: "fallback",
      label: t("parseStatus.fallbackCount"),
      value: s?.fallback_count ?? 0,
      sub: raw(formatPercent(s?.fallback_ratio ?? 0)),
      icon: "data-plus-line",
      tone: "warning",
      dataTest: "parse-status-stat-fallback",
    },
    {
      key: "failure",
      label: t("parseStatus.parseFailureCount"),
      value: s?.parse_failure_count ?? 0,
      sub: raw(formatPercent(s?.parse_failure_ratio ?? 0)),
      icon: "notifications-active",
      tone: "error",
      dataTest: "parse-status-stat-failure",
    },
  ];
});

interface FailureDisplayRow {
  time: string;
  source: string;
  parser_id: string;
  failure_stage: string;
  failure_code: string;
  failure_message: string;
  raw_log: string;
}

const parserUsageRows = computed(
  () =>
    stats.value?.parser_usage.map((u) => ({
      parser_id: u.parser_id,
      count: u.count,
      percentage: formatPercent(u.percentage),
    })) ?? [],
);

const failureReasonRows = computed(() => stats.value?.failure_reasons ?? []);
const fallbackSourceRows = computed(() => stats.value?.fallback_sources ?? []);
const failureSourceRows = computed(() => stats.value?.failure_sources ?? []);

const failureRows = computed<FailureDisplayRow[]>(() =>
  failures.value.map((f) => ({
    time: formatTimestamp(f._timestamp, "yyyy-MM-dd HH:mm:ss"),
    source: f.source_name ?? "-",
    parser_id: f.parser_id ?? "-",
    failure_stage: f.failure_stage,
    failure_code: f.failure_code,
    failure_message: f.failure_message,
    raw_log: f.raw_log,
  })),
);

function failureRowKey(row: FailureDisplayRow): string {
  return `${row.time}:${row.raw_log}`;
}

const parserUsageColumns: OTableColumnDef[] = [
  { id: "parser_id", header: t("parseStatus.parserId"), accessorKey: "parser_id", meta: { isName: true } },
  { id: "count", header: t("parseStatus.count"), accessorKey: "count", size: 120 },
  { id: "percentage", header: t("parseStatus.percentage"), accessorKey: "percentage", size: 120 },
];

const namedCountColumns: OTableColumnDef[] = [
  { id: "name", header: t("parseStatus.name"), accessorKey: "name", meta: { isName: true } },
  { id: "count", header: t("parseStatus.count"), accessorKey: "count", size: 120 },
];

const failureReasonColumns: OTableColumnDef[] = [
  { id: "name", header: t("parseStatus.failureCode"), accessorKey: "name", meta: { isName: true } },
  { id: "count", header: t("parseStatus.count"), accessorKey: "count", size: 120 },
];

const failureRecordColumns: OTableColumnDef[] = [
  { id: "time", header: t("parseStatus.time"), accessorKey: "time", size: 170 },
  { id: "source", header: t("parseStatus.source"), accessorKey: "source", size: 120 },
  { id: "parser_id", header: t("parseStatus.parserId"), accessorKey: "parser_id", size: 130 },
  { id: "failure_code", header: t("parseStatus.failureCode"), accessorKey: "failure_code", size: 180 },
  { id: "failure_message", header: t("parseStatus.failureMessage"), accessorKey: "failure_message" },
];
</script>

<template>
  <OPageLayout
    :title="t('menu.parseStatus')"
    :subtitle="t('parseStatus.subtitle')"
    icon="query-stats"
    data-test="parse-status"
  >
    <template #actions>
      <div class="flex items-center gap-3">
        <OButtonGroup>
          <OButton
            v-for="r in TIME_RANGES"
            :key="r"
            :active="range === r"
            variant="ghost"
            size="sm"
            :data-test="`parse-status-range-${r}`"
            @click="setRange(r)"
          >
            {{ r }}
          </OButton>
        </OButtonGroup>
        <OButton
          variant="outline"
          size="sm"
          icon-left="refresh"
          :loading="loading"
          data-test="parse-status-refresh"
          @click="load"
        >
          {{ t("parseStatus.refresh") }}
        </OButton>
      </div>
    </template>

    <div class="flex flex-col gap-4 overflow-auto p-4">
      <OStatStrip :items="summaryStats" />

      <div class="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <section
          class="rounded-surface border-border-default bg-surface-base border p-4"
          data-test="parse-status-ingestion-trend"
        >
          <h2 class="text-text-heading mb-3 text-sm font-semibold">
            {{ t("parseStatus.ingestionTrend") }}
          </h2>
          <OSparkline
            :points="ingestionTrend"
            shape="bar"
            size="sm"
            :aria-label="t('parseStatus.ingestionTrend')"
            data-test="parse-status-ingestion-trend-sparkline"
          />
        </section>

        <section
          class="rounded-surface border-border-default bg-surface-base border p-4"
          data-test="parse-status-failure-trend"
        >
          <h2 class="text-text-heading mb-3 text-sm font-semibold">
            {{ t("parseStatus.failureTrend") }}
          </h2>
          <OSparkline
            :points="failureTrend"
            shape="bar"
            tone="danger"
            size="sm"
            :aria-label="t('parseStatus.failureTrend')"
            data-test="parse-status-failure-trend-sparkline"
          />
        </section>
      </div>

      <section
        class="rounded-surface border-border-default bg-surface-base border p-4"
        data-test="parse-status-parser-usage"
      >
        <h2 class="text-text-heading mb-3 text-sm font-semibold">
          {{ t("parseStatus.parserUsage") }}
        </h2>
        <OTable
          :data="parserUsageRows"
          :columns="parserUsageColumns"
          :frame="false"
          :loading="loading"
        />
      </section>

      <div class="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <section
          class="rounded-surface border-border-default bg-surface-base border p-4"
          data-test="parse-status-failure-reasons"
        >
          <h2 class="text-text-heading mb-3 text-sm font-semibold">
            {{ t("parseStatus.failureReasons") }}
          </h2>
          <OTable
            :data="failureReasonRows"
            :columns="failureReasonColumns"
            :frame="false"
            :loading="loading"
          />
        </section>

        <section
          class="rounded-surface border-border-default bg-surface-base border p-4"
          data-test="parse-status-fallback-sources"
        >
          <h2 class="text-text-heading mb-3 text-sm font-semibold">
            {{ t("parseStatus.fallbackSources") }}
          </h2>
          <OTable
            :data="fallbackSourceRows"
            :columns="namedCountColumns"
            :frame="false"
            :loading="loading"
          />
        </section>

        <section
          class="rounded-surface border-border-default bg-surface-base border p-4"
          data-test="parse-status-failure-sources"
        >
          <h2 class="text-text-heading mb-3 text-sm font-semibold">
            {{ t("parseStatus.failureSources") }}
          </h2>
          <OTable
            :data="failureSourceRows"
            :columns="namedCountColumns"
            :frame="false"
            :loading="loading"
          />
        </section>
      </div>

      <section
        class="rounded-surface border-border-default bg-surface-base border p-4"
        data-test="parse-status-failure-records"
      >
        <h2 class="text-text-heading mb-3 text-sm font-semibold">
          {{ t("parseStatus.failureRecords") }}
        </h2>
        <OTable
          :data="failureRows"
          :columns="failureRecordColumns"
          :frame="false"
          :loading="loading"
          expansion="single"
          :row-key="failureRowKey"
        >
          <template #expansion="{ row }">
            <div class="p-4">
              <div class="text-text-secondary mb-2 text-xs font-medium">
                {{ t("parseStatus.rawLog") }}
              </div>
              <pre
                class="bg-surface-subtle text-text-body max-h-60 overflow-auto whitespace-pre-wrap break-all rounded-default p-3 text-sm"
                data-test="parse-status-raw-log"
                >{{ row.raw_log }}</pre
              >
            </div>
          </template>
        </OTable>
      </section>

      <OEmptyState
        v-if="!loading && !error && !hasData"
        :title="t('parseStatus.emptyTitle')"
        :description="t('parseStatus.emptyDescription')"
        data-test="parse-status-empty"
      />
    </div>
  </OPageLayout>
</template>
