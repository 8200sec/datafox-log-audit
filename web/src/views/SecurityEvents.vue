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
import { computed, onMounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { useStore } from "vuex";

import OButton from "@/lib/core/Button/OButton.vue";
import OEmptyState from "@/lib/core/EmptyState/OEmptyState.vue";
import OInput from "@/lib/forms/Input/OInput.vue";
import OSelect from "@/lib/forms/Select/OSelect.vue";
import ODateTimeRange from "@/lib/forms/DateTimeRange/ODateTimeRange.vue";
import type { DateTimeRangeValue } from "@/lib/forms/DateTimeRange/ODateTimeRange.types";
import OPageLayout from "@/lib/core/PageLayout/OPageLayout.vue";
import OStatStrip from "@/lib/data/StatStrip/OStatStrip.vue";
import type { StatItem } from "@/lib/data/StatStrip/OStatStrip.types";
import OTable from "@/lib/core/Table/OTable.vue";
import type { OTableColumnDef } from "@/lib/core/Table/OTable.types";
import OTag from "@/lib/core/Badge/OTag.vue";
import SecurityEventDetailDrawer from "@/components/security/SecurityEventDetailDrawer.vue";
import { fetchSecurityEventSummary, listSecurityEvents } from "@/services/security_event";
import type {
  SecurityEvent,
  SecurityEventSeverity,
  SecurityEventStatus,
  SecurityEventSummary,
} from "@/ts/interfaces";
import { useI18nTyped } from "@/types/i18n";
import { formatDate } from "@/utils/date";

const PAGE_SIZES = [20, 50, 100];
const DEFAULT_PAGE_SIZE = 50;

const store = useStore();
const route = useRoute();
const router = useRouter();
const { t } = useI18nTyped();

const org = computed(() => store.state.selectedOrganization.identifier);

const filterStatus = ref<SecurityEventStatus | undefined>(undefined);
const filterSeverity = ref<SecurityEventSeverity | undefined>(undefined);
const filterRuleId = ref("");
const filterEventType = ref("");
const filterSrcIp = ref("");
const filterUsername = ref("");
const filterTimeFrom = ref<number | undefined>(undefined);
const filterTimeTo = ref<number | undefined>(undefined);

const page = ref(1);
const pageSize = ref(DEFAULT_PAGE_SIZE);

const rows = ref<SecurityEvent[]>([]);
const total = ref(0);
const loading = ref(false);
const error = ref<string | null>(null);

const summary = ref<SecurityEventSummary | null>(null);

const selectedEvent = ref<SecurityEvent | null>(null);
const drawerOpen = ref(false);

const statusOptions = computed(() => [
  { label: t("components.badge.securityEventStatus.open"), value: "open" },
  { label: t("components.badge.securityEventStatus.acknowledged"), value: "acknowledged" },
  { label: t("components.badge.securityEventStatus.resolved"), value: "resolved" },
  { label: t("components.badge.securityEventStatus.closed"), value: "closed" },
]);

const severityOptions = computed(() => [
  { label: t("components.badge.severity.critical"), value: "critical" },
  { label: t("components.badge.severity.high"), value: "high" },
  { label: t("components.badge.severity.medium"), value: "medium" },
  { label: t("components.badge.severity.low"), value: "low" },
  { label: t("components.badge.severity.info"), value: "info" },
]);

const summaryItems = computed<StatItem[]>(() => {
  const s = summary.value;
  return [
    {
      key: "total",
      label: t("securityEvents.summaryTotal"),
      value: s?.total ?? 0,
      icon: "notifications-active",
      tone: "primary",
      dataTest: "security-event-summary-total",
    },
    {
      key: "open",
      label: t("securityEvents.summaryOpen"),
      value: s?.open ?? 0,
      icon: "shield",
      tone: "error",
      dataTest: "security-event-summary-open",
    },
    {
      key: "acknowledged",
      label: t("securityEvents.summaryAcknowledged"),
      value: s?.acknowledged ?? 0,
      icon: "check-circle",
      tone: "warning",
      dataTest: "security-event-summary-acknowledged",
    },
    {
      key: "highCritical",
      label: t("securityEvents.summaryHighCritical"),
      value: s?.highOrCritical ?? 0,
      icon: "warning",
      tone: "orange",
      dataTest: "security-event-summary-high-critical",
    },
  ];
});

const columns: OTableColumnDef[] = [
  {
    id: "last_seen",
    header: t("securityEvents.colLastSeen"),
    accessorKey: "last_seen",
    size: 170,
    meta: { format: (value: number) => formatDate(value, "yyyy-MM-dd HH:mm:ss") },
  },
  { id: "severity", header: t("securityEvents.colSeverity"), accessorKey: "severity", size: 110 },
  { id: "status", header: t("securityEvents.colStatus"), accessorKey: "status", size: 120 },
  {
    id: "title",
    header: t("securityEvents.colTitle"),
    accessorKey: "title",
    meta: { isName: true },
  },
  {
    id: "event_type",
    header: t("securityEvents.colEventType"),
    accessorKey: "event_type",
    size: 150,
  },
  { id: "src_ip", header: t("securityEvents.colSourceIp"), accessorKey: "src_ip", size: 130 },
  { id: "username", header: t("securityEvents.colUsername"), accessorKey: "username", size: 120 },
  { id: "rule_id", header: t("securityEvents.colRule"), accessorKey: "rule_id", size: 180 },
  {
    id: "event_count",
    header: t("securityEvents.colEventCount"),
    accessorKey: "event_count",
    size: 90,
  },
];

const hasActiveFilters = computed(
  () =>
    filterStatus.value !== undefined ||
    filterSeverity.value !== undefined ||
    filterRuleId.value !== "" ||
    filterEventType.value !== "" ||
    filterSrcIp.value !== "" ||
    filterUsername.value !== "" ||
    filterTimeFrom.value !== undefined ||
    filterTimeTo.value !== undefined,
);

function buildFilter(): Record<string, string | number | undefined> {
  return {
    status: filterStatus.value,
    severity: filterSeverity.value,
    rule_id: filterRuleId.value || undefined,
    event_type: filterEventType.value || undefined,
    src_ip: filterSrcIp.value || undefined,
    username: filterUsername.value || undefined,
    last_seen_from: filterTimeFrom.value,
    last_seen_to: filterTimeTo.value,
    limit: pageSize.value,
    offset: (page.value - 1) * pageSize.value,
    sort: "desc",
  };
}

async function loadList(): Promise<void> {
  if (!org.value) return;
  loading.value = true;
  error.value = null;
  try {
    const result = await listSecurityEvents(org.value, buildFilter());
    rows.value = result.items;
    total.value = result.total;
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e);
  } finally {
    loading.value = false;
  }
}

async function loadSummary(): Promise<void> {
  if (!org.value) return;
  try {
    summary.value = await fetchSecurityEventSummary(org.value);
  } catch {
    summary.value = null;
  }
}

function onPageChange(next: number): void {
  page.value = next;
  void loadList();
}

function onPageSizeChange(next: number): void {
  pageSize.value = next;
  page.value = 1;
  void loadList();
}

function resetFilters(): void {
  filterStatus.value = undefined;
  filterSeverity.value = undefined;
  filterRuleId.value = "";
  filterEventType.value = "";
  filterSrcIp.value = "";
  filterUsername.value = "";
  filterTimeFrom.value = undefined;
  filterTimeTo.value = undefined;
}

function openDetail(event: SecurityEvent): void {
  selectedEvent.value = event;
  drawerOpen.value = true;
}

function onTransitioned(event: SecurityEvent): void {
  selectedEvent.value = event;
  const index = rows.value.findIndex((r) => r.event_id === event.event_id);
  if (index !== -1) rows.value[index] = event;
  void loadSummary();
}

function onTimeRangeChange(value: DateTimeRangeValue): void {
  if (value.type !== "absolute") return;
  filterTimeFrom.value = value.startDate
    ? new Date(`${value.startDate}T${value.startTime || "00:00:00"}`).getTime()
    : undefined;
  filterTimeTo.value = value.endDate
    ? new Date(`${value.endDate}T${value.endTime || "23:59:59"}`).getTime()
    : undefined;
}

// A filter change resets pagination to the first page, then reloads.
watch(
  [
    filterStatus,
    filterSeverity,
    filterRuleId,
    filterEventType,
    filterSrcIp,
    filterUsername,
    filterTimeFrom,
    filterTimeTo,
  ],
  () => {
    page.value = 1;
    void loadList();
  },
);

// Persist the primary filters to the URL so a refresh keeps the state.
watch([filterStatus, filterSeverity, filterRuleId, filterTimeFrom, filterTimeTo], () => {
  void router.replace({
    query: {
      ...route.query,
      status: filterStatus.value || undefined,
      severity: filterSeverity.value || undefined,
      rule: filterRuleId.value || undefined,
      from: filterTimeFrom.value !== undefined ? String(filterTimeFrom.value) : undefined,
      to: filterTimeTo.value !== undefined ? String(filterTimeTo.value) : undefined,
    },
  });
});

function readQueryFilters(): void {
  const q = route.query;
  filterStatus.value = (q.status as SecurityEventStatus) || undefined;
  filterSeverity.value = (q.severity as SecurityEventSeverity) || undefined;
  filterRuleId.value = (q.rule as string) || "";
  filterTimeFrom.value = q.from ? Number(q.from) : undefined;
  filterTimeTo.value = q.to ? Number(q.to) : undefined;
}

onMounted(() => {
  readQueryFilters();
  void loadList();
  void loadSummary();
});
</script>

<template>
  <OPageLayout
    :title="t('menu.securityEvents')"
    :subtitle="t('securityEvents.subtitle')"
    icon="notifications-active"
    data-test="security-events"
  >
    <template #actions>
      <OButton
        variant="outline"
        size="sm"
        icon-left="refresh"
        :loading="loading"
        data-test="security-events-refresh"
        @click="loadList"
      >
        {{ t("securityEvents.refresh") }}
      </OButton>
    </template>

    <div class="flex flex-col gap-4 overflow-auto p-4">
      <OStatStrip :items="summaryItems" />

      <section
        class="rounded-surface border-border-default bg-surface-base border p-4"
        data-test="security-events-filter-bar"
      >
        <div class="flex flex-wrap items-end gap-3">
          <OSelect
            :model-value="filterStatus"
            :options="statusOptions"
            :label="t('securityEvents.filterStatus')"
            :placeholder="t('securityEvents.filterAllStatuses')"
            clearable
            width="sm"
            data-test="security-events-filter-status"
            @update:model-value="(v) => (filterStatus = v as SecurityEventStatus | undefined)"
          />
          <OSelect
            :model-value="filterSeverity"
            :options="severityOptions"
            :label="t('securityEvents.filterSeverity')"
            :placeholder="t('securityEvents.filterAllSeverities')"
            clearable
            width="sm"
            data-test="security-events-filter-severity"
            @update:model-value="(v) => (filterSeverity = v as SecurityEventSeverity | undefined)"
          />
          <OInput
            v-model="filterRuleId"
            :label="t('securityEvents.filterRule')"
            :debounce="400"
            clearable
            width="sm"
            data-test="security-events-filter-rule"
          />
          <OInput
            v-model="filterEventType"
            :label="t('securityEvents.filterEventType')"
            :debounce="400"
            clearable
            width="sm"
            data-test="security-events-filter-event-type"
          />
          <OInput
            v-model="filterSrcIp"
            :label="t('securityEvents.filterSrcIp')"
            :debounce="400"
            clearable
            width="sm"
            data-test="security-events-filter-src-ip"
          />
          <OInput
            v-model="filterUsername"
            :label="t('securityEvents.filterUsername')"
            :debounce="400"
            clearable
            width="sm"
            data-test="security-events-filter-username"
          />
          <ODateTimeRange
            mode="absolute"
            :disable-relative="true"
            :auto-apply="true"
            :hide-time="false"
            :label="t('securityEvents.filterTimeRange')"
            @change="onTimeRangeChange"
          />
          <OButton
            variant="ghost"
            size="sm"
            :disabled="!hasActiveFilters"
            data-test="security-events-reset-filters"
            @click="resetFilters"
          >
            {{ t("securityEvents.resetFilters") }}
          </OButton>
        </div>
      </section>

      <section
        class="rounded-surface border-border-default bg-surface-base min-h-0 flex-1 overflow-hidden border"
        data-test="security-events-table"
      >
        <OTable
          :data="rows"
          :columns="columns"
          :frame="false"
          :loading="loading"
          :error="error"
          pagination="server"
          :current-page="page"
          :page-size="pageSize"
          :page-size-options="PAGE_SIZES"
          :total-count="total"
          row-key="event_id"
          @update:current-page="onPageChange"
          @update:page-size="onPageSizeChange"
          @row-click="openDetail"
        >
          <template #cell-severity="{ row }">
            <OTag
              type="severity"
              :value="row.severity"
              :data-test="`security-events-row-${row.event_id}-severity`"
            />
          </template>
          <template #cell-status="{ row }">
            <OTag
              type="securityEventStatus"
              :value="row.status"
              :data-test="`security-events-row-${row.event_id}-status`"
            />
          </template>

          <template #empty>
            <OEmptyState
              v-if="hasActiveFilters"
              preset="no-search-results"
              :title="t('securityEvents.noResultsTitle')"
              :description="t('securityEvents.noResultsDescription')"
              :filtered="true"
              data-test="security-events-no-results"
              @action="resetFilters"
            />
            <OEmptyState
              v-else
              preset="no-data"
              :title="t('securityEvents.emptyTitle')"
              :description="t('securityEvents.emptyDescription')"
              data-test="security-events-empty"
            />
          </template>

          <template #error>
            <OEmptyState
              preset="load-error"
              :title="t('securityEvents.errorTitle')"
              :description="t('securityEvents.errorDescription')"
              :action-label="t('securityEvents.retry')"
              data-test="security-events-error"
              @action="loadList"
            />
          </template>
        </OTable>
      </section>
    </div>

    <SecurityEventDetailDrawer
      :open="drawerOpen"
      :event="selectedEvent"
      @update:open="(v) => (drawerOpen = v)"
      @transitioned="onTransitioned"
    />
  </OPageLayout>
</template>
