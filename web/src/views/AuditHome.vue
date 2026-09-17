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
import { computed } from "vue";
import { raw, useI18nTyped, type I18nText } from "@/types/i18n";
import OPageLayout from "@/lib/core/PageLayout/OPageLayout.vue";
import OStatStrip from "@/lib/data/StatStrip/OStatStrip.vue";
import OTag from "@/lib/core/Badge/OTag.vue";
import OBanner from "@/lib/feedback/Banner/OBanner.vue";
import type { StatItem } from "@/lib/data/StatStrip/OStatStrip.types";
import type { BadgeVariant } from "@/lib/core/Badge/OBadge.types";

const { t } = useI18nTyped();

// MOCK DATA — clearly-marked placeholder. Replace with the audit backend APIs
// (today's log count, source registry, security-event feed, trend series, …).
const MOCK = {
  todayLogs: 1284567,
  logSources: 42,
  securityEvents: 156,
  highRiskEvents: 23,
  logTrend: [
    3200, 4100, 3800, 5200, 6100, 5800, 4900, 5300, 7200, 8100, 7600, 6900,
    6400, 7100, 6800, 5900, 6200, 7800, 8400, 7900, 7200, 6600, 5800, 5400,
  ],
  riskLevels: [
    { level: "high", count: 23 },
    { level: "medium", count: 58 },
    { level: "low", count: 75 },
  ],
  topSources: [
    { name: "nginx-access", count: 452100 },
    { name: "auth-service", count: 231800 },
    { name: "firewall", count: 120500 },
    { name: "db-audit", count: 98200 },
    { name: "vpn-gateway", count: 54300 },
  ],
  recentEvents: [
    { time: "10:42:18", event: "Multiple failed login attempts", source: "auth-service", risk: "high", status: "open" },
    { time: "10:31:05", event: "Privilege escalation detected", source: "db-audit", risk: "high", status: "open" },
    { time: "09:58:47", event: "Unusual outbound traffic", source: "firewall", risk: "medium", status: "open" },
    { time: "09:12:33", event: "Config change detected", source: "nginx-access", risk: "medium", status: "resolved" },
    { time: "08:45:20", event: "New source onboarded", source: "vpn-gateway", risk: "low", status: "resolved" },
  ],
};

const RISK_META: Record<string, { variant: BadgeVariant; label: () => I18nText }> = {
  high: { variant: "error", label: () => t("auditHome.riskHigh") },
  medium: { variant: "warning", label: () => t("auditHome.riskMedium") },
  low: { variant: "success", label: () => t("auditHome.riskLow") },
};

const STATUS_META: Record<string, { variant: BadgeVariant; label: () => I18nText }> = {
  open: { variant: "error-soft", label: () => t("auditHome.statusOpen") },
  resolved: { variant: "success-soft", label: () => t("auditHome.statusResolved") },
};

const fmt = (n: number): string => n.toLocaleString("en-US");

const summaryStats = computed<StatItem[]>(() => [
  {
    key: "todayLogs",
    label: t("auditHome.todayLogs"),
    value: fmt(MOCK.todayLogs),
    icon: "description",
    tone: "primary",
  },
  {
    key: "logSources",
    label: t("auditHome.logSources"),
    value: MOCK.logSources,
    icon: "data-plus-line",
    tone: "info",
  },
  {
    key: "securityEvents",
    label: t("auditHome.securityEvents"),
    value: MOCK.securityEvents,
    icon: "notifications-active",
    tone: "warning",
  },
  {
    key: "highRiskEvents",
    label: t("auditHome.highRiskEvents"),
    value: MOCK.highRiskEvents,
    icon: "shield-alert-outline",
    tone: "error",
  },
]);

const trendMax = Math.max(...MOCK.logTrend);
const riskTotal = MOCK.riskLevels.reduce((sum, r) => sum + r.count, 0);
const sourcesMax = Math.max(...MOCK.topSources.map((s) => s.count));
</script>

<template>
  <OPageLayout
    :title="t('menu.home')"
    :subtitle="t('auditHome.subtitle')"
    icon="home"
    bleed
    data-test="audit-home"
  >
    <div class="flex flex-col gap-4 p-4">
      <OBanner variant="info" icon="info">
        {{ t("auditHome.sampleData") }}
      </OBanner>

      <OStatStrip :items="summaryStats" />

      <!-- Log trend -->
      <section
        class="rounded-surface border-border-default bg-surface-base border p-4"
        data-test="audit-home-log-trend"
      >
        <h2 class="text-text-heading mb-3 text-sm font-semibold">
          {{ t("auditHome.logTrend") }}
        </h2>
        <div class="flex h-32 items-end gap-1">
          <div
            v-for="(value, i) in MOCK.logTrend"
            :key="i"
            class="bg-accent/70 hover:bg-accent min-w-0 flex-1 rounded-t-default transition-colors duration-150"
            :style="{ height: `${Math.round((value / trendMax) * 100)}%` }"
            :title="fmt(value)"
          />
        </div>
        <div class="text-text-secondary mt-2 flex justify-between text-xs">
          <span>{{ raw("00:00") }}</span>
          <span>{{ raw("12:00") }}</span>
          <span>{{ raw("23:00") }}</span>
        </div>
      </section>

      <div class="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <!-- Risk levels -->
        <section
          class="rounded-surface border-border-default bg-surface-base border p-4"
          data-test="audit-home-risk-levels"
        >
          <h2 class="text-text-heading mb-3 text-sm font-semibold">
            {{ t("auditHome.riskLevels") }}
          </h2>
          <div class="flex flex-col gap-3">
            <div v-for="item in MOCK.riskLevels" :key="item.level" class="flex items-center gap-3">
              <OTag :variant="RISK_META[item.level].variant" :label="RISK_META[item.level].label()" />
              <div class="bg-surface-subtle h-2 min-w-0 flex-1 overflow-hidden rounded-full">
                <div
                  class="h-full rounded-full"
                  :class="{
                    'bg-error-500': item.level === 'high',
                    'bg-warning-500': item.level === 'medium',
                    'bg-success-500': item.level === 'low',
                  }"
                  :style="{ width: `${Math.round((item.count / riskTotal) * 100)}%` }"
                />
              </div>
              <span class="text-text-body w-12 text-right text-sm font-semibold">{{ item.count }}</span>
            </div>
          </div>
        </section>

        <!-- Top log sources -->
        <section
          class="rounded-surface border-border-default bg-surface-base border p-4"
          data-test="audit-home-log-sources-top"
        >
          <h2 class="text-text-heading mb-3 text-sm font-semibold">
            {{ t("auditHome.logSourcesTop") }}
          </h2>
          <div class="flex flex-col gap-3">
            <div v-for="source in MOCK.topSources" :key="source.name" class="flex items-center gap-3">
              <span class="text-text-body w-28 truncate text-sm">{{ raw(source.name) }}</span>
              <div class="bg-surface-subtle h-2 min-w-0 flex-1 overflow-hidden rounded-full">
                <div
                  class="bg-accent h-full rounded-full"
                  :style="{ width: `${Math.round((source.count / sourcesMax) * 100)}%` }"
                />
              </div>
              <span class="text-text-secondary w-20 text-right text-xs">{{ fmt(source.count) }}</span>
            </div>
          </div>
        </section>
      </div>

      <!-- Recent security events -->
      <section
        class="rounded-surface border-border-default bg-surface-base border p-4"
        data-test="audit-home-recent-events"
      >
        <h2 class="text-text-heading mb-3 text-sm font-semibold">
          {{ t("auditHome.recentSecurityEvents") }}
        </h2>
        <div class="flex flex-col">
          <div class="text-text-secondary flex items-center gap-3 border-b border-border-default pb-2 text-xs font-medium">
            <span class="w-20 shrink-0">{{ t("auditHome.time") }}</span>
            <span class="min-w-0 flex-1">{{ t("auditHome.event") }}</span>
            <span class="w-28 shrink-0">{{ t("auditHome.source") }}</span>
            <span class="w-24 shrink-0">{{ t("auditHome.riskLevel") }}</span>
            <span class="w-24 shrink-0">{{ t("auditHome.status") }}</span>
          </div>
          <div
            v-for="event in MOCK.recentEvents"
            :key="event.time"
            class="text-text-body flex items-center gap-3 border-b border-border-default py-2 text-sm last:border-b-0"
          >
            <span class="text-text-secondary w-20 shrink-0 text-xs">{{ raw(event.time) }}</span>
            <span class="min-w-0 flex-1 truncate">{{ raw(event.event) }}</span>
            <span class="w-28 shrink-0 truncate">{{ raw(event.source) }}</span>
            <span class="w-24 shrink-0">
              <OTag :variant="RISK_META[event.risk].variant" :label="RISK_META[event.risk].label()" />
            </span>
            <span class="w-24 shrink-0">
              <OTag :variant="STATUS_META[event.status].variant" :label="STATUS_META[event.status].label()" />
            </span>
          </div>
        </div>
      </section>
    </div>
  </OPageLayout>
</template>
