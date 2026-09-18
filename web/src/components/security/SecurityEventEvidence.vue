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

import OCollapsible from "@/lib/core/Collapsible/OCollapsible.vue";
import { useI18nTyped } from "@/types/i18n";

const { t } = useI18nTyped();

const props = defineProps<{ evidence: Record<string, unknown> }>();

const KNOWN_KEYS = [
  "threshold",
  "window_seconds",
  "group_by",
  "group_values",
  "current_count",
] as const;

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "-";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (Array.isArray(value) && value.every((v) => typeof v === "string")) {
    return value.join(", ");
  }
  try {
    const json = JSON.stringify(value);
    return json.length > 500 ? `${json.slice(0, 500)}…` : json;
  } catch {
    return String(value);
  }
}

const threshold = computed(() => props.evidence.threshold);
const windowSeconds = computed(() => props.evidence.window_seconds);
const groupBy = computed(() => props.evidence.group_by);
const groupValues = computed(() => props.evidence.group_values);
const currentCount = computed(() => props.evidence.current_count);

const otherFields = computed(() =>
  Object.entries(props.evidence)
    .filter(([key]) => !KNOWN_KEYS.includes(key as (typeof KNOWN_KEYS)[number]))
    .map(([key, value]) => ({ key, value: formatValue(value) })),
);
</script>

<template>
  <div class="flex flex-col gap-3" data-test="security-event-evidence">
    <div v-if="threshold !== undefined" class="flex justify-between gap-4 text-sm">
      <span class="text-text-secondary">{{ t("securityEvents.evidenceThreshold") }}</span>
      <span class="text-text-body font-medium">{{ formatValue(threshold) }}</span>
    </div>
    <div v-if="windowSeconds !== undefined" class="flex justify-between gap-4 text-sm">
      <span class="text-text-secondary">{{ t("securityEvents.evidenceWindowSeconds") }}</span>
      <span class="text-text-body font-medium">{{ formatValue(windowSeconds) }}</span>
    </div>
    <div v-if="groupBy !== undefined" class="flex justify-between gap-4 text-sm">
      <span class="text-text-secondary">{{ t("securityEvents.evidenceGroupBy") }}</span>
      <span class="text-text-body font-medium">{{ formatValue(groupBy) }}</span>
    </div>
    <div v-if="groupValues !== undefined" class="flex justify-between gap-4 text-sm">
      <span class="text-text-secondary">{{ t("securityEvents.evidenceGroupValues") }}</span>
      <span class="text-text-body text-right font-medium break-all">{{
        formatValue(groupValues)
      }}</span>
    </div>
    <div v-if="currentCount !== undefined" class="flex justify-between gap-4 text-sm">
      <span class="text-text-secondary">{{ t("securityEvents.evidenceCurrentCount") }}</span>
      <span class="text-text-body font-medium">{{ formatValue(currentCount) }}</span>
    </div>

    <OCollapsible
      v-if="otherFields.length > 0"
      :label="t('securityEvents.evidenceOther')"
      :default-open="false"
    >
      <div class="flex flex-col gap-2">
        <div
          v-for="field in otherFields"
          :key="field.key"
          class="flex justify-between gap-4 text-sm"
        >
          <span class="text-text-secondary">{{ field.key }}</span>
          <span class="text-text-body text-right break-all">{{ field.value }}</span>
        </div>
      </div>
    </OCollapsible>
  </div>
</template>
