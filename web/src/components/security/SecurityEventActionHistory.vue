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
import OSpinner from "@/lib/feedback/Spinner/OSpinner.vue";
import OTag from "@/lib/core/Badge/OTag.vue";
import type { I18nKey } from "@/types/i18n";
import { raw, useI18nTyped } from "@/types/i18n";
import type { SecurityEventAction, SecurityEventActionType } from "@/ts/interfaces";
import { formatDate } from "@/utils/date";

const { t } = useI18nTyped();

defineProps<{
  actions: SecurityEventAction[];
  loading?: boolean;
}>();

const ACTION_LABELS: Record<SecurityEventActionType, I18nKey> = {
  acknowledge: "securityEvents.actionAcknowledge",
  resolve: "securityEvents.actionResolve",
  close: "securityEvents.actionClose",
};
</script>

<template>
  <div class="flex flex-col gap-3" data-test="security-event-action-history">
    <OSpinner v-if="loading" size="sm" />

    <div
      v-for="action in actions"
      :key="action.id"
      class="rounded-default border-border-default bg-surface-subtle border p-3"
      data-test="security-event-action-history-row"
    >
      <div class="flex items-center justify-between gap-2 text-xs">
        <span class="text-text-secondary">{{
          formatDate(action.created_at, "yyyy-MM-dd HH:mm")
        }}</span>
        <span class="text-text-body truncate">{{ action.actor_id }}</span>
      </div>
      <div class="mt-1 flex items-center gap-2 text-sm">
        <span class="text-text-body font-medium">{{ t(ACTION_LABELS[action.action]) }}</span>
        <OTag type="securityEventStatus" :value="action.from_status" size="sm" />
        <span class="text-text-secondary">{{ raw("→") }}</span>
        <OTag type="securityEventStatus" :value="action.to_status" size="sm" />
      </div>
      <div
        v-if="action.comment"
        class="text-text-secondary mt-1 text-sm break-words"
        data-test="security-event-action-history-comment"
      >
        {{ action.comment }}
      </div>
    </div>
  </div>
</template>
