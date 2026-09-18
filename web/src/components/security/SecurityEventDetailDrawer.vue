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
import { computed, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { useStore } from "vuex";

import OButton from "@/lib/core/Button/OButton.vue";
import OInput from "@/lib/forms/Input/OInput.vue";
import OTag from "@/lib/core/Badge/OTag.vue";
import ODialog from "@/lib/overlay/Dialog/ODialog.vue";
import ODrawer from "@/lib/overlay/Drawer/ODrawer.vue";
import { useToast } from "@/lib/feedback/Toast/useToast";
import SecurityEventActionHistory from "@/components/security/SecurityEventActionHistory.vue";
import SecurityEventEvidence from "@/components/security/SecurityEventEvidence.vue";
import {
  getSecurityEvent,
  isConflictError,
  listSecurityEventActions,
  transitionSecurityEvent,
} from "@/services/security_event";
import type {
  SecurityEvent,
  SecurityEventAction,
  SecurityEventActionType,
  SecurityEventCategory,
} from "@/ts/interfaces";
import type { I18nKey, I18nText } from "@/types/i18n";
import { useI18nTyped } from "@/types/i18n";
import { formatDate } from "@/utils/date";
import { b64EncodeUnicode, escapeSingleQuotes } from "@/utils/zincutils";

const MAX_COMMENT_LENGTH = 4000;

const props = defineProps<{
  open: boolean;
  event: SecurityEvent | null;
}>();

const emit = defineEmits<{
  "update:open": [value: boolean];
  transitioned: [event: SecurityEvent];
}>();

const store = useStore();
const router = useRouter();
const { t } = useI18nTyped();
const { toast } = useToast();

const org = computed(() => store.state.selectedOrganization.identifier);

const actions = ref<SecurityEventAction[]>([]);
const loadingActions = ref(false);

const pendingAction = ref<SecurityEventActionType | null>(null);
const dialogOpen = ref(false);
const comment = ref("");
const submitting = ref(false);

const ACTION_LABELS: Record<SecurityEventActionType, I18nKey> = {
  acknowledge: "securityEvents.actionAcknowledge",
  resolve: "securityEvents.actionResolve",
  close: "securityEvents.actionClose",
};

const CONFIRM_TITLES: Record<SecurityEventActionType, I18nKey> = {
  acknowledge: "securityEvents.confirmAcknowledgeTitle",
  resolve: "securityEvents.confirmResolveTitle",
  close: "securityEvents.confirmCloseTitle",
};

const CATEGORY_LABELS: Record<SecurityEventCategory, I18nKey> = {
  authentication: "securityEvents.category.authentication",
  privilege: "securityEvents.category.privilege",
  network: "securityEvents.category.network",
  malware: "securityEvents.category.malware",
  policy: "securityEvents.category.policy",
  data_access: "securityEvents.category.data_access",
  system: "securityEvents.category.system",
  other: "securityEvents.category.other",
};

const allowedActions = computed<SecurityEventActionType[]>(() => {
  switch (props.event?.status) {
    case "open":
      return ["acknowledge", "resolve", "close"];
    case "acknowledged":
      return ["resolve", "close"];
    case "resolved":
      return ["close"];
    default:
      return [];
  }
});

const relatedIds = computed(() => props.event?.related_event_ids ?? []);

interface DetailField {
  label: I18nText;
  value: string;
}

const detailFields = computed<DetailField[]>(() => {
  const e = props.event;
  if (!e) return [];
  const fields: DetailField[] = [
    { label: t("securityEvents.fieldEventType"), value: e.event_type },
    { label: t("securityEvents.fieldCategory"), value: t(CATEGORY_LABELS[e.category]) },
    { label: t("securityEvents.fieldRuleId"), value: e.rule_id },
    { label: t("securityEvents.fieldRuleVersion"), value: e.rule_version },
    { label: t("securityEvents.fieldEventCount"), value: String(e.event_count) },
    {
      label: t("securityEvents.fieldFirstSeen"),
      value: formatDate(e.first_seen, "yyyy-MM-dd HH:mm:ss"),
    },
    {
      label: t("securityEvents.fieldLastSeen"),
      value: formatDate(e.last_seen, "yyyy-MM-dd HH:mm:ss"),
    },
    {
      label: t("securityEvents.fieldCreatedAt"),
      value: formatDate(e.created_at, "yyyy-MM-dd HH:mm:ss"),
    },
    {
      label: t("securityEvents.fieldUpdatedAt"),
      value: formatDate(e.updated_at, "yyyy-MM-dd HH:mm:ss"),
    },
  ];
  if (e.src_ip) fields.push({ label: t("securityEvents.fieldSrcIp"), value: e.src_ip });
  if (e.dst_ip) fields.push({ label: t("securityEvents.fieldDstIp"), value: e.dst_ip });
  if (e.username) fields.push({ label: t("securityEvents.fieldUsername"), value: e.username });
  if (e.asset_id) fields.push({ label: t("securityEvents.fieldAssetId"), value: e.asset_id });
  return fields;
});

async function loadActions(eventId: string): Promise<void> {
  loadingActions.value = true;
  try {
    actions.value = await listSecurityEventActions(org.value, eventId);
  } catch {
    actions.value = [];
  } finally {
    loadingActions.value = false;
  }
}

watch(
  () => [props.open, props.event?.event_id] as const,
  ([open, eventId]) => {
    if (open && eventId) void loadActions(eventId);
  },
  { immediate: true },
);

function openConfirm(action: SecurityEventActionType): void {
  pendingAction.value = action;
  comment.value = "";
  dialogOpen.value = true;
}

async function submitTransition(): Promise<void> {
  const action = pendingAction.value;
  const event = props.event;
  if (!action || !event) return;
  submitting.value = true;
  try {
    const updated = await transitionSecurityEvent(
      org.value,
      event.event_id,
      action,
      comment.value.trim() || undefined,
    );
    toast({ variant: "success", message: t("securityEvents.transitionSuccess") });
    emit("transitioned", updated);
    void loadActions(event.event_id);
    closeDialog();
  } catch (err) {
    if (isConflictError(err)) {
      toast({
        variant: "warning",
        title: t("securityEvents.conflictTitle"),
        message: t("securityEvents.conflictMessage"),
      });
      await refreshLatest(event.event_id);
      closeDialog();
    } else {
      toast({ variant: "error", message: t("securityEvents.transitionFailed") });
    }
  } finally {
    submitting.value = false;
  }
}

async function refreshLatest(eventId: string): Promise<void> {
  try {
    const latest = await getSecurityEvent(org.value, eventId);
    emit("transitioned", latest);
    void loadActions(eventId);
  } catch {
    // The event may have been deleted; the list refresh will reconcile.
  }
}

function closeDialog(): void {
  dialogOpen.value = false;
  pendingAction.value = null;
  comment.value = "";
}

function viewRelatedLogs(): void {
  const event = props.event;
  if (!event || relatedIds.value.length === 0) return;
  const filterQuery = relatedIds.value
    .map((id) => `event_id='${escapeSingleQuotes(id)}'`)
    .join(" OR ");
  store.dispatch("logs/setIsInitialized", false);
  router.push({
    path: "/logs",
    query: {
      stream_type: "logs",
      stream: "audit_events",
      sql_mode: "false",
      query: b64EncodeUnicode(filterQuery),
      period: "15m",
      org_identifier: org.value,
    },
  });
}
</script>

<template>
  <ODrawer
    :open="open"
    size="lg"
    :title="t('securityEvents.detailTitle')"
    data-test="security-event-detail-drawer"
    @update:open="(v) => emit('update:open', v)"
  >
    <template v-if="event">
      <div class="flex flex-col gap-5">
        <div class="flex items-start justify-between gap-3">
          <h3
            class="text-text-heading text-base font-semibold"
            data-test="security-event-detail-title"
          >
            {{ event.title }}
          </h3>
          <div class="flex shrink-0 items-center gap-2">
            <OTag
              type="severity"
              :value="event.severity"
              data-test="security-event-detail-severity"
            />
            <OTag
              type="securityEventStatus"
              :value="event.status"
              data-test="security-event-detail-status"
            />
          </div>
        </div>

        <p v-if="event.description" class="text-text-body text-sm">{{ event.description }}</p>

        <div class="grid grid-cols-2 gap-x-4 gap-y-3">
          <div v-for="field in detailFields" :key="field.label" class="flex flex-col gap-1">
            <span class="text-text-secondary text-xs">{{ field.label }}</span>
            <span class="text-text-body text-sm break-all">{{ field.value }}</span>
          </div>
        </div>

        <section>
          <h4 class="text-text-heading mb-2 text-sm font-semibold">
            {{ t("securityEvents.evidenceTitle") }}
          </h4>
          <div
            class="rounded-surface border-border-default bg-surface-base border p-3"
            data-test="security-event-detail-evidence"
          >
            <SecurityEventEvidence :evidence="event.evidence" />
          </div>
        </section>

        <section>
          <h4 class="text-text-heading mb-2 text-sm font-semibold">
            {{ t("securityEvents.relatedTitle") }}
          </h4>
          <div class="rounded-surface border-border-default bg-surface-base border p-3">
            <p class="text-text-body text-sm" data-test="security-event-related-count">
              {{
                t("securityEvents.relatedCount", { count: relatedIds.length }, relatedIds.length)
              }}
            </p>
            <div
              v-if="relatedIds.length > 0"
              class="bg-surface-subtle text-text-secondary rounded-default mt-2 max-h-32 overflow-auto p-2 text-xs"
            >
              <div v-for="id in relatedIds" :key="id" class="break-all">{{ id }}</div>
            </div>
            <OButton
              v-if="relatedIds.length > 0"
              class="mt-3"
              variant="outline"
              size="sm"
              icon-left="search"
              data-test="security-event-view-related-logs"
              @click="viewRelatedLogs"
            >
              {{ t("securityEvents.viewRelatedLogs") }}
            </OButton>
          </div>
        </section>

        <section>
          <h4 class="text-text-heading mb-2 text-sm font-semibold">
            {{ t("securityEvents.historyTitle") }}
          </h4>
          <SecurityEventActionHistory :actions="actions" :loading="loadingActions" />
        </section>
      </div>
    </template>

    <template #footer>
      <div class="flex items-center justify-end gap-2">
        <OButton
          v-for="(action, index) in allowedActions"
          :key="action"
          :variant="index === 0 ? 'primary' : 'outline'"
          size="sm"
          :data-test="`security-event-action-${action}`"
          @click="openConfirm(action)"
        >
          {{ t(ACTION_LABELS[action]) }}
        </OButton>
      </div>
    </template>
  </ODrawer>

  <ODialog
    v-model:open="dialogOpen"
    :title="pendingAction ? t(CONFIRM_TITLES[pendingAction]) : undefined"
    :secondary-button-label="t('securityEvents.cancel')"
    :primary-button-label="t('securityEvents.confirm')"
    :primary-button-loading="submitting"
    :persistent="submitting"
    data-test="security-event-confirm-dialog"
    @click:primary="submitTransition"
    @click:secondary="closeDialog"
  >
    <div class="flex flex-col gap-3">
      <p class="text-text-body text-sm">{{ t("securityEvents.confirmMessage") }}</p>
      <OInput
        v-model="comment"
        type="textarea"
        :label="t('securityEvents.commentLabel')"
        :placeholder="t('securityEvents.commentPlaceholder')"
        :maxlength="MAX_COMMENT_LENGTH"
        :rows="3"
        autogrow
      />
      <p class="text-text-secondary text-xs">
        {{ t("securityEvents.commentMax", { max: MAX_COMMENT_LENGTH }) }}
      </p>
    </div>
  </ODialog>
</template>
