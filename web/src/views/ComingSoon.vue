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
import { useRoute } from "vue-router";
import { useI18nTyped, type I18nKey } from "@/types/i18n";
import OPageLayout from "@/lib/core/PageLayout/OPageLayout.vue";
import OEmptyState from "@/lib/core/EmptyState/OEmptyState.vue";

const { t } = useI18nTyped();
const route = useRoute();
</script>

<template>
  <OPageLayout :title="t(route.meta.titleKey as I18nKey)">
    <OEmptyState size="block" :title="t('common.comingSoon')" />
  </OPageLayout>
</template>
