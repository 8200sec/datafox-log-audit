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
import { mount } from "@vue/test-utils";

import i18n from "@/locales";
import SecurityEventActionHistory from "./SecurityEventActionHistory.vue";
import type { SecurityEventAction } from "@/ts/interfaces";

const makeAction = (overrides: Partial<SecurityEventAction> = {}): SecurityEventAction => ({
  id: "a1",
  tenant_id: "default",
  security_event_id: "evt-1",
  action: "acknowledge",
  from_status: "open",
  to_status: "acknowledged",
  actor_id: "root@example.com",
  comment: null,
  created_at: 1700000000000,
  ...overrides,
});

describe("SecurityEventActionHistory.vue", () => {
  it("renders action rows", () => {
    const wrapper = mount(SecurityEventActionHistory, {
      props: { actions: [makeAction()] },
      global: { plugins: [i18n] },
    });
    expect(wrapper.find('[data-test="security-event-action-history-row"]').exists()).toBe(true);
    expect(wrapper.text()).toContain("root@example.com");
  });

  it("renders the comment when present", () => {
    const wrapper = mount(SecurityEventActionHistory, {
      props: { actions: [makeAction({ comment: "investigating" })] },
      global: { plugins: [i18n] },
    });
    expect(wrapper.find('[data-test="security-event-action-history-comment"]').text()).toBe(
      "investigating",
    );
  });

  it("renders loading spinner when loading", () => {
    const wrapper = mount(SecurityEventActionHistory, {
      props: { actions: [], loading: true },
      global: { plugins: [i18n] },
    });
    expect(wrapper.findComponent({ name: "OSpinner" }).exists()).toBe(true);
  });

  it("renders an empty container with no actions", () => {
    const wrapper = mount(SecurityEventActionHistory, {
      props: { actions: [] },
      global: { plugins: [i18n] },
    });
    expect(wrapper.findAll('[data-test="security-event-action-history-row"]')).toHaveLength(0);
  });
});
