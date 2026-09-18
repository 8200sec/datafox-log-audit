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

import { beforeEach, describe, expect, it, vi } from "vitest";
import { flushPromises, mount } from "@vue/test-utils";

import i18n from "@/locales";
import store from "@/test/unit/helpers/store";
import router from "@/test/unit/helpers/router";

const serviceMocks = vi.hoisted(() => ({
  listSecurityEvents: vi.fn(),
  fetchSecurityEventSummary: vi.fn(),
  getSecurityEvent: vi.fn(),
  listSecurityEventActions: vi.fn(),
  transitionSecurityEvent: vi.fn(),
  isConflictError: vi.fn(),
}));

vi.mock("@/services/security_event", () => serviceMocks);

vi.mock("@/lib/feedback/Toast/useToast", () => ({
  useToast: () => ({ toast: vi.fn() }),
}));

import SecurityEvents from "./SecurityEvents.vue";

const makeEvent = (id: string, overrides: Record<string, unknown> = {}) => ({
  event_id: id,
  tenant_id: "default",
  rule_id: "builtin.ssh_bruteforce",
  rule_version: "1.0.0",
  title: "SSH brute force",
  category: "authentication",
  event_type: "ssh_brute_force",
  severity: "high",
  status: "open",
  first_seen: 1700000000000,
  last_seen: 1700000001000,
  event_count: 10,
  related_event_ids: ["e1", "e2"],
  evidence: {},
  created_at: 1700000000000,
  updated_at: 1700000001000,
  ...overrides,
});

describe("SecurityEvents.vue", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    store.state.selectedOrganization = {
      label: "default Organization",
      id: 159,
      identifier: "default",
      user_email: "example@gmail.com",
      subscription_type: "",
    };
    serviceMocks.listSecurityEvents.mockResolvedValue({
      items: [],
      total: 0,
      limit: 50,
      offset: 0,
    });
    serviceMocks.fetchSecurityEventSummary.mockResolvedValue({
      total: 0,
      open: 0,
      acknowledged: 0,
      highOrCritical: 0,
    });
    vi.spyOn(router, "replace").mockResolvedValue(undefined as never);
  });

  const mountView = () =>
    mount(SecurityEvents, {
      global: {
        plugins: [i18n, store, router],
        stubs: {
          SecurityEventDetailDrawer: true,
        },
      },
    });

  it("renders the page header", () => {
    const wrapper = mountView();
    expect(wrapper.find('[data-test="security-events"]').exists()).toBe(true);
  });

  it("shows the empty state when there are no events", async () => {
    const wrapper = mountView();
    await flushPromises();
    expect(wrapper.vm.rows).toHaveLength(0);
    expect(wrapper.vm.total).toBe(0);
    expect(wrapper.vm.error).toBeNull();
  });

  it("shows an error state when the list API fails", async () => {
    serviceMocks.listSecurityEvents.mockRejectedValue(new Error("boom"));
    const wrapper = mountView();
    await flushPromises();
    expect(wrapper.vm.error).toBe("boom");
  });

  it("renders event rows from the list API", async () => {
    serviceMocks.listSecurityEvents.mockResolvedValue({
      items: [makeEvent("evt-1"), makeEvent("evt-2", { status: "closed", severity: "critical" })],
      total: 2,
      limit: 50,
      offset: 0,
    });
    const wrapper = mountView();
    await flushPromises();
    expect(wrapper.vm.rows).toHaveLength(2);
    expect(wrapper.vm.total).toBe(2);
  });

  it("passes pagination params to the list API", async () => {
    mountView();
    await flushPromises();
    expect(serviceMocks.listSecurityEvents).toHaveBeenCalledWith(
      "default",
      expect.objectContaining({ limit: 50, offset: 0, sort: "desc" }),
    );
  });

  it("filters by status and resets pagination", async () => {
    const wrapper = mountView();
    await flushPromises();
    serviceMocks.listSecurityEvents.mockClear();

    wrapper.vm.filterStatus = "open";
    await flushPromises();

    expect(serviceMocks.listSecurityEvents).toHaveBeenCalledWith(
      "default",
      expect.objectContaining({ status: "open", offset: 0 }),
    );
  });

  it("filters by severity", async () => {
    const wrapper = mountView();
    await flushPromises();
    serviceMocks.listSecurityEvents.mockClear();

    wrapper.vm.filterSeverity = "critical";
    await flushPromises();

    expect(serviceMocks.listSecurityEvents).toHaveBeenCalledWith(
      "default",
      expect.objectContaining({ severity: "critical" }),
    );
  });

  it("filters by time range", async () => {
    const wrapper = mountView();
    await flushPromises();
    serviceMocks.listSecurityEvents.mockClear();

    wrapper.vm.onTimeRangeChange({
      type: "absolute",
      startDate: "2026-01-01",
      startTime: "00:00:00",
      endDate: "2026-01-02",
      endTime: "23:59:59",
      timezone: "",
    });
    await flushPromises();

    expect(serviceMocks.listSecurityEvents).toHaveBeenCalledWith(
      "default",
      expect.objectContaining({
        last_seen_from: expect.any(Number),
        last_seen_to: expect.any(Number),
      }),
    );
  });

  it("renders summary tiles from the summary API", async () => {
    serviceMocks.fetchSecurityEventSummary.mockResolvedValue({
      total: 12,
      open: 3,
      acknowledged: 2,
      highOrCritical: 5,
    });
    const wrapper = mountView();
    await flushPromises();
    expect(wrapper.find('[data-test="security-event-summary-total"]').exists()).toBe(true);
    expect(wrapper.find('[data-test="security-event-summary-open"]').exists()).toBe(true);
    expect(wrapper.find('[data-test="security-event-summary-high-critical"]').exists()).toBe(true);
  });

  it("changes page size via the table", async () => {
    const wrapper = mountView();
    await flushPromises();
    serviceMocks.listSecurityEvents.mockClear();

    wrapper.vm.onPageSizeChange(20);
    await flushPromises();

    expect(serviceMocks.listSecurityEvents).toHaveBeenCalledWith(
      "default",
      expect.objectContaining({ limit: 20, offset: 0 }),
    );
  });
});
