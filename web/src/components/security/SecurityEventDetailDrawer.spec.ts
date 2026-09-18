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

const toastMocks = vi.hoisted(() => ({ toast: vi.fn() }));
vi.mock("@/lib/feedback/Toast/useToast", () => ({
  useToast: () => ({ toast: toastMocks.toast }),
}));

import SecurityEventDetailDrawer from "./SecurityEventDetailDrawer.vue";
import type { SecurityEvent } from "@/ts/interfaces";

// ODrawer/ODialog stub — renders slots inline so internal data-test selectors
// are queryable (the real components teleport content outside the wrapper).
const ODrawerStub = {
  name: "ODrawer",
  props: ["open", "title", "size"],
  emits: ["update:open"],
  template: '<div v-if="open"><slot /><slot name="footer" /></div>',
};

const ODialogStub = {
  name: "ODialog",
  props: ["open", "title", "primaryButtonLabel", "secondaryButtonLabel", "primaryButtonLoading"],
  emits: ["update:open", "click:primary", "click:secondary"],
  template: '<div v-if="open"><slot /></div>',
};

const makeEvent = (overrides: Partial<SecurityEvent> = {}): SecurityEvent => ({
  event_id: "evt-1",
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
  evidence: { threshold: 10 },
  created_at: 1700000000000,
  updated_at: 1700000001000,
  ...overrides,
});

describe("SecurityEventDetailDrawer.vue", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    store.state.selectedOrganization = {
      label: "default Organization",
      id: 159,
      identifier: "default",
      user_email: "example@gmail.com",
      subscription_type: "",
    };
    serviceMocks.listSecurityEventActions.mockResolvedValue([]);
    serviceMocks.transitionSecurityEvent.mockResolvedValue(makeEvent({ status: "acknowledged" }));
    serviceMocks.getSecurityEvent.mockResolvedValue(makeEvent({ status: "resolved" }));
    serviceMocks.isConflictError.mockReturnValue(false);
    vi.spyOn(store, "dispatch").mockResolvedValue(undefined as never);
  });

  const mountDrawer = (event: SecurityEvent) =>
    mount(SecurityEventDetailDrawer, {
      props: { open: true, event },
      global: {
        plugins: [i18n, store, router],
        stubs: { ODrawer: ODrawerStub, ODialog: ODialogStub },
      },
    });

  it("renders the detail fields", async () => {
    const wrapper = mountDrawer(makeEvent());
    await flushPromises();
    expect(wrapper.find('[data-test="security-event-detail-title"]').text()).toBe(
      "SSH brute force",
    );
    expect(wrapper.text()).toContain("builtin.ssh_bruteforce");
    expect(wrapper.text()).toContain("ssh_brute_force");
  });

  it("renders severity and status badges", async () => {
    const wrapper = mountDrawer(makeEvent());
    await flushPromises();
    const tags = wrapper.findAllComponents({ name: "OTag" });
    const severity = tags.find((tag) => tag.props("type") === "severity");
    const status = tags.find((tag) => tag.props("type") === "securityEventStatus");
    expect(severity?.props("value")).toBe("high");
    expect(status?.props("value")).toBe("open");
  });

  it("shows acknowledge/resolve/close for an open event", () => {
    const wrapper = mountDrawer(makeEvent({ status: "open" }));
    expect(wrapper.vm.allowedActions).toEqual(["acknowledge", "resolve", "close"]);
  });

  it("shows resolve/close for an acknowledged event", () => {
    const wrapper = mountDrawer(makeEvent({ status: "acknowledged" }));
    expect(wrapper.vm.allowedActions).toEqual(["resolve", "close"]);
  });

  it("shows only close for a resolved event", () => {
    const wrapper = mountDrawer(makeEvent({ status: "resolved" }));
    expect(wrapper.vm.allowedActions).toEqual(["close"]);
  });

  it("shows no workflow buttons for a closed event", () => {
    const wrapper = mountDrawer(makeEvent({ status: "closed" }));
    expect(wrapper.vm.allowedActions).toEqual([]);
  });

  it("acknowledges an event and emits the updated event", async () => {
    const updated = makeEvent({ status: "acknowledged" });
    serviceMocks.transitionSecurityEvent.mockResolvedValue(updated);
    const wrapper = mountDrawer(makeEvent());

    await wrapper.vm.openConfirm("acknowledge");
    await wrapper.vm.submitTransition();

    expect(serviceMocks.transitionSecurityEvent).toHaveBeenCalledWith(
      "default",
      "evt-1",
      "acknowledge",
      undefined,
    );
    expect(wrapper.emitted("transitioned")![0][0].status).toBe("acknowledged");
    expect(toastMocks.toast).toHaveBeenCalledWith(expect.objectContaining({ variant: "success" }));
  });

  it("resolves an event with a comment", async () => {
    const wrapper = mountDrawer(makeEvent({ status: "acknowledged" }));
    await wrapper.vm.openConfirm("resolve");
    wrapper.vm.comment = "shadow access confirmed benign";
    await wrapper.vm.submitTransition();

    expect(serviceMocks.transitionSecurityEvent).toHaveBeenCalledWith(
      "default",
      "evt-1",
      "resolve",
      "shadow access confirmed benign",
    );
  });

  it("closes an event", async () => {
    const wrapper = mountDrawer(makeEvent({ status: "resolved" }));
    await wrapper.vm.openConfirm("close");
    await wrapper.vm.submitTransition();
    expect(serviceMocks.transitionSecurityEvent).toHaveBeenCalledWith(
      "default",
      "evt-1",
      "close",
      undefined,
    );
  });

  it("re-fetches and warns on a 409 conflict", async () => {
    serviceMocks.isConflictError.mockReturnValue(true);
    serviceMocks.transitionSecurityEvent.mockRejectedValue({ response: { status: 409 } });
    const latest = makeEvent({ status: "resolved" });
    serviceMocks.getSecurityEvent.mockResolvedValue(latest);

    const wrapper = mountDrawer(makeEvent());
    await wrapper.vm.openConfirm("resolve");
    await wrapper.vm.submitTransition();

    expect(serviceMocks.getSecurityEvent).toHaveBeenCalledWith("default", "evt-1");
    expect(wrapper.emitted("transitioned")![0][0].status).toBe("resolved");
    expect(toastMocks.toast).toHaveBeenCalledWith(expect.objectContaining({ variant: "warning" }));
  });

  it("caps the comment input at 4000 characters", async () => {
    const wrapper = mountDrawer(makeEvent());
    await wrapper.vm.openConfirm("acknowledge");
    const input = wrapper.findComponent({ name: "OInput" });
    expect(input.props("maxlength")).toBe(4000);
  });

  it("loads the action history lazily on open", async () => {
    serviceMocks.listSecurityEventActions.mockResolvedValue([
      {
        id: "a1",
        tenant_id: "default",
        security_event_id: "evt-1",
        action: "acknowledge",
        from_status: "open",
        to_status: "acknowledged",
        actor_id: "root@example.com",
        created_at: 1700000000000,
      },
    ]);
    mountDrawer(makeEvent());
    await flushPromises();
    expect(serviceMocks.listSecurityEventActions).toHaveBeenCalledWith("default", "evt-1");
  });

  it("renders related event ids and a view-related-logs action", async () => {
    const wrapper = mountDrawer(makeEvent({ related_event_ids: ["e1", "e2", "e3"] }));
    await flushPromises();
    expect(wrapper.find('[data-test="security-event-related-count"]').exists()).toBe(true);
    expect(wrapper.find('[data-test="security-event-view-related-logs"]').exists()).toBe(true);
  });
});
