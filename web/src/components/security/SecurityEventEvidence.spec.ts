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
import SecurityEventEvidence from "./SecurityEventEvidence.vue";

describe("SecurityEventEvidence.vue", () => {
  const mountEvidence = (evidence: Record<string, unknown>) =>
    mount(SecurityEventEvidence, {
      props: { evidence },
      global: { plugins: [i18n] },
    });

  it("renders known evidence fields", () => {
    const wrapper = mountEvidence({
      threshold: 10,
      window_seconds: 300,
      group_by: ["src_ip"],
      group_values: { src_ip: "10.0.0.1" },
      current_count: 11,
    });
    const text = wrapper.text();
    expect(text).toContain("10");
    expect(text).toContain("300");
    expect(text).toContain("src_ip");
    expect(text).toContain("10.0.0.1");
    expect(text).toContain("11");
  });

  it("renders group_by as a comma-separated list", () => {
    const wrapper = mountEvidence({ group_by: ["src_ip", "username"] });
    expect(wrapper.text()).toContain("src_ip, username");
  });

  it("renders unknown fields in a collapsible section", () => {
    const wrapper = mountEvidence({ rule_type: "threshold", matched_fields: ["event_type"] });
    // Unknown fields are detected and collected (collapsed by default).
    expect(wrapper.vm.otherFields).toEqual([
      { key: "rule_type", value: "threshold" },
      { key: "matched_fields", value: "event_type" },
    ]);
    expect(wrapper.text()).toContain("Other evidence");
  });

  it("truncates large JSON values", () => {
    const long = "x".repeat(2000);
    const wrapper = mountEvidence({ evidence_blob: { data: long } });
    expect(wrapper.text().length).toBeLessThan(1200);
  });

  it("renders nothing for an empty evidence object", () => {
    const wrapper = mountEvidence({});
    expect(wrapper.find('[data-test="security-event-evidence"]').exists()).toBe(true);
    // No known rows, no collapsible.
    expect(wrapper.findComponent({ name: "OCollapsible" }).exists()).toBe(false);
  });
});
