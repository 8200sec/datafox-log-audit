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

import { describe, it, expect } from "vitest";
import {
  SEVERITY_VALUES,
  RESULT_VALUES,
  SOURCE_TYPE_VALUES,
  AUDIT_STREAM_NAMES,
  AuditEventSchema,
  AuditParseFailureSchema,
  auditEventFirewallDenyFixture,
  auditEventMinimalFixture,
  auditParseFailureFixture,
} from "./index";

describe("AuditEvent enums", () => {
  it("normalizes severity to exactly the five allowed values", () => {
    expect(SEVERITY_VALUES).toEqual(["info", "low", "medium", "high", "critical"]);
  });

  it("normalizes result to success / failure / unknown", () => {
    expect(RESULT_VALUES).toEqual(["success", "failure", "unknown"]);
  });

  it("covers the intended source domains without vendor-specific tokens", () => {
    expect(SOURCE_TYPE_VALUES).toEqual(
      expect.arrayContaining(["os", "firewall", "router", "database", "web", "application"]),
    );
    // No vendor names leak into the public source-type vocabulary.
    expect(SOURCE_TYPE_VALUES).not.toEqual(expect.arrayContaining(["cisco", "windows", "linux"]));
  });

  it("declares the two target stream names", () => {
    expect(AUDIT_STREAM_NAMES.AUDIT_EVENTS).toBe("audit_events");
    expect(AUDIT_STREAM_NAMES.AUDIT_PARSE_FAILURES).toBe("audit_parse_failures");
  });
});

describe("AuditEventSchema", () => {
  it("accepts the full firewall fixture", () => {
    expect(AuditEventSchema.safeParse(auditEventFirewallDenyFixture).success).toBe(true);
  });

  it("accepts a minimal event with only required fields", () => {
    expect(AuditEventSchema.safeParse(auditEventMinimalFixture).success).toBe(true);
  });

  it("rejects an out-of-band severity", () => {
    const result = AuditEventSchema.safeParse({
      ...auditEventMinimalFixture,
      severity: "fatal",
    });
    expect(result.success).toBe(false);
  });

  it("rejects an out-of-band result", () => {
    const result = AuditEventSchema.safeParse({
      ...auditEventFirewallDenyFixture,
      result: "partial",
    });
    expect(result.success).toBe(false);
  });

  it("requires raw_log (empty string rejected)", () => {
    const result = AuditEventSchema.safeParse({ ...auditEventMinimalFixture, raw_log: "" });
    expect(result.success).toBe(false);
  });

  it("requires a unique event_id, tenant_id and source_type", () => {
    const base = { ...auditEventMinimalFixture };
    for (const key of ["event_id", "tenant_id"] as const) {
      expect(AuditEventSchema.safeParse({ ...base, [key]: "" }).success).toBe(false);
    }
    expect(
      AuditEventSchema.safeParse({ ...base, source_type: "made-up" }).success,
    ).toBe(false);
  });

  it("accepts vendor-specific extensions only under event_attributes", () => {
    const result = AuditEventSchema.safeParse({
      ...auditEventMinimalFixture,
      event_attributes: { "cisco.asa.message_id": "106023", count: 3 },
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.event_attributes).toEqual({ "cisco.asa.message_id": "106023", count: 3 });
    }
  });
});

describe("AuditParseFailureSchema", () => {
  it("accepts the parse-failure fixture", () => {
    expect(AuditParseFailureSchema.safeParse(auditParseFailureFixture).success).toBe(true);
  });

  it("requires raw_log and an error message", () => {
    expect(
      AuditParseFailureSchema.safeParse({ ...auditParseFailureFixture, error_message: "" })
        .success,
    ).toBe(false);
  });
});
