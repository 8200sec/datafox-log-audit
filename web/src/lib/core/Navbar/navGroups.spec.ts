// Copyright 2026 OpenObserve Inc.

import { describe, it, expect } from "vitest";
import { groupNavLinks, NAV_GROUPS, NAV_SUBNAV, GATE_PREDICATES } from "./navGroups";
import type { NavGateContext } from "./ONavbar.types";
import type { NavItem, RailEntry } from "./ONavbar.types";

const link = (name: string, extra: Partial<NavItem> = {}): NavItem => ({
  title: name,
  icon: "x",
  link: `/${name}`,
  name,
  ...extra,
});

function keysOf(entries: RailEntry[]): string[] {
  return entries.map((e) => (e.type === "group" ? `group:${e.key}` : `${e.type}:${e.item.name}`));
}

/** Find a link+subnav group tile by its group key. */
const groupByKey = (entries: RailEntry[], key: string) =>
  entries.find(
    (e): e is Extract<RailEntry, { type: "linkGroup" }> =>
      e.type === "linkGroup" && e.item.name === key,
  );

describe("groupNavLinks", () => {
  it("keeps Home as a plain link and folds the audit modules into five groups", () => {
    const input = [
      link("home"),
      link("logs"),
      link("searchHistory"),
      link("logSources"),
      link("streams"),
      link("functionList"),
      link("securityEvents"),
      link("auditPolicies"),
      link("alertList"),
      link("dashboards"),
      link("auditReports"),
      link("aiAnalysis"),
      link("iam"),
      link("settings"),
      link("about"),
    ];
    expect(keysOf(groupNavLinks(input))).toEqual([
      "link:home",
      "linkGroup:logCenter",
      "linkGroup:logIngestion",
      "linkGroup:security",
      "linkGroup:analysis",
      "linkGroup:management",
    ]);
  });

  it("folds logs + saved queries into the Log Center group", () => {
    const entries = groupNavLinks([link("home"), link("logs"), link("searchHistory")]);
    const g = groupByKey(entries, "logCenter");
    expect(g?.item.link).toBe("/logs");
    expect(g?.children.map((c) => c.name)).toEqual(["logs", "searchHistory"]);
  });

  it("folds log sources, streams and parse rules into the Log Ingestion group", () => {
    const entries = groupNavLinks([
      link("home"),
      link("logSources"),
      link("streams"),
      link("functionList"),
    ]);
    const g = groupByKey(entries, "logIngestion");
    expect(g?.item.link).toBe("/log-sources");
    // `streams` (the rail item) maps to the `logstreams` route name.
    expect(g?.children.map((c) => c.name)).toEqual(["logSources", "logstreams", "functionList"]);
  });

  it("folds security events, audit policies and alerts into the Security group", () => {
    const entries = groupNavLinks([
      link("home"),
      link("securityEvents"),
      link("auditPolicies"),
      link("alertList"),
    ]);
    const g = groupByKey(entries, "security");
    expect(g?.item.link).toBe("/alerts");
    expect(g?.children.map((c) => c.name)).toEqual([
      "securityEvents",
      "auditPolicies",
      "alertList",
    ]);
  });

  it("folds dashboards, audit reports and AI analysis into the Analysis group", () => {
    const entries = groupNavLinks([
      link("home"),
      link("dashboards"),
      link("auditReports"),
      link("aiAnalysis"),
    ]);
    const g = groupByKey(entries, "analysis");
    expect(g?.item.link).toBe("/dashboards");
    expect(g?.children.map((c) => c.name)).toEqual(["dashboards", "auditReports", "aiAnalysis"]);
  });

  it("folds IAM, settings and about into the Management group", () => {
    const entries = groupNavLinks([link("home"), link("iam"), link("settings"), link("about")]);
    const g = groupByKey(entries, "management");
    expect(g?.item.link).toBe("/settings");
    expect(g?.children.map((c) => c.name)).toEqual(["iam", "settings", "about"]);
  });

  it("does not surface Metrics, Traces or RUM", () => {
    const keys = keysOf(groupNavLinks([link("home"), link("logs"), link("searchHistory")]));
    expect(keys).not.toContain("link:metrics");
    expect(keys).not.toContain("link:traces");
    expect(keys).not.toContain("link:rum");
  });

  it("collapses a group to a plain link when it has fewer than two present children", () => {
    // Only `logs` present → Log Center would hold a single child, so it does
    // not form and `logs` stays a plain link rather than a one-item flyout.
    expect(keysOf(groupNavLinks([link("home"), link("logs")]))).toEqual([
      "link:home",
      "link:logs",
    ]);
  });

  it("keeps the NAV_SUBNAV traces flyout definition intact", () => {
    expect(NAV_SUBNAV.traces).toEqual([
      expect.objectContaining({ name: "traces", tab: "spans", defaultForRoute: true }),
      expect.objectContaining({ name: "traces", tab: "traces" }),
      expect.objectContaining({ name: "traces", tab: "service-graph", gate: "enterprise" }),
      expect.objectContaining({ name: "traces", tab: "services-catalog" }),
    ]);
  });
});

describe("GATE_PREDICATES", () => {
  const ctx = (over: Partial<NavGateContext> = {}): NavGateContext => ({
    isEnterprise: false,
    isCloud: false,
    isMeta: false,
    rbac: false,
    serviceAccount: true,
    orgStorage: false,
    modelPricing: false,
    serviceStreams: true,
    onlineEvals: false,
    databaseMonitoring: false,
    hiddenMenus: new Set<string>(),
    ...over,
  });

  it("databaseMonitoring gates on the runtime flag ALONE — it is an OSS feature", () => {
    expect(GATE_PREDICATES.databaseMonitoring(ctx({ databaseMonitoring: true }))).toBe(true);
    // The point of the test: an OSS build with the flag on must still show it.
    expect(
      GATE_PREDICATES.databaseMonitoring(ctx({ databaseMonitoring: true, isEnterprise: false })),
    ).toBe(true);
    expect(GATE_PREDICATES.databaseMonitoring(ctx({ isEnterprise: true }))).toBe(false);
    expect(GATE_PREDICATES.databaseMonitoring(ctx())).toBe(false);
  });

  it("enterpriseMeta (e.g. Nodes) needs BOTH enterprise and meta-org", () => {
    expect(GATE_PREDICATES.enterpriseMeta(ctx({ isEnterprise: true, isMeta: true }))).toBe(true);
    expect(GATE_PREDICATES.enterpriseMeta(ctx({ isEnterprise: true }))).toBe(false);
    expect(GATE_PREDICATES.enterpriseMeta(ctx({ isMeta: true }))).toBe(false);
    // OSS non-meta (the reported "I see Nodes but the page doesn't" case) → hidden.
    expect(GATE_PREDICATES.enterpriseMeta(ctx())).toBe(false);
  });

  it("rbac (IAM Groups/Roles) accepts enterprise OR cloud, plus rbac flag", () => {
    expect(GATE_PREDICATES.rbac(ctx({ isCloud: true, rbac: true }))).toBe(true);
    expect(GATE_PREDICATES.rbac(ctx({ isEnterprise: true, rbac: true }))).toBe(true);
    expect(GATE_PREDICATES.rbac(ctx({ rbac: true }))).toBe(false);
    expect(GATE_PREDICATES.rbac(ctx({ isEnterprise: true }))).toBe(false);
  });

  it("storage is enterprise, and on cloud also requires org_storage_enabled", () => {
    expect(GATE_PREDICATES.storage(ctx({ isEnterprise: true }))).toBe(true); // self-hosted
    expect(GATE_PREDICATES.storage(ctx({ isEnterprise: true, isCloud: true }))).toBe(false);
    expect(
      GATE_PREDICATES.storage(ctx({ isEnterprise: true, isCloud: true, orgStorage: true })),
    ).toBe(true);
  });

  it("streamPipelines hides only when custom_hide_menus lists 'pipelines'", () => {
    expect(GATE_PREDICATES.streamPipelines(ctx())).toBe(true);
    expect(GATE_PREDICATES.streamPipelines(ctx({ hiddenMenus: new Set(["pipelines"]) }))).toBe(
      false,
    );
  });
});
