// Copyright 2026 OpenObserve Inc.
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

import type { NavItem, RailEntry, SubnavChild, NavGateContext } from "./ONavbar.types";
import { raw, type I18nKey, type TranslateFn } from "@/types/i18n";

/**
 * Visibility gates — each predicate mirrors the EXACT `visible` condition the
 * target page applies to that section (IdentityAccessManagement.vue,
 * settings/index.vue). Keeping these in sync is what guarantees the flyout never
 * offers a section the page itself hides (e.g. Nodes is enterprise-meta-only).
 *
 * NOTE: IAM treats "enterprise" as enterprise OR cloud; Settings treats it as
 * enterprise only — hence the separate `isEnterprise`/`isCloud` flags rather
 * than one combined flag.
 */
export const GATE_PREDICATES: Record<string, (c: NavGateContext) => boolean> = {
  // Settings (isEnt = enterprise only)
  enterprise: (c) => c.isEnterprise,
  enterpriseMeta: (c) => c.isEnterprise && c.isMeta,
  cloudMeta: (c) => c.isCloud && c.isMeta,
  storage: (c) => c.isEnterprise && (!c.isCloud || c.orgStorage),
  modelPricing: (c) => (c.isEnterprise || c.isCloud) && c.modelPricing,
  correlation: (c) => c.isEnterprise && c.serviceStreams,
  llmProviders: (c) => (c.isEnterprise || c.isCloud) && c.onlineEvals,
  // IAM (isEnt = enterprise OR cloud)
  cloud: (c) => c.isCloud,
  serviceAccount: (c) => c.serviceAccount,
  rbac: (c) => (c.isEnterprise || c.isCloud) && c.rbac,
  rbacMeta: (c) => (c.isEnterprise || c.isCloud) && c.rbac && c.isMeta,
  // Pipelines: the Stream Pipelines tab hides when custom_hide_menus lists
  // "pipelines" — mirrors PipelineSectionTabs.vue exactly.
  streamPipelines: (c) => !c.hiddenMenus.has("pipelines"),
  // The runtime flag is the whole gate for the MENU ENTRY, which is not
  // enterprise-only. Three of Database Monitoring's seven tabs (deadlocks,
  // blocked queries, table health) ARE enterprise-only, but they are gated
  // per-tab in DbmSectionTabs.vue and per-route in router.ts — not here. An
  // isEnterprise conjunct at this level would take the four OSS tabs down with
  // them and hide the section from a build that still serves most of it.
  databaseMonitoring: (c) => c.databaseMonitoring,
};

/**
 * Left-rail information architecture — the SINGLE place that decides what stays
 * on the rail, what becomes a flyout group, and which top-level links reveal
 * their own sub-pages on hover.
 *
 * Three shapes (see `RailEntry`):
 *   • plain link    — most items (Home, Logs, Metrics, Traces, Actions,
 *     Billings, AI, IAM, Management).
 *   • link + subnav — a tile that navigates to a main page on click AND surfaces
 *     a section nav on hover. Produced by NAV_GROUPS (Reliability → /alerts,
 *     Data → /streams, Dashboards → /dashboards, Infra → /infra/databases) and
 *     by any NAV_SUBNAV entry.
 *   • pure group    — a flyout with no page of its own (click toggles it).
 *     Supported by the renderer but not emitted by any current entry.
 *
 * The child entries below mirror each page's OWN section nav (label / icon /
 * category) so the flyout and the page's SectionRail stay identical. Children
 * navigate by route `name` and are filtered through `router.hasRoute(name)` so
 * feature-gated (enterprise / cloud / RBAC) sections never render dead links.
 *
 * To move an item, edit ONLY this file.
 */

/**
 * A rail group: a tile that gathers destinations under one label. Clicking the
 * tile navigates to `parentLink` (its first/primary destination) and hovering
 * reveals the full submenu — i.e. it renders as a link+subnav tile.
 *
 * Two shapes: a COLLAPSING group folds existing top-level tiles into itself
 * (`absorbs`), while a `standalone` group introduces a new rail section for
 * pages that never had a tile of their own.
 */
export interface NavGroupDef {
  key: string;
  /** i18n key for the group tile's label (resolved with t() at render). */
  titleKey: I18nKey;
  icon: string;
  /** Where clicking the tile navigates (its first item). */
  parentLink: string;
  children: SubnavChild[];
  /** Top-level `name`s this group replaces (removed from the rail). */
  absorbs: string[];
  /**
   * Emit the group's tile immediately AFTER this anchor — either a top-level
   * item `name` or another group's `key` (when that anchor is present/active).
   * Defaults to the position of the group's first absorbed item.
   */
  placeAfter?: string;
  pinBottom?: boolean;
  /**
   * Emit this group even though it absorbs nothing and may hold a single child.
   *
   * Normally a group must absorb ≥1 present rail item and keep ≥2 children,
   * because it EXISTS to fold items that already have their own tiles — a
   * one-item flyout would just duplicate the tile it replaced. Infra is the
   * other shape: it is a NEW rail section that introduces a home for pages
   * which never had a top-level tile, so there is nothing to absorb and, until
   * a second section lands beside Database Monitoring, nothing to fold.
   *
   * Deliberately opt-in per group rather than a relaxed global rule: the ≥2
   * rule still protects every collapsing group from degenerating into a
   * pointless flyout when its members are hidden.
   *
   * This does NOT bypass `requires` filtering — a standalone group whose
   * children all filter out still emits nothing (see `groupNavLinks`), and a
   * group whose children are all `gate`d out is dropped by ONavGroup so the
   * rail never shows a tile with an empty flyout.
   */
  standalone?: boolean;
}

export const NAV_GROUPS: NavGroupDef[] = [
  {
    key: "logCenter",
    titleKey: "menu.logCenter",
    icon: "search",
    parentLink: "/logs",
    absorbs: ["logs", "searchHistory"],
    children: [
      { titleKey: "menu.logSearch", icon: "search", name: "logs", requires: "logs" },
      {
        titleKey: "menu.savedQueries",
        icon: "history",
        name: "searchHistory",
        requires: "searchHistory",
      },
    ],
  },
  {
    key: "logIngestion",
    titleKey: "menu.logIngestion",
    icon: "data-plus-line",
    parentLink: "/log-sources",
    absorbs: ["logSources", "streams", "functionList"],
    children: [
      {
        titleKey: "menu.logSources",
        icon: "data-plus-line",
        name: "logSources",
        requires: "logSources",
      },
      { titleKey: "menu.streams", icon: "window", name: "logstreams", requires: "streams" },
      {
        titleKey: "menu.parseRules",
        icon: "function",
        name: "functionList",
        requires: "functionList",
      },
    ],
  },
  {
    key: "security",
    titleKey: "menu.security",
    icon: "shield-alert-outline",
    parentLink: "/alerts",
    absorbs: ["securityEvents", "auditPolicies", "alertList"],
    children: [
      {
        titleKey: "menu.securityEvents",
        icon: "notifications-active",
        name: "securityEvents",
        requires: "securityEvents",
      },
      {
        titleKey: "menu.auditPolicies",
        icon: "rule",
        name: "auditPolicies",
        requires: "auditPolicies",
      },
      {
        titleKey: "menu.alertCenter",
        icon: "shield-alert-outline",
        name: "alertList",
        requires: "alertList",
      },
    ],
  },
  {
    key: "analysis",
    titleKey: "menu.analysis",
    icon: "dashboard",
    parentLink: "/dashboards",
    absorbs: ["dashboards", "auditReports", "aiAnalysis"],
    children: [
      { titleKey: "menu.dashboards", icon: "dashboard", name: "dashboards", requires: "dashboards" },
      {
        titleKey: "menu.auditReports",
        icon: "description",
        name: "auditReports",
        requires: "auditReports",
      },
      { titleKey: "menu.aiAnalysis", icon: "auto-awesome", name: "aiAnalysis", requires: "aiAnalysis" },
    ],
  },
  {
    key: "management",
    titleKey: "menu.management",
    icon: "settings",
    parentLink: "/settings",
    absorbs: ["iam", "settings", "about"],
    children: [
      { titleKey: "menu.userManagement", icon: "manage-accounts", name: "iam", requires: "iam" },
      { titleKey: "menu.systemSettings", icon: "settings", name: "settings", requires: "settings" },
      { titleKey: "menu.about", icon: "info", name: "about", requires: "about" },
    ],
  },
];


/**
 * Top-level links that ALSO reveal their own in-page section nav on hover,
 * keyed by the top-level item's `name`.
 *
 * AI / IAM / Management are intentionally plain links (no rail submenu) — their
 * in-page SectionRail is the place to switch sections. Re-add an entry here
 * (mirroring the page's SectionRail) to restore a hover flyout.
 *
 * Traces: every flyout child targets the Traces page's existing `?tab=` views,
 * keeping one URL and one shared query/stream/time context for all four modes.
 * Service Graph carries the same enterprise gate as its in-page tab.
 */
export const NAV_SUBNAV: Record<string, SubnavChild[]> = {
  traces: [
    {
      titleKey: "traces.spansTab",
      icon: "layers",
      name: "traces",
      tab: "spans",
      defaultForRoute: true,
    },
    {
      titleKey: "menu.traces",
      icon: "account-tree",
      name: "traces",
      tab: "traces",
    },
    {
      titleKey: "menu.serviceGraph",
      icon: "share",
      name: "traces",
      tab: "service-graph",
      gate: "enterprise",
    },
    {
      titleKey: "menu.services",
      icon: "menu-book",
      name: "traces",
      tab: "services-catalog",
    },
    // Databases is NOT here — it moved to the Infra group (see NAV_GROUPS).
    // It sat on this flyout while Database Monitoring was read as a view over
    // the database spans inside these traces. It is not: it reads the database
    // server's own statistics, so it stands up without a single trace and is a
    // destination for a DBA who never opens Traces. Filing it under Traces made
    // it findable only by someone already looking at request traffic.
    //
    // Traces keeps its flyout regardless — Traces / Service Graph / Service
    // Catalog remain three views of the same trace data.
  ],
};

/**
 * Transform the flat `linksList` into rail entries, PRESERVING the input order
 * (which is the main-branch menu order — MainLayout builds it). A group's tile
 * is emitted at the position of its FIRST present absorbed item; the group's
 * other absorbed items are removed. Everything else stays exactly where it was.
 */
export function groupNavLinks(
  links: NavItem[],
  // `raw` brands the key unchanged — the identity fallback for callers with no translator.
  t: TranslateFn = raw,
): RailEntry[] {
  const presentNames = new Set(links.map((l) => l.name));

  // Activate a COLLAPSING group only when it has ≥1 present absorbed item AND
  // ≥2 children (after `requires` filtering): such a group exists to fold tiles
  // that already stand on their own, so with nothing absorbed there is no fold
  // to make, and with one child the flyout would merely duplicate its own tile.
  //
  // A `standalone` group is the other shape — a new rail section whose pages
  // never had a top-level tile (Infra). It absorbs nothing by definition and
  // may legitimately hold a single child, so it only has to keep ≥1 child.
  // `router.hasRoute`/`gate` filtering of children happens later, in the
  // component, which drops the whole tile when nothing survives.
  const groupChildren = new Map<string, SubnavChild[]>();
  const absorbedToGroup = new Map<string, NavGroupDef>();
  for (const def of NAV_GROUPS) {
    const children = def.children.filter((c) => !c.requires || presentNames.has(c.requires));
    const hasAbsorbed = def.absorbs.some((n) => presentNames.has(n));
    if (def.standalone) {
      if (children.length === 0) continue;
    } else if (children.length < 2 || !hasAbsorbed) {
      continue;
    }
    groupChildren.set(def.key, children);
    for (const n of def.absorbs) absorbedToGroup.set(n, def);
  }

  const entryFor = (item: NavItem): RailEntry => {
    const subnav = NAV_SUBNAV[item.name];
    if (subnav && subnav.length > 0) {
      return { type: "linkGroup", item, children: subnav };
    }
    return { type: "link", item };
  };

  // A group is emitted either AFTER its `placeAfter` anchor or in place of its
  // first absorbed item (default). Map anchor → group keys to emit right after
  // it. The anchor is a top-level item `name` or another group's `key`; it only
  // counts when that item is present / that group is active, so a group whose
  // anchor never materialises falls back to default placement.
  //
  // Iterate NAV_GROUPS, not the absorbed-item map: a `standalone` group absorbs
  // nothing and so never appears in that map, and `placeAfter` is the ONLY
  // placement it has — missing it here would drop it to the safety-net append at
  // the foot of the rail. The `groupChildren` guard already skips inactive
  // groups, so this is identical to the old iteration for collapsing groups.
  const anchorExists = (anchor: string) => presentNames.has(anchor) || groupChildren.has(anchor);
  const emitAfter = new Map<string, string[]>();
  for (const def of NAV_GROUPS) {
    if (!groupChildren.has(def.key)) continue;
    if (def.placeAfter && anchorExists(def.placeAfter)) {
      const list = emitAfter.get(def.placeAfter) ?? [];
      if (!list.includes(def.key)) list.push(def.key);
      emitAfter.set(def.placeAfter, list);
    }
  }

  const result: RailEntry[] = [];
  const emittedGroups = new Set<string>();
  const emitGroup = (def: NavGroupDef) => {
    if (emittedGroups.has(def.key)) return;
    emittedGroups.add(def.key);
    result.push({
      type: "linkGroup",
      item: {
        title: t(def.titleKey),
        icon: def.icon,
        link: def.parentLink,
        name: def.key,
      },
      children: groupChildren.get(def.key)!,
    });
    // Groups anchored after THIS group (e.g. Data follows Reliability).
    emitAnchored(def.key);
  };
  const emitAnchored = (anchor: string) => {
    for (const key of emitAfter.get(anchor) ?? []) {
      emitGroup(NAV_GROUPS.find((d) => d.key === key)!);
    }
  };

  for (const item of links) {
    const group = absorbedToGroup.get(item.name);
    if (group) {
      // Absorbed item — drop it. Emit the group here only when it has no
      // (present) `placeAfter` anchor (default first-absorbed placement).
      const usesPlaceAfter = group.placeAfter && anchorExists(group.placeAfter);
      if (!usesPlaceAfter) emitGroup(group);
      continue;
    }
    result.push(entryFor(item));
    emitAnchored(item.name);
  }

  // Safety net: append any active group not yet placed.
  for (const def of NAV_GROUPS) {
    if (groupChildren.has(def.key)) emitGroup(def);
  }

  return result;
}
