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

/// Single source of truth for DataFox Log Audit product branding.
/// Components read these values instead of hardcoding the product name or logo.
export interface ProductBranding {
  productName: string;
  shortName: string;
  companyName: string;
  /** Light-theme logo, resolved via `getImageURL()` (path under `src/assets/`). */
  logo: string;
  darkLogo: string;
  /** Favicon URL (public/ asset, e.g. "/favicon.ico"). */
  favicon: string;
  showEnterpriseBanner: boolean;
  showUpstreamBranding: boolean;
  enabledModules: string[];
}

export const branding: ProductBranding = {
  productName: "DataFox Log Audit",
  shortName: "DataFox",
  companyName: "DataFox",
  // OpenObserve artwork stands in until DataFox brand assets are supplied.
  logo: "images/common/openobserve_latest_light_2.svg",
  darkLogo: "images/common/openobserve_latest_dark_2.svg",
  favicon: "/favicon.ico",
  showEnterpriseBanner: false,
  showUpstreamBranding: false,
  enabledModules: ["logs", "search", "alerts", "dashboards", "reports"],
};

export const isModuleEnabled = (moduleId: string): boolean =>
  branding.enabledModules.includes(moduleId);
