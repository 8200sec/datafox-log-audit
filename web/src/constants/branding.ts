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
  productName: "DataFox 日志审计系统",
  shortName: "DataFox",
  companyName: "DataFox",
  logo: "images/common/datafox_logo_light.svg",
  darkLogo: "images/common/datafox_logo_dark.svg",
  favicon: "/datafox_favicon.svg",
  showEnterpriseBanner: false,
  showUpstreamBranding: false,
  enabledModules: ["logs", "search", "alerts", "dashboards", "reports"],
};

export const isModuleEnabled = (moduleId: string): boolean =>
  branding.enabledModules.includes(moduleId);
