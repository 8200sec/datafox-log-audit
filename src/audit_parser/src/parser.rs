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

use crate::types::{ParsedEvent, RawLogInput};

/// Contract every parser implements. `detect` (cheap recognition) and `parse`
/// (full extraction) are separate. Parsers must NOT mutate `input.raw_log` —
/// they return a new `ParsedEvent` whose `raw_log` equals the input byte-for-byte.
pub trait Parser: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    /// Semver. Bump the major on a breaking output change.
    fn version(&self) -> &str;
    /// Higher is tried first.
    fn priority(&self) -> i32;
    /// Source types this parser claims; empty = any.
    fn supported_source_types(&self) -> &[&'static str];
    fn detect(&self, input: &RawLogInput) -> bool;
    fn parse(&self, input: &RawLogInput) -> anyhow::Result<ParsedEvent>;
}
