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

/// Logical classification of a parser, used by the observability / failure
/// center to measure how much ingestion is handled by dedicated parsers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParserClass {
    /// A dedicated parser for a specific product / vendor / domain (e.g. linux-auth).
    Specialized,
    /// A broad parser that handles a whole format without domain semantics.
    Generic,
    /// The catch-all parser that accepts anything no dedicated parser claimed.
    Fallback,
}

impl ParserClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Specialized => "specialized",
            Self::Generic => "generic",
            Self::Fallback => "fallback",
        }
    }
}

/// Map a parser id to its classification. Unknown ids (e.g. a test parser or a
/// future vendor parser not yet catalogued) default to `Generic` — the safe
/// assumption is "broad, not dedicated" until it is explicitly classified.
pub fn classify_parser(parser_id: &str) -> ParserClass {
    match parser_id {
        "linux-auth" => ParserClass::Specialized,
        "generic-json" | "generic-syslog" => ParserClass::Generic,
        "fallback" => ParserClass::Fallback,
        _ => ParserClass::Generic,
    }
}
