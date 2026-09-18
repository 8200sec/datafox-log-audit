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

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Maximum nesting depth of the `all`/`any` match tree.
pub const MAX_CONDITION_DEPTH: usize = 4;

/// Standard top-level AuditEvent fields a rule may match on. Any other
/// top-level field is rejected; nested values are addressed via
/// `event_attributes.<key>`.
pub const STANDARD_FIELDS: [&str; 12] = [
    "event_type",
    "category",
    "result",
    "severity",
    "username",
    "hostname",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "source_type",
    "source_name",
];

/// A validated field path: either a standard AuditEvent field or
/// `event_attributes.<key>` (single key, no deeper nesting).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FieldPath(pub String);

impl FieldPath {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_valid(&self) -> bool {
        is_valid_field_path(&self.0)
    }
}

/// True when `s` is a standard field or `event_attributes.<single-key>`.
pub fn is_valid_field_path(s: &str) -> bool {
    if STANDARD_FIELDS.contains(&s) {
        return true;
    }
    match s.strip_prefix("event_attributes.") {
        Some(key) => !key.is_empty() && !key.contains('.'),
        None => false,
    }
}

/// Comparison operators for a match condition. No `regex` in v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    Eq,
    Neq,
    Contains,
    NotContains,
    StartsWith,
    EndsWith,
    Gt,
    Gte,
    Lt,
    Lte,
    In,
    NotIn,
    Exists,
    NotExists,
}

impl Operator {
    /// Canonical wire token (matches the serde representation).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Neq => "neq",
            Self::Contains => "contains",
            Self::NotContains => "not_contains",
            Self::StartsWith => "starts_with",
            Self::EndsWith => "ends_with",
            Self::Gt => "gt",
            Self::Gte => "gte",
            Self::Lt => "lt",
            Self::Lte => "lte",
            Self::In => "in",
            Self::NotIn => "not_in",
            Self::Exists => "exists",
            Self::NotExists => "not_exists",
        }
    }

    /// Whether the operator needs a `value` (exists/not_exists do not).
    pub fn requires_value(self) -> bool {
        !matches!(self, Self::Exists | Self::NotExists)
    }

    /// Whether the value must be a JSON array (in/not_in).
    pub fn value_must_be_array(self) -> bool {
        matches!(self, Self::In | Self::NotIn)
    }

    /// Whether the value must be a JSON number (gt/gte/lt/lte).
    pub fn value_must_be_number(self) -> bool {
        matches!(self, Self::Gt | Self::Gte | Self::Lt | Self::Lte)
    }

    /// Whether the value must be a JSON string (contains/starts_with/ends_with).
    pub fn value_must_be_string(self) -> bool {
        matches!(
            self,
            Self::Contains | Self::NotContains | Self::StartsWith | Self::EndsWith
        )
    }
}

/// A single `field operator value` condition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeafCondition {
    pub field: FieldPath,
    pub operator: Operator,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

/// A match tree: `all`/`any` combinators over leaves, or a single leaf.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Condition {
    All { all: Vec<Condition> },
    Any { any: Vec<Condition> },
    Leaf(LeafCondition),
}

impl Condition {
    /// Whether the tree has no leaf conditions (an empty all/any list).
    pub fn is_empty(&self) -> bool {
        match self {
            Self::All { all } => all.is_empty(),
            Self::Any { any } => any.is_empty(),
            Self::Leaf(_) => false,
        }
    }

    /// Nesting depth (a leaf is 1; each all/any level adds one).
    pub fn depth(&self) -> usize {
        match self {
            Self::Leaf(_) => 1,
            Self::All { all } => 1 + all.iter().map(Self::depth).max().unwrap_or(0),
            Self::Any { any } => 1 + any.iter().map(Self::depth).max().unwrap_or(0),
        }
    }
}
