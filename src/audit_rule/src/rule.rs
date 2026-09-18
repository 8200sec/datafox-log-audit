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
use thiserror::Error;

use crate::{
    condition::{Condition, FieldPath, LeafCondition, MAX_CONDITION_DEPTH, is_valid_field_path},
    security_event::{Category, Severity},
};

/// Upper bound on `group_by` fields for a threshold aggregation.
pub const MAX_GROUP_BY_FIELDS: usize = 3;

/// How a rule triggers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleType {
    /// One matching AuditEvent triggers the rule.
    Single,
    /// A threshold of matching events within a window triggers the rule.
    Threshold,
}

impl RuleType {
    /// Canonical wire token (matches the serde representation).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::Threshold => "threshold",
        }
    }
}

/// Where a rule came from. Informational only — never used for authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleSource {
    Builtin,
    Custom,
    Imported,
}

/// Aggregation config for a `threshold` rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Aggregation {
    pub group_by: Vec<FieldPath>,
    pub window_seconds: u64,
    pub threshold: u64,
}

/// A serializable, storage-agnostic detection rule definition. Rule execution
/// (W3-07C) consumes this; this module only defines and validates the model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDefinition {
    pub id: String,
    pub version: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub source: RuleSource,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub category: Category,
    pub event_type: String,
    pub severity: Severity,
    pub rule_type: RuleType,
    #[serde(rename = "match")]
    pub r#match: Condition,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregation: Option<Aggregation>,
}

fn default_enabled() -> bool {
    true
}

/// Validation failure for a RuleDefinition.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RuleDefinitionError {
    #[error("id must not be empty")]
    EmptyId,
    #[error("version must be valid semver (MAJOR.MINOR.PATCH)")]
    InvalidVersion,
    #[error("title must not be empty")]
    EmptyTitle,
    #[error("match must not be empty")]
    EmptyMatch,
    #[error("match nesting exceeds {MAX_CONDITION_DEPTH}")]
    MatchTooDeep,
    #[error("invalid field path")]
    InvalidField,
    #[error("operator requires a value")]
    MissingValue,
    #[error("operator does not accept a value")]
    UnexpectedValue,
    #[error("value must be an array for in/not_in")]
    ValueMustBeArray,
    #[error("value must be a number for gt/gte/lt/lte")]
    ValueMustBeNumber,
    #[error("value must be a string for contains/starts_with/ends_with")]
    ValueMustBeString,
    #[error("threshold rule requires aggregation")]
    MissingAggregation,
    #[error("window_seconds must be > 0")]
    InvalidWindow,
    #[error("threshold must be >= 1")]
    InvalidThreshold,
    #[error("group_by must not be empty")]
    EmptyGroupBy,
    #[error("group_by must not exceed {MAX_GROUP_BY_FIELDS} fields")]
    TooManyGroupBy,
    #[error("group_by contains an invalid field path")]
    InvalidGroupByField,
}

/// Validate that a version string is strict `MAJOR.MINOR.PATCH` (numeric).
pub fn is_semver(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

impl RuleDefinition {
    /// Validate every invariant a rule definition must satisfy.
    pub fn validate(&self) -> Result<(), RuleDefinitionError> {
        if self.id.trim().is_empty() {
            return Err(RuleDefinitionError::EmptyId);
        }
        if !is_semver(&self.version) {
            return Err(RuleDefinitionError::InvalidVersion);
        }
        if self.title.trim().is_empty() {
            return Err(RuleDefinitionError::EmptyTitle);
        }
        if self.r#match.is_empty() {
            return Err(RuleDefinitionError::EmptyMatch);
        }
        if self.r#match.depth() > MAX_CONDITION_DEPTH {
            return Err(RuleDefinitionError::MatchTooDeep);
        }
        validate_condition(&self.r#match)?;

        match self.rule_type {
            RuleType::Threshold => {
                let agg = self
                    .aggregation
                    .as_ref()
                    .ok_or(RuleDefinitionError::MissingAggregation)?;
                validate_aggregation(agg)?;
            }
            // A single rule has no window/threshold; an aggregation block, if
            // present, is tolerated (validated but unused by the v1 evaluator).
            RuleType::Single => {
                if let Some(agg) = &self.aggregation {
                    validate_aggregation(agg)?;
                }
            }
        }
        Ok(())
    }
}

fn validate_condition(condition: &Condition) -> Result<(), RuleDefinitionError> {
    match condition {
        Condition::Leaf(leaf) => validate_leaf(leaf),
        Condition::All { all } => {
            for c in all {
                validate_condition(c)?;
            }
            Ok(())
        }
        Condition::Any { any } => {
            for c in any {
                validate_condition(c)?;
            }
            Ok(())
        }
    }
}

fn validate_leaf(leaf: &LeafCondition) -> Result<(), RuleDefinitionError> {
    if !leaf.field.is_valid() {
        return Err(RuleDefinitionError::InvalidField);
    }
    let op = leaf.operator;
    if op.requires_value() {
        let value = leaf
            .value
            .as_ref()
            .ok_or(RuleDefinitionError::MissingValue)?;
        if op.value_must_be_array() && !value.is_array() {
            return Err(RuleDefinitionError::ValueMustBeArray);
        }
        if op.value_must_be_number() && !value.is_number() {
            return Err(RuleDefinitionError::ValueMustBeNumber);
        }
        if op.value_must_be_string() && !value.is_string() {
            return Err(RuleDefinitionError::ValueMustBeString);
        }
    } else if leaf.value.is_some() {
        return Err(RuleDefinitionError::UnexpectedValue);
    }
    Ok(())
}

fn validate_aggregation(agg: &Aggregation) -> Result<(), RuleDefinitionError> {
    if agg.window_seconds == 0 {
        return Err(RuleDefinitionError::InvalidWindow);
    }
    if agg.threshold < 1 {
        return Err(RuleDefinitionError::InvalidThreshold);
    }
    if agg.group_by.is_empty() {
        return Err(RuleDefinitionError::EmptyGroupBy);
    }
    if agg.group_by.len() > MAX_GROUP_BY_FIELDS {
        return Err(RuleDefinitionError::TooManyGroupBy);
    }
    for f in &agg.group_by {
        if !is_valid_field_path(f.as_str()) {
            return Err(RuleDefinitionError::InvalidGroupByField);
        }
    }
    Ok(())
}
