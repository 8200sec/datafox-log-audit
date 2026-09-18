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

use audit_parser::AuditEvent;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use thiserror::Error;

use crate::{
    condition::{Condition, LeafCondition, Operator},
    resolve::{TypedValue, resolve_field, typed_to_json, value_to_typed},
    rule::RuleDefinition,
};

/// A stable result of evaluating a rule against one AuditEvent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleMatch {
    pub rule_id: String,
    pub rule_version: String,
    pub tenant_id: String,
    pub audit_event_id: String,
    /// Epoch millis of the triggering AuditEvent.
    pub matched_at: i64,
    /// `group_by` values extracted from the event (threshold rules; `{}` for single).
    #[serde(default)]
    pub group_values: Value,
    #[serde(default)]
    pub evidence: Value,
}

/// Outcome of a stateless rule evaluation. A type error or an invalid rule is
/// reported as `Error` — never silently folded into `NotMatched`.
#[derive(Debug, Clone, PartialEq)]
pub enum EvaluationResult {
    Matched(Box<RuleMatch>),
    NotMatched,
    Error(EvaluationError),
}

/// Evaluation failure (type mismatch, unknown field, missing value).
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum EvaluationError {
    #[error("unknown field: {0}")]
    UnknownField(String),
    #[error("type mismatch evaluating field '{field}' with operator '{operator}'")]
    TypeMismatch {
        field: String,
        operator: &'static str,
    },
    #[error("operator requires a value for field '{0}'")]
    MissingValue(String),
    #[error("match nesting exceeds the maximum depth")]
    ConditionTooDeep,
}

/// Stateless rule evaluator. It holds no state, caches nothing, and keeps no
/// reference to events after `evaluate` returns — a hard requirement for
/// low-memory deployments.
#[derive(Debug, Clone, Copy, Default)]
pub struct RuleEvaluator;

impl RuleEvaluator {
    /// Evaluate one rule against one AuditEvent. `matched_at` is the event's own
    /// timestamp; `tenant_id` always comes from the AuditEvent's trusted context.
    pub fn evaluate(&self, rule: &RuleDefinition, event: &AuditEvent) -> EvaluationResult {
        // Respect the DSL depth bound even for an unvalidated rule, so a deeply
        // nested tree is rejected instead of recursing without limit.
        if rule.r#match.depth() > crate::condition::MAX_CONDITION_DEPTH {
            return EvaluationResult::Error(EvaluationError::ConditionTooDeep);
        }
        let mut matched_fields = Vec::new();
        match evaluate_condition(&rule.r#match, event, &mut matched_fields) {
            Ok(true) => {
                let group_values = extract_group_values(rule, event);
                let evidence = json!({
                    "rule_type": rule.rule_type.as_str(),
                    "matched_fields": matched_fields,
                });
                EvaluationResult::Matched(Box::new(RuleMatch {
                    rule_id: rule.id.clone(),
                    rule_version: rule.version.clone(),
                    tenant_id: event.tenant_id.clone(),
                    audit_event_id: event.event_id.clone(),
                    matched_at: event.timestamp,
                    group_values,
                    evidence,
                }))
            }
            Ok(false) => EvaluationResult::NotMatched,
            Err(e) => EvaluationResult::Error(e),
        }
    }
}

/// Recursively evaluate a condition tree with short-circuiting, collecting the
/// leaf fields that evaluated true (for `evidence`).
fn evaluate_condition(
    cond: &Condition,
    event: &AuditEvent,
    matched: &mut Vec<String>,
) -> Result<bool, EvaluationError> {
    match cond {
        Condition::Leaf(leaf) => {
            let ok = evaluate_leaf(leaf, event)?;
            if ok {
                matched.push(leaf.field.as_str().to_string());
            }
            Ok(ok)
        }
        Condition::All { all } => {
            for c in all {
                if !evaluate_condition(c, event, matched)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        Condition::Any { any } => {
            for c in any {
                if evaluate_condition(c, event, matched)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

fn evaluate_leaf(leaf: &LeafCondition, event: &AuditEvent) -> Result<bool, EvaluationError> {
    let resolved = resolve_field(event, &leaf.field)?;
    let op = leaf.operator;
    match op {
        Operator::Exists => Ok(resolved.is_some()),
        Operator::NotExists => Ok(resolved.is_none()),
        _ => {
            // A missing field is NotMatched for every comparison operator.
            let Some(field) = resolved else {
                return Ok(false);
            };
            let value = leaf
                .value
                .as_ref()
                .ok_or_else(|| EvaluationError::MissingValue(leaf.field.as_str().to_string()))?;
            evaluate_operator(op, &field, value, leaf.field.as_str())
        }
    }
}

fn type_mismatch(field: &str, op: Operator) -> EvaluationError {
    EvaluationError::TypeMismatch {
        field: field.to_string(),
        operator: op.as_str(),
    }
}

fn same_type_eq(a: &TypedValue, b: &TypedValue) -> Result<bool, ()> {
    match (a, b) {
        (TypedValue::String(x), TypedValue::String(y)) => Ok(x == y),
        (TypedValue::Number(x), TypedValue::Number(y)) => Ok(x == y),
        (TypedValue::Boolean(x), TypedValue::Boolean(y)) => Ok(x == y),
        (TypedValue::Null, TypedValue::Null) => Ok(true),
        _ => Err(()),
    }
}

fn evaluate_operator(
    op: Operator,
    field: &TypedValue,
    value: &Value,
    field_name: &str,
) -> Result<bool, EvaluationError> {
    match op {
        Operator::Eq => {
            same_type_eq(field, &value_to_typed(value)).map_err(|_| type_mismatch(field_name, op))
        }
        Operator::Neq => same_type_eq(field, &value_to_typed(value))
            .map(|eq| !eq)
            .map_err(|_| type_mismatch(field_name, op)),
        Operator::Contains => string_op(field, value, field_name, op, |s, sub| s.contains(sub)),
        Operator::NotContains => {
            string_op(field, value, field_name, op, |s, sub| s.contains(sub)).map(|b| !b)
        }
        Operator::StartsWith => {
            string_op(field, value, field_name, op, |s, sub| s.starts_with(sub))
        }
        Operator::EndsWith => string_op(field, value, field_name, op, |s, sub| s.ends_with(sub)),
        Operator::Gt => numeric_op(field, value, field_name, op, |a, b| a > b),
        Operator::Gte => numeric_op(field, value, field_name, op, |a, b| a >= b),
        Operator::Lt => numeric_op(field, value, field_name, op, |a, b| a < b),
        Operator::Lte => numeric_op(field, value, field_name, op, |a, b| a <= b),
        Operator::In => collection_op(field, value, field_name, op),
        Operator::NotIn => collection_op(field, value, field_name, op).map(|found| !found),
        Operator::Exists | Operator::NotExists => unreachable!("handled in evaluate_leaf"),
    }
}

fn string_op(
    field: &TypedValue,
    value: &Value,
    field_name: &str,
    op: Operator,
    f: impl Fn(&str, &str) -> bool,
) -> Result<bool, EvaluationError> {
    let TypedValue::String(fv) = field else {
        return Err(type_mismatch(field_name, op));
    };
    let Value::String(rv) = value else {
        return Err(type_mismatch(field_name, op));
    };
    Ok(f(fv.as_str(), rv.as_str()))
}

fn numeric_op(
    field: &TypedValue,
    value: &Value,
    field_name: &str,
    op: Operator,
    f: fn(f64, f64) -> bool,
) -> Result<bool, EvaluationError> {
    let TypedValue::Number(fv) = field else {
        return Err(type_mismatch(field_name, op));
    };
    let TypedValue::Number(rv) = value_to_typed(value) else {
        return Err(type_mismatch(field_name, op));
    };
    Ok(f(*fv, rv))
}

fn collection_op(
    field: &TypedValue,
    value: &Value,
    field_name: &str,
    op: Operator,
) -> Result<bool, EvaluationError> {
    let Value::Array(elements) = value else {
        return Err(type_mismatch(field_name, op));
    };
    for e in elements {
        if matches!(same_type_eq(field, &value_to_typed(e)), Ok(true)) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Extract `aggregation.group_by` values from the event into a JSON object.
fn extract_group_values(rule: &RuleDefinition, event: &AuditEvent) -> Value {
    let Some(agg) = &rule.aggregation else {
        return Value::Object(Map::new());
    };
    let mut map = Map::new();
    for path in &agg.group_by {
        if let Ok(Some(value)) = resolve_field(event, path) {
            map.insert(path.as_str().to_string(), typed_to_json(&value));
        }
    }
    Value::Object(map)
}
