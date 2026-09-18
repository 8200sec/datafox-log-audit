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

use audit_parser::{AuditEvent, EventResult, Severity, SourceType};
use serde_json::Value;

use crate::{condition::FieldPath, evaluator::EvaluationError};

/// A typed value resolved from an AuditEvent field. Comparison happens on this
/// typed value — never by stringifying every field.
#[derive(Debug, Clone, PartialEq)]
pub enum TypedValue {
    String(String),
    Number(f64),
    Boolean(bool),
    Null,
}

impl TypedValue {
    /// A short type name for error messages.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::String(_) => "string",
            Self::Number(_) => "number",
            Self::Boolean(_) => "boolean",
            Self::Null => "null",
        }
    }
}

fn severity_str(s: &Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn result_str(r: &EventResult) -> &'static str {
    match r {
        EventResult::Success => "success",
        EventResult::Failure => "failure",
        EventResult::Unknown => "unknown",
    }
}

fn source_type_str(s: &SourceType) -> &'static str {
    match s {
        SourceType::Os => "os",
        SourceType::Firewall => "firewall",
        SourceType::Router => "router",
        SourceType::Database => "database",
        SourceType::Web => "web",
        SourceType::Application => "application",
        SourceType::Network => "network",
        SourceType::Other => "other",
    }
}

/// Convert a JSON value (a rule's comparison value) to a typed value.
/// Arrays/objects become `Null` — they are only meaningful to `in`/`not_in`,
/// which handle them before this conversion.
pub fn value_to_typed(v: &Value) -> TypedValue {
    match v {
        Value::String(s) => TypedValue::String(s.clone()),
        Value::Number(n) => TypedValue::Number(n.as_f64().unwrap_or(0.0)),
        Value::Bool(b) => TypedValue::Boolean(*b),
        _ => TypedValue::Null,
    }
}

/// Convert a typed value back to JSON (for `group_values`).
pub fn typed_to_json(v: &TypedValue) -> Value {
    match v {
        TypedValue::String(s) => Value::String(s.clone()),
        TypedValue::Number(n) => Value::from(*n),
        TypedValue::Boolean(b) => Value::Bool(*b),
        TypedValue::Null => Value::Null,
    }
}

/// Resolve a `FieldPath` against an AuditEvent to a typed value.
///
/// `Ok(None)` means the field is a valid path but has no value on this event
/// (missing). `Err` means the field path itself is unknown (an invalid rule).
pub fn resolve_field(
    event: &AuditEvent,
    path: &FieldPath,
) -> Result<Option<TypedValue>, EvaluationError> {
    let s = path.as_str();
    let value = match s {
        "event_type" => event
            .event_type
            .as_deref()
            .map(|v| TypedValue::String(v.to_string())),
        "category" => event
            .category
            .as_deref()
            .map(|v| TypedValue::String(v.to_string())),
        "result" => event
            .result
            .as_ref()
            .map(|r| TypedValue::String(result_str(r).to_string())),
        "severity" => Some(TypedValue::String(
            severity_str(&event.severity).to_string(),
        )),
        "username" => event
            .username
            .as_deref()
            .map(|v| TypedValue::String(v.to_string())),
        "hostname" => event
            .hostname
            .as_deref()
            .map(|v| TypedValue::String(v.to_string())),
        "src_ip" => event
            .src_ip
            .as_deref()
            .map(|v| TypedValue::String(v.to_string())),
        "src_port" => event.src_port.map(|v| TypedValue::Number(f64::from(v))),
        "dst_ip" => event
            .dst_ip
            .as_deref()
            .map(|v| TypedValue::String(v.to_string())),
        "dst_port" => event.dst_port.map(|v| TypedValue::Number(f64::from(v))),
        "source_type" => Some(TypedValue::String(
            source_type_str(&event.source_type).to_string(),
        )),
        "source_name" => event
            .source_name
            .as_deref()
            .map(|v| TypedValue::String(v.to_string())),
        _ => match s.strip_prefix("event_attributes.") {
            Some(key) => event
                .event_attributes
                .as_ref()
                .and_then(|attrs| attrs.get(key))
                .map(value_to_typed),
            None => return Err(EvaluationError::UnknownField(s.to_string())),
        },
    };
    Ok(value)
}
