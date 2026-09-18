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

use serde_json::{Map, Value};

use crate::{
    parser::Parser,
    types::{ParsedEvent, RawLogInput, Timestamp},
};

const TIMESTAMP_KEYS: &[&str] = &["@timestamp", "timestamp", "time", "ts"];
const MESSAGE_KEYS: &[&str] = &["message", "msg", "log"];
const SEVERITY_KEYS: &[&str] = &["severity", "level", "log.level"];
const HOSTNAME_KEYS: &[&str] = &["host.name", "hostname", "host"];
const USERNAME_KEYS: &[&str] = &["user.name", "username", "user"];
const SRC_IP_KEYS: &[&str] = &["source.ip", "src_ip", "client.ip", "remote_ip"];
const SRC_PORT_KEYS: &[&str] = &["source.port", "src_port", "client.port"];
const DST_IP_KEYS: &[&str] = &["destination.ip", "dst_ip", "server.ip"];
const DST_PORT_KEYS: &[&str] = &["destination.port", "dst_port", "server.port"];
const CATEGORY_KEYS: &[&str] = &["event.category", "category"];
const EVENT_TYPE_KEYS: &[&str] = &["event.type", "event_type"];
const ACTION_KEYS: &[&str] = &["event.action", "action"];
const RESULT_KEYS: &[&str] = &["event.outcome", "result", "outcome"];

/// Generic JSON object parser. Priority 20: below future dedicated JSON parsers,
/// above the fallback. It never touches trusted fields (`tenant_id`, `event_id`,
/// `collector_id`, `parser_id`, `parser_version`, `ingest_timestamp`) — those are
/// always server-side/system generated; any such key in the input JSON just
/// falls through to `event_attributes.unmapped_json`.
pub struct GenericJsonParser;

impl Parser for GenericJsonParser {
    fn id(&self) -> &str {
        "generic-json"
    }
    fn name(&self) -> &str {
        "Generic JSON"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn priority(&self) -> i32 {
        20
    }
    fn supported_source_types(&self) -> &[&'static str] {
        &[]
    }
    fn detect(&self, input: &RawLogInput) -> bool {
        let trimmed = input.raw_log.trim_start();
        if !trimmed.starts_with('{') {
            return false;
        }
        matches!(
            serde_json::from_str::<Value>(trimmed),
            Ok(v) if v.is_object()
        )
    }
    fn parse(&self, input: &RawLogInput) -> anyhow::Result<ParsedEvent> {
        let trimmed = input.raw_log.trim_start();
        let value: Value = serde_json::from_str(trimmed)?;
        let mut map = match value {
            Value::Object(m) => m,
            _ => anyhow::bail!("JSON root is not an object"),
        };

        let timestamp = extract_timestamp(&mut map);
        let message = take_string(&mut map, MESSAGE_KEYS);
        let severity = take_string(&mut map, SEVERITY_KEYS);
        let result = take_string(&mut map, RESULT_KEYS);
        let hostname = take_string(&mut map, HOSTNAME_KEYS);
        let username = take_string(&mut map, USERNAME_KEYS);
        let src_ip = take_string(&mut map, SRC_IP_KEYS);
        let src_port = take_string(&mut map, SRC_PORT_KEYS);
        let dst_ip = take_string(&mut map, DST_IP_KEYS);
        let dst_port = take_string(&mut map, DST_PORT_KEYS);
        let category = take_string(&mut map, CATEGORY_KEYS);
        let event_type = take_string(&mut map, EVENT_TYPE_KEYS);
        let action = take_string(&mut map, ACTION_KEYS);

        let mut attrs = Map::new();
        if let Some(v) = &severity {
            attrs.insert("original_severity".to_string(), Value::String(v.clone()));
        }
        if let Some(v) = &result {
            attrs.insert("original_result".to_string(), Value::String(v.clone()));
        }
        // Remaining (unmapped) fields → one compact JSON string, so unknown keys
        // never explode into AuditEvent columns. Trusted fields land here too.
        if !map.is_empty() {
            attrs.insert(
                "unmapped_json".to_string(),
                Value::String(Value::Object(map).to_string()),
            );
        }

        Ok(ParsedEvent {
            parser_id: "generic-json".to_string(),
            parser_version: "1.0.0".to_string(),
            raw_log: input.raw_log.clone(),
            timestamp,
            severity,
            result,
            hostname,
            username,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            category,
            event_type,
            action,
            message,
            attributes: if attrs.is_empty() {
                None
            } else {
                Some(Value::Object(attrs))
            },
            ..Default::default()
        })
    }
}

fn extract_timestamp(map: &mut Map<String, Value>) -> Option<Timestamp> {
    for key in TIMESTAMP_KEYS {
        if let Some(v) = take_path(map, key) {
            return match v {
                Value::Number(n) => Some(Timestamp::RawNumber(n.as_f64().unwrap_or(0.0))),
                Value::String(s) => Some(Timestamp::RawString(s)),
                _ => None,
            };
        }
    }
    None
}

fn take_string(map: &mut Map<String, Value>, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(v) = take_path(map, key) {
            return value_to_string(v);
        }
    }
    None
}

fn value_to_string(v: Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Remove the value at a (possibly dotted) path and prune an emptied parent.
fn take_path(map: &mut Map<String, Value>, path: &str) -> Option<Value> {
    let (parent, leaf) = match path.split_once('.') {
        Some((p, l)) => (p, l),
        None => return map.remove(path),
    };
    let value = map.get_mut(parent)?.as_object_mut()?.remove(leaf)?;
    if map
        .get(parent)
        .and_then(|v| v.as_object())
        .is_some_and(|o| o.is_empty())
    {
        map.remove(parent);
    }
    Some(value)
}
