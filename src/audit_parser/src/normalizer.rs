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

use chrono::{DateTime, NaiveDateTime};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::{
    failure::{FailureCode, FailureStage, ParseFailure},
    observability::classify_parser,
    types::{AuditEvent, EventResult, ParsedEvent, RawLogInput, Severity, SourceType, Timestamp},
};

fn lower(s: Option<&str>) -> Option<String> {
    s.map(|v| v.to_lowercase())
}

/// Add `parser_quality` to a parser's attributes so the observability layer can
/// aggregate specialized/generic/fallback with a plain GROUP BY — no new top-level
/// AuditEvent field. Attributes are always an object in practice; anything else is
/// wrapped into a fresh object rather than lost.
fn with_parser_quality(attrs: Option<Value>, parser_id: &str) -> Option<Value> {
    let mut map = match attrs {
        Some(Value::Object(m)) => m,
        Some(other) => {
            let mut m = Map::new();
            m.insert("unmapped".to_string(), other);
            m
        }
        None => Map::new(),
    };
    map.insert(
        "parser_quality".to_string(),
        json!(classify_parser(parser_id).as_str()),
    );
    Some(Value::Object(map))
}

/// Turns a parser's `ParsedEvent` into a validated `AuditEvent`. Lenient for
/// optional fields; strict about `raw_log` (must be non-empty) and `timestamp`
/// (must be non-negative). `tenant_id` always comes from the trusted input
/// context, never the raw log.
#[derive(Default)]
pub struct Normalizer;

impl Normalizer {
    pub fn new() -> Self {
        Self
    }

    pub fn normalize_severity(&self, raw: Option<&str>) -> Severity {
        match lower(raw).as_deref() {
            Some("low") | Some("minor") => Severity::Low,
            Some("medium") | Some("moderate") | Some("warning") | Some("warn") => Severity::Medium,
            Some("high") | Some("error") | Some("major") | Some("alert") => Severity::High,
            Some("critical") | Some("fatal") | Some("emergency") | Some("emerg")
            | Some("severe") => Severity::Critical,
            _ => Severity::Info,
        }
    }

    pub fn normalize_result(&self, raw: Option<&str>) -> EventResult {
        match lower(raw).as_deref() {
            Some("success") | Some("ok") | Some("allowed") | Some("passed") | Some("accept")
            | Some("accepted") | Some("permit") | Some("permitted") => EventResult::Success,
            Some("failure") | Some("fail") | Some("failed") | Some("deny") | Some("denied")
            | Some("error") | Some("reject") | Some("rejected") | Some("block")
            | Some("blocked") => EventResult::Failure,
            _ => EventResult::Unknown,
        }
    }

    pub fn normalize_source_type(&self, raw: Option<&str>) -> SourceType {
        match lower(raw).as_deref() {
            Some("os") | Some("linux") | Some("windows") | Some("unix") => SourceType::Os,
            Some("firewall") | Some("fw") | Some("ids") | Some("ips") => SourceType::Firewall,
            Some("router") | Some("switch") => SourceType::Router,
            Some("network") => SourceType::Network,
            Some("database") | Some("db") => SourceType::Database,
            Some("web") | Some("webserver") | Some("http") => SourceType::Web,
            Some("application") | Some("app") => SourceType::Application,
            _ => SourceType::Other,
        }
    }

    /// Lenient IP validation: returns `Some(ip)` only for a plausible address.
    pub fn normalize_ip(&self, raw: Option<&str>) -> Option<String> {
        let ip = raw?;
        if is_ipv4(ip) || is_ipv6(ip) {
            Some(ip.to_string())
        } else {
            None
        }
    }

    /// Lenient port validation: parses 0..=65535, else `None`.
    pub fn normalize_port(&self, raw: Option<&str>) -> Option<u16> {
        raw?.parse::<u16>().ok()
    }

    /// Resolve a parser-extracted timestamp candidate to epoch milliseconds.
    /// `None` means the candidate was present but not a valid timestamp.
    pub fn normalize_timestamp(&self, ts: &Timestamp) -> Option<i64> {
        match ts {
            Timestamp::EpochMillis(ms) if *ms >= 0 => Some(*ms),
            Timestamp::RawString(s) => parse_timestamp_str(s),
            Timestamp::RawNumber(n) => {
                // Unix seconds (< 1e11) vs milliseconds (>= 1e11).
                let ms = if *n >= 1e11 { *n } else { *n * 1000.0 };
                (ms >= 0.0).then_some(ms as i64)
            }
            _ => None,
        }
    }

    pub fn normalize(
        &self,
        parsed: &ParsedEvent,
        input: &RawLogInput,
        now: i64,
    ) -> Result<AuditEvent, ParseFailure> {
        if parsed.raw_log.is_empty() {
            return Err(self.failure(
                input,
                parsed,
                FailureStage::Normalize,
                FailureCode::MissingRequiredField,
                "raw_log is empty",
            ));
        }
        let timestamp = match parsed.timestamp.as_ref() {
            Some(ts) => match self.normalize_timestamp(ts) {
                Some(ms) => ms,
                None => {
                    return Err(self.failure(
                        input,
                        parsed,
                        FailureStage::Normalize,
                        FailureCode::InvalidTimestamp,
                        "invalid timestamp",
                    ));
                }
            },
            None => input.received_at,
        };

        Ok(AuditEvent {
            timestamp,
            // A UUIDv7 occurrence id: unique per ingestion even for identical raw
            // logs. Never a content hash — two independent occurrences must differ.
            event_id: format!("evt-{}", Uuid::now_v7()),
            tenant_id: input.tenant.tenant_id.clone(),
            source_type: self.normalize_source_type(
                parsed
                    .source_type
                    .as_deref()
                    .or(input.source_type.as_deref()),
            ),
            source_name: parsed
                .source_name
                .clone()
                .or_else(|| input.source_name.clone()),
            collector_id: input.collector_id.clone(),
            vendor: parsed.vendor.clone(),
            product: parsed.product.clone(),
            product_version: parsed.product_version.clone(),
            hostname: parsed.hostname.clone(),
            asset_id: parsed.asset_id.clone(),
            src_ip: self.normalize_ip(parsed.src_ip.as_deref()),
            src_port: self.normalize_port(parsed.src_port.as_deref()),
            dst_ip: self.normalize_ip(parsed.dst_ip.as_deref()),
            dst_port: self.normalize_port(parsed.dst_port.as_deref()),
            username: parsed.username.clone(),
            category: parsed.category.clone(),
            event_type: parsed.event_type.clone(),
            action: parsed.action.clone(),
            result: Some(self.normalize_result(parsed.result.as_deref())),
            severity: self.normalize_severity(parsed.severity.as_deref()),
            message: parsed.message.clone(),
            raw_log: parsed.raw_log.clone(),
            parser_id: Some(parsed.parser_id.clone()),
            parser_version: Some(parsed.parser_version.clone()),
            ingest_timestamp: now,
            event_attributes: with_parser_quality(parsed.attributes.clone(), &parsed.parser_id),
        })
    }

    fn failure(
        &self,
        input: &RawLogInput,
        parsed: &ParsedEvent,
        stage: FailureStage,
        code: FailureCode,
        message: &str,
    ) -> ParseFailure {
        ParseFailure {
            timestamp: parsed
                .timestamp
                .as_ref()
                .and_then(|t| self.normalize_timestamp(t))
                .unwrap_or(input.received_at),
            raw_log: if parsed.raw_log.is_empty() {
                input.raw_log.clone()
            } else {
                parsed.raw_log.clone()
            },
            source_type: parsed
                .source_type
                .clone()
                .or_else(|| input.source_type.clone()),
            source_name: parsed
                .source_name
                .clone()
                .or_else(|| input.source_name.clone()),
            collector_id: input.collector_id.clone(),
            parser_id: Some(parsed.parser_id.clone()),
            parser_version: Some(parsed.parser_version.clone()),
            failure_stage: stage,
            failure_code: code,
            failure_message: message.to_string(),
        }
    }
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 3 && p.parse::<u8>().is_ok())
}

/// Parse a timestamp string to epoch milliseconds. Accepts a numeric string
/// (Unix seconds or milliseconds), RFC3339/ISO 8601 with an offset, and a few
/// naive UTC formats.
fn parse_timestamp_str(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Ok(n) = s.parse::<f64>() {
        return Some(if n >= 1e11 {
            n as i64
        } else {
            (n * 1000.0) as i64
        });
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.timestamp_millis());
    }
    for fmt in [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(ndt.and_utc().timestamp_millis());
        }
    }
    None
}

fn is_ipv6(s: &str) -> bool {
    s.contains(':') && !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
}
