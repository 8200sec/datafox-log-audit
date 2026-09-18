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

use crate::{
    failure::{FailureCode, FailureStage, ParseFailure},
    types::{AuditEvent, EventResult, ParsedEvent, RawLogInput, Severity, SourceType},
};

/// Deterministic djb2 event id — stable for the same tenant+source+raw+time.
fn generate_event_id(tenant: &str, source: Option<&str>, raw: &str, ts: i64) -> String {
    let material = format!("{}:{}:{}:{}", tenant, source.unwrap_or(""), raw, ts);
    let mut hash: u32 = 5381;
    for b in material.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(b as u32);
    }
    format!("evt-{}-{:08x}", ts, hash)
}

fn lower(s: Option<&str>) -> Option<String> {
    s.map(|v| v.to_lowercase())
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
        let timestamp = parsed.timestamp.unwrap_or(input.received_at);
        if timestamp < 0 {
            return Err(self.failure(
                input,
                parsed,
                FailureStage::Normalize,
                FailureCode::InvalidTimestamp,
                "invalid timestamp",
            ));
        }

        Ok(AuditEvent {
            timestamp,
            event_id: generate_event_id(
                &input.tenant.tenant_id,
                parsed
                    .source_name
                    .as_deref()
                    .or(input.source_name.as_deref()),
                &parsed.raw_log,
                timestamp,
            ),
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
            event_attributes: parsed.attributes.clone(),
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
            timestamp: parsed.timestamp.unwrap_or(input.received_at),
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

fn is_ipv6(s: &str) -> bool {
    s.contains(':') && !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
}
