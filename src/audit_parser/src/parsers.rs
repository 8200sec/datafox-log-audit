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
    parser::Parser,
    types::{ParsedEvent, RawLogInput},
};

/// Generic fallback for logs no dedicated parser claims. Never drops a log.
pub struct FallbackParser;

impl Parser for FallbackParser {
    fn id(&self) -> &str {
        "fallback"
    }
    fn name(&self) -> &str {
        "Generic Fallback"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn priority(&self) -> i32 {
        -100
    }
    fn supported_source_types(&self) -> &[&'static str] {
        &[]
    }
    fn detect(&self, _: &RawLogInput) -> bool {
        true
    }
    fn parse(&self, input: &RawLogInput) -> anyhow::Result<ParsedEvent> {
        Ok(ParsedEvent {
            parser_id: "fallback".to_string(),
            parser_version: "1.0.0".to_string(),
            raw_log: input.raw_log.clone(),
            source_type: input.source_type.clone(),
            source_name: input.source_name.clone(),
            severity: Some("info".to_string()),
            result: Some("unknown".to_string()),
            message: Some("Unrecognized log format".to_string()),
            ..Default::default()
        })
    }
}

/// Minimal parser used only to exercise the framework. Emits unnormalized
/// aliases (`warning` → medium, `ok` → success) so tests assert the Normalizer
/// coerces them.
pub struct DummyParser;

impl Parser for DummyParser {
    fn id(&self) -> &str {
        "dummy"
    }
    fn name(&self) -> &str {
        "Dummy Test Parser"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn priority(&self) -> i32 {
        100
    }
    fn supported_source_types(&self) -> &[&'static str] {
        &["test"]
    }
    fn detect(&self, input: &RawLogInput) -> bool {
        input.source_type.as_deref() == Some("test") || input.raw_log.contains("DUMMY")
    }
    fn parse(&self, input: &RawLogInput) -> anyhow::Result<ParsedEvent> {
        Ok(ParsedEvent {
            parser_id: "dummy".to_string(),
            parser_version: "1.0.0".to_string(),
            raw_log: input.raw_log.clone(),
            timestamp: Some(input.received_at),
            source_type: Some("application".to_string()),
            source_name: Some("dummy-source".to_string()),
            hostname: Some("dummy-host".to_string()),
            src_ip: Some("10.0.0.7".to_string()),
            src_port: Some("1234".to_string()),
            dst_ip: Some("10.0.0.8".to_string()),
            dst_port: Some("443".to_string()),
            username: Some("alice".to_string()),
            category: Some("test".to_string()),
            event_type: Some("dummy_event".to_string()),
            action: Some("test".to_string()),
            severity: Some("warning".to_string()),
            result: Some("ok".to_string()),
            message: Some("parsed by dummy".to_string()),
            attributes: Some(serde_json::json!({ "dummy.marker": true })),
            ..Default::default()
        })
    }
}
