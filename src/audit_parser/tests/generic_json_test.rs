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

use std::sync::Arc;

use audit_parser::{
    DispatchResult, Dispatcher, GenericJsonParser, Normalizer, ParsedEvent, Parser, ParserRegistry,
    RawLogInput, TenantContext, default_dispatcher,
};

const NOW: i64 = 1735689600999;

fn make_input(raw_log: &str) -> RawLogInput {
    RawLogInput {
        raw_log: raw_log.to_string(),
        received_at: 1735689600000,
        source_type: Some("application".to_string()),
        source_name: Some("test-app".to_string()),
        collector_id: Some("collector-1".to_string()),
        tenant: TenantContext {
            tenant_id: "tenant-trusted".to_string(),
        },
        transport: None,
    }
}

fn dispatch_event(raw_log: &str) -> audit_parser::AuditEvent {
    match default_dispatcher().dispatch(&make_input(raw_log), NOW) {
        DispatchResult::Ok(e) => *e,
        DispatchResult::Failure(f) => panic!("expected ok: {}", f.failure_message),
    }
}

#[test]
fn detect_valid_json_object() {
    assert!(GenericJsonParser.detect(&make_input(r#"{"a":1}"#)));
}

#[test]
fn detect_rejects_invalid_json() {
    assert!(!GenericJsonParser.detect(&make_input("plain text")));
    assert!(!GenericJsonParser.detect(&make_input("{invalid json")));
}

#[test]
fn detect_rejects_array() {
    assert!(!GenericJsonParser.detect(&make_input("[1,2,3]")));
}

#[test]
fn detect_ignores_leading_whitespace() {
    assert!(GenericJsonParser.detect(&make_input("  \n\t {\"a\":1}")));
}

#[test]
fn alias_precedence_first_wins() {
    // `severity` is the first alias, so it beats `level`.
    let e = dispatch_event(r#"{"severity":"high","level":"low"}"#);
    assert_eq!(e.severity, audit_parser::Severity::High);
    // `message` beats `msg`.
    let e = dispatch_event(r#"{"message":"first","msg":"second"}"#);
    assert_eq!(e.message.as_deref(), Some("first"));
}

#[test]
fn nested_source_ip() {
    let e = dispatch_event(r#"{"source":{"ip":"10.10.10.5"}}"#);
    assert_eq!(e.src_ip.as_deref(), Some("10.10.10.5"));
}

#[test]
fn nested_user_name() {
    let e = dispatch_event(r#"{"user":{"name":"admin"}}"#);
    assert_eq!(e.username.as_deref(), Some("admin"));
}

#[test]
fn severity_normalization_warning_to_medium() {
    let e = dispatch_event(r#"{"level":"warning"}"#);
    assert_eq!(e.severity, audit_parser::Severity::Medium);
    assert_eq!(
        e.event_attributes
            .as_ref()
            .and_then(|a| a["original_severity"].as_str()),
        Some("warning")
    );
}

#[test]
fn result_normalization_fail_to_failure() {
    let e = dispatch_event(r#"{"event":{"outcome":"fail"}}"#);
    assert_eq!(e.result, Some(audit_parser::EventResult::Failure));
}

#[test]
fn iso_timestamp() {
    let raw = r#"{"timestamp":"2026-09-18T10:30:00+08:00"}"#;
    let expected = chrono::DateTime::parse_from_rfc3339("2026-09-18T10:30:00+08:00")
        .unwrap()
        .timestamp_millis();
    let e = dispatch_event(raw);
    assert_eq!(e.timestamp, expected);
}

#[test]
fn unix_seconds_timestamp() {
    let e = dispatch_event(r#"{"timestamp":1789700000}"#);
    assert_eq!(e.timestamp, 1789700000000);
}

#[test]
fn unix_milliseconds_timestamp() {
    let e = dispatch_event(r#"{"timestamp":1789700000000}"#);
    assert_eq!(e.timestamp, 1789700000000);
}

#[test]
fn unknown_fields_go_to_unmapped_json() {
    let e = dispatch_event(r#"{"message":"hi","request_id":"abc123"}"#);
    let unmapped = e
        .event_attributes
        .as_ref()
        .and_then(|a| a["unmapped_json"].as_str())
        .unwrap();
    assert_eq!(unmapped, r#"{"request_id":"abc123"}"#);
}

#[test]
fn unknown_nested_object_not_expanded() {
    let e = dispatch_event(r#"{"message":"hi","foo":{"bar":1}}"#);
    let unmapped = e
        .event_attributes
        .as_ref()
        .and_then(|a| a["unmapped_json"].as_str())
        .unwrap();
    // `foo` stays nested, not flattened into foo.bar.
    assert_eq!(unmapped, r#"{"foo":{"bar":1}}"#);
}

#[test]
fn trusted_tenant_id_not_overridable() {
    let e = dispatch_event(r#"{"tenant_id":"tenant-EVIL"}"#);
    assert_eq!(e.tenant_id, "tenant-trusted");
}

#[test]
fn event_id_not_overridable() {
    let e = dispatch_event(r#"{"event_id":"evt-EVIL"}"#);
    assert_ne!(e.event_id, "evt-EVIL");
    assert!(e.event_id.starts_with("evt-"));
}

#[test]
fn parser_id_and_version_not_overridable() {
    let e = dispatch_event(r#"{"parser_id":"evil","parser_version":"9.9"}"#);
    assert_eq!(e.parser_id.as_deref(), Some("generic-json"));
    assert_eq!(e.parser_version.as_deref(), Some("1.0.0"));
}

#[test]
fn raw_log_byte_for_byte_preserved() {
    let raw = "  \t{\"message\":\"x\",\"中文\":\"值\"}";
    let e = dispatch_event(raw);
    assert_eq!(e.raw_log, raw);
}

#[test]
fn malformed_values_do_not_panic() {
    let result =
        default_dispatcher().dispatch(&make_input(r#"{"timestamp":null,"severity":{"a":1}}"#), NOW);
    assert!(matches!(
        result,
        DispatchResult::Ok(_) | DispatchResult::Failure(_)
    ));
}

#[test]
fn dispatch_chooses_generic_json() {
    let e = dispatch_event(r#"{"message":"hello"}"#);
    assert_eq!(e.parser_id.as_deref(), Some("generic-json"));
    assert_eq!(e.parser_version.as_deref(), Some("1.0.0"));
}

struct HighPriorityJson;
impl Parser for HighPriorityJson {
    fn id(&self) -> &str {
        "high-json"
    }
    fn name(&self) -> &str {
        "High JSON"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn priority(&self) -> i32 {
        30
    }
    fn supported_source_types(&self) -> &[&'static str] {
        &[]
    }
    fn detect(&self, input: &RawLogInput) -> bool {
        GenericJsonParser.detect(input)
    }
    fn parse(&self, input: &RawLogInput) -> anyhow::Result<ParsedEvent> {
        Ok(ParsedEvent {
            parser_id: "high-json".to_string(),
            parser_version: "1.0.0".to_string(),
            raw_log: input.raw_log.clone(),
            ..Default::default()
        })
    }
}

#[test]
fn higher_priority_parser_beats_generic_json() {
    let mut r = ParserRegistry::new();
    r.register(Arc::new(GenericJsonParser)).unwrap();
    r.register(Arc::new(HighPriorityJson)).unwrap();
    r.set_fallback(Arc::new(audit_parser::FallbackParser));
    let d = Dispatcher::new(r, Normalizer::new());
    match d.dispatch(&make_input(r#"{"a":1}"#), NOW) {
        DispatchResult::Ok(e) => assert_eq!(e.parser_id.as_deref(), Some("high-json")),
        DispatchResult::Failure(f) => panic!("expected ok: {}", f.failure_message),
    }
}

#[test]
fn fallback_handles_non_json() {
    let e = dispatch_event("this is not json at all");
    assert_eq!(e.parser_id.as_deref(), Some("fallback"));
}
