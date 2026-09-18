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
    DispatchResult, Dispatcher, DummyParser, FailureCode, FallbackParser, Normalizer, ParsedEvent,
    Parser, ParserRegistry, RawLogInput, Severity, TenantContext,
};

const FIXED_NOW: i64 = 1735689600999;

fn make_input() -> RawLogInput {
    RawLogInput {
        raw_log: "DUMMY test log line".to_string(),
        received_at: 1735689600000,
        source_type: Some("test".to_string()),
        source_name: Some("src-1".to_string()),
        collector_id: Some("collector-1".to_string()),
        tenant: TenantContext {
            tenant_id: "tenant-trusted".to_string(),
        },
        transport: None,
    }
}

fn make_registry() -> ParserRegistry {
    let mut r = ParserRegistry::new();
    r.register(Arc::new(DummyParser)).unwrap();
    r.set_fallback(Arc::new(FallbackParser));
    r
}

fn make_dispatcher() -> Dispatcher {
    Dispatcher::new(make_registry(), Normalizer::new())
}

struct ThrowingParser;
impl Parser for ThrowingParser {
    fn id(&self) -> &str {
        "throwing"
    }
    fn name(&self) -> &str {
        "Throwing"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn priority(&self) -> i32 {
        1000
    }
    fn supported_source_types(&self) -> &[&'static str] {
        &["test"]
    }
    fn detect(&self, _: &RawLogInput) -> bool {
        true
    }
    fn parse(&self, _: &RawLogInput) -> anyhow::Result<ParsedEvent> {
        anyhow::bail!("boom")
    }
}

struct BadTimestampParser;
impl Parser for BadTimestampParser {
    fn id(&self) -> &str {
        "bad-ts"
    }
    fn name(&self) -> &str {
        "BadTs"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn priority(&self) -> i32 {
        1000
    }
    fn supported_source_types(&self) -> &[&'static str] {
        &["test"]
    }
    fn detect(&self, _: &RawLogInput) -> bool {
        true
    }
    fn parse(&self, input: &RawLogInput) -> anyhow::Result<ParsedEvent> {
        Ok(ParsedEvent {
            parser_id: "bad-ts".to_string(),
            parser_version: "1.0.0".to_string(),
            raw_log: input.raw_log.clone(),
            timestamp: Some(audit_parser::Timestamp::EpochMillis(-1)),
            severity: Some("info".to_string()),
            ..Default::default()
        })
    }
}

struct EvilTenantParser;
impl Parser for EvilTenantParser {
    fn id(&self) -> &str {
        "evil"
    }
    fn name(&self) -> &str {
        "Evil"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn priority(&self) -> i32 {
        1000
    }
    fn supported_source_types(&self) -> &[&'static str] {
        &["test"]
    }
    fn detect(&self, _: &RawLogInput) -> bool {
        true
    }
    fn parse(&self, input: &RawLogInput) -> anyhow::Result<ParsedEvent> {
        Ok(ParsedEvent {
            parser_id: "evil".to_string(),
            parser_version: "1.0.0".to_string(),
            raw_log: input.raw_log.clone(),
            attributes: Some(serde_json::json!({ "tenant_id": "tenant-EVIL" })),
            ..Default::default()
        })
    }
}

#[test]
fn registration_and_lookup() {
    let mut r = ParserRegistry::new();
    r.register(Arc::new(DummyParser)).unwrap();
    assert!(r.lookup("dummy").is_some());
    assert!(r.lookup("missing").is_none());
}

#[test]
fn duplicate_id_rejected() {
    let mut r = ParserRegistry::new();
    r.register(Arc::new(DummyParser)).unwrap();
    assert!(r.register(Arc::new(DummyParser)).is_err());
}

#[test]
fn priority_ordering() {
    let mut r = ParserRegistry::new();
    r.register(Arc::new(DummyParser)).unwrap(); // priority 100
    r.register(Arc::new(ThrowingParser)).unwrap(); // priority 1000
    let ids: Vec<String> = r.list().iter().map(|p| p.id().to_string()).collect();
    assert_eq!(ids, vec!["throwing".to_string(), "dummy".to_string()]);
}

#[test]
fn detect_returns_only_matches() {
    let r = make_registry();
    assert_eq!(r.detect(&make_input()).len(), 1);
    let mut other = make_input();
    other.source_type = Some("firewall".to_string());
    other.raw_log = "something else".to_string();
    assert!(r.detect(&other).is_empty());
}

#[test]
fn normal_parse_and_normalize() {
    let result = make_dispatcher().dispatch(&make_input(), FIXED_NOW);
    match result {
        DispatchResult::Ok(event) => {
            assert_eq!(event.severity, Severity::Medium); // "warning" -> medium
            assert_eq!(event.result, Some(audit_parser::EventResult::Success)); // "ok" -> success
            assert_eq!(event.username.as_deref(), Some("alice"));
        }
        DispatchResult::Failure(f) => panic!("expected ok, got failure: {}", f.failure_message),
    }
}

#[test]
fn fallback_when_no_match() {
    let mut input = make_input();
    input.source_type = Some("unknown".to_string());
    input.raw_log = "no parser knows me".to_string();
    match make_dispatcher().dispatch(&input, FIXED_NOW) {
        DispatchResult::Ok(event) => assert_eq!(event.parser_id.as_deref(), Some("fallback")),
        DispatchResult::Failure(f) => panic!("expected fallback event, got {}", f.failure_message),
    }
}

#[test]
fn fallback_preserves_minimum_event() {
    let mut input = make_input();
    input.source_type = Some("unknown".to_string());
    input.raw_log = "garbage".to_string();
    match make_dispatcher().dispatch(&input, FIXED_NOW) {
        DispatchResult::Ok(event) => {
            assert_eq!(event.severity, Severity::Info);
            assert_eq!(event.result, Some(audit_parser::EventResult::Unknown));
            assert_eq!(event.raw_log, "garbage");
        }
        DispatchResult::Failure(f) => panic!("expected ok, got {}", f.failure_message),
    }
}

#[test]
fn parser_error_becomes_failure_not_loss() {
    let mut r = ParserRegistry::new();
    r.register(Arc::new(ThrowingParser)).unwrap();
    r.set_fallback(Arc::new(FallbackParser));
    let d = Dispatcher::new(r, Normalizer::new());
    match d.dispatch(&make_input(), FIXED_NOW) {
        DispatchResult::Failure(f) => {
            assert_eq!(f.failure_code, FailureCode::ParserException);
            assert!(f.failure_message.contains("boom"));
            assert_eq!(f.raw_log, make_input().raw_log);
        }
        DispatchResult::Ok(_) => panic!("expected failure"),
    }
}

#[test]
fn normalization_error_invalid_timestamp() {
    let mut r = ParserRegistry::new();
    r.register(Arc::new(BadTimestampParser)).unwrap();
    r.set_fallback(Arc::new(FallbackParser));
    let d = Dispatcher::new(r, Normalizer::new());
    match d.dispatch(&make_input(), FIXED_NOW) {
        DispatchResult::Failure(f) => assert_eq!(f.failure_code, FailureCode::InvalidTimestamp),
        DispatchResult::Ok(_) => panic!("expected failure"),
    }
}

#[test]
fn raw_log_preserved_byte_for_byte() {
    let mut input = make_input();
    input.raw_log = "odd \u{0} bytes \u{2713} and 中文 and \r\n newline".to_string();
    let original = input.raw_log.clone();
    match make_dispatcher().dispatch(&input, FIXED_NOW) {
        DispatchResult::Ok(event) => assert_eq!(event.raw_log, original),
        DispatchResult::Failure(f) => panic!("expected ok, got {}", f.failure_message),
    }
}

#[test]
fn tenant_not_overridable_by_raw_log() {
    let mut r = ParserRegistry::new();
    r.register(Arc::new(EvilTenantParser)).unwrap();
    r.set_fallback(Arc::new(FallbackParser));
    let d = Dispatcher::new(r, Normalizer::new());
    match d.dispatch(&make_input(), FIXED_NOW) {
        DispatchResult::Ok(event) => {
            assert_eq!(event.tenant_id, "tenant-trusted");
            // The smuggled value lands in event_attributes, not the trusted field.
            assert_eq!(
                event.event_attributes.as_ref().unwrap()["tenant_id"],
                "tenant-EVIL"
            );
        }
        DispatchResult::Failure(f) => panic!("expected ok, got {}", f.failure_message),
    }
}

#[test]
fn parser_id_and_version_written() {
    match make_dispatcher().dispatch(&make_input(), FIXED_NOW) {
        DispatchResult::Ok(event) => {
            assert_eq!(event.parser_id.as_deref(), Some("dummy"));
            assert_eq!(event.parser_version.as_deref(), Some("1.0.0"));
        }
        DispatchResult::Failure(f) => panic!("expected ok, got {}", f.failure_message),
    }
}

#[test]
fn malformed_input_does_not_crash() {
    let mut input = make_input();
    input.source_type = Some("other".to_string());
    input.raw_log = "\u{0}\u{1}\u{2} binary garbage".to_string();
    let result = make_dispatcher().dispatch(&input, FIXED_NOW);
    assert!(matches!(
        result,
        DispatchResult::Ok(_) | DispatchResult::Failure(_)
    ));
}

#[test]
fn severity_normalization() {
    let n = Normalizer::new();
    assert_eq!(n.normalize_severity(Some("warning")), Severity::Medium);
    assert_eq!(n.normalize_severity(Some("fatal")), Severity::Critical);
    assert_eq!(n.normalize_severity(Some("error")), Severity::High);
    assert_eq!(n.normalize_severity(None), Severity::Info);
    assert_eq!(n.normalize_severity(Some("gibberish")), Severity::Info);
}

#[test]
fn result_normalization() {
    let n = Normalizer::new();
    assert_eq!(
        n.normalize_result(Some("ok")),
        audit_parser::EventResult::Success
    );
    assert_eq!(
        n.normalize_result(Some("deny")),
        audit_parser::EventResult::Failure
    );
    assert_eq!(n.normalize_result(None), audit_parser::EventResult::Unknown);
    assert_eq!(
        n.normalize_result(Some("gibberish")),
        audit_parser::EventResult::Unknown
    );
}

#[test]
fn audit_event_serializes_with_schema_fields() {
    let event = match make_dispatcher().dispatch(&make_input(), FIXED_NOW) {
        DispatchResult::Ok(e) => e,
        DispatchResult::Failure(f) => panic!("expected ok: {}", f.failure_message),
    };
    let v = serde_json::to_value(&*event).unwrap();
    for key in [
        "_timestamp",
        "event_id",
        "tenant_id",
        "source_type",
        "source_name",
        "collector_id",
        "severity",
        "result",
        "message",
        "raw_log",
        "parser_id",
        "parser_version",
        "ingest_timestamp",
        "event_attributes",
    ] {
        assert!(v.get(key).is_some(), "missing field {key}");
    }
}

#[test]
fn parse_failure_serializes_with_failure_fields() {
    let mut r = ParserRegistry::new();
    r.register(Arc::new(ThrowingParser)).unwrap();
    r.set_fallback(Arc::new(FallbackParser));
    let d = Dispatcher::new(r, Normalizer::new());
    let failure = match d.dispatch(&make_input(), FIXED_NOW) {
        DispatchResult::Failure(f) => f,
        DispatchResult::Ok(_) => panic!("expected failure"),
    };
    let v = serde_json::to_value(&failure).unwrap();
    for key in [
        "_timestamp",
        "raw_log",
        "failure_stage",
        "failure_code",
        "failure_message",
    ] {
        assert!(v.get(key).is_some(), "missing field {key}");
    }
    assert_eq!(v["failure_code"], "PARSER_EXCEPTION");
}
