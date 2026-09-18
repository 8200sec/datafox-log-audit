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
    DispatchResult, Dispatcher, GenericJsonParser, GenericSyslogParser, Normalizer, ParsedEvent,
    Parser, ParserRegistry, RawLogInput, Severity, TenantContext, default_dispatcher,
};
use serde_json::Value;

const NOW: i64 = 1735689600999;

fn make_input(raw_log: &str, received_at: i64) -> RawLogInput {
    RawLogInput {
        raw_log: raw_log.to_string(),
        received_at,
        source_type: None,
        source_name: Some("syslog-src".to_string()),
        collector_id: Some("collector-1".to_string()),
        tenant: TenantContext {
            tenant_id: "tenant-trusted".to_string(),
        },
        transport: None,
    }
}

fn dispatch_event(raw_log: &str, received_at: i64) -> audit_parser::AuditEvent {
    match default_dispatcher().dispatch(&make_input(raw_log, received_at), NOW) {
        DispatchResult::Ok(e) => *e,
        DispatchResult::Failure(f) => panic!("expected ok: {}", f.failure_message),
    }
}

fn attr<'a>(event: &'a audit_parser::AuditEvent, key: &str) -> Option<&'a Value> {
    event.event_attributes.as_ref().and_then(|a| a.get(key))
}

const RFC3164: &str = "<34>Sep 18 15:28:31 web01 sshd[1024]: login failed";
const RFC5424: &str = "<34>1 2026-09-18T15:30:00+08:00 web01 sshd 1024 ID47 - login failed";

#[test]
fn detect_rfc3164() {
    assert!(GenericSyslogParser.detect(&make_input(RFC3164, NOW)));
}

#[test]
fn detect_rfc5424() {
    assert!(GenericSyslogParser.detect(&make_input(RFC5424, NOW)));
}

#[test]
fn detect_rejects_invalid_pri() {
    assert!(!GenericSyslogParser.detect(&make_input("<abc>msg", NOW)));
    assert!(!GenericSyslogParser.detect(&make_input("<34", NOW)));
    assert!(!GenericSyslogParser.detect(&make_input("hello <34>", NOW)));
    assert!(!GenericSyslogParser.detect(&make_input("", NOW)));
}

#[test]
fn detect_rejects_pri_over_191() {
    assert!(!GenericSyslogParser.detect(&make_input("<999>abc", NOW)));
}

#[test]
fn facility_calculation() {
    // PRI 34 → facility 4.
    let e = dispatch_event(RFC3164, NOW);
    assert_eq!(attr(&e, "syslog_facility"), Some(&Value::from(4)));
}

#[test]
fn severity_calculation() {
    // PRI 34 → severity 2.
    let e = dispatch_event(RFC3164, NOW);
    assert_eq!(attr(&e, "syslog_severity"), Some(&Value::from(2)));
    assert_eq!(attr(&e, "syslog_pri"), Some(&Value::from(34)));
}

fn severity_of(pri: u8) -> Severity {
    dispatch_event(&format!("<{pri}>Sep 18 15:28:31 h app: msg"), NOW).severity
}

#[test]
fn severity_mapping_0_emergency() {
    assert_eq!(severity_of(32), Severity::Critical); // 4*8+0
}

#[test]
fn severity_mapping_3_error() {
    assert_eq!(severity_of(35), Severity::High); // 4*8+3
}

#[test]
fn severity_mapping_4_warning() {
    assert_eq!(severity_of(36), Severity::Medium); // 4*8+4
}

#[test]
fn severity_mapping_7_debug() {
    assert_eq!(severity_of(39), Severity::Info); // 4*8+7
}

#[test]
fn rfc3164_hostname() {
    let e = dispatch_event(RFC3164, NOW);
    assert_eq!(e.hostname.as_deref(), Some("web01"));
}

#[test]
fn rfc3164_message() {
    let e = dispatch_event(RFC3164, NOW);
    assert_eq!(e.message.as_deref(), Some("login failed"));
}

#[test]
fn rfc3164_app_and_procid() {
    let e = dispatch_event(RFC3164, NOW);
    assert_eq!(attr(&e, "syslog_app_name"), Some(&Value::from("sshd")));
    assert_eq!(attr(&e, "syslog_procid"), Some(&Value::from("1024")));
}

#[test]
fn rfc3164_normal_timestamp() {
    // received 1s after the log time → same year, no future timestamp.
    let received = chrono::DateTime::parse_from_rfc3339("2026-09-18T15:28:32Z")
        .unwrap()
        .timestamp_millis();
    let expected = chrono::DateTime::parse_from_rfc3339("2026-09-18T15:28:31Z")
        .unwrap()
        .timestamp_millis();
    let e = dispatch_event("<34>Sep 18 15:28:31 web01 sshd: x", received);
    assert_eq!(e.timestamp, expected);
}

#[test]
fn rfc3164_clock_skew_within_tolerance() {
    // 30s of device clock skew stays in the current year.
    let received = chrono::DateTime::parse_from_rfc3339("2026-09-18T15:28:00Z")
        .unwrap()
        .timestamp_millis();
    let expected = chrono::DateTime::parse_from_rfc3339("2026-09-18T15:28:30Z")
        .unwrap()
        .timestamp_millis();
    let e = dispatch_event("<34>Sep 18 15:28:30 web01 sshd: x", received);
    assert_eq!(e.timestamp, expected);
}

#[test]
fn rfc3164_future_timestamp_rolls_back_year() {
    // A log dated one day ahead of received_at belongs to the previous year.
    let received = chrono::DateTime::parse_from_rfc3339("2026-09-18T00:00:00Z")
        .unwrap()
        .timestamp_millis();
    let expected = chrono::DateTime::parse_from_rfc3339("2025-09-19T12:00:00Z")
        .unwrap()
        .timestamp_millis();
    let e = dispatch_event("<34>Sep 19 12:00:00 web01 sshd: x", received);
    assert_eq!(e.timestamp, expected);
}

#[test]
fn rfc3164_year_boundary_timestamp() {
    // received_at Jan 1 2027 → log Dec 31 23:59 must be 2026, not ~1 year ahead.
    let received = chrono::DateTime::parse_from_rfc3339("2027-01-01T00:00:00Z")
        .unwrap()
        .timestamp_millis();
    let expected = chrono::DateTime::parse_from_rfc3339("2026-12-31T23:59:59Z")
        .unwrap()
        .timestamp_millis();
    let e = dispatch_event("<34>Dec 31 23:59:59 web01 sshd: x", received);
    assert_eq!(e.timestamp, expected);
}

#[test]
fn rfc5424_timestamp() {
    let expected = chrono::DateTime::parse_from_rfc3339("2026-09-18T15:30:00+08:00")
        .unwrap()
        .timestamp_millis();
    let e = dispatch_event(RFC5424, NOW);
    assert_eq!(e.timestamp, expected);
}

#[test]
fn rfc5424_hostname() {
    let e = dispatch_event(RFC5424, NOW);
    assert_eq!(e.hostname.as_deref(), Some("web01"));
}

#[test]
fn rfc5424_app_name() {
    let e = dispatch_event(RFC5424, NOW);
    assert_eq!(attr(&e, "syslog_app_name"), Some(&Value::from("sshd")));
}

#[test]
fn rfc5424_procid() {
    let e = dispatch_event(RFC5424, NOW);
    assert_eq!(attr(&e, "syslog_procid"), Some(&Value::from("1024")));
}

#[test]
fn rfc5424_msgid() {
    let e = dispatch_event(RFC5424, NOW);
    assert_eq!(attr(&e, "syslog_msgid"), Some(&Value::from("ID47")));
}

#[test]
fn rfc5424_nilvalue_not_real() {
    // "-" hostname/app-name must not become real values.
    let e = dispatch_event("<34>1 - - - - - - x", NOW);
    assert_eq!(e.hostname, None);
    assert_eq!(attr(&e, "syslog_app_name"), None);
}

#[test]
fn rfc5424_one_structured_data_element() {
    let e = dispatch_event(
        r#"<34>1 2026-09-18T15:30:00Z web01 app 1 ID [exampleSDID@32473 iut="3" eventSource="Application"] msg"#,
        NOW,
    );
    let sd = attr(&e, "syslog_structured_data")
        .unwrap()
        .as_str()
        .unwrap();
    assert!(sd.contains("exampleSDID@32473"));
    assert!(sd.contains("eventSource"));
}

#[test]
fn rfc5424_multiple_structured_data_elements() {
    let e = dispatch_event(
        r#"<34>1 2026-09-18T15:30:00Z web01 app 1 ID [a@1 x="1"][b@2 y="2"] msg"#,
        NOW,
    );
    let sd = attr(&e, "syslog_structured_data")
        .unwrap()
        .as_str()
        .unwrap();
    assert!(sd.contains("a@1"));
    assert!(sd.contains("b@2"));
}

#[test]
fn rfc5424_structured_data_escaping() {
    let e = dispatch_event(
        r#"<34>1 2026-09-18T15:30:00Z web01 app 1 ID [a@1 msg="say \"hi\" back\\slash"] m"#,
        NOW,
    );
    let sd = attr(&e, "syslog_structured_data")
        .unwrap()
        .as_str()
        .unwrap();
    let parsed: Value = serde_json::from_str(sd).unwrap();
    assert_eq!(
        parsed[0]["a@1"]["msg"].as_str().unwrap(),
        r#"say "hi" back\slash"#
    );
}

#[test]
fn raw_log_preserved() {
    let e = dispatch_event(RFC3164, NOW);
    assert_eq!(e.raw_log, RFC3164);
}

#[test]
fn malformed_syslog_does_not_panic() {
    let result = default_dispatcher().dispatch(&make_input("<34>", NOW), NOW);
    assert!(matches!(
        result,
        DispatchResult::Ok(_) | DispatchResult::Failure(_)
    ));
    let result = default_dispatcher().dispatch(&make_input("<34>Sep", NOW), NOW);
    assert!(matches!(
        result,
        DispatchResult::Ok(_) | DispatchResult::Failure(_)
    ));
}

#[test]
fn registry_dispatches_generic_syslog() {
    let e = dispatch_event(RFC3164, NOW);
    assert_eq!(e.parser_id.as_deref(), Some("generic-syslog"));
}

struct HighPrioritySyslog;
impl Parser for HighPrioritySyslog {
    fn id(&self) -> &str {
        "vendor-syslog"
    }
    fn name(&self) -> &str {
        "Vendor Syslog"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn priority(&self) -> i32 {
        50
    }
    fn supported_source_types(&self) -> &[&'static str] {
        &[]
    }
    fn detect(&self, input: &RawLogInput) -> bool {
        GenericSyslogParser.detect(input)
    }
    fn parse(&self, input: &RawLogInput) -> anyhow::Result<ParsedEvent> {
        Ok(ParsedEvent {
            parser_id: "vendor-syslog".to_string(),
            parser_version: "1.0.0".to_string(),
            raw_log: input.raw_log.clone(),
            ..Default::default()
        })
    }
}

#[test]
fn higher_priority_beats_generic_syslog() {
    let mut r = ParserRegistry::new();
    r.register(Arc::new(GenericSyslogParser)).unwrap();
    r.register(Arc::new(HighPrioritySyslog)).unwrap();
    r.set_fallback(Arc::new(audit_parser::FallbackParser));
    let d = Dispatcher::new(r, Normalizer::new());
    match d.dispatch(&make_input(RFC3164, NOW), NOW) {
        DispatchResult::Ok(e) => assert_eq!(e.parser_id.as_deref(), Some("vendor-syslog")),
        DispatchResult::Failure(f) => panic!("expected ok: {}", f.failure_message),
    }
}

#[test]
fn generic_syslog_beats_fallback() {
    let e = dispatch_event(RFC3164, NOW);
    assert_ne!(e.parser_id.as_deref(), Some("fallback"));
}

#[test]
fn json_still_goes_to_generic_json() {
    // A JSON object (not syslog) must still route to generic-json, not syslog.
    let e = dispatch_event(r#"{"message":"hi"}"#, NOW);
    assert_eq!(e.parser_id.as_deref(), Some("generic-json"));
    let _ = GenericJsonParser; // keep the import used
}
