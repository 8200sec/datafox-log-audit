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

use audit_parser::{
    DispatchResult, ParserClass, RawLogInput, TenantContext, classify_parser, default_dispatcher,
};
use serde_json::Value;

const NOW: i64 = 1735689600999;

fn make_input(raw_log: &str) -> RawLogInput {
    RawLogInput {
        raw_log: raw_log.to_string(),
        received_at: NOW,
        source_type: None,
        source_name: Some("edge01".to_string()),
        collector_id: Some("collector-1".to_string()),
        tenant: TenantContext {
            tenant_id: "tenant-trusted".to_string(),
        },
        transport: None,
    }
}

fn dispatch(raw_log: &str) -> audit_parser::AuditEvent {
    match default_dispatcher().dispatch(&make_input(raw_log), NOW) {
        DispatchResult::Ok(e) => *e,
        DispatchResult::Failure(f) => panic!("expected ok: {}", f.failure_message),
    }
}

fn quality(e: &audit_parser::AuditEvent) -> &str {
    e.event_attributes
        .as_ref()
        .and_then(|a| a.get("parser_quality"))
        .and_then(Value::as_str)
        .expect("parser_quality missing")
}

#[test]
fn classification_mapping() {
    assert_eq!(classify_parser("linux-auth"), ParserClass::Specialized);
    assert_eq!(classify_parser("generic-json"), ParserClass::Generic);
    assert_eq!(classify_parser("generic-syslog"), ParserClass::Generic);
    assert_eq!(classify_parser("fallback"), ParserClass::Fallback);
    // Unknown / future / test parser ids default to generic.
    assert_eq!(classify_parser("dummy"), ParserClass::Generic);
    assert_eq!(classify_parser("cisco-asa"), ParserClass::Generic);
}

#[test]
fn classification_as_str() {
    assert_eq!(ParserClass::Specialized.as_str(), "specialized");
    assert_eq!(ParserClass::Generic.as_str(), "generic");
    assert_eq!(ParserClass::Fallback.as_str(), "fallback");
}

#[test]
fn linux_auth_is_specialized() {
    let e = dispatch(
        "<34>Sep 18 15:28:31 web01 sshd[1024]: Accepted password for alice from 10.0.0.2 port 55231 ssh2",
    );
    assert_eq!(e.parser_id.as_deref(), Some("linux-auth"));
    assert_eq!(quality(&e), "specialized");
}

#[test]
fn generic_syslog_is_generic() {
    let e = dispatch("<34>Sep 18 15:28:31 web01 cron[1024]: (root) CMD (run-parts)");
    assert_eq!(e.parser_id.as_deref(), Some("generic-syslog"));
    assert_eq!(quality(&e), "generic");
}

#[test]
fn generic_json_is_generic() {
    let e = dispatch(r#"{"timestamp":"2026-09-18T15:30:00Z","message":"hi"}"#);
    assert_eq!(e.parser_id.as_deref(), Some("generic-json"));
    assert_eq!(quality(&e), "generic");
}

#[test]
fn fallback_is_fallback() {
    let e = dispatch("this is not syslog or json");
    assert_eq!(e.parser_id.as_deref(), Some("fallback"));
    assert_eq!(quality(&e), "fallback");
}

#[test]
fn parser_quality_does_not_clobber_other_attributes() {
    // linux-auth keeps its auth-specific attributes alongside parser_quality.
    let e = dispatch(
        "<34>Sep 18 15:28:31 web01 sshd[1024]: Accepted password for alice from 10.0.0.2 port 55231 ssh2",
    );
    let attrs = e.event_attributes.as_ref().unwrap();
    assert_eq!(attrs["auth_method"], Value::from("password"));
    assert_eq!(attrs["parser_quality"], Value::from("specialized"));
}
