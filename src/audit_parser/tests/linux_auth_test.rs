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
    DispatchResult, EventResult, LinuxAuthParser, Parser, RawLogInput, TenantContext,
    default_dispatcher,
};
use serde_json::Value;

const NOW: i64 = 1735689600999;

fn make_input(raw_log: &str, received_at: i64) -> RawLogInput {
    RawLogInput {
        raw_log: raw_log.to_string(),
        received_at,
        source_type: None,
        source_name: Some("edge01".to_string()),
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

/// Build an RFC3164 syslog line with the given tag and message body.
fn syslog_line(tag: &str, msg: &str) -> String {
    format!("<34>Sep 18 15:28:31 web01 {tag}[1024]: {msg}")
}

fn sshd(msg: &str) -> String {
    syslog_line("sshd", msg)
}

// --- SSH login --------------------------------------------------------------

#[test]
fn ssh_accepted_password() {
    let e = dispatch_event(
        &sshd("Accepted password for alice from 10.10.10.5 port 55231 ssh2"),
        NOW,
    );
    assert_eq!(e.parser_id.as_deref(), Some("linux-auth"));
    assert_eq!(e.hostname.as_deref(), Some("web01"));
    assert_eq!(e.username.as_deref(), Some("alice"));
    assert_eq!(e.src_ip.as_deref(), Some("10.10.10.5"));
    assert_eq!(e.src_port, Some(55231));
    assert_eq!(e.category.as_deref(), Some("authentication"));
    assert_eq!(e.event_type.as_deref(), Some("ssh_login"));
    assert_eq!(e.action.as_deref(), Some("login"));
    assert_eq!(e.result, Some(EventResult::Success));
    assert_eq!(attr(&e, "auth_method"), Some(&Value::from("password")));
    assert_eq!(
        e.raw_log,
        sshd("Accepted password for alice from 10.10.10.5 port 55231 ssh2")
    );
}

#[test]
fn ssh_accepted_publickey() {
    let e = dispatch_event(
        &sshd("Accepted publickey for alice from 10.0.0.2 port 55231 ssh2: RSA SHA256:abc"),
        NOW,
    );
    assert_eq!(e.event_type.as_deref(), Some("ssh_login"));
    assert_eq!(e.action.as_deref(), Some("login"));
    assert_eq!(e.result, Some(EventResult::Success));
    assert_eq!(attr(&e, "auth_method"), Some(&Value::from("publickey")));
    assert_eq!(e.username.as_deref(), Some("alice"));
}

#[test]
fn ssh_failed_password() {
    let e = dispatch_event(
        &sshd("Failed password for alice from 10.10.10.5 port 55231 ssh2"),
        NOW,
    );
    assert_eq!(e.event_type.as_deref(), Some("ssh_login"));
    assert_eq!(e.action.as_deref(), Some("login"));
    assert_eq!(e.result, Some(EventResult::Failure));
    assert_eq!(e.username.as_deref(), Some("alice"));
    assert_eq!(e.src_ip.as_deref(), Some("10.10.10.5"));
    assert_eq!(e.src_port, Some(55231));
    assert_eq!(attr(&e, "auth_method"), Some(&Value::from("password")));
    assert_eq!(attr(&e, "invalid_user"), None);
}

#[test]
fn ssh_failed_password_invalid_user() {
    let e = dispatch_event(
        &sshd("Failed password for invalid user admin from 10.10.10.5 port 55231 ssh2"),
        NOW,
    );
    assert_eq!(e.result, Some(EventResult::Failure));
    assert_eq!(e.username.as_deref(), Some("admin"));
    assert_eq!(attr(&e, "invalid_user"), Some(&Value::from(true)));
}

#[test]
fn ssh_invalid_user() {
    let e = dispatch_event(&sshd("Invalid user admin from 10.0.0.2 port 55231"), NOW);
    assert_eq!(e.result, Some(EventResult::Failure));
    assert_eq!(e.username.as_deref(), Some("admin"));
    assert_eq!(e.src_ip.as_deref(), Some("10.0.0.2"));
    assert_eq!(e.src_port, Some(55231));
    assert_eq!(attr(&e, "invalid_user"), Some(&Value::from(true)));
}

#[test]
fn ssh_invalid_user_no_port() {
    let e = dispatch_event(&sshd("Invalid user admin from 10.0.0.2"), NOW);
    assert_eq!(e.result, Some(EventResult::Failure));
    assert_eq!(e.username.as_deref(), Some("admin"));
    assert_eq!(e.src_ip.as_deref(), Some("10.0.0.2"));
    assert_eq!(e.src_port, None);
    assert_eq!(attr(&e, "invalid_user"), Some(&Value::from(true)));
}

// --- SSH / PAM session ------------------------------------------------------

#[test]
fn ssh_session_opened() {
    let e = dispatch_event(
        &sshd("pam_unix(sshd:session): session opened for user alice by (uid=0)"),
        NOW,
    );
    assert_eq!(e.category.as_deref(), Some("authentication"));
    assert_eq!(e.event_type.as_deref(), Some("session"));
    assert_eq!(e.action.as_deref(), Some("session_open"));
    assert_eq!(e.result, Some(EventResult::Success));
    assert_eq!(e.username.as_deref(), Some("alice"));
}

#[test]
fn ssh_session_closed() {
    let e = dispatch_event(
        &sshd("pam_unix(sshd:session): session closed for user alice"),
        NOW,
    );
    assert_eq!(e.event_type.as_deref(), Some("session"));
    assert_eq!(e.action.as_deref(), Some("session_close"));
    assert_eq!(e.result, Some(EventResult::Success));
    assert_eq!(e.username.as_deref(), Some("alice"));
}

// --- sudo -------------------------------------------------------------------

#[test]
fn sudo_command_full() {
    let e = dispatch_event(
        &syslog_line(
            "sudo",
            "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
        ),
        NOW,
    );
    assert_eq!(e.category.as_deref(), Some("privilege"));
    assert_eq!(e.event_type.as_deref(), Some("sudo_command"));
    assert_eq!(e.action.as_deref(), Some("execute"));
    assert_eq!(e.username.as_deref(), Some("alice"));
    assert_eq!(attr(&e, "target_user"), Some(&Value::from("root")));
    assert_eq!(attr(&e, "tty"), Some(&Value::from("pts/0")));
    assert_eq!(attr(&e, "cwd"), Some(&Value::from("/home/alice")));
    assert_eq!(
        attr(&e, "command"),
        Some(&Value::from("/usr/bin/cat /etc/shadow"))
    );
}

#[test]
fn sudo_command_failure() {
    let e = dispatch_event(
        &syslog_line(
            "sudo",
            "alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
        ),
        NOW,
    );
    assert_eq!(e.event_type.as_deref(), Some("sudo_command"));
    assert_eq!(e.action.as_deref(), Some("execute"));
    assert_eq!(e.result, Some(EventResult::Failure));
    assert_eq!(e.username.as_deref(), Some("alice"));
    assert_eq!(attr(&e, "target_user"), Some(&Value::from("root")));
}

// --- su ---------------------------------------------------------------------

#[test]
fn su_session_opened() {
    let e = dispatch_event(
        &syslog_line(
            "su",
            "pam_unix(su:session): session opened for user root by alice(uid=1000)",
        ),
        NOW,
    );
    assert_eq!(e.category.as_deref(), Some("privilege"));
    assert_eq!(e.event_type.as_deref(), Some("user_switch"));
    assert_eq!(e.action.as_deref(), Some("switch_user"));
    assert_eq!(e.result, Some(EventResult::Success));
    assert_eq!(e.username.as_deref(), Some("alice"));
    assert_eq!(attr(&e, "target_user"), Some(&Value::from("root")));
}

#[test]
fn su_session_closed() {
    let e = dispatch_event(
        &syslog_line("su", "pam_unix(su:session): session closed for user root"),
        NOW,
    );
    assert_eq!(e.event_type.as_deref(), Some("user_switch"));
    assert_eq!(e.action.as_deref(), Some("switch_user"));
    assert_eq!(e.result, Some(EventResult::Success));
    assert_eq!(attr(&e, "target_user"), Some(&Value::from("root")));
}

// --- PAM --------------------------------------------------------------------

#[test]
fn pam_auth_failure() {
    let e = dispatch_event(
        &sshd(
            "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.0.0.5 user=alice",
        ),
        NOW,
    );
    assert_eq!(e.category.as_deref(), Some("authentication"));
    assert_eq!(e.event_type.as_deref(), Some("pam_auth"));
    assert_eq!(e.action.as_deref(), Some("authenticate"));
    assert_eq!(e.result, Some(EventResult::Failure));
    assert_eq!(attr(&e, "pam_service"), Some(&Value::from("sshd")));
    assert_eq!(attr(&e, "rhost"), Some(&Value::from("10.0.0.5")));
    assert_eq!(e.src_ip.as_deref(), Some("10.0.0.5"));
    assert_eq!(attr(&e, "target_user"), Some(&Value::from("alice")));
}

#[test]
fn su_auth_failure() {
    let e = dispatch_event(
        &syslog_line(
            "su",
            "pam_unix(su:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost= user=root",
        ),
        NOW,
    );
    assert_eq!(e.category.as_deref(), Some("authentication"));
    assert_eq!(e.event_type.as_deref(), Some("pam_auth"));
    assert_eq!(e.action.as_deref(), Some("authenticate"));
    assert_eq!(e.result, Some(EventResult::Failure));
    assert_eq!(attr(&e, "pam_service"), Some(&Value::from("su")));
    assert_eq!(attr(&e, "target_user"), Some(&Value::from("root")));
}

// --- Dispatcher routing -----------------------------------------------------

#[test]
fn linux_auth_wins_over_generic_syslog() {
    let e = dispatch_event(
        &sshd("Accepted password for alice from 10.0.0.2 port 55231 ssh2"),
        NOW,
    );
    assert_eq!(e.parser_id.as_deref(), Some("linux-auth"));
    assert_eq!(e.parser_version.as_deref(), Some("1.0.0"));
}

#[test]
fn unknown_sshd_falls_back_to_generic_syslog() {
    for msg in [
        "Server listening on 0.0.0.0 port 22",
        "Received signal 15; terminating",
        "Connection reset by 10.0.0.2 port 55231",
    ] {
        let e = dispatch_event(&sshd(msg), NOW);
        assert_eq!(e.parser_id.as_deref(), Some("generic-syslog"), "{msg}");
    }
}

#[test]
fn generic_syslog_still_handles_ordinary_syslog() {
    let e = dispatch_event(
        "<34>Sep 18 15:28:31 web01 cron[1024]: (root) CMD (run-parts /etc/cron.hourly)",
        NOW,
    );
    assert_eq!(e.parser_id.as_deref(), Some("generic-syslog"));
}

#[test]
fn generic_json_remains_unaffected() {
    let e = dispatch_event(
        r#"{"timestamp":"2026-09-18T15:30:00Z","message":"hi"}"#,
        NOW,
    );
    assert_eq!(e.parser_id.as_deref(), Some("generic-json"));
}

#[test]
fn fallback_remains_functional() {
    let e = dispatch_event("this is not syslog or json", NOW);
    assert_eq!(e.parser_id.as_deref(), Some("fallback"));
}

#[test]
fn detect_rejects_plain_json() {
    assert!(!LinuxAuthParser.detect(&make_input(r#"{"a":1}"#, NOW)));
}

#[test]
fn detect_rejects_unknown_sshd() {
    assert!(!LinuxAuthParser.detect(&make_input(
        &sshd("Server listening on 0.0.0.0 port 22"),
        NOW
    )));
}

#[test]
fn detect_accepts_ssh_login() {
    assert!(LinuxAuthParser.detect(&make_input(
        &sshd("Accepted password for alice from 10.0.0.2 port 55231 ssh2"),
        NOW
    )));
}

// --- Security ---------------------------------------------------------------

#[test]
fn tenant_not_overridable() {
    let e = dispatch_event(
        &sshd("Accepted password for alice from 10.0.0.2 port 55231 ssh2"),
        NOW,
    );
    assert_eq!(e.tenant_id, "tenant-trusted");
}

#[test]
fn event_id_generated() {
    let e = dispatch_event(
        &sshd("Accepted password for alice from 10.0.0.2 port 55231 ssh2"),
        NOW,
    );
    assert!(e.event_id.starts_with("evt-"));
}

#[test]
fn same_raw_log_gets_distinct_event_ids() {
    // Two independent ingestions of an identical line are two occurrences —
    // they must get distinct event ids (never a content fingerprint).
    let raw = sshd("Failed password for alice from 10.0.0.1 port 55231 ssh2");
    let e1 = dispatch_event(&raw, NOW);
    let e2 = dispatch_event(&raw, NOW);
    assert_ne!(e1.event_id, e2.event_id);
    assert_eq!(e1.raw_log, raw);
    assert_eq!(e2.raw_log, raw);
    assert_eq!(e1.raw_log, e2.raw_log);
}

#[test]
fn raw_log_unchanged_byte_for_byte() {
    let raw = sshd("Accepted password for alice from 10.0.0.2 port 55231 ssh2");
    let e = dispatch_event(&raw, NOW);
    assert_eq!(e.raw_log, raw);
}

// --- Robustness -------------------------------------------------------------

#[test]
fn malformed_ssh_does_not_panic() {
    let r = default_dispatcher().dispatch(&make_input(&sshd("Failed password for from"), NOW), NOW);
    assert!(matches!(
        r,
        DispatchResult::Ok(_) | DispatchResult::Failure(_)
    ));
}

#[test]
fn malformed_sudo_does_not_panic() {
    let r = default_dispatcher().dispatch(
        &make_input(&syslog_line("sudo", "alice : USER=root"), NOW),
        NOW,
    );
    assert!(matches!(
        r,
        DispatchResult::Ok(_) | DispatchResult::Failure(_)
    ));
}

#[test]
fn unicode_username() {
    let e = dispatch_event(
        &sshd("Accepted password for ünïcodé from 10.0.0.2 port 55231 ssh2"),
        NOW,
    );
    assert_eq!(e.username.as_deref(), Some("ünïcodé"));
}

#[test]
fn long_sudo_command() {
    let cmd = "x".repeat(5000);
    let e = dispatch_event(
        &syslog_line(
            "sudo",
            &format!("alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND={cmd}"),
        ),
        NOW,
    );
    assert_eq!(e.event_type.as_deref(), Some("sudo_command"));
    assert_eq!(attr(&e, "command"), Some(&Value::from(cmd)));
}
