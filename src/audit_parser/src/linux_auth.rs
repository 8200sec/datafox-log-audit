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

use std::sync::OnceLock;

use regex::{Captures, Regex};
use serde_json::{Map, Value, json};

use crate::{
    parser::Parser,
    syslog::{parse_syslog_envelope, syslog_envelope_attributes, syslog_to_audit_severity},
    types::{ParsedEvent, RawLogInput},
};

/// Syslog tags (RFC3164 TAG / RFC5424 APP-NAME) this parser recognizes.
const SUPPORTED_APPS: [&str; 4] = ["sshd", "sudo", "su", "login"];

/// Linux Authentication & Privilege parser. Priority 60: above Generic Syslog
/// (40), below future vendor/product-specific parsers. It reuses the syslog
/// envelope helper and parses only recognized auth/privilege message bodies;
/// every other sshd/sudo/su/login line falls through to Generic Syslog.
pub struct LinuxAuthParser;

impl Parser for LinuxAuthParser {
    fn id(&self) -> &str {
        "linux-auth"
    }
    fn name(&self) -> &str {
        "Linux Authentication"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn priority(&self) -> i32 {
        60
    }
    fn supported_source_types(&self) -> &[&'static str] {
        &[]
    }
    fn detect(&self, input: &RawLogInput) -> bool {
        let Some(env) = parse_syslog_envelope(input) else {
            return false;
        };
        let (Some(app), Some(msg)) = (env.app_name.as_deref(), env.message.as_deref()) else {
            return false;
        };
        SUPPORTED_APPS.contains(&app) && match_auth(app, msg).is_some()
    }
    fn parse(&self, input: &RawLogInput) -> anyhow::Result<ParsedEvent> {
        let env = parse_syslog_envelope(input).ok_or_else(|| anyhow::anyhow!("not syslog"))?;
        let app = env
            .app_name
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing app name"))?;
        let msg = env
            .message
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing message"))?;
        let m = match_auth(app, msg)
            .ok_or_else(|| anyhow::anyhow!("unsupported linux auth message"))?;

        let mut attrs = syslog_envelope_attributes(&env);
        m.write_attributes(&mut attrs);

        Ok(ParsedEvent {
            parser_id: "linux-auth".to_string(),
            parser_version: "1.0.0".to_string(),
            raw_log: input.raw_log.clone(),
            timestamp: env.timestamp,
            severity: Some(syslog_to_audit_severity(env.severity).to_string()),
            source_name: input.source_name.clone(),
            hostname: env.hostname,
            src_ip: m.src_ip,
            src_port: m.src_port,
            username: m.username,
            category: Some(m.category.to_string()),
            event_type: Some(m.event_type.to_string()),
            action: Some(m.action.to_string()),
            result: m.result.map(str::to_string),
            message: Some(msg.to_string()),
            attributes: Some(Value::Object(attrs)),
            ..Default::default()
        })
    }
}

/// Semantic result of matching one auth/privilege message.
struct AuthMatch {
    category: &'static str,
    event_type: &'static str,
    action: &'static str,
    result: Option<&'static str>,
    username: Option<String>,
    src_ip: Option<String>,
    src_port: Option<String>,
    auth_method: Option<String>,
    invalid_user: bool,
    target_user: Option<String>,
    tty: Option<String>,
    cwd: Option<String>,
    command: Option<String>,
    pam_service: Option<String>,
    rhost: Option<String>,
}

impl AuthMatch {
    fn base(
        category: &'static str,
        event_type: &'static str,
        action: &'static str,
        result: Option<&'static str>,
    ) -> Self {
        AuthMatch {
            category,
            event_type,
            action,
            result,
            username: None,
            src_ip: None,
            src_port: None,
            auth_method: None,
            invalid_user: false,
            target_user: None,
            tty: None,
            cwd: None,
            command: None,
            pam_service: None,
            rhost: None,
        }
    }

    fn write_attributes(&self, attrs: &mut Map<String, Value>) {
        if let Some(v) = &self.auth_method {
            attrs.insert("auth_method".to_string(), json!(v));
        }
        if self.invalid_user {
            attrs.insert("invalid_user".to_string(), json!(true));
        }
        if let Some(v) = &self.target_user {
            attrs.insert("target_user".to_string(), json!(v));
        }
        if let Some(v) = &self.tty {
            attrs.insert("tty".to_string(), json!(v));
        }
        if let Some(v) = &self.cwd {
            attrs.insert("cwd".to_string(), json!(v));
        }
        if let Some(v) = &self.command {
            attrs.insert("command".to_string(), json!(v));
        }
        if let Some(v) = &self.pam_service {
            attrs.insert("pam_service".to_string(), json!(v));
        }
        if let Some(v) = &self.rhost {
            attrs.insert("rhost".to_string(), json!(v));
        }
    }
}

struct Patterns {
    ssh_accepted: Regex,
    ssh_failed_password: Regex,
    ssh_invalid_user: Regex,
    session_open: Regex,
    session_close: Regex,
    sudo_command: Regex,
    sudo_failure_kw: Regex,
    pam_auth_failure: Regex,
    pam_service: Regex,
    pam_rhost: Regex,
    pam_user: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        ssh_accepted: Regex::new(
            r"^Accepted (?P<method>password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)",
        )
        .unwrap(),
        ssh_failed_password: Regex::new(
            r"^Failed password for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)",
        )
        .unwrap(),
        ssh_invalid_user: Regex::new(
            r"^Invalid user (?P<user>\S+) from (?P<ip>\S+)(?: port (?P<port>\d+))?",
        )
        .unwrap(),
        session_open: Regex::new(
            r"session opened for user (?P<target>\S+)(?: by (?P<actor>\S+)\(uid=\d+\))?",
        )
        .unwrap(),
        session_close: Regex::new(
            r"session closed for user (?P<target>\S+)(?: by (?P<actor>\S+)\(uid=\d+\))?",
        )
        .unwrap(),
        sudo_command: Regex::new(
            r"^(?P<actor>\S+)\s*:\s*(?:(?:\d+ incorrect password attempts|a password is required)\s*;\s*)?(?:TTY=(?P<tty>[^;]*?)\s*;\s*)?(?:PWD=(?P<cwd>[^;]*?)\s*;\s*)?USER=(?P<target>[^;]*?)\s*;\s*COMMAND=(?P<command>.*)$",
        )
        .unwrap(),
        sudo_failure_kw: Regex::new(r"incorrect password|a password is required").unwrap(),
        pam_auth_failure: Regex::new(r"(?i)authentication\s+failure").unwrap(),
        pam_service: Regex::new(r"pam_[A-Za-z0-9_]+\((?P<service>[^:]+):(?:auth|session|account|password)\)")
            .unwrap(),
        pam_rhost: Regex::new(r"\brhost=(?P<rhost>\S+)").unwrap(),
        pam_user: Regex::new(r"\buser=(?P<user>\S+)").unwrap(),
    })
}

fn cap(c: &Captures, name: &str) -> Option<String> {
    c.name(name).map(|m| m.as_str().to_string())
}

fn match_auth(app: &str, msg: &str) -> Option<AuthMatch> {
    let pat = patterns();
    match app {
        "sshd" => match_sshd(pat, msg),
        "sudo" => match_sudo(pat, msg),
        "su" => match_su(pat, msg),
        "login" => match_session(pat, msg),
        _ => None,
    }
}

fn match_sshd(pat: &Patterns, msg: &str) -> Option<AuthMatch> {
    if let Some(c) = pat.ssh_accepted.captures(msg) {
        let mut m = AuthMatch::base("authentication", "ssh_login", "login", Some("success"));
        m.username = cap(&c, "user");
        m.src_ip = cap(&c, "ip");
        m.src_port = cap(&c, "port");
        m.auth_method = cap(&c, "method");
        return Some(m);
    }
    if let Some(c) = pat.ssh_failed_password.captures(msg) {
        let mut m = AuthMatch::base("authentication", "ssh_login", "login", Some("failure"));
        m.username = cap(&c, "user");
        m.src_ip = cap(&c, "ip");
        m.src_port = cap(&c, "port");
        m.auth_method = Some("password".to_string());
        m.invalid_user = c.name("invalid").is_some();
        return Some(m);
    }
    if let Some(c) = pat.ssh_invalid_user.captures(msg) {
        let mut m = AuthMatch::base("authentication", "ssh_login", "login", Some("failure"));
        m.username = cap(&c, "user");
        m.src_ip = cap(&c, "ip");
        m.src_port = cap(&c, "port");
        m.invalid_user = true;
        return Some(m);
    }
    match_session(pat, msg).or_else(|| pam_failure_if_matched(pat, msg))
}

fn match_sudo(pat: &Patterns, msg: &str) -> Option<AuthMatch> {
    if let Some(c) = pat.sudo_command.captures(msg) {
        let mut m = AuthMatch::base("privilege", "sudo_command", "execute", None);
        m.username = cap(&c, "actor");
        m.target_user = cap(&c, "target");
        m.tty = cap(&c, "tty");
        m.cwd = cap(&c, "cwd");
        m.command = cap(&c, "command");
        if pat.sudo_failure_kw.is_match(msg) {
            m.result = Some("failure");
        }
        return Some(m);
    }
    pam_failure_if_matched(pat, msg)
}

fn match_su(pat: &Patterns, msg: &str) -> Option<AuthMatch> {
    if let Some(c) = pat.session_open.captures(msg) {
        let mut m = AuthMatch::base("privilege", "user_switch", "switch_user", Some("success"));
        m.username = cap(&c, "actor");
        m.target_user = cap(&c, "target");
        return Some(m);
    }
    if let Some(c) = pat.session_close.captures(msg) {
        let mut m = AuthMatch::base("privilege", "user_switch", "switch_user", Some("success"));
        m.username = cap(&c, "actor");
        m.target_user = cap(&c, "target");
        return Some(m);
    }
    pam_failure_if_matched(pat, msg)
}

fn match_session(pat: &Patterns, msg: &str) -> Option<AuthMatch> {
    if let Some(c) = pat.session_open.captures(msg) {
        let mut m = AuthMatch::base("authentication", "session", "session_open", Some("success"));
        m.username = cap(&c, "target");
        return Some(m);
    }
    if let Some(c) = pat.session_close.captures(msg) {
        let mut m = AuthMatch::base(
            "authentication",
            "session",
            "session_close",
            Some("success"),
        );
        m.username = cap(&c, "target");
        return Some(m);
    }
    pam_failure_if_matched(pat, msg)
}

fn pam_failure_if_matched(pat: &Patterns, msg: &str) -> Option<AuthMatch> {
    if !pat.pam_auth_failure.is_match(msg) {
        return None;
    }
    let mut m = AuthMatch::base(
        "authentication",
        "pam_auth",
        "authenticate",
        Some("failure"),
    );
    if let Some(c) = pat.pam_service.captures(msg) {
        m.pam_service = cap(&c, "service");
    }
    if let Some(c) = pat.pam_rhost.captures(msg)
        && let Some(rhost) = cap(&c, "rhost")
    {
        m.src_ip = Some(rhost.clone());
        m.rhost = Some(rhost);
    }
    if let Some(c) = pat.pam_user.captures(msg) {
        m.target_user = cap(&c, "user");
    }
    Some(m)
}
