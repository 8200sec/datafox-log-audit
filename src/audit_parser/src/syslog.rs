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

use chrono::{Datelike, NaiveDate, NaiveTime, TimeZone, Utc};
use serde_json::{Map, Value, json};

use crate::types::{RawLogInput, Timestamp};

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Acceptable clock skew when inferring the RFC3164 year, in milliseconds.
const FUTURE_TOLERANCE_MS: i64 = 3_600_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyslogFormat {
    Rfc3164,
    Rfc5424,
}

impl SyslogFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Rfc3164 => "rfc3164",
            Self::Rfc5424 => "rfc5424",
        }
    }
}

/// The parsed syslog envelope — the standard header shared by every syslog
/// parser. The message body is left untouched for a vendor/security parser.
#[derive(Debug, Clone)]
pub struct SyslogEnvelope {
    pub pri: u8,
    pub facility: u8,
    pub severity: u8,
    pub format: SyslogFormat,
    pub timestamp: Option<Timestamp>,
    pub hostname: Option<String>,
    pub app_name: Option<String>,
    pub procid: Option<String>,
    pub msgid: Option<String>,
    pub version: Option<String>,
    pub structured_data: Option<Value>,
    pub message: Option<String>,
}

/// Parse the standard syslog envelope (RFC3164 or RFC5424) from a raw line.
/// Returns `None` when the line is not syslog (no valid `<PRI>`).
pub fn parse_syslog_envelope(input: &RawLogInput) -> Option<SyslogEnvelope> {
    let (pri, rest) = parse_pri(&input.raw_log)?;
    let facility = pri / 8;
    let severity = pri % 8;
    // RFC5424 starts with a numeric VERSION right after PRI; RFC3164 starts
    // with a month abbreviation.
    let is_5424 = rest.chars().next().is_some_and(|c| c.is_ascii_digit());
    if is_5424 {
        parse_rfc5424_envelope(rest, pri, facility, severity)
    } else {
        parse_rfc3164_envelope(rest, input.received_at, pri, facility, severity)
    }
}

/// Build the `syslog_*` attribute map shared by every syslog-based parser.
pub fn syslog_envelope_attributes(env: &SyslogEnvelope) -> Map<String, Value> {
    let mut attrs = Map::new();
    attrs.insert("syslog_pri".to_string(), json!(env.pri));
    attrs.insert("syslog_facility".to_string(), json!(env.facility));
    attrs.insert("syslog_severity".to_string(), json!(env.severity));
    attrs.insert(
        "original_severity".to_string(),
        json!(syslog_severity_name(env.severity)),
    );
    attrs.insert("syslog_format".to_string(), json!(env.format.as_str()));
    if let Some(v) = &env.version {
        attrs.insert("syslog_version".to_string(), json!(v));
    }
    if let Some(a) = &env.app_name {
        attrs.insert("syslog_app_name".to_string(), json!(a));
    }
    if let Some(p) = &env.procid {
        attrs.insert("syslog_procid".to_string(), json!(p));
    }
    if let Some(m) = &env.msgid {
        attrs.insert("syslog_msgid".to_string(), json!(m));
    }
    if let Some(sd) = &env.structured_data {
        attrs.insert("syslog_structured_data".to_string(), json!(sd.to_string()));
    }
    attrs
}

/// Map a numeric syslog severity (0..=7) to the 5-level audit severity.
pub fn syslog_to_audit_severity(sev: u8) -> &'static str {
    match sev {
        0..=2 => "critical",
        3 => "high",
        4 => "medium",
        5 => "low",
        _ => "info",
    }
}

fn syslog_severity_name(sev: u8) -> &'static str {
    match sev {
        0 => "Emergency",
        1 => "Alert",
        2 => "Critical",
        3 => "Error",
        4 => "Warning",
        5 => "Notice",
        6 => "Informational",
        _ => "Debug",
    }
}

/// Parse a leading `<PRI>` (numeric, 0..=191). Returns the PRI and the remainder.
fn parse_pri(s: &str) -> Option<(u8, &str)> {
    let rest = s.strip_prefix('<')?;
    let end = rest.find('>')?;
    let pri_str = &rest[..end];
    if pri_str.is_empty() || !pri_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let pri: u8 = pri_str.parse().ok()?;
    if pri > 191 {
        return None;
    }
    Some((pri, &rest[end + 1..]))
}

/// Parse the RFC5424 envelope: VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID
/// STRUCTURED-DATA [MSG].
fn parse_rfc5424_envelope(
    rest: &str,
    pri: u8,
    facility: u8,
    severity: u8,
) -> Option<SyslogEnvelope> {
    let mut tokens = rest.splitn(7, ' ');
    let version = tokens.next().unwrap_or_default();
    let timestamp = tokens.next().unwrap_or_default();
    let hostname = tokens.next().unwrap_or_default();
    let app_name = tokens.next().unwrap_or_default();
    let procid = tokens.next().unwrap_or_default();
    let msgid = tokens.next().unwrap_or_default();
    let sd_and_msg = tokens.next().unwrap_or_default();

    let nil = |s: &str| s == "-";
    let (sd, msg) = parse_sd_and_msg(sd_and_msg);

    Some(SyslogEnvelope {
        pri,
        facility,
        severity,
        format: SyslogFormat::Rfc5424,
        timestamp: (!nil(timestamp)).then(|| Timestamp::RawString(timestamp.to_string())),
        hostname: (!nil(hostname)).then(|| hostname.to_string()),
        app_name: (!nil(app_name)).then(|| app_name.to_string()),
        procid: (!nil(procid)).then(|| procid.to_string()),
        msgid: (!nil(msgid)).then(|| msgid.to_string()),
        version: (!nil(version)).then(|| version.to_string()),
        structured_data: sd.as_deref().and_then(parse_structured_data),
        message: (!msg.is_empty()).then(|| msg.to_string()),
    })
}

/// Parse the RFC3164 envelope: Mmm DD HH:MM:SS HOSTNAME TAG[: MSG].
fn parse_rfc3164_envelope(
    rest: &str,
    received_at: i64,
    pri: u8,
    facility: u8,
    severity: u8,
) -> Option<SyslogEnvelope> {
    let mut tokens = rest.splitn(5, ' ');
    let month = tokens.next().unwrap_or_default();
    let day = tokens.next().unwrap_or_default();
    let time = tokens.next().unwrap_or_default();
    let hostname = tokens.next().unwrap_or_default();
    let tag_and_msg = tokens.next().unwrap_or_default();

    let ts_str = format!("{month} {day} {time}");
    let timestamp = parse_rfc3164_timestamp(&ts_str, received_at).map(Timestamp::EpochMillis);
    let (app_name, procid, msg) = parse_rfc3164_tag(tag_and_msg);

    Some(SyslogEnvelope {
        pri,
        facility,
        severity,
        format: SyslogFormat::Rfc3164,
        timestamp,
        hostname: (!hostname.is_empty()).then(|| hostname.to_string()),
        app_name,
        procid,
        msgid: None,
        version: None,
        structured_data: None,
        message: (!msg.is_empty()).then(|| msg.to_string()),
    })
}

/// Split `STRUCTURED-DATA [SP MSG]` into the raw structured-data string and MSG.
fn parse_sd_and_msg(s: &str) -> (Option<String>, &str) {
    let s = s.trim_start();
    if let Some(rest) = s.strip_prefix('-') {
        return (None, rest.trim_start());
    }
    if !s.starts_with('[') {
        return (None, s);
    }
    // SD-ELEMENTs are concatenated with no separator; consume the whole run.
    let mut end = 0usize;
    while let Some(elem_end) = scan_element(s, end) {
        end = elem_end;
        if !s.as_bytes().get(end).is_some_and(|&b| b == b'[') {
            break;
        }
    }
    if end == 0 {
        // Unterminated structured data — treat the whole thing as SD with no MSG.
        return (Some(s.to_string()), "");
    }
    (Some(s[..end].to_string()), s[end..].trim_start())
}

/// Return the byte index just past the closing `]` of the element at `start`.
fn scan_element(s: &str, start: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut in_quote = false;
    let mut escaped = false;
    let mut i = start + 1;
    while i < bytes.len() {
        let c = bytes[i];
        if escaped {
            escaped = false;
        } else {
            match c {
                b'\\' => escaped = true,
                b'"' => in_quote = !in_quote,
                b']' if !in_quote => return Some(i + 1),
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// Parse RFC5424 structured data into a JSON array of `{SD-ID: {param: value}}`.
fn parse_structured_data(sd: &str) -> Option<Value> {
    let inner = sd.trim().trim_start_matches('[').trim_end_matches(']');
    if inner.is_empty() {
        return Some(json!([]));
    }
    let elements: Vec<&str> = if inner.contains("][") {
        inner.split("][").collect()
    } else {
        vec![inner]
    };
    let mut result = Vec::new();
    for elem in elements {
        let mut parts = elem.splitn(2, ' ');
        let sd_id = parts.next()?;
        let params = parse_sd_params(parts.next().unwrap_or(""));
        result.push(json!({ sd_id: params }));
    }
    Some(Value::Array(result))
}

/// Parse `key="value" key="value"` (values may contain spaces) with escapes.
fn parse_sd_params(s: &str) -> Map<String, Value> {
    let mut params = Map::new();
    let mut chars = s.chars().peekable();
    loop {
        while chars.peek() == Some(&' ') {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
        let mut key = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' || c == ' ' {
                break;
            }
            key.push(c);
            chars.next();
        }
        if chars.next() != Some('=') {
            break;
        }
        if chars.next() != Some('"') {
            break;
        }
        let mut value = String::new();
        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(n) = chars.next() {
                    value.push(n);
                }
            } else if c == '"' {
                break;
            } else {
                value.push(c);
            }
        }
        params.insert(key, json!(value));
    }
    params
}

/// Parse an RFC3164 `tag[pid]: message` into (app_name, procid, message).
fn parse_rfc3164_tag(s: &str) -> (Option<String>, Option<String>, String) {
    let (tag_part, msg) = match s.split_once(':') {
        Some((t, m)) => (t, m.trim_start()),
        None => (s.trim_end_matches(':'), ""),
    };
    let (app, pid) = match tag_part.find('[') {
        Some(open) => {
            let app = tag_part[..open].to_string();
            let pid = tag_part[open + 1..].trim_end_matches(']').to_string();
            (Some(app), (!pid.is_empty()).then_some(pid))
        }
        None => (Some(tag_part.to_string()), None),
    };
    (app, pid, msg.to_string())
}

/// Parse an RFC3164 `Mmm DD HH:MM:SS` timestamp, inferring the year from
/// `received_at`. The naive time is treated as UTC (the framework has no
/// source-timezone context yet).
fn parse_rfc3164_timestamp(ts_str: &str, received_at: i64) -> Option<i64> {
    let mut parts = ts_str.split(' ');
    let month_str = parts.next()?;
    let day: u32 = parts.next()?.parse().ok()?;
    let time_str = parts.next()?;
    let month = MONTHS.iter().position(|m| *m == month_str)? as u32 + 1;
    let time = NaiveTime::parse_from_str(time_str, "%H:%M:%S").ok()?;
    let received = Utc.timestamp_millis_opt(received_at).single()?;
    let build = |y: i32| -> Option<i64> {
        Some(
            NaiveDate::from_ymd_opt(y, month, day)?
                .and_time(time)
                .and_utc()
                .timestamp_millis(),
        )
    };
    // Assume the current year; a log more than one hour in the future is a
    // Dec 31 / Jan 1 cross-year boundary and belongs to the previous year.
    let this_year = build(received.year())?;
    if this_year - received_at <= FUTURE_TOLERANCE_MS {
        Some(this_year)
    } else {
        build(received.year() - 1)
    }
}
