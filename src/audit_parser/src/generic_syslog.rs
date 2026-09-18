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

use serde_json::Value;

use crate::{
    parser::Parser,
    syslog::{parse_syslog_envelope, syslog_envelope_attributes, syslog_to_audit_severity},
    types::{ParsedEvent, RawLogInput},
};

/// Generic Syslog envelope parser (RFC3164 + RFC5424). Priority 40: above the
/// Generic JSON parser (20), below the Linux Auth parser (60) and future
/// vendor-specific syslog parsers. It parses only the standard syslog
/// header/envelope — never the message body.
pub struct GenericSyslogParser;

impl Parser for GenericSyslogParser {
    fn id(&self) -> &str {
        "generic-syslog"
    }
    fn name(&self) -> &str {
        "Generic Syslog"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn priority(&self) -> i32 {
        40
    }
    fn supported_source_types(&self) -> &[&'static str] {
        &[]
    }
    fn detect(&self, input: &RawLogInput) -> bool {
        parse_syslog_envelope(input).is_some()
    }
    fn parse(&self, input: &RawLogInput) -> anyhow::Result<ParsedEvent> {
        let env = parse_syslog_envelope(input).ok_or_else(|| anyhow::anyhow!("not syslog"))?;
        let attrs = syslog_envelope_attributes(&env);
        Ok(ParsedEvent {
            parser_id: "generic-syslog".to_string(),
            parser_version: "1.0.0".to_string(),
            raw_log: input.raw_log.clone(),
            timestamp: env.timestamp,
            severity: Some(syslog_to_audit_severity(env.severity).to_string()),
            source_name: input.source_name.clone(),
            hostname: env.hostname,
            message: env.message,
            attributes: Some(Value::Object(attrs)),
            ..Default::default()
        })
    }
}
