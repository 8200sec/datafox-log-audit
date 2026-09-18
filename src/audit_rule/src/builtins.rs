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

use serde_json::json;

use crate::{
    condition::{Condition, FieldPath, LeafCondition, Operator},
    rule::{Aggregation, RuleDefinition, RuleSource, RuleType},
    security_event::{Category, Severity},
};

fn leaf(field: &str, operator: Operator, value: serde_json::Value) -> Condition {
    Condition::Leaf(LeafCondition {
        field: FieldPath(field.to_string()),
        operator,
        value: Some(value),
    })
}

fn all(conds: Vec<Condition>) -> Condition {
    Condition::All { all: conds }
}

/// `builtin.ssh_bruteforce` — repeated failed SSH logins from one source IP.
pub fn ssh_bruteforce() -> RuleDefinition {
    RuleDefinition {
        id: "builtin.ssh_bruteforce".to_string(),
        version: "1.0.0".to_string(),
        title: "SSH brute force".to_string(),
        description: Some("Repeated failed SSH logins from one source".to_string()),
        enabled: true,
        source: RuleSource::Builtin,
        tags: vec!["ssh".to_string(), "brute-force".to_string()],
        category: Category::Authentication,
        event_type: "ssh_brute_force".to_string(),
        severity: Severity::High,
        rule_type: RuleType::Threshold,
        r#match: all(vec![
            leaf("event_type", Operator::Eq, json!("ssh_login")),
            leaf("result", Operator::Eq, json!("failure")),
        ]),
        aggregation: Some(Aggregation {
            group_by: vec![FieldPath("src_ip".to_string())],
            window_seconds: 300,
            threshold: 10,
        }),
    }
}

/// `builtin.suspicious_sudo_shadow` — a sudo command touching /etc/shadow.
pub fn suspicious_sudo_shadow() -> RuleDefinition {
    RuleDefinition {
        id: "builtin.suspicious_sudo_shadow".to_string(),
        version: "1.0.0".to_string(),
        title: "Sensitive sudo command".to_string(),
        description: Some("sudo command that reads /etc/shadow".to_string()),
        enabled: true,
        source: RuleSource::Builtin,
        tags: vec!["sudo".to_string(), "privilege".to_string()],
        category: Category::Privilege,
        event_type: "suspicious_sudo".to_string(),
        severity: Severity::High,
        rule_type: RuleType::Single,
        r#match: all(vec![
            leaf("event_type", Operator::Eq, json!("sudo_command")),
            leaf(
                "event_attributes.command",
                Operator::Contains,
                json!("/etc/shadow"),
            ),
        ]),
        aggregation: None,
    }
}

/// `builtin.repeated_pam_failure` — repeated PAM auth failures for one user.
pub fn repeated_pam_failure() -> RuleDefinition {
    RuleDefinition {
        id: "builtin.repeated_pam_failure".to_string(),
        version: "1.0.0".to_string(),
        title: "Repeated PAM authentication failure".to_string(),
        description: Some("Repeated PAM auth failures for one user".to_string()),
        enabled: true,
        source: RuleSource::Builtin,
        tags: vec!["pam".to_string(), "authentication".to_string()],
        category: Category::Authentication,
        event_type: "repeated_pam_failure".to_string(),
        severity: Severity::Medium,
        rule_type: RuleType::Threshold,
        r#match: all(vec![
            leaf("event_type", Operator::Eq, json!("pam_auth")),
            leaf("result", Operator::Eq, json!("failure")),
        ]),
        aggregation: Some(Aggregation {
            group_by: vec![FieldPath("event_attributes.target_user".to_string())],
            window_seconds: 300,
            threshold: 5,
        }),
    }
}

/// The v1 built-in rule set, in deterministic registration order.
pub fn default_rules() -> Vec<RuleDefinition> {
    vec![
        ssh_bruteforce(),
        suspicious_sudo_shadow(),
        repeated_pam_failure(),
    ]
}
