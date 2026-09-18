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

use audit_rule::{
    Aggregation, Category, Condition, FieldPath, LeafCondition, Operator, RuleDefinition,
    RuleDefinitionError, RuleSource, RuleType, Severity,
};
use serde_json::{Value, json};

fn leaf(field: &str, operator: Operator, value: Option<Value>) -> Condition {
    Condition::Leaf(LeafCondition {
        field: FieldPath(field.to_string()),
        operator,
        value,
    })
}

fn all(conds: Vec<Condition>) -> Condition {
    Condition::All { all: conds }
}

fn any(conds: Vec<Condition>) -> Condition {
    Condition::Any { any: conds }
}

fn base(rule_type: RuleType, severity: Severity, r#match: Condition) -> RuleDefinition {
    RuleDefinition {
        id: "builtin.test".to_string(),
        version: "1.0.0".to_string(),
        title: "Test rule".to_string(),
        description: None,
        enabled: true,
        source: RuleSource::Builtin,
        tags: vec![],
        category: Category::Authentication,
        event_type: "test_event".to_string(),
        severity,
        rule_type,
        r#match,
        aggregation: None,
    }
}

// ── Fixtures ────────────────────────────────────────────────────────────────

fn ssh_bruteforce() -> RuleDefinition {
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
            leaf("event_type", Operator::Eq, Some(json!("ssh_login"))),
            leaf("result", Operator::Eq, Some(json!("failure"))),
        ]),
        aggregation: Some(Aggregation {
            group_by: vec![FieldPath("src_ip".to_string())],
            window_seconds: 300,
            threshold: 10,
        }),
    }
}

fn suspicious_sudo_shadow() -> RuleDefinition {
    RuleDefinition {
        id: "builtin.suspicious_sudo_shadow".to_string(),
        version: "1.0.0".to_string(),
        title: "Sensitive sudo command".to_string(),
        description: None,
        enabled: true,
        source: RuleSource::Builtin,
        tags: vec![],
        category: Category::Privilege,
        event_type: "suspicious_sudo".to_string(),
        severity: Severity::High,
        rule_type: RuleType::Single,
        r#match: all(vec![
            leaf("event_type", Operator::Eq, Some(json!("sudo_command"))),
            leaf(
                "event_attributes.command",
                Operator::Contains,
                Some(json!("/etc/shadow")),
            ),
        ]),
        aggregation: None,
    }
}

fn repeated_pam_failure() -> RuleDefinition {
    RuleDefinition {
        id: "builtin.repeated_pam_failure".to_string(),
        version: "1.0.0".to_string(),
        title: "Repeated PAM authentication failure".to_string(),
        description: None,
        enabled: true,
        source: RuleSource::Builtin,
        tags: vec![],
        category: Category::Authentication,
        event_type: "repeated_pam_failure".to_string(),
        severity: Severity::Medium,
        rule_type: RuleType::Threshold,
        r#match: all(vec![
            leaf("event_type", Operator::Eq, Some(json!("pam_auth"))),
            leaf("result", Operator::Eq, Some(json!("failure"))),
        ]),
        aggregation: Some(Aggregation {
            group_by: vec![FieldPath("username".to_string())],
            window_seconds: 300,
            threshold: 5,
        }),
    }
}

// ── Valid rules ─────────────────────────────────────────────────────────────

#[test]
fn single_rule_valid() {
    let r = base(
        RuleType::Single,
        Severity::High,
        leaf("event_type", Operator::Eq, Some(json!("sudo_command"))),
    );
    assert_eq!(r.validate(), Ok(()));
}

#[test]
fn threshold_rule_valid() {
    let mut r = base(
        RuleType::Threshold,
        Severity::High,
        leaf("event_type", Operator::Eq, Some(json!("ssh_login"))),
    );
    r.aggregation = Some(Aggregation {
        group_by: vec![FieldPath("src_ip".to_string())],
        window_seconds: 300,
        threshold: 10,
    });
    assert_eq!(r.validate(), Ok(()));
}

#[test]
fn ssh_fixture_valid() {
    let r = ssh_bruteforce();
    assert_eq!(r.validate(), Ok(()));
    assert_eq!(r.rule_type, RuleType::Threshold);
    assert_eq!(r.severity, Severity::High);
    assert_eq!(r.aggregation.as_ref().unwrap().threshold, 10);
    assert_eq!(r.aggregation.as_ref().unwrap().window_seconds, 300);
}

#[test]
fn sudo_fixture_valid() {
    let r = suspicious_sudo_shadow();
    assert_eq!(r.validate(), Ok(()));
    assert_eq!(r.rule_type, RuleType::Single);
    assert_eq!(r.severity, Severity::High);
}

#[test]
fn pam_fixture_valid() {
    let r = repeated_pam_failure();
    assert_eq!(r.validate(), Ok(()));
    assert_eq!(r.severity, Severity::Medium);
    assert_eq!(r.aggregation.as_ref().unwrap().threshold, 5);
}

// ── Validation failures ─────────────────────────────────────────────────────

#[test]
fn invalid_id() {
    let mut r = base(
        RuleType::Single,
        Severity::High,
        leaf("event_type", Operator::Eq, Some(json!("x"))),
    );
    r.id = "  ".to_string();
    assert_eq!(r.validate(), Err(RuleDefinitionError::EmptyId));
}

#[test]
fn invalid_semver() {
    let mut r = base(
        RuleType::Single,
        Severity::High,
        leaf("event_type", Operator::Eq, Some(json!("x"))),
    );
    r.version = "one.two".to_string();
    assert_eq!(r.validate(), Err(RuleDefinitionError::InvalidVersion));
    let mut r = base(
        RuleType::Single,
        Severity::High,
        leaf("event_type", Operator::Eq, Some(json!("x"))),
    );
    r.version = "1.0".to_string();
    assert_eq!(r.validate(), Err(RuleDefinitionError::InvalidVersion));
}

#[test]
fn invalid_operator_rejected_on_deserialize() {
    let s = r#"{"id":"r","version":"1.0.0","title":"t","source":"builtin","category":"authentication","event_type":"e","severity":"high","rule_type":"single","match":{"field":"event_type","operator":"regex","value":"x"}}"#;
    assert!(serde_json::from_str::<RuleDefinition>(s).is_err());
}

#[test]
fn invalid_field() {
    let r = base(
        RuleType::Single,
        Severity::High,
        leaf("bogus_field", Operator::Eq, Some(json!("x"))),
    );
    assert_eq!(r.validate(), Err(RuleDefinitionError::InvalidField));
}

#[test]
fn event_attributes_field_is_valid() {
    let r = base(
        RuleType::Single,
        Severity::High,
        leaf(
            "event_attributes.command",
            Operator::Contains,
            Some(json!("/etc/shadow")),
        ),
    );
    assert_eq!(r.validate(), Ok(()));
}

#[test]
fn nested_condition_depth() {
    // depth 4 (three nested all/any around a leaf) is valid.
    let d3 = all(vec![any(vec![all(vec![leaf(
        "event_type",
        Operator::Eq,
        Some(json!("x")),
    )])])]);
    assert_eq!(d3.depth(), 4);
    let r = base(RuleType::Single, Severity::High, d3);
    assert_eq!(r.validate(), Ok(()));

    // depth 5 exceeds the limit.
    let d4 = all(vec![all(vec![all(vec![all(vec![leaf(
        "event_type",
        Operator::Eq,
        Some(json!("x")),
    )])])])]);
    assert_eq!(d4.depth(), 5);
    let r = base(RuleType::Single, Severity::High, d4);
    assert_eq!(r.validate(), Err(RuleDefinitionError::MatchTooDeep));
}

#[test]
fn empty_conditions() {
    let r = base(
        RuleType::Single,
        Severity::High,
        Condition::All { all: vec![] },
    );
    assert_eq!(r.validate(), Err(RuleDefinitionError::EmptyMatch));
}

#[test]
fn missing_value_for_operator() {
    let r = base(
        RuleType::Single,
        Severity::High,
        leaf("event_type", Operator::Eq, None),
    );
    assert_eq!(r.validate(), Err(RuleDefinitionError::MissingValue));
}

#[test]
fn unexpected_value_for_exists() {
    let r = base(
        RuleType::Single,
        Severity::High,
        leaf("username", Operator::Exists, Some(json!("x"))),
    );
    assert_eq!(r.validate(), Err(RuleDefinitionError::UnexpectedValue));
}

#[test]
fn exists_without_value_is_valid() {
    let r = base(
        RuleType::Single,
        Severity::High,
        leaf("username", Operator::Exists, None),
    );
    assert_eq!(r.validate(), Ok(()));
}

#[test]
fn in_requires_array() {
    let r = base(
        RuleType::Single,
        Severity::High,
        leaf("src_ip", Operator::In, Some(json!("10.0.0.1"))),
    );
    assert_eq!(r.validate(), Err(RuleDefinitionError::ValueMustBeArray));
    let r = base(
        RuleType::Single,
        Severity::High,
        leaf("src_ip", Operator::In, Some(json!(["10.0.0.1"]))),
    );
    assert_eq!(r.validate(), Ok(()));
}

#[test]
fn gt_requires_number() {
    let r = base(
        RuleType::Single,
        Severity::High,
        leaf("src_port", Operator::Gt, Some(json!("22"))),
    );
    assert_eq!(r.validate(), Err(RuleDefinitionError::ValueMustBeNumber));
    let r = base(
        RuleType::Single,
        Severity::High,
        leaf("src_port", Operator::Gt, Some(json!(22))),
    );
    assert_eq!(r.validate(), Ok(()));
}

#[test]
fn contains_requires_string() {
    let r = base(
        RuleType::Single,
        Severity::High,
        leaf(
            "event_attributes.command",
            Operator::Contains,
            Some(json!(42)),
        ),
    );
    assert_eq!(r.validate(), Err(RuleDefinitionError::ValueMustBeString));
}

#[test]
fn invalid_threshold() {
    let mut r = base(
        RuleType::Threshold,
        Severity::High,
        leaf("event_type", Operator::Eq, Some(json!("x"))),
    );
    r.aggregation = Some(Aggregation {
        group_by: vec![FieldPath("src_ip".to_string())],
        window_seconds: 300,
        threshold: 0,
    });
    assert_eq!(r.validate(), Err(RuleDefinitionError::InvalidThreshold));
}

#[test]
fn invalid_window() {
    let mut r = base(
        RuleType::Threshold,
        Severity::High,
        leaf("event_type", Operator::Eq, Some(json!("x"))),
    );
    r.aggregation = Some(Aggregation {
        group_by: vec![FieldPath("src_ip".to_string())],
        window_seconds: 0,
        threshold: 1,
    });
    assert_eq!(r.validate(), Err(RuleDefinitionError::InvalidWindow));
}

#[test]
fn too_many_group_by() {
    let mut r = base(
        RuleType::Threshold,
        Severity::High,
        leaf("event_type", Operator::Eq, Some(json!("x"))),
    );
    r.aggregation = Some(Aggregation {
        group_by: vec![
            FieldPath("src_ip".to_string()),
            FieldPath("username".to_string()),
            FieldPath("src_port".to_string()),
            FieldPath("hostname".to_string()),
        ],
        window_seconds: 300,
        threshold: 1,
    });
    assert_eq!(r.validate(), Err(RuleDefinitionError::TooManyGroupBy));
}

#[test]
fn aggregation_missing_for_threshold() {
    let r = base(
        RuleType::Threshold,
        Severity::High,
        leaf("event_type", Operator::Eq, Some(json!("x"))),
    );
    assert_eq!(r.validate(), Err(RuleDefinitionError::MissingAggregation));
}

#[test]
fn single_rule_with_optional_aggregation_policy() {
    // A single rule without aggregation is valid.
    let r = base(
        RuleType::Single,
        Severity::High,
        leaf("event_type", Operator::Eq, Some(json!("x"))),
    );
    assert_eq!(r.validate(), Ok(()));

    // A single rule with an (unused but valid) aggregation block is tolerated.
    let mut r2 = base(
        RuleType::Single,
        Severity::High,
        leaf("event_type", Operator::Eq, Some(json!("x"))),
    );
    r2.aggregation = Some(Aggregation {
        group_by: vec![FieldPath("src_ip".to_string())],
        window_seconds: 60,
        threshold: 1,
    });
    assert_eq!(r2.validate(), Ok(()));
}

// ── Serde ───────────────────────────────────────────────────────────────────

#[test]
fn json_serialization_uses_match_key() {
    let r = ssh_bruteforce();
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(v["rule_type"], "threshold");
    assert_eq!(v["severity"], "high");
    assert_eq!(v["source"], "builtin");
    assert!(v.get("match").is_some());
    assert_eq!(v["aggregation"]["threshold"], 10);
    assert_eq!(v["aggregation"]["group_by"][0], "src_ip");
}

#[test]
fn json_deserialization() {
    let s = r#"{
        "id": "builtin.ssh_bruteforce",
        "version": "1.0.0",
        "title": "SSH brute force",
        "enabled": true,
        "source": "builtin",
        "tags": ["ssh"],
        "category": "authentication",
        "event_type": "ssh_brute_force",
        "severity": "high",
        "rule_type": "threshold",
        "match": { "all": [
            { "field": "event_type", "operator": "eq", "value": "ssh_login" },
            { "field": "result", "operator": "eq", "value": "failure" }
        ]},
        "aggregation": { "group_by": ["src_ip"], "window_seconds": 300, "threshold": 10 }
    }"#;
    let r: RuleDefinition = serde_json::from_str(s).unwrap();
    assert_eq!(r.id, "builtin.ssh_bruteforce");
    assert_eq!(r.rule_type, RuleType::Threshold);
    assert_eq!(r.severity, Severity::High);
    assert_eq!(r.validate(), Ok(()));
}

#[test]
fn round_trip() {
    let r = suspicious_sudo_shadow();
    let json = serde_json::to_string(&r).unwrap();
    let back: RuleDefinition = serde_json::from_str(&json).unwrap();
    assert_eq!(back.id, r.id);
    assert_eq!(back.rule_type, RuleType::Single);
    assert_eq!(back.validate(), Ok(()));
}
