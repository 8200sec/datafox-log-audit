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

use audit_parser::{AuditEvent, EventResult, Severity as AuditSeverity, SourceType};
use audit_rule::{
    Aggregation, Category, Condition, EvaluationError, EvaluationResult, FieldPath, LeafCondition,
    Operator, RuleDefinition, RuleEvaluator, RuleMatch, RuleSource, RuleType, Severity,
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

fn rule(
    rule_type: RuleType,
    severity: Severity,
    r#match: Condition,
    aggregation: Option<Aggregation>,
) -> RuleDefinition {
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
        aggregation,
    }
}

/// A baseline ssh_login failure event.
fn base_event() -> AuditEvent {
    AuditEvent {
        timestamp: 1700000000000,
        event_id: "evt-1".to_string(),
        tenant_id: "tenant-a".to_string(),
        source_type: SourceType::Os,
        source_name: Some("edge01".to_string()),
        collector_id: None,
        vendor: None,
        product: None,
        product_version: None,
        hostname: Some("web01".to_string()),
        asset_id: None,
        src_ip: Some("10.10.10.5".to_string()),
        src_port: Some(55231),
        dst_ip: None,
        dst_port: None,
        username: Some("alice".to_string()),
        category: Some("authentication".to_string()),
        event_type: Some("ssh_login".to_string()),
        action: Some("login".to_string()),
        result: Some(EventResult::Failure),
        severity: AuditSeverity::High,
        message: None,
        raw_log: "<34>Sep 18 15:28:31 web01 sshd[1]: Failed password".to_string(),
        parser_id: Some("linux-auth".to_string()),
        parser_version: Some("1.0.0".to_string()),
        ingest_timestamp: 1700000000000,
        event_attributes: None,
    }
}

fn ssh_bruteforce() -> RuleDefinition {
    RuleDefinition {
        id: "builtin.ssh_bruteforce".to_string(),
        version: "1.0.0".to_string(),
        title: "SSH brute force".to_string(),
        description: None,
        enabled: true,
        source: RuleSource::Builtin,
        tags: vec![],
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

fn eval(rule: &RuleDefinition, event: &AuditEvent) -> EvaluationResult {
    RuleEvaluator.evaluate(rule, event)
}

fn assert_matched(result: EvaluationResult) -> RuleMatch {
    match result {
        EvaluationResult::Matched(m) => *m,
        EvaluationResult::NotMatched => panic!("expected matched"),
        EvaluationResult::Error(e) => panic!("expected matched, got error: {e}"),
    }
}

// ── Operators ───────────────────────────────────────────────────────────────

#[test]
fn eq_string() {
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf("event_type", Operator::Eq, Some(json!("ssh_login"))),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::Matched(_)
    ));
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf("event_type", Operator::Eq, Some(json!("sudo"))),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::NotMatched
    ));
}

#[test]
fn neq() {
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf("event_type", Operator::Neq, Some(json!("sudo"))),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::Matched(_)
    ));
}

#[test]
fn contains_and_not_contains() {
    let mut e = base_event();
    e.event_attributes = Some(json!({ "command": "/usr/bin/cat /etc/shadow" }));
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf(
            "event_attributes.command",
            Operator::Contains,
            Some(json!("/etc/shadow")),
        ),
        None,
    );
    assert!(matches!(eval(&r, &e), EvaluationResult::Matched(_)));
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf(
            "event_attributes.command",
            Operator::NotContains,
            Some(json!("/etc/passwd")),
        ),
        None,
    );
    assert!(matches!(eval(&r, &e), EvaluationResult::Matched(_)));
}

#[test]
fn starts_with_and_ends_with() {
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf("event_type", Operator::StartsWith, Some(json!("ssh"))),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::Matched(_)
    ));
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf("event_type", Operator::EndsWith, Some(json!("login"))),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::Matched(_)
    ));
}

#[test]
fn numeric_gt_gte_lt_lte() {
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf("src_port", Operator::Gt, Some(json!(1000))),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::Matched(_)
    ));
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf("src_port", Operator::Gte, Some(json!(55231))),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::Matched(_)
    ));
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf("src_port", Operator::Lt, Some(json!(60000))),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::Matched(_)
    ));
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf("src_port", Operator::Lte, Some(json!(1000))),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::NotMatched
    ));
}

#[test]
fn in_and_not_in() {
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf(
            "src_ip",
            Operator::In,
            Some(json!(["10.10.10.5", "10.0.0.1"])),
        ),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::Matched(_)
    ));
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf("src_ip", Operator::In, Some(json!(["10.0.0.1"]))),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::NotMatched
    ));
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf("src_ip", Operator::NotIn, Some(json!(["10.0.0.1"]))),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::Matched(_)
    ));
}

#[test]
fn exists_and_not_exists() {
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf("username", Operator::Exists, None),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::Matched(_)
    ));
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf("dst_ip", Operator::NotExists, None),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::Matched(_)
    ));
}

#[test]
fn missing_field_is_not_matched() {
    // dst_ip is None; an eq on it is NotMatched (not an error).
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf("dst_ip", Operator::Eq, Some(json!("10.0.0.9"))),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::NotMatched
    ));
    // exists → false, not_exists → true.
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf("dst_ip", Operator::Exists, None),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::NotMatched
    ));
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf("dst_ip", Operator::NotExists, None),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::Matched(_)
    ));
}

#[test]
fn wrong_type_is_error() {
    // eq on a string field with a numeric value → type mismatch error.
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf("event_type", Operator::Eq, Some(json!(42))),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::Error(EvaluationError::TypeMismatch { .. })
    ));
    // contains on a numeric field → type mismatch.
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf("src_port", Operator::Contains, Some(json!("2"))),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::Error(_)
    ));
}

#[test]
fn unknown_field_is_error() {
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf("bogus_field", Operator::Eq, Some(json!("x"))),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::Error(EvaluationError::UnknownField(_))
    ));
}

// ── all / any ───────────────────────────────────────────────────────────────

#[test]
fn all_true() {
    let r = rule(
        RuleType::Single,
        Severity::High,
        all(vec![
            leaf("event_type", Operator::Eq, Some(json!("ssh_login"))),
            leaf("result", Operator::Eq, Some(json!("failure"))),
        ]),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::Matched(_)
    ));
}

#[test]
fn all_short_circuits_false() {
    // First leaf is false, second would error — short-circuit returns NotMatched.
    let r = rule(
        RuleType::Single,
        Severity::High,
        all(vec![
            leaf("event_type", Operator::Eq, Some(json!("sudo"))),
            leaf("src_port", Operator::Contains, Some(json!("2"))),
        ]),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::NotMatched
    ));
}

#[test]
fn any_matches_and_short_circuits() {
    let r = rule(
        RuleType::Single,
        Severity::High,
        any(vec![
            leaf("event_type", Operator::Eq, Some(json!("ssh_login"))),
            leaf("src_port", Operator::Contains, Some(json!("2"))),
        ]),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::Matched(_)
    ));
}

#[test]
fn any_no_match() {
    let r = rule(
        RuleType::Single,
        Severity::High,
        any(vec![
            leaf("event_type", Operator::Eq, Some(json!("sudo"))),
            leaf("result", Operator::Eq, Some(json!("success"))),
        ]),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::NotMatched
    ));
}

#[test]
fn nested_all_any() {
    let r = rule(
        RuleType::Single,
        Severity::High,
        all(vec![
            leaf("event_type", Operator::Eq, Some(json!("ssh_login"))),
            any(vec![
                leaf("result", Operator::Eq, Some(json!("failure"))),
                leaf("result", Operator::Eq, Some(json!("unknown"))),
            ]),
        ]),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::Matched(_)
    ));
}

#[test]
fn max_depth_safety() {
    // depth 5 exceeds MAX_CONDITION_DEPTH=4 → error, not a panic.
    let d = all(vec![all(vec![all(vec![all(vec![leaf(
        "event_type",
        Operator::Eq,
        Some(json!("x")),
    )])])])]);
    let r = rule(RuleType::Single, Severity::High, d, None);
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::Error(EvaluationError::ConditionTooDeep)
    ));
}

#[test]
fn malformed_rule_does_not_panic() {
    // Unknown field, missing value — all resolve to Error, never panic.
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf("no_such", Operator::Eq, Some(json!("x"))),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::Error(_)
    ));
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf("event_type", Operator::Eq, None),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::Error(_)
    ));
}

// ── Field resolution ────────────────────────────────────────────────────────

#[test]
fn event_attributes_command() {
    let mut e = base_event();
    e.event_attributes = Some(json!({ "command": "/usr/bin/cat /etc/shadow" }));
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf(
            "event_attributes.command",
            Operator::Contains,
            Some(json!("/etc/shadow")),
        ),
        None,
    );
    assert!(matches!(eval(&r, &e), EvaluationResult::Matched(_)));
}

#[test]
fn unknown_attribute_not_exists() {
    // An absent event_attributes key is a missing field → not_exists matches.
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf("event_attributes.command", Operator::NotExists, None),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::Matched(_)
    ));
}

// ── RuleMatch propagation ───────────────────────────────────────────────────

#[test]
fn tenant_and_event_id_propagation() {
    let m = assert_matched(eval(&ssh_bruteforce(), &base_event()));
    assert_eq!(m.tenant_id, "tenant-a");
    assert_eq!(m.audit_event_id, "evt-1");
    assert_eq!(m.rule_id, "builtin.ssh_bruteforce");
    assert_eq!(m.matched_at, 1700000000000);
}

#[test]
fn single_rule_match_and_no_match() {
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf("event_type", Operator::Eq, Some(json!("ssh_login"))),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::Matched(_)
    ));
    let r = rule(
        RuleType::Single,
        Severity::High,
        leaf("event_type", Operator::Eq, Some(json!("sudo"))),
        None,
    );
    assert!(matches!(
        eval(&r, &base_event()),
        EvaluationResult::NotMatched
    ));
}

#[test]
fn threshold_candidate_match_extracts_group_values() {
    let m = assert_matched(eval(&ssh_bruteforce(), &base_event()));
    assert_eq!(m.group_values["src_ip"], "10.10.10.5");
    // Evidence carries rule_type, not raw_log.
    assert_eq!(m.evidence["rule_type"], "threshold");
    assert!(m.evidence.get("raw_log").is_none());
}

#[test]
fn multiple_group_by() {
    let mut r = repeated_pam_failure();
    r.aggregation = Some(Aggregation {
        group_by: vec![
            FieldPath("username".to_string()),
            FieldPath("src_ip".to_string()),
        ],
        window_seconds: 300,
        threshold: 5,
    });
    let mut e = base_event();
    e.event_type = Some("pam_auth".to_string());
    let m = assert_matched(eval(&r, &e));
    assert_eq!(m.group_values["username"], "alice");
    assert_eq!(m.group_values["src_ip"], "10.10.10.5");
}

// ── Built-in fixtures ───────────────────────────────────────────────────────

#[test]
fn ssh_bruteforce_fixture_matches() {
    let m = assert_matched(eval(&ssh_bruteforce(), &base_event()));
    assert_eq!(m.group_values["src_ip"], "10.10.10.5");
}

#[test]
fn sudo_fixture_matches() {
    let mut e = base_event();
    e.event_type = Some("sudo_command".to_string());
    e.result = Some(EventResult::Unknown);
    e.event_attributes =
        Some(json!({ "command": "/usr/bin/cat /etc/shadow", "target_user": "root" }));
    let m = assert_matched(eval(&suspicious_sudo_shadow(), &e));
    assert_eq!(m.rule_id, "builtin.suspicious_sudo_shadow");
}

#[test]
fn pam_fixture_matches() {
    let mut e = base_event();
    e.event_type = Some("pam_auth".to_string());
    e.result = Some(EventResult::Failure);
    let m = assert_matched(eval(&repeated_pam_failure(), &e));
    assert_eq!(m.group_values["username"], "alice");
}

// ── Statelessness ───────────────────────────────────────────────────────────

#[test]
fn evaluator_is_zero_sized() {
    // A unit struct carries no state, so evaluation cannot accumulate memory.
    assert_eq!(std::mem::size_of::<RuleEvaluator>(), 0);
}

#[test]
fn repeated_evaluation_is_deterministic() {
    // Evaluating the same rule against the same event many times yields the
    // identical result — no hidden state accumulates between calls.
    let r = ssh_bruteforce();
    let e = base_event();
    let first = eval(&r, &e);
    assert!(matches!(first, EvaluationResult::Matched(_)));
    for _ in 0..10_000 {
        assert_eq!(eval(&r, &e), first);
    }
}
