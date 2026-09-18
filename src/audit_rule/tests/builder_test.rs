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
    Aggregation, BuilderError, Category, Condition, DetectionKey, FieldPath, LeafCondition,
    Operator, RuleDefinition, RuleMatch, RuleSource, RuleType, SecurityEventBuilder,
    SecurityEventMutation, Severity, Status, WindowEvaluation,
};
use serde_json::{Value, json};

const NOW: i64 = 1700000000000;

fn single_rule() -> RuleDefinition {
    RuleDefinition {
        id: "builtin.suspicious_sudo_shadow".to_string(),
        version: "1.0.0".to_string(),
        title: "Sensitive sudo command".to_string(),
        description: Some("desc".to_string()),
        enabled: true,
        source: RuleSource::Builtin,
        tags: vec![],
        category: Category::Privilege,
        event_type: "suspicious_sudo".to_string(),
        severity: Severity::High,
        rule_type: RuleType::Single,
        r#match: Condition::Leaf(LeafCondition {
            field: FieldPath("event_type".to_string()),
            operator: Operator::Eq,
            value: Some(json!("sudo_command")),
        }),
        aggregation: None,
    }
}

fn threshold_rule(group_by: &[&str], window_seconds: u64, threshold: u64) -> RuleDefinition {
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
        r#match: Condition::Leaf(LeafCondition {
            field: FieldPath("event_type".to_string()),
            operator: Operator::Eq,
            value: Some(json!("ssh_login")),
        }),
        aggregation: Some(Aggregation {
            group_by: group_by.iter().map(|f| FieldPath(f.to_string())).collect(),
            window_seconds,
            threshold,
        }),
    }
}

fn rmatch(tenant: &str, rule_id: &str, version: &str, event_id: &str, ts: i64) -> RuleMatch {
    RuleMatch {
        rule_id: rule_id.to_string(),
        rule_version: version.to_string(),
        tenant_id: tenant.to_string(),
        audit_event_id: event_id.to_string(),
        matched_at: ts,
        group_values: json!({ "src_ip": "10.0.0.1" }),
        evidence: json!({ "rule_type": "single", "matched_fields": ["event_type"] }),
    }
}

// Mirrors the WindowEvaluation struct field-for-field, so the wide signature is
// intentional for a test helper.
#[allow(clippy::too_many_arguments)]
fn weval(
    tenant: &str,
    rule_id: &str,
    version: &str,
    group_values: Value,
    count: usize,
    first_seen: i64,
    last_seen: i64,
    threshold: u64,
    reached: bool,
    crossed: bool,
    episode_started_at: Option<i64>,
    sample_event_ids: Vec<String>,
) -> WindowEvaluation {
    WindowEvaluation {
        tenant_id: tenant.to_string(),
        rule_id: rule_id.to_string(),
        rule_version: version.to_string(),
        group_values,
        count,
        first_seen,
        last_seen,
        threshold,
        threshold_reached: reached,
        threshold_crossed: crossed,
        sample_event_ids,
        episode_started_at,
    }
}

fn as_create(m: SecurityEventMutation) -> (audit_rule::SecurityEvent, DetectionKey, String) {
    match m {
        SecurityEventMutation::Create {
            security_event,
            detection_key,
            episode_id,
        } => (*security_event, detection_key, episode_id),
        other => panic!("expected Create, got {other:?}"),
    }
}

// ── Single ──────────────────────────────────────────────────────────────────

#[test]
fn single_creates_security_event() {
    let b = SecurityEventBuilder;
    let m = rmatch(
        "tenant-a",
        "builtin.suspicious_sudo_shadow",
        "1.0.0",
        "evt-1",
        1000,
    );
    let (ev, key, episode) = as_create(b.build_single(&single_rule(), &m, NOW).unwrap());
    assert_eq!(ev.status, Status::Open);
    assert_eq!(ev.event_count, 1);
    assert_eq!(ev.related_event_ids, vec!["evt-1".to_string()]);
    assert_eq!(ev.first_seen, 1000);
    assert_eq!(ev.last_seen, 1000);
    assert_eq!(ev.created_at, NOW);
    assert_eq!(ev.updated_at, NOW);
    assert_eq!(key.tenant_id, "tenant-a");
    assert_eq!(key.rule_id, "builtin.suspicious_sudo_shadow");
    assert_eq!(episode, "evt-1");
}

#[test]
fn single_rule_metadata_propagation() {
    let b = SecurityEventBuilder;
    let m = rmatch("t", "builtin.suspicious_sudo_shadow", "1.0.0", "e1", 1000);
    let (ev, ..) = as_create(b.build_single(&single_rule(), &m, NOW).unwrap());
    assert_eq!(ev.title, "Sensitive sudo command");
    assert_eq!(ev.category, Category::Privilege);
    assert_eq!(ev.event_type, "suspicious_sudo");
    assert_eq!(ev.severity, Severity::High);
    assert_eq!(ev.rule_id, "builtin.suspicious_sudo_shadow");
    assert_eq!(ev.rule_version, "1.0.0");
}

#[test]
fn two_single_events_produce_distinct_events() {
    let b = SecurityEventBuilder;
    let (ev1, ..) = as_create(
        b.build_single(&single_rule(), &rmatch("t", "r", "1.0.0", "e1", 1000), NOW)
            .unwrap(),
    );
    let (ev2, ..) = as_create(
        b.build_single(&single_rule(), &rmatch("t", "r", "1.0.0", "e2", 1001), NOW)
            .unwrap(),
    );
    assert_ne!(ev1.event_id, ev2.event_id);
}

#[test]
fn single_event_id_is_uuid_not_audit_id() {
    let b = SecurityEventBuilder;
    let m = rmatch("t", "r", "1.0.0", "evt-1", 1000);
    let (ev, ..) = as_create(b.build_single(&single_rule(), &m, NOW).unwrap());
    // The SecurityEvent id is server-generated (UUID), never the AuditEvent id.
    assert_ne!(ev.event_id, "evt-1");
    assert!(!ev.event_id.is_empty());
}

// ── Threshold ───────────────────────────────────────────────────────────────

#[test]
fn threshold_below_is_noop() {
    let b = SecurityEventBuilder;
    let e = weval(
        "t",
        "r",
        "1.0.0",
        json!({"src_ip":"10.0.0.1"}),
        3,
        1000,
        1002,
        10,
        false,
        false,
        None,
        vec![],
    );
    assert_eq!(
        b.build_threshold(&threshold_rule(&["src_ip"], 300, 10), &e, NOW)
            .unwrap(),
        SecurityEventMutation::NoOp
    );
}

#[test]
fn threshold_crossing_creates() {
    let b = SecurityEventBuilder;
    let e = weval(
        "t",
        "r",
        "1.0.0",
        json!({"src_ip":"10.0.0.1"}),
        10,
        1000,
        1009,
        10,
        true,
        true,
        Some(1009),
        (1..=10).map(|i| format!("e{i}")).collect(),
    );
    let (ev, key, episode) = as_create(
        b.build_threshold(&threshold_rule(&["src_ip"], 300, 10), &e, NOW)
            .unwrap(),
    );
    assert_eq!(ev.status, Status::Open);
    assert_eq!(ev.event_count, 10);
    assert_eq!(ev.first_seen, 1000);
    assert_eq!(ev.last_seen, 1009);
    assert_eq!(ev.src_ip.as_deref(), Some("10.0.0.1"));
    assert_eq!(key.group_values, "src_ip=10.0.0.1");
    assert_eq!(episode, "1009");
}

#[test]
fn threshold_above_is_update() {
    let b = SecurityEventBuilder;
    let e = weval(
        "t",
        "r",
        "1.0.0",
        json!({"src_ip":"10.0.0.1"}),
        11,
        1000,
        1010,
        10,
        true,
        false,
        Some(1009),
        (1..=11).map(|i| format!("e{i}")).collect(),
    );
    match b
        .build_threshold(&threshold_rule(&["src_ip"], 300, 10), &e, NOW)
        .unwrap()
    {
        SecurityEventMutation::Update {
            detection_key,
            episode_id,
            last_seen,
            event_count,
            updated_at,
            ..
        } => {
            assert_eq!(detection_key.group_values, "src_ip=10.0.0.1");
            assert_eq!(episode_id, "1009");
            assert_eq!(last_seen, 1010);
            assert_eq!(event_count, 11);
            assert_eq!(updated_at, NOW);
        }
        other => panic!("expected Update, got {other:?}"),
    }
}

#[test]
fn threshold_rearm_creates_new_episode() {
    let b = SecurityEventBuilder;
    // First crossing at 1009 → episode "1009".
    let e1 = weval(
        "t",
        "r",
        "1.0.0",
        json!({"src_ip":"10.0.0.1"}),
        10,
        1000,
        1009,
        10,
        true,
        true,
        Some(1009),
        vec!["e1".to_string()],
    );
    let (_, _, ep1) = as_create(
        b.build_threshold(&threshold_rule(&["src_ip"], 300, 10), &e1, NOW)
            .unwrap(),
    );
    // Later re-cross at 5009 → NEW episode "5009".
    let e2 = weval(
        "t",
        "r",
        "1.0.0",
        json!({"src_ip":"10.0.0.1"}),
        10,
        5000,
        5009,
        10,
        true,
        true,
        Some(5009),
        vec!["e2".to_string()],
    );
    let (_, _, ep2) = as_create(
        b.build_threshold(&threshold_rule(&["src_ip"], 300, 10), &e2, NOW)
            .unwrap(),
    );
    assert_ne!(ep1, ep2);
}

#[test]
fn threshold_tenant_and_version_isolation() {
    let b = SecurityEventBuilder;
    let r = threshold_rule(&["src_ip"], 300, 10);
    let e = weval(
        "tenant-a",
        "r",
        "1.0.0",
        json!({"src_ip":"10.0.0.1"}),
        10,
        1000,
        1009,
        10,
        true,
        true,
        Some(1009),
        vec![],
    );
    let (_, key_a, _) = as_create(b.build_threshold(&r, &e, NOW).unwrap());
    let e = weval(
        "tenant-b",
        "r",
        "1.0.0",
        json!({"src_ip":"10.0.0.1"}),
        10,
        1000,
        1009,
        10,
        true,
        true,
        Some(1009),
        vec![],
    );
    let (_, key_b, _) = as_create(b.build_threshold(&r, &e, NOW).unwrap());
    assert_ne!(key_a.tenant_id, key_b.tenant_id);

    let e = weval(
        "tenant-a",
        "r",
        "2.0.0",
        json!({"src_ip":"10.0.0.1"}),
        10,
        1000,
        1009,
        10,
        true,
        true,
        Some(1009),
        vec![],
    );
    let (_, key_v2, _) = as_create(b.build_threshold(&r, &e, NOW).unwrap());
    assert_ne!(key_a.rule_version, key_v2.rule_version);
}

#[test]
fn threshold_missing_episode_is_error() {
    let b = SecurityEventBuilder;
    let e = weval(
        "t",
        "r",
        "1.0.0",
        json!({"src_ip":"10.0.0.1"}),
        10,
        1000,
        1009,
        10,
        true,
        true,
        None,
        vec![],
    );
    assert_eq!(
        b.build_threshold(&threshold_rule(&["src_ip"], 300, 10), &e, NOW)
            .unwrap_err(),
        BuilderError::MissingEpisode
    );
}

#[test]
fn wrong_rule_type_is_error() {
    let b = SecurityEventBuilder;
    let m = rmatch("t", "r", "1.0.0", "e1", 1000);
    assert_eq!(
        b.build_single(&threshold_rule(&["src_ip"], 300, 10), &m, NOW)
            .unwrap_err(),
        BuilderError::RuleTypeMismatch
    );
    let e = weval(
        "t",
        "r",
        "1.0.0",
        json!({"src_ip":"10.0.0.1"}),
        10,
        1000,
        1009,
        10,
        true,
        true,
        Some(1009),
        vec![],
    );
    assert_eq!(
        b.build_threshold(&single_rule(), &e, NOW).unwrap_err(),
        BuilderError::RuleTypeMismatch
    );
}

#[test]
fn threshold_evidence_shape() {
    let b = SecurityEventBuilder;
    let e = weval(
        "t",
        "r",
        "1.0.0",
        json!({"src_ip":"10.0.0.1"}),
        10,
        1000,
        1009,
        10,
        true,
        true,
        Some(1009),
        vec![],
    );
    let (ev, ..) = as_create(
        b.build_threshold(&threshold_rule(&["src_ip"], 300, 10), &e, NOW)
            .unwrap(),
    );
    assert_eq!(ev.evidence["threshold"], 10);
    assert_eq!(ev.evidence["window_seconds"], 300);
    assert_eq!(ev.evidence["group_by"][0], "src_ip");
    assert_eq!(ev.evidence["current_count"], 10);
    // No raw_log in evidence.
    assert!(ev.evidence.get("raw_log").is_none());
}
