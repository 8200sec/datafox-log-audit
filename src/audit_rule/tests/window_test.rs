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
    Aggregation, Category, Condition, FieldPath, LeafCondition, MAX_SAMPLE_EVENT_IDS, Operator,
    RuleDefinition, RuleMatch, RuleSource, RuleType, Severity, WindowError, WindowEvaluation,
    WindowLimits, WindowOutcome, WindowStateManager,
};
use serde_json::{Value, json};

fn rule(group_by: &[&str], window_seconds: u64, threshold: u64) -> RuleDefinition {
    RuleDefinition {
        id: "builtin.test".to_string(),
        version: "1.0.0".to_string(),
        title: "Test".to_string(),
        description: None,
        enabled: true,
        source: RuleSource::Builtin,
        tags: vec![],
        category: Category::Authentication,
        event_type: "test".to_string(),
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

fn m(
    tenant: &str,
    rule_id: &str,
    version: &str,
    event_id: &str,
    ts: i64,
    group_values: Value,
) -> RuleMatch {
    RuleMatch {
        rule_id: rule_id.to_string(),
        rule_version: version.to_string(),
        tenant_id: tenant.to_string(),
        audit_event_id: event_id.to_string(),
        matched_at: ts,
        group_values,
        evidence: json!({}),
    }
}

fn rec(
    mgr: &mut WindowStateManager,
    rule: &RuleDefinition,
    m: &RuleMatch,
) -> Result<WindowOutcome, WindowError> {
    mgr.record(rule, m)
}

fn eval(outcome: Result<WindowOutcome, WindowError>) -> WindowEvaluation {
    match outcome.unwrap() {
        WindowOutcome::Recorded(e) => e,
        other => panic!("expected recorded, got {other:?}"),
    }
}

fn src_ip(ip: &str) -> Value {
    json!({ "src_ip": ip })
}

#[test]
fn new_window() {
    let mut mgr = WindowStateManager::new();
    let r = rule(&["src_ip"], 300, 10);
    let e = eval(rec(
        &mut mgr,
        &r,
        &m(
            "t",
            "builtin.test",
            "1.0.0",
            "evt-1",
            1000,
            src_ip("10.0.0.1"),
        ),
    ));
    assert_eq!(e.count, 1);
    assert!(!e.threshold_reached);
    assert_eq!(e.first_seen, 1000);
    assert_eq!(e.last_seen, 1000);
}

#[test]
fn same_group_accumulates() {
    let mut mgr = WindowStateManager::new();
    let r = rule(&["src_ip"], 300, 10);
    rec(
        &mut mgr,
        &r,
        &m(
            "t",
            "builtin.test",
            "1.0.0",
            "evt-1",
            1000,
            src_ip("10.0.0.1"),
        ),
    )
    .unwrap();
    let e = eval(rec(
        &mut mgr,
        &r,
        &m(
            "t",
            "builtin.test",
            "1.0.0",
            "evt-2",
            1001,
            src_ip("10.0.0.1"),
        ),
    ));
    assert_eq!(e.count, 2);
}

#[test]
fn different_group_isolation() {
    let mut mgr = WindowStateManager::new();
    let r = rule(&["src_ip"], 300, 10);
    rec(
        &mut mgr,
        &r,
        &m("t", "builtin.test", "1.0.0", "e1", 1000, src_ip("10.0.0.1")),
    )
    .unwrap();
    let e = eval(rec(
        &mut mgr,
        &r,
        &m("t", "builtin.test", "1.0.0", "e2", 1001, src_ip("10.0.0.2")),
    ));
    assert_eq!(e.count, 1); // separate window for the second IP
}

#[test]
fn different_rule_isolation() {
    let mut mgr = WindowStateManager::new();
    let r1 = rule(&["src_ip"], 300, 10);
    let mut r2 = rule(&["src_ip"], 300, 10);
    r2.id = "builtin.other".to_string();
    rec(
        &mut mgr,
        &r1,
        &m("t", "builtin.test", "1.0.0", "e1", 1000, src_ip("10.0.0.1")),
    )
    .unwrap();
    let e = eval(rec(
        &mut mgr,
        &r2,
        &m(
            "t",
            "builtin.other",
            "1.0.0",
            "e2",
            1001,
            src_ip("10.0.0.1"),
        ),
    ));
    assert_eq!(e.count, 1);
}

#[test]
fn different_rule_version_isolation() {
    let mut mgr = WindowStateManager::new();
    let r = rule(&["src_ip"], 300, 10);
    rec(
        &mut mgr,
        &r,
        &m("t", "builtin.test", "1.0.0", "e1", 1000, src_ip("10.0.0.1")),
    )
    .unwrap();
    // Same rule_id + same group, different version → a NEW window.
    let e = eval(rec(
        &mut mgr,
        &r,
        &m("t", "builtin.test", "2.0.0", "e2", 1001, src_ip("10.0.0.1")),
    ));
    assert_eq!(e.count, 1);
}

#[test]
fn different_tenant_isolation() {
    let mut mgr = WindowStateManager::new();
    let r = rule(&["src_ip"], 300, 10);
    rec(
        &mut mgr,
        &r,
        &m(
            "tenant-a",
            "builtin.test",
            "1.0.0",
            "e1",
            1000,
            src_ip("10.0.0.1"),
        ),
    )
    .unwrap();
    let e = eval(rec(
        &mut mgr,
        &r,
        &m(
            "tenant-b",
            "builtin.test",
            "1.0.0",
            "e2",
            1001,
            src_ip("10.0.0.1"),
        ),
    ));
    assert_eq!(e.count, 1);
}

#[test]
fn threshold_not_reached() {
    let mut mgr = WindowStateManager::new();
    let r = rule(&["src_ip"], 300, 3);
    for i in 0..2 {
        let e = eval(rec(
            &mut mgr,
            &r,
            &m(
                "t",
                "builtin.test",
                "1.0.0",
                &format!("e{i}"),
                1000 + i,
                src_ip("10.0.0.1"),
            ),
        ));
        assert!(!e.threshold_reached);
        assert!(!e.threshold_crossed);
    }
}

#[test]
fn threshold_crossing() {
    let mut mgr = WindowStateManager::new();
    let r = rule(&["src_ip"], 300, 3);
    for i in 0..3 {
        let e = eval(rec(
            &mut mgr,
            &r,
            &m(
                "t",
                "builtin.test",
                "1.0.0",
                &format!("e{i}"),
                1000 + i,
                src_ip("10.0.0.1"),
            ),
        ));
        if i == 2 {
            assert!(e.threshold_reached);
            assert!(e.threshold_crossed);
        }
    }
}

#[test]
fn above_threshold_no_repeated_crossing() {
    let mut mgr = WindowStateManager::new();
    let r = rule(&["src_ip"], 300, 3);
    for i in 0..4 {
        let e = eval(rec(
            &mut mgr,
            &r,
            &m(
                "t",
                "builtin.test",
                "1.0.0",
                &format!("e{i}"),
                1000 + i,
                src_ip("10.0.0.1"),
            ),
        ));
        if i == 2 {
            assert!(e.threshold_crossed);
        } else if i == 3 {
            assert!(e.threshold_reached);
            assert!(!e.threshold_crossed);
        }
    }
}

#[test]
fn window_expiration_and_rearm() {
    let mut mgr = WindowStateManager::new();
    let r = rule(&["src_ip"], 300, 3);
    // 3 events within window → reached.
    for i in 0..3 {
        rec(
            &mut mgr,
            &r,
            &m(
                "t",
                "builtin.test",
                "1.0.0",
                &format!("e{i}"),
                1000 + i,
                src_ip("10.0.0.1"),
            ),
        )
        .unwrap();
    }
    // A much later event (beyond window) evicts the old 3 → count 1, re-armed.
    let e = eval(rec(
        &mut mgr,
        &r,
        &m("t", "builtin.test", "1.0.0", "e3", 5000, src_ip("10.0.0.1")),
    ));
    assert_eq!(e.count, 1);
    assert!(!e.threshold_reached);
}

#[test]
fn second_threshold_crossing_after_rearm() {
    let mut mgr = WindowStateManager::new();
    let r = rule(&["src_ip"], 300, 3);
    for i in 0..3 {
        rec(
            &mut mgr,
            &r,
            &m(
                "t",
                "builtin.test",
                "1.0.0",
                &format!("a{i}"),
                1000 + i,
                src_ip("10.0.0.1"),
            ),
        )
        .unwrap();
    }
    // Expire, then cross again.
    rec(
        &mut mgr,
        &r,
        &m("t", "builtin.test", "1.0.0", "b1", 5000, src_ip("10.0.0.1")),
    )
    .unwrap();
    rec(
        &mut mgr,
        &r,
        &m("t", "builtin.test", "1.0.0", "b2", 5001, src_ip("10.0.0.1")),
    )
    .unwrap();
    let e = eval(rec(
        &mut mgr,
        &r,
        &m("t", "builtin.test", "1.0.0", "b3", 5002, src_ip("10.0.0.1")),
    ));
    assert_eq!(e.count, 3);
    assert!(e.threshold_crossed);
}

#[test]
fn duplicate_event_not_counted() {
    let mut mgr = WindowStateManager::new();
    let r = rule(&["src_ip"], 300, 10);
    rec(
        &mut mgr,
        &r,
        &m("t", "builtin.test", "1.0.0", "e1", 1000, src_ip("10.0.0.1")),
    )
    .unwrap();
    let out = rec(
        &mut mgr,
        &r,
        &m("t", "builtin.test", "1.0.0", "e1", 1001, src_ip("10.0.0.1")),
    )
    .unwrap();
    assert_eq!(out, WindowOutcome::Duplicate);
    let e = eval(rec(
        &mut mgr,
        &r,
        &m("t", "builtin.test", "1.0.0", "e2", 1002, src_ip("10.0.0.1")),
    ));
    assert_eq!(e.count, 2); // e1 not re-counted
}

#[test]
fn out_of_window_event_ignored() {
    let mut mgr = WindowStateManager::new();
    let r = rule(&["src_ip"], 300, 10);
    rec(
        &mut mgr,
        &r,
        &m("t", "builtin.test", "1.0.0", "e1", 5000, src_ip("10.0.0.1")),
    )
    .unwrap();
    // An event older than the window (anchored at 5000) is ignored.
    let out = rec(
        &mut mgr,
        &r,
        &m("t", "builtin.test", "1.0.0", "e2", 1000, src_ip("10.0.0.1")),
    )
    .unwrap();
    assert_eq!(out, WindowOutcome::OutOfWindow);
}

#[test]
fn multiple_group_by() {
    let mut mgr = WindowStateManager::new();
    let r = rule(&["src_ip", "username"], 300, 10);
    rec(
        &mut mgr,
        &r,
        &m(
            "t",
            "builtin.test",
            "1.0.0",
            "e1",
            1000,
            json!({"src_ip":"10.0.0.1","username":"alice"}),
        ),
    )
    .unwrap();
    let e = eval(rec(
        &mut mgr,
        &r,
        &m(
            "t",
            "builtin.test",
            "1.0.0",
            "e2",
            1001,
            json!({"src_ip":"10.0.0.1","username":"alice"}),
        ),
    ));
    assert_eq!(e.count, 2);
    // Different username → different window.
    let e = eval(rec(
        &mut mgr,
        &r,
        &m(
            "t",
            "builtin.test",
            "1.0.0",
            "e3",
            1002,
            json!({"src_ip":"10.0.0.1","username":"bob"}),
        ),
    ));
    assert_eq!(e.count, 1);
}

#[test]
fn canonical_group_key_uses_declaration_order() {
    // Two group_by orders produce different keys for the same values.
    let mut mgr = WindowStateManager::new();
    let r1 = rule(&["src_ip", "username"], 300, 10);
    let r2 = rule(&["username", "src_ip"], 300, 10);
    let g = json!({"src_ip":"10.0.0.1","username":"alice"});
    rec(
        &mut mgr,
        &r1,
        &m("t", "builtin.test", "1.0.0", "e1", 1000, g.clone()),
    )
    .unwrap();
    // r2 (different order) → different canonical key → separate window.
    let e = eval(rec(
        &mut mgr,
        &r2,
        &m("t", "builtin.test", "1.0.0", "e2", 1001, g),
    ));
    assert_eq!(e.count, 1);
}

#[test]
fn long_group_value_rejected() {
    let mut mgr = WindowStateManager::with_limits(WindowLimits {
        max_group_value_length: 8,
        ..Default::default()
    });
    let r = rule(&["src_ip"], 300, 10);
    let out = rec(
        &mut mgr,
        &r,
        &m(
            "t",
            "builtin.test",
            "1.0.0",
            "e1",
            1000,
            src_ip("10.0.0.999"),
        ),
    );
    assert_eq!(out, Err(WindowError::GroupValueTooLong));
}

#[test]
fn missing_group_value_is_invalid() {
    let mut mgr = WindowStateManager::new();
    let r = rule(&["src_ip"], 300, 10);
    let out = rec(
        &mut mgr,
        &r,
        &m("t", "builtin.test", "1.0.0", "e1", 1000, json!({})),
    );
    assert_eq!(out, Err(WindowError::InvalidGroupKey));
}

#[test]
fn single_rule_bypasses_window_manager() {
    let mut mgr = WindowStateManager::new();
    let mut r = rule(&["src_ip"], 300, 10);
    r.rule_type = RuleType::Single;
    r.aggregation = None;
    let out = rec(
        &mut mgr,
        &r,
        &m("t", "builtin.test", "1.0.0", "e1", 1000, src_ip("10.0.0.1")),
    );
    assert_eq!(out, Err(WindowError::InvalidWindow));
}

#[test]
fn per_tenant_capacity() {
    let mut mgr = WindowStateManager::with_limits(WindowLimits {
        max_active_windows_per_tenant: 2,
        ..Default::default()
    });
    let r = rule(&["src_ip"], 300, 10);
    rec(
        &mut mgr,
        &r,
        &m("t", "builtin.test", "1.0.0", "e1", 1000, src_ip("10.0.0.1")),
    )
    .unwrap();
    rec(
        &mut mgr,
        &r,
        &m("t", "builtin.test", "1.0.0", "e2", 1000, src_ip("10.0.0.2")),
    )
    .unwrap();
    // Third distinct group exceeds the per-tenant limit.
    let out = rec(
        &mut mgr,
        &r,
        &m("t", "builtin.test", "1.0.0", "e3", 1000, src_ip("10.0.0.3")),
    );
    assert_eq!(out, Err(WindowError::CapacityExceeded));
    // Another tenant is unaffected.
    let e = eval(rec(
        &mut mgr,
        &r,
        &m(
            "other",
            "builtin.test",
            "1.0.0",
            "e4",
            1000,
            src_ip("10.0.0.1"),
        ),
    ));
    assert_eq!(e.count, 1);
}

#[test]
fn global_capacity() {
    let mut mgr = WindowStateManager::with_limits(WindowLimits {
        max_active_windows_global: 3,
        max_active_windows_per_tenant: 100,
        ..Default::default()
    });
    let r = rule(&["src_ip"], 300, 10);
    for i in 0..3 {
        rec(
            &mut mgr,
            &r,
            &m(
                "t",
                "builtin.test",
                "1.0.0",
                &format!("e{i}"),
                1000,
                src_ip(&format!("10.0.0.{i}")),
            ),
        )
        .unwrap();
    }
    let out = rec(
        &mut mgr,
        &r,
        &m("t", "builtin.test", "1.0.0", "e4", 1000, src_ip("10.0.0.9")),
    );
    assert_eq!(out, Err(WindowError::CapacityExceeded));
}

#[test]
fn expired_cleanup_reclaims_capacity() {
    let mut mgr = WindowStateManager::with_limits(WindowLimits {
        max_active_windows_per_tenant: 1,
        ..Default::default()
    });
    let r = rule(&["src_ip"], 300, 10);
    rec(
        &mut mgr,
        &r,
        &m("t", "builtin.test", "1.0.0", "e1", 1000, src_ip("10.0.0.1")),
    )
    .unwrap();
    // A much-later event for a new group triggers cleanup of the stale window.
    let e = eval(rec(
        &mut mgr,
        &r,
        &m(
            "t",
            "builtin.test",
            "1.0.0",
            "e2",
            100_000,
            src_ip("10.0.0.2"),
        ),
    ));
    assert_eq!(e.count, 1);
}

#[test]
fn capacity_attack_does_not_evict_active_windows() {
    let mut mgr = WindowStateManager::with_limits(WindowLimits {
        max_active_windows_per_tenant: 2,
        ..Default::default()
    });
    let r = rule(&["src_ip"], 300, 10);
    // Two active windows.
    rec(
        &mut mgr,
        &r,
        &m("t", "builtin.test", "1.0.0", "e1", 1000, src_ip("10.0.0.1")),
    )
    .unwrap();
    rec(
        &mut mgr,
        &r,
        &m("t", "builtin.test", "1.0.0", "e2", 1000, src_ip("10.0.0.2")),
    )
    .unwrap();
    // High-cardinality attack: many new distinct groups → CapacityExceeded, but
    // the two active windows must NOT be evicted.
    for i in 3..20 {
        let out = rec(
            &mut mgr,
            &r,
            &m(
                "t",
                "builtin.test",
                "1.0.0",
                &format!("e{i}"),
                1000,
                src_ip(&format!("10.0.0.{i}")),
            ),
        );
        assert_eq!(out, Err(WindowError::CapacityExceeded));
    }
    // The original active windows still accumulate.
    let e = eval(rec(
        &mut mgr,
        &r,
        &m(
            "t",
            "builtin.test",
            "1.0.0",
            "e20",
            1001,
            src_ip("10.0.0.1"),
        ),
    ));
    assert_eq!(e.count, 2);
}

#[test]
fn max_events_per_window() {
    let mut mgr = WindowStateManager::with_limits(WindowLimits {
        max_events_per_window: 3,
        ..Default::default()
    });
    let r = rule(&["src_ip"], 300, 100);
    for i in 0..3 {
        rec(
            &mut mgr,
            &r,
            &m(
                "t",
                "builtin.test",
                "1.0.0",
                &format!("e{i}"),
                1000 + i,
                src_ip("10.0.0.1"),
            ),
        )
        .unwrap();
    }
    let out = rec(
        &mut mgr,
        &r,
        &m("t", "builtin.test", "1.0.0", "e4", 1004, src_ip("10.0.0.1")),
    );
    assert_eq!(out, Err(WindowError::MaxEventsPerWindow));
}

#[test]
fn sample_event_ids_capped() {
    let mut mgr = WindowStateManager::new();
    let r = rule(&["src_ip"], 100_000, 10_000);
    let mut last = WindowEvaluation {
        tenant_id: String::new(),
        rule_id: String::new(),
        rule_version: String::new(),
        group_values: json!({}),
        count: 0,
        first_seen: 0,
        last_seen: 0,
        threshold: 10_000,
        threshold_reached: false,
        threshold_crossed: false,
        sample_event_ids: vec![],
        episode_started_at: None,
    };
    for i in 0..(MAX_SAMPLE_EVENT_IDS + 50) {
        last = eval(rec(
            &mut mgr,
            &r,
            &m(
                "t",
                "builtin.test",
                "1.0.0",
                &format!("e{i}"),
                1000 + i as i64,
                src_ip("10.0.0.1"),
            ),
        ));
    }
    assert_eq!(last.sample_event_ids.len(), MAX_SAMPLE_EVENT_IDS);
    assert_eq!(last.count, MAX_SAMPLE_EVENT_IDS + 50);
}

#[test]
fn malformed_state_does_not_panic() {
    let mut mgr = WindowStateManager::new();
    let r = rule(&["src_ip"], 300, 10);
    // Missing group value, missing aggregation on single rule — all Errors.
    assert!(
        rec(
            &mut mgr,
            &r,
            &m("t", "builtin.test", "1.0.0", "e1", 1000, json!({}))
        )
        .is_err()
    );
    let mut single = r.clone();
    single.rule_type = RuleType::Single;
    single.aggregation = None;
    assert!(
        rec(
            &mut mgr,
            &single,
            &m("t", "builtin.test", "1.0.0", "e1", 1000, src_ip("10.0.0.1"))
        )
        .is_err()
    );
}
