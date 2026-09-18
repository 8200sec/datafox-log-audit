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

use std::sync::Arc;

use audit_rule::{
    Category, CreateOutcome, DetectionKey, MAX_RELATED_EVENT_IDS, SecurityEvent,
    SecurityEventRepository, SecurityEventUpdate, Severity, SqliteSecurityEventRepository, Status,
    UpdateOutcome,
};
use serde_json::json;

fn make_event(
    tenant: &str,
    event_id: &str,
    rule_id: &str,
    count: u64,
    last_seen: i64,
) -> SecurityEvent {
    SecurityEvent {
        event_id: event_id.to_string(),
        tenant_id: tenant.to_string(),
        rule_id: rule_id.to_string(),
        rule_version: "1.0.0".to_string(),
        title: "SSH brute force".to_string(),
        description: None,
        category: Category::Authentication,
        event_type: "ssh_brute_force".to_string(),
        severity: Severity::High,
        status: Status::Open,
        first_seen: 1000,
        last_seen,
        event_count: count,
        src_ip: Some("10.0.0.1".to_string()),
        dst_ip: None,
        username: None,
        asset_id: None,
        related_event_ids: (1..=count as usize).map(|i| format!("e{i}")).collect(),
        evidence: json!({ "threshold": 10 }),
        created_at: 1000,
        updated_at: last_seen,
    }
}

fn key(tenant: &str, rule_id: &str, version: &str, group: &str) -> DetectionKey {
    DetectionKey {
        tenant_id: tenant.to_string(),
        rule_id: rule_id.to_string(),
        rule_version: version.to_string(),
        group_values: group.to_string(),
    }
}

#[test]
fn create_and_get_by_event_id() {
    let repo = SqliteSecurityEventRepository::open_in_memory().unwrap();
    let e = make_event("tenant-a", "evt-1", "builtin.ssh_bruteforce", 10, 1009);
    let out = repo
        .create(
            &e,
            &key(
                "tenant-a",
                "builtin.ssh_bruteforce",
                "1.0.0",
                "src_ip=10.0.0.1",
            ),
            "ep-1",
        )
        .unwrap();
    assert_eq!(
        out,
        CreateOutcome::Created {
            event_id: "evt-1".to_string()
        }
    );

    let found = repo.get_by_event_id("tenant-a", "evt-1").unwrap().unwrap();
    assert_eq!(found.event_id, "evt-1");
    assert_eq!(found.event_count, 10);
    assert_eq!(found.severity, Severity::High);
    assert_eq!(found.evidence["threshold"], 10);
    assert_eq!(found.related_event_ids.len(), 10);
}

#[test]
fn get_by_episode() {
    let repo = SqliteSecurityEventRepository::open_in_memory().unwrap();
    let e = make_event("tenant-a", "evt-1", "builtin.ssh_bruteforce", 10, 1009);
    repo.create(
        &e,
        &key(
            "tenant-a",
            "builtin.ssh_bruteforce",
            "1.0.0",
            "src_ip=10.0.0.1",
        ),
        "ep-1",
    )
    .unwrap();
    let found = repo
        .get_by_episode(
            "tenant-a",
            &key(
                "tenant-a",
                "builtin.ssh_bruteforce",
                "1.0.0",
                "src_ip=10.0.0.1",
            ),
            "ep-1",
        )
        .unwrap()
        .unwrap();
    assert_eq!(found.event_id, "evt-1");
}

#[test]
fn duplicate_create_is_idempotent() {
    let repo = SqliteSecurityEventRepository::open_in_memory().unwrap();
    let e = make_event("tenant-a", "evt-1", "builtin.ssh_bruteforce", 10, 1009);
    let k = key(
        "tenant-a",
        "builtin.ssh_bruteforce",
        "1.0.0",
        "src_ip=10.0.0.1",
    );
    assert!(matches!(
        repo.create(&e, &k, "ep-1").unwrap(),
        CreateOutcome::Created { .. }
    ));
    // Retry with a DIFFERENT event_id but same (tenant, detection_key, episode).
    let e2 = make_event("tenant-a", "evt-2", "builtin.ssh_bruteforce", 10, 1009);
    let out = repo.create(&e2, &k, "ep-1").unwrap();
    match out {
        CreateOutcome::AlreadyExists { event_id } => assert_eq!(event_id, "evt-1"),
        other => panic!("expected AlreadyExists, got {other:?}"),
    }
    // Only one row exists.
    assert_eq!(repo.list("tenant-a", 100).unwrap().len(), 1);
}

#[test]
fn different_tenant_same_detection_key_isolated() {
    let repo = SqliteSecurityEventRepository::open_in_memory().unwrap();
    let k_a = key(
        "tenant-a",
        "builtin.ssh_bruteforce",
        "1.0.0",
        "src_ip=10.0.0.1",
    );
    let k_b = key(
        "tenant-b",
        "builtin.ssh_bruteforce",
        "1.0.0",
        "src_ip=10.0.0.1",
    );
    repo.create(
        &make_event("tenant-a", "evt-a", "builtin.ssh_bruteforce", 10, 1009),
        &k_a,
        "ep-1",
    )
    .unwrap();
    repo.create(
        &make_event("tenant-b", "evt-b", "builtin.ssh_bruteforce", 10, 1009),
        &k_b,
        "ep-1",
    )
    .unwrap();
    // Same event_id is impossible across tenants, but same detection_key + episode differs.
    assert!(repo.get_by_event_id("tenant-a", "evt-b").unwrap().is_none());
    assert!(repo.get_by_event_id("tenant-b", "evt-a").unwrap().is_none());
}

#[test]
fn different_episode_isolated() {
    let repo = SqliteSecurityEventRepository::open_in_memory().unwrap();
    let k = key(
        "tenant-a",
        "builtin.ssh_bruteforce",
        "1.0.0",
        "src_ip=10.0.0.1",
    );
    repo.create(
        &make_event("tenant-a", "evt-1", "builtin.ssh_bruteforce", 10, 1009),
        &k,
        "ep-1",
    )
    .unwrap();
    repo.create(
        &make_event("tenant-a", "evt-2", "builtin.ssh_bruteforce", 10, 5009),
        &k,
        "ep-2",
    )
    .unwrap();
    assert_eq!(repo.list("tenant-a", 100).unwrap().len(), 2);
}

#[test]
fn update_event_count_and_last_seen_monotonic() {
    let repo = SqliteSecurityEventRepository::open_in_memory().unwrap();
    let k = key(
        "tenant-a",
        "builtin.ssh_bruteforce",
        "1.0.0",
        "src_ip=10.0.0.1",
    );
    repo.create(
        &make_event("tenant-a", "evt-1", "builtin.ssh_bruteforce", 10, 1009),
        &k,
        "ep-1",
    )
    .unwrap();

    let update = SecurityEventUpdate {
        detection_key: k.clone(),
        episode_id: "ep-1".to_string(),
        last_seen: 1010,
        event_count: 11,
        evidence: json!({ "current_count": 11 }),
        related_event_ids: vec!["e11".to_string()],
        updated_at: 1010,
    };
    assert_eq!(
        repo.apply_detection_update(&update).unwrap(),
        UpdateOutcome::Updated {
            event_id: "evt-1".to_string()
        }
    );

    let found = repo.get_by_event_id("tenant-a", "evt-1").unwrap().unwrap();
    assert_eq!(found.event_count, 11);
    assert_eq!(found.last_seen, 1010);
    assert_eq!(found.updated_at, 1010);
}

#[test]
fn update_does_not_regress_count_or_last_seen() {
    let repo = SqliteSecurityEventRepository::open_in_memory().unwrap();
    let k = key(
        "tenant-a",
        "builtin.ssh_bruteforce",
        "1.0.0",
        "src_ip=10.0.0.1",
    );
    repo.create(
        &make_event("tenant-a", "evt-1", "builtin.ssh_bruteforce", 10, 1009),
        &k,
        "ep-1",
    )
    .unwrap();

    // A stale/out-of-order update with LOWER values must not regress.
    let update = SecurityEventUpdate {
        detection_key: k.clone(),
        episode_id: "ep-1".to_string(),
        last_seen: 900, // older
        event_count: 5, // lower
        evidence: json!({}),
        related_event_ids: vec![],
        updated_at: 900,
    };
    repo.apply_detection_update(&update).unwrap();
    let found = repo.get_by_event_id("tenant-a", "evt-1").unwrap().unwrap();
    assert_eq!(found.event_count, 10);
    assert_eq!(found.last_seen, 1009);
}

#[test]
fn update_related_event_ids_dedup_and_bounded() {
    let repo = SqliteSecurityEventRepository::open_in_memory().unwrap();
    let k = key(
        "tenant-a",
        "builtin.ssh_bruteforce",
        "1.0.0",
        "src_ip=10.0.0.1",
    );
    repo.create(
        &make_event("tenant-a", "evt-1", "builtin.ssh_bruteforce", 1, 1000),
        &k,
        "ep-1",
    )
    .unwrap();

    // Incoming has many ids (beyond MAX_RELATED_EVENT_IDS) + duplicates.
    let mut ids: Vec<String> = (0..(MAX_RELATED_EVENT_IDS + 50))
        .map(|i| format!("x{i}"))
        .collect();
    ids.push("x0".to_string()); // duplicate
    let update = SecurityEventUpdate {
        detection_key: k.clone(),
        episode_id: "ep-1".to_string(),
        last_seen: 2000,
        event_count: 200,
        evidence: json!({}),
        related_event_ids: ids,
        updated_at: 2000,
    };
    repo.apply_detection_update(&update).unwrap();
    let found = repo.get_by_event_id("tenant-a", "evt-1").unwrap().unwrap();
    assert!(found.related_event_ids.len() <= MAX_RELATED_EVENT_IDS);
    // event_count keeps the full count (not the sample length).
    assert_eq!(found.event_count, 200);
}

#[test]
fn update_preserves_immutable_fields_and_status() {
    let repo = SqliteSecurityEventRepository::open_in_memory().unwrap();
    let k = key(
        "tenant-a",
        "builtin.ssh_bruteforce",
        "1.0.0",
        "src_ip=10.0.0.1",
    );
    repo.create(
        &make_event("tenant-a", "evt-1", "builtin.ssh_bruteforce", 10, 1009),
        &k,
        "ep-1",
    )
    .unwrap();

    let update = SecurityEventUpdate {
        detection_key: k.clone(),
        episode_id: "ep-1".to_string(),
        last_seen: 1010,
        event_count: 11,
        evidence: json!({ "x": 1 }),
        related_event_ids: vec![],
        updated_at: 1010,
    };
    repo.apply_detection_update(&update).unwrap();
    let found = repo.get_by_event_id("tenant-a", "evt-1").unwrap().unwrap();
    // Immutable fields unchanged.
    assert_eq!(found.event_id, "evt-1");
    assert_eq!(found.tenant_id, "tenant-a");
    assert_eq!(found.rule_id, "builtin.ssh_bruteforce");
    assert_eq!(found.rule_version, "1.0.0");
    assert_eq!(found.created_at, 1000);
    // Status unchanged by detection update.
    assert_eq!(found.status, Status::Open);
}

#[test]
fn update_missing_episode_is_not_found() {
    let repo = SqliteSecurityEventRepository::open_in_memory().unwrap();
    let k = key(
        "tenant-a",
        "builtin.ssh_bruteforce",
        "1.0.0",
        "src_ip=10.0.0.1",
    );
    let update = SecurityEventUpdate {
        detection_key: k,
        episode_id: "nope".to_string(),
        last_seen: 1000,
        event_count: 1,
        evidence: json!({}),
        related_event_ids: vec![],
        updated_at: 1000,
    };
    assert_eq!(
        repo.apply_detection_update(&update).unwrap(),
        UpdateOutcome::NotFound
    );
}

#[test]
fn tenant_isolation_on_get() {
    let repo = SqliteSecurityEventRepository::open_in_memory().unwrap();
    let k = key("tenant-a", "r", "1.0.0", "g=1");
    repo.create(&make_event("tenant-a", "evt-1", "r", 1, 1000), &k, "ep-1")
        .unwrap();
    // Cross-tenant get returns None.
    assert!(repo.get_by_event_id("tenant-b", "evt-1").unwrap().is_none());
    assert!(
        repo.get_by_episode("tenant-b", &k, "ep-1")
            .unwrap()
            .is_none()
    );
    // list scoped to tenant.
    assert_eq!(repo.list("tenant-b", 100).unwrap().len(), 0);
    assert_eq!(repo.list("tenant-a", 100).unwrap().len(), 1);
}

#[test]
fn concurrent_create_single_row() {
    let repo = Arc::new(SqliteSecurityEventRepository::open_in_memory().unwrap());
    let mut handles = vec![];
    for i in 0..8 {
        let repo = Arc::clone(&repo);
        handles.push(std::thread::spawn(move || {
            let e = make_event("tenant-a", &format!("evt-{i}"), "r", 1, 1000);
            let k = key("tenant-a", "r", "1.0.0", "g=1");
            repo.create(&e, &k, "ep-1").unwrap()
        }));
    }
    let outcomes: Vec<CreateOutcome> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, CreateOutcome::Created { .. }))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, CreateOutcome::AlreadyExists { .. }))
            .count(),
        7
    );
    assert_eq!(repo.list("tenant-a", 100).unwrap().len(), 1);
}

#[test]
fn concurrent_update_monotonic() {
    let repo = Arc::new(SqliteSecurityEventRepository::open_in_memory().unwrap());
    let k = key("tenant-a", "r", "1.0.0", "g=1");
    repo.create(&make_event("tenant-a", "evt-1", "r", 1, 1000), &k, "ep-1")
        .unwrap();

    let mut handles = vec![];
    for i in 1..=8 {
        let repo = Arc::clone(&repo);
        let k = k.clone();
        handles.push(std::thread::spawn(move || {
            let update = SecurityEventUpdate {
                detection_key: k,
                episode_id: "ep-1".to_string(),
                last_seen: 1000 + i,
                event_count: 1 + i as u64,
                evidence: json!({ "n": i }),
                related_event_ids: vec![format!("e{i}")],
                updated_at: 1000 + i,
            };
            repo.apply_detection_update(&update).unwrap()
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let found = repo.get_by_event_id("tenant-a", "evt-1").unwrap().unwrap();
    // Final values are the max across all concurrent updates.
    assert_eq!(found.event_count, 9);
    assert_eq!(found.last_seen, 1008);
}

#[test]
fn persistence_across_reopen() {
    let path = std::env::temp_dir().join(format!("datafox_repo_test_{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    {
        let repo = SqliteSecurityEventRepository::open(&path).unwrap();
        let k = key("tenant-a", "r", "1.0.0", "g=1");
        repo.create(&make_event("tenant-a", "evt-1", "r", 5, 1000), &k, "ep-1")
            .unwrap();
    }
    // Reopen the same file — migration is a no-op and the row persists.
    let repo = SqliteSecurityEventRepository::open(&path).unwrap();
    let found = repo.get_by_event_id("tenant-a", "evt-1").unwrap().unwrap();
    assert_eq!(found.event_count, 5);
    let _ = std::fs::remove_file(&path);
}
