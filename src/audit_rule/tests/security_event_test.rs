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
    Category, MAX_RELATED_EVENT_IDS, SecurityEvent, SecurityEventError, Severity, Status,
};
use serde_json::{Value, json};

/// A minimal, valid SecurityEvent. Every test starts from this and mutates one
/// field to assert a specific validation failure.
fn minimal() -> SecurityEvent {
    SecurityEvent {
        event_id: "sev-1".to_string(),
        tenant_id: "tenant-a".to_string(),
        rule_id: "builtin.ssh_bruteforce".to_string(),
        rule_version: "1.0.0".to_string(),
        title: "SSH brute force".to_string(),
        description: None,
        category: Category::Authentication,
        event_type: "ssh_brute_force".to_string(),
        severity: Severity::High,
        status: Status::Open,
        first_seen: 1000,
        last_seen: 2000,
        event_count: 1,
        src_ip: Some("10.10.10.5".to_string()),
        dst_ip: None,
        username: None,
        asset_id: None,
        related_event_ids: vec!["evt-1".to_string()],
        evidence: json!({}),
        created_at: 1000,
        updated_at: 2000,
    }
}

/// The SSH brute-force fixture from the schema doc (item 15).
fn ssh_brute_force_fixture() -> SecurityEvent {
    SecurityEvent {
        event_id: "sev-bf-0001".to_string(),
        tenant_id: "tenant-a".to_string(),
        rule_id: "builtin.ssh_bruteforce".to_string(),
        rule_version: "1.0.0".to_string(),
        title: "SSH brute force".to_string(),
        description: Some("Repeated failed SSH logins from one source".to_string()),
        category: Category::Authentication,
        event_type: "ssh_brute_force".to_string(),
        severity: Severity::High,
        status: Status::Open,
        first_seen: 1700000000000,
        last_seen: 1700000300000,
        event_count: 10,
        src_ip: Some("10.10.10.5".to_string()),
        dst_ip: None,
        username: None,
        asset_id: None,
        related_event_ids: (1..=10).map(|i| format!("evt-{i}")).collect(),
        evidence: json!({
            "threshold": 10,
            "window_seconds": 300,
            "group_by": "src_ip",
            "group_value": "10.10.10.5",
        }),
        created_at: 1700000300000,
        updated_at: 1700000300000,
    }
}

#[test]
fn minimal_valid() {
    assert_eq!(minimal().validate(), Ok(()));
}

#[test]
fn full_event_valid() {
    let mut e = minimal();
    e.description = Some("desc".to_string());
    e.dst_ip = Some("10.0.0.9".to_string());
    e.username = Some("root".to_string());
    e.asset_id = Some("web01".to_string());
    e.related_event_ids = vec!["evt-1".to_string(), "evt-2".to_string()];
    e.evidence = json!({"threshold": 10, "window_seconds": 300});
    e.event_count = 2;
    assert_eq!(e.validate(), Ok(()));
}

#[test]
fn invalid_severity_rejected_on_deserialize() {
    let s = r#"{"event_id":"s","tenant_id":"t","rule_id":"r","rule_version":"1","title":"x","category":"authentication","event_type":"e","severity":"extreme","status":"open","first_seen":1,"last_seen":1,"event_count":1,"created_at":1,"updated_at":1}"#;
    assert!(serde_json::from_str::<SecurityEvent>(s).is_err());
}

#[test]
fn invalid_status_rejected_on_deserialize() {
    let s = r#"{"event_id":"s","tenant_id":"t","rule_id":"r","rule_version":"1","title":"x","category":"authentication","event_type":"e","severity":"high","status":"triaged","first_seen":1,"last_seen":1,"event_count":1,"created_at":1,"updated_at":1}"#;
    assert!(serde_json::from_str::<SecurityEvent>(s).is_err());
}

#[test]
fn invalid_category_rejected_on_deserialize() {
    let s = r#"{"event_id":"s","tenant_id":"t","rule_id":"r","rule_version":"1","title":"x","category":"nonsense","event_type":"e","severity":"high","status":"open","first_seen":1,"last_seen":1,"event_count":1,"created_at":1,"updated_at":1}"#;
    assert!(serde_json::from_str::<SecurityEvent>(s).is_err());
}

#[test]
fn event_count_zero_invalid() {
    let mut e = minimal();
    e.event_count = 0;
    assert_eq!(e.validate(), Err(SecurityEventError::InvalidEventCount));
}

#[test]
fn first_seen_after_last_seen_invalid() {
    let mut e = minimal();
    e.first_seen = 3000;
    e.last_seen = 2000;
    assert_eq!(e.validate(), Err(SecurityEventError::InvalidTimeRange));
}

#[test]
fn created_after_updated_invalid() {
    let mut e = minimal();
    e.created_at = 3000;
    e.updated_at = 2000;
    assert_eq!(e.validate(), Err(SecurityEventError::InvalidUpdateTime));
}

#[test]
fn missing_tenant_invalid() {
    let mut e = minimal();
    e.tenant_id = "  ".to_string();
    assert_eq!(e.validate(), Err(SecurityEventError::EmptyTenantId));
}

#[test]
fn missing_rule_invalid() {
    let mut e = minimal();
    e.rule_id = String::new();
    assert_eq!(e.validate(), Err(SecurityEventError::EmptyRuleId));

    let mut e = minimal();
    e.rule_version = String::new();
    assert_eq!(e.validate(), Err(SecurityEventError::EmptyRuleVersion));
}

#[test]
fn missing_event_id_invalid() {
    let mut e = minimal();
    e.event_id = String::new();
    assert_eq!(e.validate(), Err(SecurityEventError::EmptyEventId));
}

#[test]
fn missing_title_invalid() {
    let mut e = minimal();
    e.title = String::new();
    assert_eq!(e.validate(), Err(SecurityEventError::EmptyTitle));
}

#[test]
fn related_event_deduplicate() {
    let mut e = minimal();
    e.related_event_ids.clear();
    e.event_count = 0;
    e.record_related_event("evt-1".to_string());
    e.record_related_event("evt-1".to_string());
    e.record_related_event("evt-2".to_string());
    // A duplicate id is not a distinct event — not double-counted, not re-stored.
    assert_eq!(e.event_count, 2);
    assert_eq!(
        e.related_event_ids,
        vec!["evt-1".to_string(), "evt-2".to_string()]
    );
}

#[test]
fn related_event_upper_limit() {
    let mut e = minimal();
    e.related_event_ids.clear();
    e.event_count = 0;
    for i in 0..(MAX_RELATED_EVENT_IDS + 50) {
        e.record_related_event(format!("evt-{i}"));
    }
    // Sample list is capped…
    assert_eq!(e.related_event_ids.len(), MAX_RELATED_EVENT_IDS);
    // …but the full count keeps growing.
    assert_eq!(e.event_count, (MAX_RELATED_EVENT_IDS + 50) as u64);
    assert_eq!(e.validate(), Ok(()));
}

#[test]
fn related_event_over_limit_invalid() {
    let mut e = minimal();
    e.related_event_ids = (0..(MAX_RELATED_EVENT_IDS + 1))
        .map(|i| format!("evt-{i}"))
        .collect();
    assert_eq!(e.validate(), Err(SecurityEventError::TooManyRelatedEvents));
}

#[test]
fn evidence_serializes_as_json() {
    let e = minimal();
    let v = serde_json::to_value(&e).unwrap();
    assert!(v.get("evidence").is_some());
    // A populated evidence object round-trips.
    let mut e2 = minimal();
    e2.evidence = json!({"threshold": 10, "window_seconds": 300, "group_by": "src_ip"});
    let v2 = serde_json::to_value(&e2).unwrap();
    assert_eq!(v2["evidence"]["threshold"], 10);
    assert_eq!(v2["evidence"]["group_by"], "src_ip");
}

#[test]
fn json_round_trip() {
    let e = ssh_brute_force_fixture();
    let json = serde_json::to_string(&e).unwrap();
    let parsed: SecurityEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.event_id, e.event_id);
    assert_eq!(parsed.rule_id, "builtin.ssh_bruteforce");
    assert_eq!(parsed.severity, Severity::High);
    assert_eq!(parsed.status, Status::Open);
    assert_eq!(parsed.event_count, 10);
    assert_eq!(parsed.src_ip.as_deref(), Some("10.10.10.5"));
    assert_eq!(parsed.evidence["threshold"], 10);
    assert_eq!(parsed.validate(), Ok(()));
}

#[test]
fn ssh_brute_force_fixture_has_required_shape() {
    let e = ssh_brute_force_fixture();
    assert_eq!(e.rule_id, "builtin.ssh_bruteforce");
    assert_eq!(e.event_type, "ssh_brute_force");
    assert_eq!(e.category, Category::Authentication);
    assert_eq!(e.severity, Severity::High);
    assert_eq!(e.status, Status::Open);
    assert_eq!(e.event_count, 10);
    assert_eq!(e.src_ip.as_deref(), Some("10.10.10.5"));
    assert_eq!(e.evidence["threshold"], 10);
    assert_eq!(e.evidence["window_seconds"], 300);
    assert_eq!(e.validate(), Ok(()));
}

#[test]
fn severity_and_status_serde_tokens() {
    assert_eq!(
        serde_json::to_value(Severity::Critical).unwrap(),
        Value::String("critical".into())
    );
    assert_eq!(
        serde_json::to_value(Status::Acknowledged).unwrap(),
        Value::String("acknowledged".into())
    );
    assert_eq!(
        serde_json::to_value(Category::DataAccess).unwrap(),
        Value::String("data_access".into())
    );
    assert_eq!(
        serde_json::to_value(Category::Privilege).unwrap(),
        Value::String("privilege".into())
    );
}
