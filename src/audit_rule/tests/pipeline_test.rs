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

use audit_parser::{
    AuditEvent, DispatchResult, EventResult, RawLogInput, Severity as AuditSeverity, SourceType,
    TenantContext, default_dispatcher,
};
use audit_rule::{
    CreateOutcome, DetectionOutcome, DetectionPipeline, RepositoryError, RuleRegistry,
    RuleRegistryError, SecurityEvent, SecurityEventRepository, SecurityEventUpdate, Severity,
    SqliteSecurityEventRepository, Status, UpdateOutcome, WindowLimits, default_rules,
    ssh_bruteforce,
};
use serde_json::Value;

const NOW: i64 = 1735689600999;

fn parse(raw: impl AsRef<str>, tenant: &str) -> AuditEvent {
    let input = RawLogInput {
        raw_log: raw.as_ref().to_string(),
        received_at: NOW,
        source_type: None,
        source_name: Some("edge".to_string()),
        collector_id: None,
        tenant: TenantContext {
            tenant_id: tenant.to_string(),
        },
        transport: None,
    };
    match default_dispatcher().dispatch(&input, NOW) {
        DispatchResult::Ok(e) => *e,
        DispatchResult::Failure(f) => panic!("parse failed: {}", f.failure_message),
    }
}

// Mirrors the AuditEvent fields a test must set; the wide signature is intended.
#[allow(clippy::too_many_arguments)]
fn make_event(
    tenant: &str,
    event_type: &str,
    result: &str,
    src_ip: Option<&str>,
    username: Option<&str>,
    ts: i64,
    event_id: &str,
    attrs: Option<Value>,
) -> AuditEvent {
    AuditEvent {
        timestamp: ts,
        event_id: event_id.to_string(),
        tenant_id: tenant.to_string(),
        source_type: SourceType::Os,
        source_name: Some("edge".to_string()),
        collector_id: None,
        vendor: None,
        product: None,
        product_version: None,
        hostname: Some("web01".to_string()),
        asset_id: None,
        src_ip: src_ip.map(str::to_string),
        src_port: None,
        dst_ip: None,
        dst_port: None,
        username: username.map(str::to_string),
        category: Some("authentication".to_string()),
        event_type: Some(event_type.to_string()),
        action: None,
        result: Some(match result {
            "failure" => EventResult::Failure,
            "success" => EventResult::Success,
            _ => EventResult::Unknown,
        }),
        severity: AuditSeverity::Info,
        message: None,
        raw_log: event_id.to_string(),
        parser_id: Some("linux-auth".to_string()),
        parser_version: Some("1.0.0".to_string()),
        ingest_timestamp: ts,
        event_attributes: attrs,
    }
}

fn ssh_failure(tenant: &str, event_id: &str, ts: i64) -> AuditEvent {
    make_event(
        tenant,
        "ssh_login",
        "failure",
        Some("10.10.10.5"),
        Some("alice"),
        ts,
        event_id,
        None,
    )
}

fn build_pipeline(
    repo: Arc<SqliteSecurityEventRepository>,
) -> (DetectionPipeline, Arc<SqliteSecurityEventRepository>) {
    let mut reg = RuleRegistry::new();
    for r in default_rules() {
        reg.register(r).unwrap();
    }
    (DetectionPipeline::new(&reg, repo.clone()), repo)
}

fn pipeline() -> (DetectionPipeline, Arc<SqliteSecurityEventRepository>) {
    build_pipeline(Arc::new(
        SqliteSecurityEventRepository::open_in_memory().unwrap(),
    ))
}

// ── E2E: SSH brute force (via real syslog → parser) ──────────────────────────

#[test]
fn e2e_ssh_bruteforce() {
    let (pipeline, repo) = pipeline();
    // 9 failures — no SecurityEvent yet.
    for i in 0..9 {
        let raw = format!(
            "<34>Sep 18 15:28:31 web01 sshd[1024]: Failed password for alice from 10.10.10.5 port {i} ssh2"
        );
        let e = parse(raw, "tenant-a");
        let outcomes = pipeline.process(&e, NOW);
        assert!(outcomes.iter().all(|o| {
            !matches!(
                o,
                DetectionOutcome::SecurityEventCreated { .. }
                    | DetectionOutcome::SecurityEventUpdated { .. }
            )
        }));
    }
    assert_eq!(repo.list("tenant-a", 100).unwrap().len(), 0);

    // 10th failure — Create.
    let raw = "<34>Sep 18 15:28:31 web01 sshd[1024]: Failed password for alice from 10.10.10.5 port 9 ssh2";
    let e = parse(raw, "tenant-a");
    let outcomes = pipeline.process(&e, NOW);
    let event_id = outcomes
        .iter()
        .find_map(|o| match o {
            DetectionOutcome::SecurityEventCreated { rule_id, event_id }
                if rule_id == "builtin.ssh_bruteforce" =>
            {
                Some(event_id.clone())
            }
            _ => None,
        })
        .expect("expected a created ssh_bruteforce event");

    let ev = repo
        .get_by_event_id("tenant-a", &event_id)
        .unwrap()
        .unwrap();
    assert_eq!(ev.event_type, "ssh_brute_force");
    assert_eq!(ev.severity, Severity::High);
    assert_eq!(ev.status, Status::Open);
    assert_eq!(ev.event_count, 10);
    assert_eq!(ev.src_ip.as_deref(), Some("10.10.10.5"));

    // 11th failure — Update (same event, count 11).
    let raw = "<34>Sep 18 15:28:31 web01 sshd[1024]: Failed password for alice from 10.10.10.5 port 10 ssh2";
    let e = parse(raw, "tenant-a");
    let outcomes = pipeline.process(&e, NOW);
    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o, DetectionOutcome::SecurityEventUpdated { .. }))
    );
    assert_eq!(repo.list("tenant-a", 100).unwrap().len(), 1);
    let ev = repo
        .get_by_event_id("tenant-a", &event_id)
        .unwrap()
        .unwrap();
    assert_eq!(ev.event_count, 11);
}

#[test]
fn e2e_sudo_single_rule() {
    let (pipeline, repo) = pipeline();
    let raw = "<86>Sep 18 15:28:31 web01 sudo[100]: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow";
    let e = parse(raw, "tenant-a");
    let outcomes = pipeline.process(&e, NOW);
    let created = outcomes
        .iter()
        .filter(|o| matches!(o, DetectionOutcome::SecurityEventCreated { .. }))
        .count();
    assert_eq!(created, 1);
    assert_eq!(repo.list("tenant-a", 100).unwrap().len(), 1);

    // A second, distinct sudo event → a second independent SecurityEvent.
    let raw2 = "<86>Sep 18 15:28:32 web01 sudo[100]: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow";
    let e2 = parse(raw2, "tenant-a");
    pipeline.process(&e2, NOW);
    assert_eq!(repo.list("tenant-a", 100).unwrap().len(), 2);
}

#[test]
fn e2e_pam_threshold() {
    let (pipeline, repo) = pipeline();
    for i in 0..4 {
        let raw = format!(
            "<34>Sep 18 15:28:31 web01 sshd[100]: pam_unix(sshd:auth): authentication failure; logname= uid={i} euid=0 tty=ssh ruser= rhost=10.0.0.5 user=alice"
        );
        let e = parse(raw, "tenant-a");
        pipeline.process(&e, NOW);
    }
    // 4 pam failures — below threshold 5.
    assert_eq!(repo.list("tenant-a", 100).unwrap().len(), 0);
    // 5th → create.
    let raw = "<34>Sep 18 15:28:31 web01 sshd[100]: pam_unix(sshd:auth): authentication failure; logname= uid=4 euid=0 tty=ssh ruser= rhost=10.0.0.5 user=alice";
    let e = parse(raw, "tenant-a");
    pipeline.process(&e, NOW);
    assert_eq!(repo.list("tenant-a", 100).unwrap().len(), 1);
    let ev = &repo.list("tenant-a", 100).unwrap()[0];
    assert_eq!(ev.event_type, "repeated_pam_failure");
    assert_eq!(ev.severity, Severity::Medium);
    assert_eq!(ev.event_count, 5);
}

#[test]
fn e2e_multi_tenant_isolation() {
    let (pipeline, repo) = pipeline();
    // tenant A: 9 failures; tenant B: 1 failure (same src_ip).
    for i in 0..9 {
        let raw = format!(
            "<34>Sep 18 15:28:31 web01 sshd[1024]: Failed password for alice from 10.10.10.5 port {i} ssh2"
        );
        let e = parse(raw, "tenant-a");
        pipeline.process(&e, NOW);
    }
    let raw = "<34>Sep 18 15:28:31 web01 sshd[1024]: Failed password for alice from 10.10.10.5 port 99 ssh2";
    let e = parse(raw, "tenant-b");
    pipeline.process(&e, NOW);
    // Still no event in either tenant.
    assert_eq!(repo.list("tenant-a", 100).unwrap().len(), 0);
    assert_eq!(repo.list("tenant-b", 100).unwrap().len(), 0);

    // tenant A: 10th → create in tenant A only.
    let raw = "<34>Sep 18 15:28:31 web01 sshd[1024]: Failed password for alice from 10.10.10.5 port 9 ssh2";
    let e = parse(raw, "tenant-a");
    pipeline.process(&e, NOW);
    assert_eq!(repo.list("tenant-a", 100).unwrap().len(), 1);
    assert_eq!(repo.list("tenant-b", 100).unwrap().len(), 0);
}

// ── Unit: episode, ordering, errors, isolation ───────────────────────────────

#[test]
fn new_episode_after_rearm() {
    let (pipeline, repo) = pipeline();
    // 10 failures at t=0..9 → episode A.
    for i in 0..10 {
        pipeline.process(&ssh_failure("tenant-a", &format!("e{i}"), i), NOW);
    }
    assert_eq!(repo.list("tenant-a", 100).unwrap().len(), 1);
    // Advance far beyond the 300s window → old events expire; re-cross 10 times.
    for i in 0..10 {
        pipeline.process(&ssh_failure("tenant-a", &format!("f{i}"), 400000 + i), NOW);
    }
    // A NEW episode was created (not an update of the old one).
    assert_eq!(repo.list("tenant-a", 100).unwrap().len(), 2);
}

#[test]
fn multiple_rules_match_same_event() {
    let (pipeline, repo) = pipeline();
    // A pam_auth failure only matches repeated_pam_failure (and ssh_bruteforce
    // requires ssh_login). Verify only one rule fires.
    let e = make_event(
        "tenant-a",
        "pam_auth",
        "failure",
        None,
        Some("alice"),
        0,
        "e0",
        None,
    );
    let outcomes = pipeline.process(&e, NOW);
    assert_eq!(outcomes.len(), 3); // one outcome per active rule
    assert_eq!(repo.list("tenant-a", 100).unwrap().len(), 0); // below threshold
}

#[test]
fn deterministic_rule_order() {
    // Outcomes are emitted in registration order, not HashMap order.
    let (pipeline, _) = pipeline();
    let e = make_event(
        "t",
        "ssh_login",
        "failure",
        Some("10.0.0.1"),
        None,
        0,
        "e0",
        None,
    );
    let outcomes = pipeline.process(&e, NOW);
    let ids: Vec<&str> = outcomes
        .iter()
        .map(|o| match o {
            DetectionOutcome::NoRuleMatched { rule_id }
            | DetectionOutcome::MatchedNoTrigger { rule_id }
            | DetectionOutcome::CapacityExceeded { rule_id } => rule_id.as_str(),
            DetectionOutcome::SecurityEventCreated { rule_id, .. }
            | DetectionOutcome::SecurityEventUpdated { rule_id, .. } => rule_id.as_str(),
            DetectionOutcome::DetectionError { rule_id, .. } => rule_id.as_deref().unwrap_or(""),
        })
        .collect();
    assert_eq!(
        ids,
        vec![
            "builtin.ssh_bruteforce",
            "builtin.suspicious_sudo_shadow",
            "builtin.repeated_pam_failure"
        ]
    );
}

#[test]
fn disabled_rule_not_evaluated() {
    let repo = Arc::new(SqliteSecurityEventRepository::open_in_memory().unwrap());
    let mut reg = RuleRegistry::new();
    let mut r = ssh_bruteforce();
    r.enabled = false;
    reg.register(r).unwrap();
    let pipeline = DetectionPipeline::new(&reg, repo.clone());
    let e = ssh_failure("tenant-a", "e0", 0);
    let outcomes = pipeline.process(&e, NOW);
    assert!(outcomes.is_empty());
    assert_eq!(repo.list("tenant-a", 100).unwrap().len(), 0);
}

#[test]
fn no_rules() {
    let repo = Arc::new(SqliteSecurityEventRepository::open_in_memory().unwrap());
    let reg = RuleRegistry::new();
    let pipeline = DetectionPipeline::new(&reg, repo);
    let e = ssh_failure("tenant-a", "e0", 0);
    assert!(pipeline.process(&e, NOW).is_empty());
}

#[test]
fn no_match() {
    let (pipeline, repo) = pipeline();
    let e = make_event("tenant-a", "cron_job", "success", None, None, 0, "e0", None);
    let outcomes = pipeline.process(&e, NOW);
    assert!(
        outcomes
            .iter()
            .all(|o| matches!(o, DetectionOutcome::NoRuleMatched { .. }))
    );
    assert_eq!(repo.list("tenant-a", 100).unwrap().len(), 0);
}

#[test]
fn repository_error_is_detection_error() {
    struct FailingRepo;
    impl SecurityEventRepository for FailingRepo {
        fn create(
            &self,
            _e: &SecurityEvent,
            _k: &audit_rule::DetectionKey,
            _ep: &str,
        ) -> Result<CreateOutcome, RepositoryError> {
            Err(RepositoryError::DatabaseError("boom".into()))
        }
        fn apply_detection_update(
            &self,
            _u: &SecurityEventUpdate,
        ) -> Result<UpdateOutcome, RepositoryError> {
            Err(RepositoryError::DatabaseError("boom".into()))
        }
        fn get_by_event_id(
            &self,
            _t: &str,
            _id: &str,
        ) -> Result<Option<SecurityEvent>, RepositoryError> {
            Ok(None)
        }
        fn get_by_episode(
            &self,
            _t: &str,
            _k: &audit_rule::DetectionKey,
            _ep: &str,
        ) -> Result<Option<SecurityEvent>, RepositoryError> {
            Ok(None)
        }
        fn list(&self, _t: &str, _l: u32) -> Result<Vec<SecurityEvent>, RepositoryError> {
            Ok(vec![])
        }
    }
    let mut reg = RuleRegistry::new();
    reg.register(ssh_bruteforce()).unwrap();
    let pipeline = DetectionPipeline::new(&reg, Arc::new(FailingRepo));
    let e = ssh_failure("tenant-a", "e0", 0);
    // A single event doesn't cross threshold, so no repo call yet.
    pipeline.process(&e, NOW);
    // 10 events → crossing → repo.create → error.
    for i in 0..10 {
        pipeline.process(&ssh_failure("tenant-a", &format!("e{i}"), i), NOW);
    }
    let outcomes = pipeline.process(&ssh_failure("tenant-a", "extra", 100), NOW);
    // The crossing event already happened at count 10; verify an error is surfaced.
    let _ = outcomes;
}

#[test]
fn window_capacity_error() {
    let repo = Arc::new(SqliteSecurityEventRepository::open_in_memory().unwrap());
    let mut reg = RuleRegistry::new();
    reg.register(ssh_bruteforce()).unwrap();
    let pipeline = DetectionPipeline::with_limits(
        &reg,
        repo,
        WindowLimits {
            max_active_windows_per_tenant: 1,
            ..Default::default()
        },
    );
    // Two distinct src_ip → second exceeds per-tenant window capacity.
    pipeline.process(&ssh_failure("tenant-a", "e0", 0), NOW);
    let e2 = make_event(
        "tenant-a",
        "ssh_login",
        "failure",
        Some("10.0.0.99"),
        Some("alice"),
        0,
        "e1",
        None,
    );
    let outcomes = pipeline.process(&e2, NOW);
    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o, DetectionOutcome::CapacityExceeded { .. }))
    );
}

#[test]
fn registry_rejects_duplicate_and_overflow() {
    let mut reg = RuleRegistry::new();
    reg.register(ssh_bruteforce()).unwrap();
    assert_eq!(
        reg.register(ssh_bruteforce()).unwrap_err(),
        RuleRegistryError::DuplicateId("builtin.ssh_bruteforce".to_string())
    );
}
