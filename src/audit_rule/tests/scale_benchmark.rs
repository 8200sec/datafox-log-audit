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

use std::{path::PathBuf, time::Instant};

use audit_rule::{
    Category, DetectionKey, SecurityEvent, SecurityEventFilter, SecurityEventRepository,
    SecurityEventUpdate, Severity, SqliteSecurityEventRepository, Status,
};
use serde_json::json;

/// W3-10 milestone scale benchmark: 1k / 10k / 50k SecurityEvents against a
/// file-backed repository. Run with `cargo test --test scale_benchmark -- --ignored --nocapture`.
#[test]
#[ignore]
fn scale_benchmark() {
    let path = PathBuf::from("benchmark-scale.db");
    let _ = std::fs::remove_file(&path);
    let repo = SqliteSecurityEventRepository::open(&path).unwrap();

    for &n in &[1_000usize, 10_000, 50_000] {
        // Insert with a spread of status/severity/rule/last_seen.
        let mut insert_lat = Vec::with_capacity(n);
        for i in 0..n {
            let severity = [
                Severity::Critical,
                Severity::High,
                Severity::Medium,
                Severity::Low,
                Severity::Info,
            ][i % 5];
            let status = [
                Status::Open,
                Status::Acknowledged,
                Status::Resolved,
                Status::Closed,
            ][i % 4];
            let rule = [
                "builtin.ssh_bruteforce",
                "builtin.suspicious_sudo_shadow",
                "builtin.repeated_pam_failure",
            ][i % 3];
            let ev = SecurityEvent {
                event_id: format!("evt-{i}"),
                tenant_id: "bench".to_string(),
                rule_id: rule.to_string(),
                rule_version: "1.0.0".to_string(),
                title: format!("Event {i}"),
                description: None,
                category: Category::Authentication,
                event_type: "ssh_brute_force".to_string(),
                severity,
                status,
                first_seen: 1_000_000 + i as i64,
                last_seen: 1_000_000 + i as i64,
                event_count: 1,
                src_ip: Some(format!("10.0.{}.{}", i / 256, i % 256)),
                dst_ip: None,
                username: None,
                asset_id: None,
                related_event_ids: vec![format!("e{i}")],
                evidence: json!({"threshold": 10}),
                created_at: 1_000_000 + i as i64,
                updated_at: 1_000_000 + i as i64,
            };
            let key = DetectionKey {
                tenant_id: "bench".to_string(),
                rule_id: rule.to_string(),
                rule_version: "1.0.0".to_string(),
                group_values: format!("g={i}"),
            };
            let t = Instant::now();
            repo.create(&ev, &key, &format!("ep-{i}")).unwrap();
            insert_lat.push(t.elapsed().as_micros() as f64);
        }

        // Update all rows.
        let mut update_lat = Vec::with_capacity(n);
        for i in 0..n {
            let u = SecurityEventUpdate {
                detection_key: DetectionKey {
                    tenant_id: "bench".to_string(),
                    rule_id: [
                        "builtin.ssh_bruteforce",
                        "builtin.suspicious_sudo_shadow",
                        "builtin.repeated_pam_failure",
                    ][i % 3]
                        .to_string(),
                    rule_version: "1.0.0".to_string(),
                    group_values: format!("g={i}"),
                },
                episode_id: format!("ep-{i}"),
                last_seen: 2_000_000 + i as i64,
                event_count: 2,
                evidence: json!({}),
                related_event_ids: vec![format!("e{i}")],
                updated_at: 2_000_000 + i as i64,
            };
            let t = Instant::now();
            repo.apply_detection_update(&u).unwrap();
            update_lat.push(t.elapsed().as_micros() as f64);
        }

        // List page + filters + detail.
        let mut list_lat = Vec::new();
        let mut detail_lat = Vec::new();
        for page in 0..20 {
            let t = Instant::now();
            repo.list_filtered(
                "bench",
                &SecurityEventFilter {
                    limit: 50,
                    offset: page * 50,
                    ..Default::default()
                },
            )
            .unwrap();
            list_lat.push(t.elapsed().as_micros() as f64);
        }
        let status_t = Instant::now();
        repo.list_filtered(
            "bench",
            &SecurityEventFilter {
                status: Some(Status::Open),
                limit: 50,
                ..Default::default()
            },
        )
        .unwrap();
        let status_lat = status_t.elapsed().as_micros() as f64;
        let sev_t = Instant::now();
        repo.list_filtered(
            "bench",
            &SecurityEventFilter {
                severity: Some(Severity::Critical),
                limit: 50,
                ..Default::default()
            },
        )
        .unwrap();
        let sev_lat = sev_t.elapsed().as_micros() as f64;
        let rule_t = Instant::now();
        repo.list_filtered(
            "bench",
            &SecurityEventFilter {
                rule_id: Some("builtin.ssh_bruteforce".to_string()),
                limit: 50,
                ..Default::default()
            },
        )
        .unwrap();
        let rule_lat = rule_t.elapsed().as_micros() as f64;
        for i in 0..1000 {
            let t = Instant::now();
            repo.get_by_event_id("bench", &format!("evt-{}", i % n))
                .unwrap();
            detail_lat.push(t.elapsed().as_micros() as f64);
        }

        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let p = |v: &[f64]| {
            let mut s = v.to_vec();
            s.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let idx = |q: f64| s[((s.len() as f64 - 1.0) * q) as usize];
            (idx(0.50), idx(0.95))
        };
        let (ins_p50, ins_p95) = p(&insert_lat);
        let (upd_p50, upd_p95) = p(&update_lat);
        let (list_p50, list_p95) = p(&list_lat);
        let (det_p50, det_p95) = p(&detail_lat);
        println!("=== scale {n} ===");
        println!("  db_file_size_bytes: {size}");
        println!("  insert_p50_us: {ins_p50:.1}  p95_us: {ins_p95:.1}");
        println!("  update_p50_us: {upd_p50:.1}  p95_us: {upd_p95:.1}");
        println!("  list_p50_us: {list_p50:.1}  p95_us: {list_p95:.1}");
        println!("  detail_p50_us: {det_p50:.1}  p95_us: {det_p95:.1}");
        println!("  status_filter_us: {status_lat:.1}");
        println!("  severity_filter_us: {sev_lat:.1}");
        println!("  rule_filter_us: {rule_lat:.1}");
    }
    let _ = std::fs::remove_file(&path);
}
