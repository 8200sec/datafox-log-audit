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

use std::time::Instant;

use audit_rule::{
    Category, DetectionKey, SecurityEvent, SecurityEventRepository, SecurityEventUpdate, Severity,
    SqliteSecurityEventRepository, Status,
};
use serde_json::json;

/// Lightweight smoke benchmark (ignored by default): records insert/update
/// throughput for the embedded SQLite store. Run with `--ignored`.
#[test]
#[ignore]
fn perf_smoke() {
    let repo = SqliteSecurityEventRepository::open_in_memory().unwrap();
    let n = 10000;
    let mk = |i: usize| SecurityEvent {
        event_id: format!("evt-{i}"),
        tenant_id: "t".to_string(),
        rule_id: "r".to_string(),
        rule_version: "1.0.0".to_string(),
        title: "x".to_string(),
        description: None,
        category: Category::Authentication,
        event_type: "e".to_string(),
        severity: Severity::High,
        status: Status::Open,
        first_seen: 1000,
        last_seen: 1000,
        event_count: 1,
        src_ip: None,
        dst_ip: None,
        username: None,
        asset_id: None,
        related_event_ids: vec![format!("e{i}")],
        evidence: json!({}),
        created_at: 1000,
        updated_at: 1000,
    };
    let key = DetectionKey {
        tenant_id: "t".to_string(),
        rule_id: "r".to_string(),
        rule_version: "1.0.0".to_string(),
        group_values: "g=1".to_string(),
    };
    let t0 = Instant::now();
    for i in 0..n {
        repo.create(&mk(i), &key, &format!("ep-{i}")).unwrap();
    }
    let t_insert = t0.elapsed();
    let t1 = Instant::now();
    for i in 0..n {
        let u = SecurityEventUpdate {
            detection_key: key.clone(),
            episode_id: format!("ep-{i}"),
            last_seen: 2000,
            event_count: 2,
            evidence: json!({}),
            related_event_ids: vec![format!("e{i}")],
            updated_at: 2000,
        };
        repo.apply_detection_update(&u).unwrap();
    }
    let t_update = t1.elapsed();
    eprintln!("insert 10000 events: {t_insert:?}");
    eprintln!("update 10000 events: {t_update:?}");
}
