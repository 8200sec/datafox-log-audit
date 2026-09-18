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

use serde::Serialize;
use serde_json::{Value, json};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    evaluator::RuleMatch,
    rule::{Aggregation, RuleDefinition, RuleType},
    security_event::{SecurityEvent, Status},
    window::{MAX_GROUP_VALUE_LENGTH, WindowEvaluation, canonical_group_key},
};

/// Stable detection identity: tenant + rule + version + canonical group values.
/// The correlation key a repository uses to find/update an existing episode.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct DetectionKey {
    pub tenant_id: String,
    pub rule_id: String,
    pub rule_version: String,
    /// Canonical group values (empty for a `single` rule).
    pub group_values: String,
}

/// The mutation a stateless builder produces. No IO, no lookup — the repository
/// (W3-07F) resolves `detection_key` + `episode_id` to an existing event.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SecurityEventMutation {
    Create {
        security_event: Box<SecurityEvent>,
        detection_key: DetectionKey,
        episode_id: String,
    },
    Update {
        detection_key: DetectionKey,
        episode_id: String,
        last_seen: i64,
        event_count: u64,
        evidence: Value,
        related_event_ids: Vec<String>,
        updated_at: i64,
    },
    NoOp,
}

/// Builder failure (malformed input). Never panics.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum BuilderError {
    #[error("rule type does not match the input")]
    RuleTypeMismatch,
    #[error("threshold evaluation is missing an episode timestamp")]
    MissingEpisode,
    #[error("invalid group key")]
    InvalidGroupKey,
}

/// Stateless SecurityEvent builder. Holds no state, caches nothing, does no IO,
/// and never generates a SecurityEvent id from the client / AuditEvent / rule.
#[derive(Debug, Clone, Copy, Default)]
pub struct SecurityEventBuilder;

impl SecurityEventBuilder {
    /// Build a mutation for a `single` rule match: every match is a new,
    /// independent SecurityEvent (episode id = the AuditEvent id).
    pub fn build_single(
        &self,
        rule: &RuleDefinition,
        m: &RuleMatch,
        now: i64,
    ) -> Result<SecurityEventMutation, BuilderError> {
        if rule.rule_type != RuleType::Single {
            return Err(BuilderError::RuleTypeMismatch);
        }
        let detection_key = DetectionKey {
            tenant_id: m.tenant_id.clone(),
            rule_id: m.rule_id.clone(),
            rule_version: m.rule_version.clone(),
            group_values: String::new(),
        };
        let episode_id = m.audit_event_id.clone();

        let security_event = SecurityEvent {
            event_id: Uuid::now_v7().to_string(),
            tenant_id: m.tenant_id.clone(),
            rule_id: rule.id.clone(),
            rule_version: rule.version.clone(),
            title: rule.title.clone(),
            description: rule.description.clone(),
            category: rule.category,
            event_type: rule.event_type.clone(),
            severity: rule.severity,
            status: Status::Open,
            first_seen: m.matched_at,
            last_seen: m.matched_at,
            event_count: 1,
            src_ip: None,
            dst_ip: None,
            username: None,
            asset_id: None,
            related_event_ids: vec![m.audit_event_id.clone()],
            evidence: single_evidence(m),
            created_at: now,
            updated_at: now,
        };

        Ok(SecurityEventMutation::Create {
            security_event: Box::new(security_event),
            detection_key,
            episode_id,
        })
    }

    /// Build a mutation for a `threshold` window evaluation:
    /// - not reached → `NoOp`
    /// - crossing (rising edge) → `Create` (a new episode)
    /// - reached but not crossing → `Update` (same episode)
    pub fn build_threshold(
        &self,
        rule: &RuleDefinition,
        eval: &WindowEvaluation,
        now: i64,
    ) -> Result<SecurityEventMutation, BuilderError> {
        if rule.rule_type != RuleType::Threshold {
            return Err(BuilderError::RuleTypeMismatch);
        }
        let agg = rule
            .aggregation
            .as_ref()
            .ok_or(BuilderError::RuleTypeMismatch)?;

        if !eval.threshold_reached {
            return Ok(SecurityEventMutation::NoOp);
        }

        let detection_key = DetectionKey {
            tenant_id: eval.tenant_id.clone(),
            rule_id: eval.rule_id.clone(),
            rule_version: eval.rule_version.clone(),
            group_values: canonical_group_key(agg, &eval.group_values, MAX_GROUP_VALUE_LENGTH)
                .map_err(|_| BuilderError::InvalidGroupKey)?,
        };
        // The episode id is the crossing timestamp — stable within an episode,
        // distinct across episodes.
        let episode_id = eval
            .episode_started_at
            .ok_or(BuilderError::MissingEpisode)?
            .to_string();

        if !eval.threshold_crossed {
            return Ok(SecurityEventMutation::Update {
                detection_key,
                episode_id,
                last_seen: eval.last_seen,
                event_count: eval.count as u64,
                evidence: threshold_evidence(agg, eval),
                related_event_ids: eval.sample_event_ids.clone(),
                updated_at: now,
            });
        }

        let security_event = SecurityEvent {
            event_id: Uuid::now_v7().to_string(),
            tenant_id: eval.tenant_id.clone(),
            rule_id: rule.id.clone(),
            rule_version: rule.version.clone(),
            title: rule.title.clone(),
            description: rule.description.clone(),
            category: rule.category,
            event_type: rule.event_type.clone(),
            severity: rule.severity,
            status: Status::Open,
            first_seen: eval.first_seen,
            last_seen: eval.last_seen,
            event_count: eval.count as u64,
            src_ip: extract_string(&eval.group_values, "src_ip"),
            dst_ip: extract_string(&eval.group_values, "dst_ip"),
            username: extract_string(&eval.group_values, "username"),
            asset_id: extract_string(&eval.group_values, "asset_id"),
            related_event_ids: eval.sample_event_ids.clone(),
            evidence: threshold_evidence(agg, eval),
            created_at: now,
            updated_at: now,
        };

        Ok(SecurityEventMutation::Create {
            security_event: Box::new(security_event),
            detection_key,
            episode_id,
        })
    }
}

fn single_evidence(m: &RuleMatch) -> Value {
    json!({
        "rule_type": "single",
        "matched_event_id": m.audit_event_id,
        "matched_fields": m.evidence.get("matched_fields").cloned().unwrap_or_else(|| json!([])),
    })
}

fn threshold_evidence(agg: &Aggregation, eval: &WindowEvaluation) -> Value {
    json!({
        "rule_type": "threshold",
        "threshold": eval.threshold,
        "window_seconds": agg.window_seconds,
        "group_by": agg.group_by.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
        "group_values": eval.group_values,
        "current_count": eval.count,
        "first_seen": eval.first_seen,
        "last_seen": eval.last_seen,
    })
}

fn extract_string(group_values: &Value, key: &str) -> Option<String> {
    group_values
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
}
