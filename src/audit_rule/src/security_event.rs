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

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Upper bound on the `related_event_ids` sample. The list is a bounded,
/// deduplicated sample of the events that triggered a security event — the full
/// count lives in `event_count`, never in this list.
pub const MAX_RELATED_EVENT_IDS: usize = 100;

/// Security event severity, decided by the detection rule. It is independent of
/// the source `AuditEvent.severity` — a rule may escalate a burst of low-severity
/// logs into a high-severity security event without mutating the source facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Security event lifecycle. v1 is deliberately simple — no custom states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Open,
    Acknowledged,
    Resolved,
    Closed,
}

impl Status {
    /// Whether `self → target` is a legal workflow transition. `closed` is
    /// terminal — nothing leaves it.
    pub fn can_transition_to(self, target: Status) -> bool {
        match self {
            Status::Open => matches!(
                target,
                Status::Acknowledged | Status::Resolved | Status::Closed
            ),
            Status::Acknowledged => matches!(target, Status::Resolved | Status::Closed),
            Status::Resolved => matches!(target, Status::Closed),
            Status::Closed => false,
        }
    }
}

/// High-level security event category. MITRE ATT&CK is intentionally NOT part of
/// the core schema — any ATT&CK metadata later lands in `evidence`/`attributes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Authentication,
    Privilege,
    Network,
    Malware,
    Policy,
    DataAccess,
    System,
    Other,
}

/// A detection result: a security event correlated from one or more `AuditEvent`s.
///
/// Lifecycle and immutability:
/// - Immutable after creation: `event_id`, `tenant_id`, `rule_id`, `created_at`.
/// - Mutable on aggregation: `last_seen`, `event_count`, `status`, `updated_at`, `evidence`,
///   `related_event_ids`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// System-generated unique id — never taken from the client, an AuditEvent,
    /// or a rule payload.
    pub event_id: String,
    /// Trusted server-side tenant. Must equal the triggering AuditEvent's tenant.
    pub tenant_id: String,
    pub rule_id: String,
    pub rule_version: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub category: Category,
    /// Stable machine-readable event type (e.g. `ssh_brute_force`).
    pub event_type: String,
    pub severity: Severity,
    pub status: Status,
    /// Epoch millis of the first correlated AuditEvent.
    pub first_seen: i64,
    /// Epoch millis of the most recent correlated AuditEvent.
    pub last_seen: i64,
    /// Total number of correlated AuditEvents (always >= 1).
    pub event_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<String>,
    /// Bounded, deduplicated sample of triggering AuditEvent ids.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related_event_ids: Vec<String>,
    /// Detection-rule trigger context; extensible, never a new top-level field.
    #[serde(default)]
    pub evidence: Value,
    /// Epoch millis the SecurityEvent was first generated (never changes).
    pub created_at: i64,
    /// Epoch millis of the last update.
    pub updated_at: i64,
}

/// Validation failure for a SecurityEvent.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecurityEventError {
    #[error("event_id must not be empty")]
    EmptyEventId,
    #[error("tenant_id must not be empty")]
    EmptyTenantId,
    #[error("rule_id must not be empty")]
    EmptyRuleId,
    #[error("rule_version must not be empty")]
    EmptyRuleVersion,
    #[error("title must not be empty")]
    EmptyTitle,
    #[error("event_count must be >= 1")]
    InvalidEventCount,
    #[error("first_seen must be <= last_seen")]
    InvalidTimeRange,
    #[error("created_at must be <= updated_at")]
    InvalidUpdateTime,
    #[error("related_event_ids must not exceed {MAX_RELATED_EVENT_IDS}")]
    TooManyRelatedEvents,
}

impl SecurityEvent {
    /// Validate the invariants a persisted SecurityEvent must satisfy.
    pub fn validate(&self) -> Result<(), SecurityEventError> {
        if self.event_id.trim().is_empty() {
            return Err(SecurityEventError::EmptyEventId);
        }
        if self.tenant_id.trim().is_empty() {
            return Err(SecurityEventError::EmptyTenantId);
        }
        if self.rule_id.trim().is_empty() {
            return Err(SecurityEventError::EmptyRuleId);
        }
        if self.rule_version.trim().is_empty() {
            return Err(SecurityEventError::EmptyRuleVersion);
        }
        if self.title.trim().is_empty() {
            return Err(SecurityEventError::EmptyTitle);
        }
        if self.event_count < 1 {
            return Err(SecurityEventError::InvalidEventCount);
        }
        if self.first_seen > self.last_seen {
            return Err(SecurityEventError::InvalidTimeRange);
        }
        if self.created_at > self.updated_at {
            return Err(SecurityEventError::InvalidUpdateTime);
        }
        if self.related_event_ids.len() > MAX_RELATED_EVENT_IDS {
            return Err(SecurityEventError::TooManyRelatedEvents);
        }
        Ok(())
    }

    /// Record one related AuditEvent. `event_count` grows by one per distinct
    /// triggering event; `related_event_ids` is a deduplicated sample capped at
    /// `MAX_RELATED_EVENT_IDS`. A duplicate id is a no-op (it is not a distinct
    /// new event). Beyond the cap the id is no longer stored, so dedup is
    /// best-effort for events that arrive after the sample is full — the rule
    /// engine should feed each triggering event exactly once.
    pub fn record_related_event(&mut self, event_id: String) {
        if event_id.trim().is_empty() {
            return;
        }
        if self.related_event_ids.contains(&event_id) {
            return;
        }
        self.event_count = self.event_count.saturating_add(1);
        if self.related_event_ids.len() < MAX_RELATED_EVENT_IDS {
            self.related_event_ids.push(event_id);
        }
    }
}
