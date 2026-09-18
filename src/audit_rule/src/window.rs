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

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    evaluator::RuleMatch,
    rule::{Aggregation, RuleDefinition, RuleType},
};

/// Default global cap on active detection windows across all tenants.
pub const MAX_ACTIVE_WINDOWS_GLOBAL: usize = 100_000;
/// Default per-tenant cap on active detection windows (tenant fairness).
pub const MAX_ACTIVE_WINDOWS_PER_TENANT: usize = 10_000;
/// Default cap on entries held inside a single window (memory bound per window).
pub const MAX_EVENTS_PER_WINDOW: usize = 10_000;
/// Default cap on a single group value string (high-cardinality key protection).
pub const MAX_GROUP_VALUE_LENGTH: usize = 256;
/// Cap on the event-id sample exposed in a WindowEvaluation (same bound as the
/// SecurityEvent related-event sample).
pub const MAX_SAMPLE_EVENT_IDS: usize = crate::security_event::MAX_RELATED_EVENT_IDS;

/// Tunable window-state capacity bounds. Defaults come from the `MAX_*` consts;
/// tests (and future config) override them for smaller footprints.
#[derive(Debug, Clone, Copy)]
pub struct WindowLimits {
    pub max_active_windows_global: usize,
    pub max_active_windows_per_tenant: usize,
    pub max_events_per_window: usize,
    pub max_group_value_length: usize,
}

impl Default for WindowLimits {
    fn default() -> Self {
        Self {
            max_active_windows_global: MAX_ACTIVE_WINDOWS_GLOBAL,
            max_active_windows_per_tenant: MAX_ACTIVE_WINDOWS_PER_TENANT,
            max_events_per_window: MAX_EVENTS_PER_WINDOW,
            max_group_value_length: MAX_GROUP_VALUE_LENGTH,
        }
    }
}

/// A stable identity for one detection window: tenant + rule + version + the
/// canonicalized `group_by` values. Never just `rule_id` + group values — tenant
/// isolation and rule-version separation are load-bearing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WindowKey {
    pub tenant_id: String,
    pub rule_id: String,
    pub rule_version: String,
    /// Canonicalized group values, in `aggregation.group_by` declaration order.
    pub group_values: String,
}

/// Minimal state held for one in-window event. Never the full AuditEvent.
#[derive(Debug, Clone)]
pub struct WindowEntry {
    pub timestamp: i64,
    pub event_id: String,
}

/// The result of recording one event into a window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WindowEvaluation {
    pub tenant_id: String,
    pub rule_id: String,
    pub rule_version: String,
    pub group_values: Value,
    pub count: usize,
    pub first_seen: i64,
    pub last_seen: i64,
    pub threshold: u64,
    pub threshold_reached: bool,
    pub threshold_crossed: bool,
    pub sample_event_ids: Vec<String>,
}

/// Non-fatal outcome of recording an event (the event was not added).
#[derive(Debug, Clone, PartialEq)]
pub enum WindowOutcome {
    Recorded(WindowEvaluation),
    /// The event_id is already in the window (not re-counted).
    Duplicate,
    /// The event is older than the current window start (ignored).
    OutOfWindow,
}

/// Fatal window-state error. Never panics, never mutates AuditEvent, never
/// affects ingestion.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum WindowError {
    #[error("window capacity exceeded")]
    CapacityExceeded,
    #[error("not a threshold rule or missing aggregation")]
    InvalidWindow,
    #[error("invalid group key: a group_by value is missing")]
    InvalidGroupKey,
    #[error("group value exceeds the maximum length")]
    GroupValueTooLong,
    #[error("events per window exceeded")]
    MaxEventsPerWindow,
}

#[derive(Debug)]
struct WindowState {
    entries: Vec<WindowEntry>,
    window_seconds: i64,
    previous_reached: bool,
}

/// In-memory sliding-window state manager for `threshold` rules. Pure in-memory,
/// cleared on restart. Not internally synchronized — the caller holds a lock for
/// the (short) `record` call and does no IO inside it.
#[derive(Debug)]
pub struct WindowStateManager {
    windows: HashMap<WindowKey, WindowState>,
    tenant_windows: HashMap<String, usize>,
    limits: WindowLimits,
}

impl Default for WindowStateManager {
    fn default() -> Self {
        Self::with_limits(WindowLimits::default())
    }
}

impl WindowStateManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_limits(limits: WindowLimits) -> Self {
        Self {
            windows: HashMap::new(),
            tenant_windows: HashMap::new(),
            limits,
        }
    }

    /// Record one RuleMatch into the appropriate threshold window and return the
    /// resulting evaluation. `single` rules never enter this manager.
    pub fn record(
        &mut self,
        rule: &RuleDefinition,
        m: &RuleMatch,
    ) -> Result<WindowOutcome, WindowError> {
        if rule.rule_type != RuleType::Threshold {
            return Err(WindowError::InvalidWindow);
        }
        let agg = rule
            .aggregation
            .as_ref()
            .ok_or(WindowError::InvalidWindow)?;
        let window_seconds = agg.window_seconds as i64;
        let threshold = agg.threshold;

        let group_key =
            canonical_group_key(agg, &m.group_values, self.limits.max_group_value_length)?;
        let key = WindowKey {
            tenant_id: m.tenant_id.clone(),
            rule_id: m.rule_id.clone(),
            rule_version: m.rule_version.clone(),
            group_values: group_key,
        };
        let entry = WindowEntry {
            timestamp: m.matched_at,
            event_id: m.audit_event_id.clone(),
        };

        if !self.windows.contains_key(&key) {
            self.ensure_capacity(&key, entry.timestamp)?;
            self.windows.insert(
                key.clone(),
                WindowState {
                    entries: Vec::new(),
                    window_seconds,
                    previous_reached: false,
                },
            );
            *self
                .tenant_windows
                .entry(key.tenant_id.clone())
                .or_insert(0) += 1;
        }

        let state = self.windows.get_mut(&key).expect("window just inserted");
        // Out-of-window: the event predates the current window (anchored at the
        // latest seen event). Ignore it without disturbing the window.
        if let Some(latest) = state.entries.last()
            && entry.timestamp < latest.timestamp - window_seconds
        {
            return Ok(WindowOutcome::OutOfWindow);
        }
        // Sliding window: evict entries that fell out of the window.
        let window_start = entry.timestamp - window_seconds;
        state.entries.retain(|e| e.timestamp >= window_start);
        // Duplicate: same event_id already counted.
        if state.entries.iter().any(|e| e.event_id == entry.event_id) {
            return Ok(WindowOutcome::Duplicate);
        }
        if state.entries.len() >= self.limits.max_events_per_window {
            return Err(WindowError::MaxEventsPerWindow);
        }
        // Insert keeping ascending-timestamp order (bounded out-of-order).
        let pos = state
            .entries
            .partition_point(|e| e.timestamp <= entry.timestamp);
        state.entries.insert(pos, entry);

        let count = state.entries.len();
        let first_seen = state.entries.first().expect("non-empty").timestamp;
        let last_seen = state.entries.last().expect("non-empty").timestamp;
        let reached = (count as u64) >= threshold;
        let crossed = reached && !state.previous_reached;
        state.previous_reached = reached;

        let sample_event_ids = state
            .entries
            .iter()
            .take(MAX_SAMPLE_EVENT_IDS)
            .map(|e| e.event_id.clone())
            .collect();

        Ok(WindowOutcome::Recorded(WindowEvaluation {
            tenant_id: m.tenant_id.clone(),
            rule_id: m.rule_id.clone(),
            rule_version: m.rule_version.clone(),
            group_values: m.group_values.clone(),
            count,
            first_seen,
            last_seen,
            threshold,
            threshold_reached: reached,
            threshold_crossed: crossed,
            sample_event_ids,
        }))
    }

    /// Enforce per-tenant then global capacity. Expired windows are reclaimed
    /// first; active detection windows are never LRU-evicted.
    fn ensure_capacity(&mut self, key: &WindowKey, reference_time: i64) -> Result<(), WindowError> {
        let tenant_count = self
            .tenant_windows
            .get(&key.tenant_id)
            .copied()
            .unwrap_or(0);
        if tenant_count >= self.limits.max_active_windows_per_tenant {
            self.cleanup_expired(reference_time);
            let tenant_count = self
                .tenant_windows
                .get(&key.tenant_id)
                .copied()
                .unwrap_or(0);
            if tenant_count >= self.limits.max_active_windows_per_tenant {
                return Err(WindowError::CapacityExceeded);
            }
        }
        if self.windows.len() >= self.limits.max_active_windows_global {
            self.cleanup_expired(reference_time);
            if self.windows.len() >= self.limits.max_active_windows_global {
                return Err(WindowError::CapacityExceeded);
            }
        }
        Ok(())
    }

    /// Drop windows whose latest event predates their own window span (stale).
    fn cleanup_expired(&mut self, reference_time: i64) {
        let stale: Vec<WindowKey> = self
            .windows
            .iter()
            .filter(|(_, s)| {
                s.entries
                    .last()
                    .is_none_or(|e| e.timestamp < reference_time - s.window_seconds)
            })
            .map(|(k, _)| k.clone())
            .collect();
        for key in stale {
            self.windows.remove(&key);
            if let Some(c) = self.tenant_windows.get_mut(&key.tenant_id) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    self.tenant_windows.remove(&key.tenant_id);
                }
            }
        }
    }
}

/// Build the canonical group key in `aggregation.group_by` declaration order —
/// never HashMap iteration order.
fn canonical_group_key(
    agg: &Aggregation,
    group_values: &Value,
    max_len: usize,
) -> Result<String, WindowError> {
    let mut parts = Vec::new();
    for path in &agg.group_by {
        let field = path.as_str();
        let value = group_values
            .get(field)
            .ok_or(WindowError::InvalidGroupKey)?;
        let s = value_to_key_string(value);
        if s.len() > max_len {
            return Err(WindowError::GroupValueTooLong);
        }
        parts.push(format!("{field}={s}"));
    }
    Ok(parts.join(","))
}

fn value_to_key_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        Value::Array(_) | Value::Object(_) => v.to_string(),
    }
}
