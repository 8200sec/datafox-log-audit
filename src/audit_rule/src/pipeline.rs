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

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

use audit_parser::AuditEvent;
use serde::Serialize;

use crate::{
    builder::{DetectionKey, SecurityEventBuilder, SecurityEventMutation},
    evaluator::{EvaluationResult, RuleEvaluator, RuleMatch},
    registry::RuleRegistry,
    repository::{CreateOutcome, SecurityEventRepository, SecurityEventUpdate, UpdateOutcome},
    rule::{RuleDefinition, RuleType},
    window::{WindowLimits, WindowOutcome, WindowStateManager},
};

/// A structured, per-rule outcome of processing one AuditEvent.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DetectionOutcome {
    NoRuleMatched {
        rule_id: String,
    },
    MatchedNoTrigger {
        rule_id: String,
    },
    SecurityEventCreated {
        rule_id: String,
        event_id: String,
    },
    SecurityEventUpdated {
        rule_id: String,
        event_id: String,
    },
    DetectionError {
        rule_id: Option<String>,
        error_code: String,
    },
    CapacityExceeded {
        rule_id: String,
    },
}

/// Internal detection counters (lightweight in-process atomics).
#[derive(Debug, Default)]
pub struct PipelineStats {
    pub events_evaluated: AtomicU64,
    pub rules_evaluated: AtomicU64,
    pub rules_matched: AtomicU64,
    pub security_events_created: AtomicU64,
    pub security_events_updated: AtomicU64,
    pub detection_errors: AtomicU64,
    pub window_capacity_errors: AtomicU64,
}

/// A plain snapshot of `PipelineStats` for tests/observability.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PipelineStatsSnapshot {
    pub events_evaluated: u64,
    pub rules_evaluated: u64,
    pub rules_matched: u64,
    pub security_events_created: u64,
    pub security_events_updated: u64,
    pub detection_errors: u64,
    pub window_capacity_errors: u64,
}

/// Single in-process orchestrator: active rules → evaluate → route → build →
/// repository. It reuses the evaluator/window/builder/repository — never
/// re-implements their logic.
pub struct DetectionPipeline {
    rules: Vec<RuleDefinition>,
    window: Mutex<WindowStateManager>,
    builder: SecurityEventBuilder,
    repo: Arc<dyn SecurityEventRepository>,
    stats: PipelineStats,
}

impl DetectionPipeline {
    pub fn new(registry: &RuleRegistry, repo: Arc<dyn SecurityEventRepository>) -> Self {
        Self::with_limits(registry, repo, WindowLimits::default())
    }

    /// Build a pipeline with explicit window capacity limits (tests, tuning).
    pub fn with_limits(
        registry: &RuleRegistry,
        repo: Arc<dyn SecurityEventRepository>,
        limits: WindowLimits,
    ) -> Self {
        Self {
            rules: registry.active_rules().cloned().collect(),
            window: Mutex::new(WindowStateManager::with_limits(limits)),
            builder: SecurityEventBuilder,
            repo,
            stats: PipelineStats::default(),
        }
    }

    /// Process one AuditEvent against all active rules (deterministic order).
    pub fn process(&self, event: &AuditEvent, now: i64) -> Vec<DetectionOutcome> {
        self.stats.events_evaluated.fetch_add(1, Ordering::Relaxed);
        let mut outcomes = Vec::with_capacity(self.rules.len());
        for rule in &self.rules {
            self.stats.rules_evaluated.fetch_add(1, Ordering::Relaxed);
            outcomes.push(self.evaluate_rule(rule, event, now));
        }
        outcomes
    }

    pub fn stats(&self) -> PipelineStatsSnapshot {
        PipelineStatsSnapshot {
            events_evaluated: self.stats.events_evaluated.load(Ordering::Relaxed),
            rules_evaluated: self.stats.rules_evaluated.load(Ordering::Relaxed),
            rules_matched: self.stats.rules_matched.load(Ordering::Relaxed),
            security_events_created: self.stats.security_events_created.load(Ordering::Relaxed),
            security_events_updated: self.stats.security_events_updated.load(Ordering::Relaxed),
            detection_errors: self.stats.detection_errors.load(Ordering::Relaxed),
            window_capacity_errors: self.stats.window_capacity_errors.load(Ordering::Relaxed),
        }
    }

    fn evaluate_rule(
        &self,
        rule: &RuleDefinition,
        event: &AuditEvent,
        now: i64,
    ) -> DetectionOutcome {
        match RuleEvaluator.evaluate(rule, event) {
            EvaluationResult::NotMatched => DetectionOutcome::NoRuleMatched {
                rule_id: rule.id.clone(),
            },
            EvaluationResult::Error(_) => {
                self.stats.detection_errors.fetch_add(1, Ordering::Relaxed);
                DetectionOutcome::DetectionError {
                    rule_id: Some(rule.id.clone()),
                    error_code: "evaluation_error".to_string(),
                }
            }
            EvaluationResult::Matched(m) => {
                self.stats.rules_matched.fetch_add(1, Ordering::Relaxed);
                match rule.rule_type {
                    RuleType::Single => self.handle_single(rule, &m, now),
                    RuleType::Threshold => self.handle_threshold(rule, &m, now),
                }
            }
        }
    }

    fn handle_single(&self, rule: &RuleDefinition, m: &RuleMatch, now: i64) -> DetectionOutcome {
        match self.builder.build_single(rule, m, now) {
            Ok(SecurityEventMutation::Create {
                security_event,
                detection_key,
                episode_id,
            }) => self.apply_create(rule, &security_event, &detection_key, &episode_id),
            Ok(_) => unreachable!("single rule always builds a Create"),
            Err(_) => {
                self.stats.detection_errors.fetch_add(1, Ordering::Relaxed);
                DetectionOutcome::DetectionError {
                    rule_id: Some(rule.id.clone()),
                    error_code: "builder_error".to_string(),
                }
            }
        }
    }

    fn handle_threshold(&self, rule: &RuleDefinition, m: &RuleMatch, now: i64) -> DetectionOutcome {
        let mut window = self.window.lock().expect("window lock poisoned");
        match window.record(rule, m) {
            Ok(WindowOutcome::Recorded(eval)) => {
                match self.builder.build_threshold(rule, &eval, now) {
                    Ok(SecurityEventMutation::Create {
                        security_event,
                        detection_key,
                        episode_id,
                    }) => self.apply_create(rule, &security_event, &detection_key, &episode_id),
                    Ok(SecurityEventMutation::Update {
                        detection_key,
                        episode_id,
                        last_seen,
                        event_count,
                        evidence,
                        related_event_ids,
                        updated_at,
                    }) => self.apply_update(
                        rule,
                        &SecurityEventUpdate {
                            detection_key,
                            episode_id,
                            last_seen,
                            event_count,
                            evidence,
                            related_event_ids,
                            updated_at,
                        },
                    ),
                    Ok(SecurityEventMutation::NoOp) => DetectionOutcome::MatchedNoTrigger {
                        rule_id: rule.id.clone(),
                    },
                    Err(_) => {
                        self.stats.detection_errors.fetch_add(1, Ordering::Relaxed);
                        DetectionOutcome::DetectionError {
                            rule_id: Some(rule.id.clone()),
                            error_code: "builder_error".to_string(),
                        }
                    }
                }
            }
            Ok(WindowOutcome::Duplicate) | Ok(WindowOutcome::OutOfWindow) => {
                DetectionOutcome::MatchedNoTrigger {
                    rule_id: rule.id.clone(),
                }
            }
            Err(crate::window::WindowError::CapacityExceeded) => {
                self.stats
                    .window_capacity_errors
                    .fetch_add(1, Ordering::Relaxed);
                DetectionOutcome::CapacityExceeded {
                    rule_id: rule.id.clone(),
                }
            }
            Err(_) => {
                self.stats.detection_errors.fetch_add(1, Ordering::Relaxed);
                DetectionOutcome::DetectionError {
                    rule_id: Some(rule.id.clone()),
                    error_code: "window_error".to_string(),
                }
            }
        }
    }

    fn apply_create(
        &self,
        rule: &RuleDefinition,
        event: &crate::security_event::SecurityEvent,
        detection_key: &DetectionKey,
        episode_id: &str,
    ) -> DetectionOutcome {
        match self.repo.create(event, detection_key, episode_id) {
            Ok(CreateOutcome::Created { event_id })
            | Ok(CreateOutcome::AlreadyExists { event_id }) => {
                self.stats
                    .security_events_created
                    .fetch_add(1, Ordering::Relaxed);
                DetectionOutcome::SecurityEventCreated {
                    rule_id: rule.id.clone(),
                    event_id,
                }
            }
            Err(_) => {
                self.stats.detection_errors.fetch_add(1, Ordering::Relaxed);
                DetectionOutcome::DetectionError {
                    rule_id: Some(rule.id.clone()),
                    error_code: "repository_error".to_string(),
                }
            }
        }
    }

    fn apply_update(
        &self,
        rule: &RuleDefinition,
        update: &SecurityEventUpdate,
    ) -> DetectionOutcome {
        match self.repo.apply_detection_update(update) {
            Ok(UpdateOutcome::Updated { event_id }) => {
                self.stats
                    .security_events_updated
                    .fetch_add(1, Ordering::Relaxed);
                DetectionOutcome::SecurityEventUpdated {
                    rule_id: rule.id.clone(),
                    event_id,
                }
            }
            Ok(UpdateOutcome::NotFound) => DetectionOutcome::MatchedNoTrigger {
                rule_id: rule.id.clone(),
            },
            Err(_) => {
                self.stats.detection_errors.fetch_add(1, Ordering::Relaxed);
                DetectionOutcome::DetectionError {
                    rule_id: Some(rule.id.clone()),
                    error_code: "repository_error".to_string(),
                }
            }
        }
    }
}
