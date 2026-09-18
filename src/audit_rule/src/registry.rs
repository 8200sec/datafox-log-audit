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

use thiserror::Error;

use crate::rule::RuleDefinition;

/// Default upper bound on the number of active rules (guards against a bad
/// future config loading unbounded rules).
pub const MAX_ACTIVE_RULES: usize = 1000;

/// Registry of detection rules. Registration order is the deterministic
/// evaluation order — never HashMap iteration order.
#[derive(Debug, Default)]
pub struct RuleRegistry {
    rules: Vec<RuleDefinition>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RuleRegistryError {
    #[error("rule id already registered: {0}")]
    DuplicateId(String),
    #[error("active rule limit exceeded ({MAX_ACTIVE_RULES})")]
    TooManyRules,
}

impl RuleRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a rule. Rejects duplicate ids and rules beyond `MAX_ACTIVE_RULES`.
    pub fn register(&mut self, rule: RuleDefinition) -> Result<(), RuleRegistryError> {
        if self.rules.len() >= MAX_ACTIVE_RULES {
            return Err(RuleRegistryError::TooManyRules);
        }
        if self.rules.iter().any(|r| r.id == rule.id) {
            return Err(RuleRegistryError::DuplicateId(rule.id));
        }
        self.rules.push(rule);
        Ok(())
    }

    /// Look up a rule by id (enabled or disabled).
    pub fn get(&self, id: &str) -> Option<&RuleDefinition> {
        self.rules.iter().find(|r| r.id == id)
    }

    /// Enabled rules only, in deterministic registration order. Disabled rules
    /// never enter the hot evaluation path.
    pub fn active_rules(&self) -> impl Iterator<Item = &RuleDefinition> {
        self.rules.iter().filter(|r| r.enabled)
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}
