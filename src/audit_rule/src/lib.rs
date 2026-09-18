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

//! DataFox audit detection & security-event schema (server-side).
//!
//! Pipeline boundary:
//!
//! ```text
//! raw log → audit_parser → AuditEvent → audit_rule → SecurityEvent
//! ```
//!
//! `audit_parser` standardizes raw logs into facts (`AuditEvent`); `audit_rule`
//! holds the rule definition DSL, the stateless rule evaluator, and the
//! SecurityEvent schema. Threshold window state / aggregation arrive in later
//! tasks.

mod condition;
mod evaluator;
mod resolve;
mod rule;
mod security_event;

pub use condition::{
    Condition, FieldPath, LeafCondition, MAX_CONDITION_DEPTH, Operator, STANDARD_FIELDS,
    is_valid_field_path,
};
pub use evaluator::{EvaluationError, EvaluationResult, RuleEvaluator, RuleMatch};
pub use resolve::{TypedValue, resolve_field};
pub use rule::{
    Aggregation, MAX_GROUP_BY_FIELDS, RuleDefinition, RuleDefinitionError, RuleSource, RuleType,
    is_semver,
};
pub use security_event::{
    Category, MAX_RELATED_EVENT_IDS, SecurityEvent, SecurityEventError, Severity, Status,
};
