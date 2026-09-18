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

//! DataFox audit-log Parser + Normalization framework (server-side runtime).
//!
//! This crate is the ONLY place real log parsing happens. The frontend never
//! runs a parser — it only consumes the resulting `AuditEvent` contract.

mod dispatcher;
mod failure;
mod normalizer;
mod parser;
mod parsers;
mod registry;
mod types;

pub use dispatcher::Dispatcher;
pub use failure::{FailureCode, FailureStage, ParseFailure};
pub use normalizer::Normalizer;
pub use parser::Parser;
pub use parsers::{DummyParser, FallbackParser};
pub use registry::ParserRegistry;
pub use types::{
    AuditEvent, DispatchResult, EventResult, ParsedEvent, RawLogInput, Severity, SourceType,
    TenantContext, TransportMetadata,
};
