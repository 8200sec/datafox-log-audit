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

/// Normalized severity (wire tokens, lowercase).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Normalized outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventResult {
    Success,
    Failure,
    Unknown,
}

/// High-level source category, never vendor-specific.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceType {
    Os,
    Firewall,
    Router,
    Database,
    Web,
    Application,
    Network,
    Other,
}

/// Trusted server-side tenant context.
#[derive(Debug, Clone, Default)]
pub struct TenantContext {
    pub tenant_id: String,
}

/// Optional transport metadata captured at the ingest edge.
#[derive(Debug, Clone, Default)]
pub struct TransportMetadata {
    pub protocol: Option<String>,
    pub remote_ip: Option<String>,
    pub remote_port: Option<u16>,
}

/// What the parser pipeline receives for one log line.
#[derive(Debug, Clone)]
pub struct RawLogInput {
    pub raw_log: String,
    /// Epoch ms — when the collector/edge received the line.
    pub received_at: i64,
    pub source_type: Option<String>,
    pub source_name: Option<String>,
    pub collector_id: Option<String>,
    pub tenant: TenantContext,
    pub transport: Option<TransportMetadata>,
}

/// A timestamp candidate extracted by a parser, resolved to epoch ms by the
/// Normalizer. Parsers extract the raw value; they never do the time parsing.
#[derive(Debug, Clone)]
pub enum Timestamp {
    /// Already epoch milliseconds (a parser that pre-computes it).
    EpochMillis(i64),
    /// Raw string candidate (ISO 8601 / RFC3339, or a numeric string).
    RawString(String),
    /// Raw numeric candidate (Unix seconds or milliseconds).
    RawNumber(f64),
}

/// Intermediate representation a parser emits (fields UNNORMALIZED).
#[derive(Debug, Clone, Default)]
pub struct ParsedEvent {
    pub parser_id: String,
    pub parser_version: String,
    pub raw_log: String,
    pub timestamp: Option<Timestamp>,
    pub severity: Option<String>,
    pub result: Option<String>,
    pub source_type: Option<String>,
    pub source_name: Option<String>,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub product_version: Option<String>,
    pub hostname: Option<String>,
    pub asset_id: Option<String>,
    pub src_ip: Option<String>,
    pub src_port: Option<String>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<String>,
    pub username: Option<String>,
    pub category: Option<String>,
    pub event_type: Option<String>,
    pub action: Option<String>,
    pub message: Option<String>,
    pub attributes: Option<serde_json::Value>,
}

/// Normalized audit event (AuditEvent v1) — the ingest/query contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    #[serde(rename = "_timestamp")]
    pub timestamp: i64,
    pub event_id: String,
    pub tenant_id: String,
    pub source_type: SourceType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collector_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<EventResult>,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub raw_log: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parser_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parser_version: Option<String>,
    pub ingest_timestamp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_attributes: Option<serde_json::Value>,
}

/// Result of dispatching one raw log: a valid event or a structured failure.
#[derive(Debug)]
pub enum DispatchResult {
    Ok(Box<AuditEvent>),
    Failure(crate::failure::ParseFailure),
}
