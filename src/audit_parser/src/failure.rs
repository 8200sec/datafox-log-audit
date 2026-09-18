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

/// Stable failure codes — keep in sync with the frontend contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailureCode {
    UnsupportedFormat,
    MissingRequiredField,
    InvalidTimestamp,
    InvalidIp,
    InvalidEnum,
    ParserException,
    NormalizationFailed,
}

impl FailureCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            FailureCode::UnsupportedFormat => "UNSUPPORTED_FORMAT",
            FailureCode::MissingRequiredField => "MISSING_REQUIRED_FIELD",
            FailureCode::InvalidTimestamp => "INVALID_TIMESTAMP",
            FailureCode::InvalidIp => "INVALID_IP",
            FailureCode::InvalidEnum => "INVALID_ENUM",
            FailureCode::ParserException => "PARSER_EXCEPTION",
            FailureCode::NormalizationFailed => "NORMALIZATION_FAILED",
        }
    }
}

/// Which phase the failure happened in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FailureStage {
    Detect,
    Parse,
    Normalize,
}

impl FailureStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            FailureStage::Detect => "detect",
            FailureStage::Parse => "parse",
            FailureStage::Normalize => "normalize",
        }
    }
}

/// Structured failure — a log that could not become an AuditEvent, never dropped.
#[derive(Debug, Clone, Serialize)]
pub struct ParseFailure {
    #[serde(rename = "_timestamp")]
    pub timestamp: i64,
    pub raw_log: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collector_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parser_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parser_version: Option<String>,
    pub failure_stage: FailureStage,
    pub failure_code: FailureCode,
    pub failure_message: String,
}
