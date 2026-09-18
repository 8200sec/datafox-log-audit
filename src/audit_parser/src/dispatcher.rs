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

use crate::{
    failure::{FailureCode, FailureStage, ParseFailure},
    normalizer::Normalizer,
    registry::ParserRegistry,
    types::{DispatchResult, RawLogInput},
};

/// Orchestrates detect → parse → normalize for one raw log. Never panics: a
/// parser error, a normalization failure, or a total miss all resolve to a
/// structured `ParseFailure` — a log is never silently dropped.
pub struct Dispatcher {
    registry: ParserRegistry,
    normalizer: Normalizer,
}

impl Dispatcher {
    pub fn new(registry: ParserRegistry, normalizer: Normalizer) -> Self {
        Self {
            registry,
            normalizer,
        }
    }

    pub fn dispatch(&self, input: &RawLogInput, now: i64) -> DispatchResult {
        let matched = self.registry.detect(input);

        let mut last_err: Option<String> = None;
        for parser in &matched {
            match parser.parse(input) {
                Ok(parsed) => match self.normalizer.normalize(&parsed, input, now) {
                    Ok(event) => return DispatchResult::Ok(Box::new(event)),
                    Err(failure) => return DispatchResult::Failure(failure),
                },
                Err(err) => last_err = Some(err.to_string()),
            }
        }
        if let Some(msg) = last_err {
            let parser = matched.last();
            return DispatchResult::Failure(self.failure(
                input,
                parser.map(|p| p.id()),
                parser.map(|p| p.version()),
                FailureStage::Parse,
                FailureCode::ParserException,
                &msg,
            ));
        }

        if let Some(fallback) = self.registry.fallback() {
            match fallback.parse(input) {
                Ok(parsed) => match self.normalizer.normalize(&parsed, input, now) {
                    Ok(event) => return DispatchResult::Ok(Box::new(event)),
                    Err(failure) => return DispatchResult::Failure(failure),
                },
                Err(err) => {
                    return DispatchResult::Failure(self.failure(
                        input,
                        Some(fallback.id()),
                        Some(fallback.version()),
                        FailureStage::Parse,
                        FailureCode::ParserException,
                        &err.to_string(),
                    ));
                }
            }
        }

        DispatchResult::Failure(self.failure(
            input,
            None,
            None,
            FailureStage::Detect,
            FailureCode::UnsupportedFormat,
            "no parser matched and no fallback configured",
        ))
    }

    fn failure(
        &self,
        input: &RawLogInput,
        parser_id: Option<&str>,
        parser_version: Option<&str>,
        stage: FailureStage,
        code: FailureCode,
        message: &str,
    ) -> ParseFailure {
        ParseFailure {
            timestamp: input.received_at,
            raw_log: input.raw_log.clone(),
            source_type: input.source_type.clone(),
            source_name: input.source_name.clone(),
            collector_id: input.collector_id.clone(),
            parser_id: parser_id.map(|s| s.to_string()),
            parser_version: parser_version.map(|s| s.to_string()),
            failure_stage: stage,
            failure_code: code,
            failure_message: message.to_string(),
        }
    }
}
