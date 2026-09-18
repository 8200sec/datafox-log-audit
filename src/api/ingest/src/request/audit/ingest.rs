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

use std::sync::{Arc, OnceLock};

use audit_parser::{DispatchResult, Dispatcher, RawLogInput, TenantContext, default_dispatcher};
use audit_rule::{
    DetectionOutcome, DetectionPipeline, RuleRegistry, SecurityEventRepository,
    SqliteSecurityEventRepository, default_rules,
};
use axum::{
    Json,
    body::Bytes,
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use ingestion_common::{IngestUser, IngestionRequest};
use openobserve_api_common::extractors::Headers;
use openobserve_core::auth::UserEmail;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    common::meta::http::HttpResponse as MetaHttpResponse,
    service::{ingestion::get_thread_id, logs},
};

/// Single-event audit ingestion body (batch contract documented separately).
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AuditIngestRequest {
    pub source_type: Option<String>,
    pub source_name: Option<String>,
    pub collector_id: Option<String>,
    pub raw_log: String,
}

static DISPATCHER: OnceLock<Dispatcher> = OnceLock::new();

fn dispatcher() -> &'static Dispatcher {
    DISPATCHER.get_or_init(default_dispatcher)
}

static DETECTION_PIPELINE: OnceLock<DetectionPipeline> = OnceLock::new();

/// Shared embedded SQLite repository, opened lazily on first use. Both the
/// detection pipeline and the SecurityEvent API read/write through this single
/// instance so window state and workflow state agree.
pub(crate) fn repository() -> Arc<dyn SecurityEventRepository> {
    static REPOSITORY: OnceLock<Arc<dyn SecurityEventRepository>> = OnceLock::new();
    REPOSITORY
        .get_or_init(|| {
            let db_path =
                std::env::var("ZO_DATAFOX_DB").unwrap_or_else(|_| "datafox.db".to_string());
            Arc::new(
                SqliteSecurityEventRepository::open(std::path::Path::new(&db_path))
                    .unwrap_or_else(|e| panic!("failed to open datafox DB {db_path}: {e}")),
            )
        })
        .clone()
}

/// The shared detection pipeline (built-in rules + in-memory window state +
/// embedded SQLite repository). Initialized lazily on first audit ingest.
fn detection_pipeline() -> &'static DetectionPipeline {
    DETECTION_PIPELINE.get_or_init(|| {
        let repo = repository();
        let mut registry = RuleRegistry::new();
        for rule in default_rules() {
            if let Err(e) = registry.register(rule) {
                log::error!("failed to register built-in rule: {e}");
            }
        }
        DetectionPipeline::new(&registry, repo)
    })
}

/// Run detection on an already-ingested AuditEvent. Best-effort: a detection
/// error is logged, never rolls back the successful audit ingestion.
fn run_detection(event: &audit_parser::AuditEvent, now: i64) {
    let outcomes = detection_pipeline().process(event, now);
    for outcome in outcomes {
        match outcome {
            DetectionOutcome::SecurityEventCreated { rule_id, event_id } => {
                log::info!("security event created: rule={rule_id} event={event_id}");
            }
            DetectionOutcome::SecurityEventUpdated { rule_id, event_id } => {
                log::info!("security event updated: rule={rule_id} event={event_id}");
            }
            DetectionOutcome::CapacityExceeded { rule_id } => {
                log::warn!("detection window capacity exceeded: rule={rule_id}");
            }
            DetectionOutcome::DetectionError {
                rule_id,
                error_code,
            } => {
                log::error!("detection error: rule={rule_id:?} code={error_code}");
            }
            _ => {}
        }
    }
}

/// Audit log ingestion entry point: HTTP → Parser → Normalizer → OpenObserve
/// ingestion. The tenant comes from the authenticated `org_id` path — never the
/// body. Failures are written to `audit_parse_failures`, never silently dropped.
#[utoipa::path(
    post,
    path = "/{org_id}/audit/ingest",
    context_path = "/api",
    tag = "Audit",
    operation_id = "AuditIngest",
    summary = "Ingest a raw audit log line",
    security(
        ("Authorization" = [])
    ),
    params(
        ("org_id" = String, Path, description = "Organization / tenant name"),
    ),
    request_body(content = AuditIngestRequest, description = "Raw audit log line"),
    responses(
        (status = 200, description = "Success", content_type = "application/json", body = Object),
        (status = 400, description = "Bad request", content_type = "application/json", body = ()),
        (status = 500, description = "Internal error", content_type = "application/json", body = ()),
    ),
    extensions(
        ("x-o2-mcp" = json!({"enabled": false}))
    )
)]
pub async fn ingest(
    Path(org_id): Path<String>,
    Headers(user_email): Headers<UserEmail>,
    Json(body): Json<AuditIngestRequest>,
) -> Response {
    let now = Utc::now().timestamp_millis();
    let input = RawLogInput {
        raw_log: body.raw_log,
        received_at: now,
        source_type: body.source_type,
        source_name: body.source_name,
        collector_id: body.collector_id,
        tenant: TenantContext {
            tenant_id: org_id.clone(),
        },
        transport: None,
    };

    match dispatcher().dispatch(&input, now) {
        DispatchResult::Ok(event) => {
            let value = match serde_json::to_value(&*event) {
                Ok(v) => v,
                Err(e) => return server_error(&org_id, "audit_events", &e.to_string()),
            };
            let (response, success) =
                ingest_values(&org_id, "audit_events", vec![value], user_email).await;
            // Detection runs only after the AuditEvent is durably ingested; it
            // never rolls back a successful ingestion.
            if success {
                run_detection(&event, now);
            }
            response
        }
        DispatchResult::Failure(failure) => {
            let value = match serde_json::to_value(&failure) {
                Ok(v) => v,
                Err(e) => return server_error(&org_id, "audit_parse_failures", &e.to_string()),
            };
            ingest_values(&org_id, "audit_parse_failures", vec![value], user_email)
                .await
                .0
        }
    }
}

/// Serialize records into the `_json` ingestion request. `IngestionRequest::JSON`
/// maps to `UsageType::Json`, so the response carries `successful`/`failed` via
/// `RecordStatus` — unlike `JsonValues(Bulk, …)`, which reports the ES bulk
/// `items` and would leave the count at 0.
fn build_ingestion_request(
    values: &[serde_json::Value],
) -> Result<IngestionRequest, serde_json::Error> {
    Ok(IngestionRequest::JSON(Bytes::from(serde_json::to_vec(
        values,
    )?)))
}

async fn ingest_values(
    org_id: &str,
    stream: &str,
    values: Vec<serde_json::Value>,
    user_email: UserEmail,
) -> (Response, bool) {
    let request = match build_ingestion_request(&values) {
        Ok(r) => r,
        Err(e) => return (server_error(org_id, stream, &e.to_string()), false),
    };
    let thread_id = get_thread_id();
    match logs::ingest::ingest(
        thread_id,
        org_id,
        stream,
        request,
        IngestUser::from_user_email(user_email.user_id),
        None,
        false,
    )
    .await
    {
        Ok(v) => {
            let success = !v.status.iter().any(|s| s.status.failed > 0);
            let response = match v.code {
                503 => (StatusCode::SERVICE_UNAVAILABLE, Json(v)).into_response(),
                _ => MetaHttpResponse::json(v),
            };
            (response, success)
        }
        Err(e) => (server_error(org_id, stream, &e.to_string()), false),
    }
}

/// A failed write is a hard server error — never swallowed.
fn server_error(org_id: &str, stream: &str, message: &str) -> Response {
    log::error!("audit ingest error for {org_id}/{stream}: {message}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(MetaHttpResponse::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            message.to_string(),
        )),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_json_request_not_bulk() {
        // The count contract (successful=1 on accept) depends on the JSON path,
        // not the ES-bulk path whose `items` report a 0 successful count.
        let req = build_ingestion_request(&[serde_json::json!({"_timestamp": 1})]).unwrap();
        assert!(matches!(req, IngestionRequest::JSON(_)));
    }

    #[test]
    fn deserializes_single_event_request() {
        let body: AuditIngestRequest = serde_json::from_str(
            r#"{"source_type":"firewall","source_name":"edge","collector_id":"syslog","raw_log":"<134>x"}"#,
        )
        .unwrap();
        assert_eq!(body.source_type.as_deref(), Some("firewall"));
        assert_eq!(body.raw_log, "<134>x");
    }
}
