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

use audit_rule::{
    ListPage, RepositoryError, SecurityEvent, SecurityEventAction, SecurityEventFilter,
    SecurityEventRepository, Severity, SortOrder, Status, TransitionOutcome,
};
use axum::{
    Json,
    extract::{Path, Query},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use openobserve_api_common::extractors::Headers;
use openobserve_core::auth::UserEmail;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::ingest::repository;
use crate::common::meta::http::HttpResponse as MetaHttpResponse;

/// Default page size when the client omits `limit`.
pub const DEFAULT_LIMIT: u32 = 50;
/// Hard ceiling on `limit` — larger values are clamped.
pub const MAX_LIMIT: u32 = 200;
/// Upper bound on a workflow comment; keeps audit-trail rows bounded.
const MAX_COMMENT_LENGTH: usize = 4000;

#[derive(Debug, Deserialize, Default)]
pub struct ListParams {
    pub status: Option<Status>,
    pub severity: Option<Severity>,
    pub rule_id: Option<String>,
    pub event_type: Option<String>,
    pub src_ip: Option<String>,
    pub username: Option<String>,
    pub last_seen_from: Option<i64>,
    pub last_seen_to: Option<i64>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub sort: Option<SortOrder>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TransitionRequest {
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListResponse {
    pub items: Vec<SecurityEvent>,
    pub total: u64,
    pub limit: u32,
    pub offset: u32,
}

#[derive(Debug)]
enum ServiceError {
    NotFound,
    Conflict,
    Invalid(String),
    Internal(String),
}

struct SecurityEventService {
    repo: Arc<dyn SecurityEventRepository>,
}

impl SecurityEventService {
    fn new(repo: Arc<dyn SecurityEventRepository>) -> Self {
        Self { repo }
    }

    fn list(&self, tenant_id: &str, params: ListParams) -> Result<ListResponse, ServiceError> {
        let limit = params.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
        let offset = params.offset.unwrap_or(0);
        let filter = SecurityEventFilter {
            status: params.status,
            severity: params.severity,
            rule_id: params.rule_id,
            event_type: params.event_type,
            src_ip: params.src_ip,
            username: params.username,
            last_seen_from: params.last_seen_from,
            last_seen_to: params.last_seen_to,
            limit,
            offset,
            sort: params.sort.unwrap_or_default(),
        };
        let ListPage { items, total } = self
            .repo
            .list_filtered(tenant_id, &filter)
            .map_err(internal)?;
        Ok(ListResponse {
            items,
            total,
            limit,
            offset,
        })
    }

    fn get(&self, tenant_id: &str, event_id: &str) -> Result<SecurityEvent, ServiceError> {
        self.repo
            .get_by_event_id(tenant_id, event_id)
            .map_err(internal)?
            .ok_or(ServiceError::NotFound)
    }

    fn transition(
        &self,
        tenant_id: &str,
        event_id: &str,
        to: Status,
        actor_id: &str,
        comment: Option<&str>,
        now: i64,
    ) -> Result<SecurityEvent, ServiceError> {
        if let Some(c) = comment
            && c.len() > MAX_COMMENT_LENGTH
        {
            return Err(ServiceError::Invalid(format!(
                "comment exceeds {MAX_COMMENT_LENGTH} characters"
            )));
        }
        match self
            .repo
            .transition_status(tenant_id, event_id, to, actor_id, comment, now)
            .map_err(internal)?
        {
            TransitionOutcome::Transitioned { .. } => self.get(tenant_id, event_id),
            TransitionOutcome::NotFound => Err(ServiceError::NotFound),
            TransitionOutcome::Conflict => Err(ServiceError::Conflict),
        }
    }

    fn actions(
        &self,
        tenant_id: &str,
        event_id: &str,
    ) -> Result<Vec<SecurityEventAction>, ServiceError> {
        // A missing event is indistinguishable from an empty history in
        // `list_actions`, so confirm existence first for a clean 404.
        self.get(tenant_id, event_id)?;
        self.repo
            .list_actions(tenant_id, event_id)
            .map_err(internal)
    }
}

static SERVICE: OnceLock<SecurityEventService> = OnceLock::new();

fn service() -> &'static SecurityEventService {
    SERVICE.get_or_init(|| SecurityEventService::new(repository()))
}

fn internal(e: RepositoryError) -> ServiceError {
    ServiceError::Internal(e.to_string())
}

fn error_response(err: ServiceError) -> Response {
    match err {
        ServiceError::NotFound => {
            MetaHttpResponse::error(StatusCode::NOT_FOUND, "security event not found")
                .into_response()
        }
        ServiceError::Conflict => {
            MetaHttpResponse::error(StatusCode::CONFLICT, "illegal status transition")
                .into_response()
        }
        ServiceError::Invalid(m) => {
            MetaHttpResponse::error(StatusCode::BAD_REQUEST, m).into_response()
        }
        ServiceError::Internal(m) => {
            log::error!("security event API error: {m}");
            MetaHttpResponse::error(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                .into_response()
        }
    }
}

#[utoipa::path(
    get,
    path = "/{org_id}/security-events",
    context_path = "/api",
    tag = "SecurityEvents",
    operation_id = "ListSecurityEvents",
    summary = "List security events for an organization",
    security(
        ("Authorization" = [])
    ),
    params(
        ("org_id" = String, Path, description = "Organization / tenant name"),
        ("status" = Option<String>, Query, description = "Filter by status"),
        ("severity" = Option<String>, Query, description = "Filter by severity"),
        ("limit" = Option<u32>, Query, description = "Page size (default 50, max 200)"),
        ("offset" = Option<u32>, Query, description = "Page offset"),
        ("sort" = Option<String>, Query, description = "asc or desc (default desc)"),
    ),
    responses(
        (status = 200, description = "Success", content_type = "application/json", body = Object),
        (status = 500, description = "Internal error", content_type = "application/json", body = ()),
    ),
    extensions(
        ("x-o2-mcp" = json!({"enabled": false}))
    )
)]
pub async fn list(
    Path(org_id): Path<String>,
    Headers(_user_email): Headers<UserEmail>,
    Query(params): Query<ListParams>,
) -> Response {
    match service().list(&org_id, params) {
        Ok(page) => MetaHttpResponse::json(page),
        Err(e) => error_response(e),
    }
}

#[utoipa::path(
    get,
    path = "/{org_id}/security-events/{event_id}",
    context_path = "/api",
    tag = "SecurityEvents",
    operation_id = "GetSecurityEvent",
    summary = "Get a single security event",
    security(
        ("Authorization" = [])
    ),
    params(
        ("org_id" = String, Path, description = "Organization / tenant name"),
        ("event_id" = String, Path, description = "Security event id"),
    ),
    responses(
        (status = 200, description = "Success", content_type = "application/json", body = Object),
        (status = 404, description = "Not found", content_type = "application/json", body = ()),
    ),
    extensions(
        ("x-o2-mcp" = json!({"enabled": false}))
    )
)]
pub async fn detail(
    Path((org_id, event_id)): Path<(String, String)>,
    Headers(_user_email): Headers<UserEmail>,
) -> Response {
    match service().get(&org_id, &event_id) {
        Ok(event) => MetaHttpResponse::json(event),
        Err(e) => error_response(e),
    }
}

#[utoipa::path(
    get,
    path = "/{org_id}/security-events/{event_id}/actions",
    context_path = "/api",
    tag = "SecurityEvents",
    operation_id = "ListSecurityEventActions",
    summary = "List workflow actions for a security event",
    security(
        ("Authorization" = [])
    ),
    params(
        ("org_id" = String, Path, description = "Organization / tenant name"),
        ("event_id" = String, Path, description = "Security event id"),
    ),
    responses(
        (status = 200, description = "Success", content_type = "application/json", body = Object),
        (status = 404, description = "Not found", content_type = "application/json", body = ()),
    ),
    extensions(
        ("x-o2-mcp" = json!({"enabled": false}))
    )
)]
pub async fn actions(
    Path((org_id, event_id)): Path<(String, String)>,
    Headers(_user_email): Headers<UserEmail>,
) -> Response {
    match service().actions(&org_id, &event_id) {
        Ok(actions) => MetaHttpResponse::json(actions),
        Err(e) => error_response(e),
    }
}

#[utoipa::path(
    post,
    path = "/{org_id}/security-events/{event_id}/acknowledge",
    context_path = "/api",
    tag = "SecurityEvents",
    operation_id = "AcknowledgeSecurityEvent",
    summary = "Acknowledge an open security event",
    security(
        ("Authorization" = [])
    ),
    params(
        ("org_id" = String, Path, description = "Organization / tenant name"),
        ("event_id" = String, Path, description = "Security event id"),
    ),
    request_body(content = TransitionRequest, description = "Optional workflow comment"),
    responses(
        (status = 200, description = "Success", content_type = "application/json", body = Object),
        (status = 404, description = "Not found", content_type = "application/json", body = ()),
        (status = 409, description = "Illegal transition", content_type = "application/json", body = ()),
    ),
    extensions(
        ("x-o2-mcp" = json!({"enabled": false}))
    )
)]
pub async fn acknowledge(
    Path((org_id, event_id)): Path<(String, String)>,
    Headers(user_email): Headers<UserEmail>,
    Json(body): Json<TransitionRequest>,
) -> Response {
    transition(
        &org_id,
        &event_id,
        Status::Acknowledged,
        &user_email.user_id,
        body.comment.as_deref(),
    )
}

#[utoipa::path(
    post,
    path = "/{org_id}/security-events/{event_id}/resolve",
    context_path = "/api",
    tag = "SecurityEvents",
    operation_id = "ResolveSecurityEvent",
    summary = "Resolve a security event",
    security(
        ("Authorization" = [])
    ),
    params(
        ("org_id" = String, Path, description = "Organization / tenant name"),
        ("event_id" = String, Path, description = "Security event id"),
    ),
    request_body(content = TransitionRequest, description = "Optional workflow comment"),
    responses(
        (status = 200, description = "Success", content_type = "application/json", body = Object),
        (status = 404, description = "Not found", content_type = "application/json", body = ()),
        (status = 409, description = "Illegal transition", content_type = "application/json", body = ()),
    ),
    extensions(
        ("x-o2-mcp" = json!({"enabled": false}))
    )
)]
pub async fn resolve(
    Path((org_id, event_id)): Path<(String, String)>,
    Headers(user_email): Headers<UserEmail>,
    Json(body): Json<TransitionRequest>,
) -> Response {
    transition(
        &org_id,
        &event_id,
        Status::Resolved,
        &user_email.user_id,
        body.comment.as_deref(),
    )
}

#[utoipa::path(
    post,
    path = "/{org_id}/security-events/{event_id}/close",
    context_path = "/api",
    tag = "SecurityEvents",
    operation_id = "CloseSecurityEvent",
    summary = "Close a security event",
    security(
        ("Authorization" = [])
    ),
    params(
        ("org_id" = String, Path, description = "Organization / tenant name"),
        ("event_id" = String, Path, description = "Security event id"),
    ),
    request_body(content = TransitionRequest, description = "Optional workflow comment"),
    responses(
        (status = 200, description = "Success", content_type = "application/json", body = Object),
        (status = 404, description = "Not found", content_type = "application/json", body = ()),
        (status = 409, description = "Illegal transition", content_type = "application/json", body = ()),
    ),
    extensions(
        ("x-o2-mcp" = json!({"enabled": false}))
    )
)]
pub async fn close(
    Path((org_id, event_id)): Path<(String, String)>,
    Headers(user_email): Headers<UserEmail>,
    Json(body): Json<TransitionRequest>,
) -> Response {
    transition(
        &org_id,
        &event_id,
        Status::Closed,
        &user_email.user_id,
        body.comment.as_deref(),
    )
}

fn transition(
    org_id: &str,
    event_id: &str,
    to: Status,
    actor_id: &str,
    comment: Option<&str>,
) -> Response {
    let now = Utc::now().timestamp_millis();
    match service().transition(org_id, event_id, to, actor_id, comment, now) {
        Ok(event) => MetaHttpResponse::json(event),
        Err(e) => error_response(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_limit_to_max() {
        let service = SecurityEventService::new(Arc::new(
            audit_rule::SqliteSecurityEventRepository::open_in_memory().unwrap(),
        ));
        let params = ListParams {
            limit: Some(10_000),
            ..Default::default()
        };
        // list() itself is exercised via integration; here we just assert the
        // clamp logic produces a bounded filter (validated through the repo call).
        let page = service.list("tenant-x", params).unwrap();
        assert_eq!(page.limit, MAX_LIMIT);
        assert_eq!(page.total, 0);
    }
}
