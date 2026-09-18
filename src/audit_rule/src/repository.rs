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

use std::{path::Path, sync::Mutex};

use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    builder::DetectionKey,
    security_event::{Category, MAX_RELATED_EVENT_IDS, SecurityEvent, Severity, Status},
};

/// The DataFox schema version, tracked via SQLite `PRAGMA user_version`.
const SCHEMA_VERSION: i32 = 2;

/// The delta a detection update applies to an existing episode. Only these
/// fields are mutable; everything else is immutable by construction.
#[derive(Debug, Clone, PartialEq)]
pub struct SecurityEventUpdate {
    pub detection_key: DetectionKey,
    pub episode_id: String,
    pub last_seen: i64,
    pub event_count: u64,
    pub evidence: Value,
    pub related_event_ids: Vec<String>,
    pub updated_at: i64,
}

/// Repository failure. Typed — never a bare string.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum RepositoryError {
    #[error("security event not found")]
    NotFound,
    #[error("security event already exists")]
    AlreadyExists,
    #[error("constraint violation: {0}")]
    ConstraintViolation(String),
    #[error("serialization error")]
    SerializationError,
    #[error("database error: {0}")]
    DatabaseError(String),
    #[error("tenant mismatch")]
    TenantMismatch,
}

/// Outcome of `create`.
#[derive(Debug, Clone, PartialEq)]
pub enum CreateOutcome {
    Created { event_id: String },
    AlreadyExists { event_id: String },
}

/// Outcome of `apply_detection_update`.
#[derive(Debug, Clone, PartialEq)]
pub enum UpdateOutcome {
    Updated { event_id: String },
    NotFound,
}

/// Outcome of a workflow status transition.
#[derive(Debug, Clone, PartialEq)]
pub enum TransitionOutcome {
    Transitioned { status: Status },
    NotFound,
    Conflict,
}

/// One workflow audit record (append-only history).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SecurityEventAction {
    pub id: String,
    pub tenant_id: String,
    pub security_event_id: String,
    pub action: String,
    pub from_status: Status,
    pub to_status: Status,
    pub actor_id: String,
    pub comment: Option<String>,
    pub created_at: i64,
}

/// Sort order for list queries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SortOrder {
    #[default]
    #[serde(rename = "desc")]
    LastSeenDesc,
    #[serde(rename = "asc")]
    LastSeenAsc,
}

/// List filters (all optional; empty = match all).
#[derive(Debug, Clone, Default)]
pub struct SecurityEventFilter {
    pub status: Option<Status>,
    pub severity: Option<Severity>,
    pub rule_id: Option<String>,
    pub event_type: Option<String>,
    pub src_ip: Option<String>,
    pub username: Option<String>,
    pub last_seen_from: Option<i64>,
    pub last_seen_to: Option<i64>,
    pub limit: u32,
    pub offset: u32,
    pub sort: SortOrder,
}

/// A page of results with a total count.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ListPage<T> {
    pub items: Vec<T>,
    pub total: u64,
}

/// Storage abstraction for SecurityEvent current state. The SQLite impl is the
/// v1 low-resource single-node store; a future PostgreSQL impl can replace it
/// behind the same trait.
pub trait SecurityEventRepository: Send + Sync {
    /// Insert a new SecurityEvent. Idempotent on `(tenant, detection_key,
    /// episode_id)` — a retry returns `AlreadyExists` instead of a duplicate.
    fn create(
        &self,
        event: &SecurityEvent,
        detection_key: &DetectionKey,
        episode_id: &str,
    ) -> Result<CreateOutcome, RepositoryError>;

    /// Apply a monotonic detection update to an existing episode. Never mutates
    /// `event_id` / `tenant_id` / `rule_id` / `rule_version` / `created_at` /
    /// `status`.
    fn apply_detection_update(
        &self,
        update: &SecurityEventUpdate,
    ) -> Result<UpdateOutcome, RepositoryError>;

    fn get_by_event_id(
        &self,
        tenant_id: &str,
        event_id: &str,
    ) -> Result<Option<SecurityEvent>, RepositoryError>;

    fn get_by_episode(
        &self,
        tenant_id: &str,
        detection_key: &DetectionKey,
        episode_id: &str,
    ) -> Result<Option<SecurityEvent>, RepositoryError>;

    fn list(&self, tenant_id: &str, limit: u32) -> Result<Vec<SecurityEvent>, RepositoryError>;

    /// Transition a SecurityEvent's workflow status. Status + action history are
    /// written atomically; only `status` / `updated_at` change. `Conflict` means
    /// the transition is illegal (or the row was concurrently modified).
    fn transition_status(
        &self,
        tenant_id: &str,
        event_id: &str,
        to: Status,
        actor_id: &str,
        comment: Option<&str>,
        now: i64,
    ) -> Result<TransitionOutcome, RepositoryError>;

    /// List SecurityEvents for a tenant with filters + pagination + sorting.
    fn list_filtered(
        &self,
        tenant_id: &str,
        filter: &SecurityEventFilter,
    ) -> Result<ListPage<SecurityEvent>, RepositoryError>;

    /// List the workflow audit trail for one SecurityEvent.
    fn list_actions(
        &self,
        tenant_id: &str,
        security_event_id: &str,
    ) -> Result<Vec<SecurityEventAction>, RepositoryError>;
}

const DDL_V1: &str = "
CREATE TABLE security_events (
    event_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    detection_key TEXT NOT NULL,
    episode_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    category TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    event_count INTEGER NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    username TEXT,
    asset_id TEXT,
    related_event_ids_json TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (tenant_id, detection_key, episode_id)
);
CREATE INDEX idx_security_events_tenant_status ON security_events (tenant_id, status);
CREATE INDEX idx_security_events_tenant_severity ON security_events (tenant_id, severity);
CREATE INDEX idx_security_events_tenant_last_seen ON security_events (tenant_id, last_seen);
CREATE INDEX idx_security_events_tenant_rule ON security_events (tenant_id, rule_id);
";

const DDL_V2: &str = "
CREATE TABLE security_event_actions (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    security_event_id TEXT NOT NULL,
    action TEXT NOT NULL,
    from_status TEXT NOT NULL,
    to_status TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    comment TEXT,
    created_at INTEGER NOT NULL
);
CREATE INDEX idx_security_event_actions_event ON security_event_actions (tenant_id, security_event_id);
";

/// Embedded SQLite repository over an independent `datafox.db` — never touches
/// OpenObserve's metadata schema. `Connection` is behind a mutex so the trait's
/// `&self` methods stay usable across threads; each method holds the lock only
/// for its own (short) SQL statements.
pub struct SqliteSecurityEventRepository {
    conn: Mutex<Connection>,
}

impl SqliteSecurityEventRepository {
    pub fn open(path: &Path) -> Result<Self, RepositoryError> {
        let conn = Connection::open(path).map_err(db_err)?;
        migrate(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Open an in-memory repository (tests and short-lived callers).
    pub fn open_in_memory() -> Result<Self, RepositoryError> {
        let conn = Connection::open_in_memory().map_err(db_err)?;
        migrate(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

impl SecurityEventRepository for SqliteSecurityEventRepository {
    fn create(
        &self,
        event: &SecurityEvent,
        detection_key: &DetectionKey,
        episode_id: &str,
    ) -> Result<CreateOutcome, RepositoryError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| RepositoryError::DatabaseError("lock poisoned".into()))?;
        let result = insert_event(&conn, event, detection_key, episode_id)?;
        match result {
            CreateOutcome::Created { event_id } => Ok(CreateOutcome::Created { event_id }),
            CreateOutcome::AlreadyExists { .. } => {
                // Read the existing row to report its id.
                let existing =
                    select_by_episode(&conn, &event.tenant_id, detection_key, episode_id)?
                        .ok_or(RepositoryError::AlreadyExists)?;
                Ok(CreateOutcome::AlreadyExists {
                    event_id: existing.event_id,
                })
            }
        }
    }

    fn apply_detection_update(
        &self,
        update: &SecurityEventUpdate,
    ) -> Result<UpdateOutcome, RepositoryError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| RepositoryError::DatabaseError("lock poisoned".into()))?;
        update_event(&conn, update)
    }

    fn get_by_event_id(
        &self,
        tenant_id: &str,
        event_id: &str,
    ) -> Result<Option<SecurityEvent>, RepositoryError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| RepositoryError::DatabaseError("lock poisoned".into()))?;
        select_by_event_id(&conn, tenant_id, event_id)
    }

    fn get_by_episode(
        &self,
        tenant_id: &str,
        detection_key: &DetectionKey,
        episode_id: &str,
    ) -> Result<Option<SecurityEvent>, RepositoryError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| RepositoryError::DatabaseError("lock poisoned".into()))?;
        select_by_episode(&conn, tenant_id, detection_key, episode_id)
    }

    fn list(&self, tenant_id: &str, limit: u32) -> Result<Vec<SecurityEvent>, RepositoryError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| RepositoryError::DatabaseError("lock poisoned".into()))?;
        list_by_tenant(&conn, tenant_id, limit)
    }

    fn transition_status(
        &self,
        tenant_id: &str,
        event_id: &str,
        to: Status,
        actor_id: &str,
        comment: Option<&str>,
        now: i64,
    ) -> Result<TransitionOutcome, RepositoryError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| RepositoryError::DatabaseError("lock poisoned".into()))?;
        transition_status(&mut conn, tenant_id, event_id, to, actor_id, comment, now)
    }

    fn list_filtered(
        &self,
        tenant_id: &str,
        filter: &SecurityEventFilter,
    ) -> Result<ListPage<SecurityEvent>, RepositoryError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| RepositoryError::DatabaseError("lock poisoned".into()))?;
        list_filtered(&conn, tenant_id, filter)
    }

    fn list_actions(
        &self,
        tenant_id: &str,
        security_event_id: &str,
    ) -> Result<Vec<SecurityEventAction>, RepositoryError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| RepositoryError::DatabaseError("lock poisoned".into()))?;
        list_actions(&conn, tenant_id, security_event_id)
    }
}

fn db_err(e: rusqlite::Error) -> RepositoryError {
    RepositoryError::DatabaseError(e.to_string())
}

/// Run migrations. `PRAGMA user_version` tracks the DataFox schema version.
fn migrate(conn: &Connection) -> Result<(), RepositoryError> {
    let version: i32 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(db_err)?;
    if version == SCHEMA_VERSION {
        return Ok(());
    }
    if version > SCHEMA_VERSION {
        return Err(RepositoryError::DatabaseError(format!(
            "schema version {version} is newer than supported {SCHEMA_VERSION}"
        )));
    }
    if version < 1 {
        conn.execute_batch(DDL_V1).map_err(db_err)?;
    }
    if version < 2 {
        conn.execute_batch(DDL_V2).map_err(db_err)?;
    }
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(db_err)?;
    Ok(())
}

fn insert_event(
    conn: &Connection,
    event: &SecurityEvent,
    detection_key: &DetectionKey,
    episode_id: &str,
) -> Result<CreateOutcome, RepositoryError> {
    let related = serde_json::to_string(&event.related_event_ids)
        .map_err(|_| RepositoryError::SerializationError)?;
    let evidence =
        serde_json::to_string(&event.evidence).map_err(|_| RepositoryError::SerializationError)?;
    let rows = conn
        .execute(
            "INSERT OR IGNORE INTO security_events (
                event_id, tenant_id, detection_key, episode_id, rule_id, rule_version,
                title, description, category, event_type, severity, status,
                first_seen, last_seen, event_count, src_ip, dst_ip, username, asset_id,
                related_event_ids_json, evidence_json, created_at, updated_at
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23)",
            rusqlite::params![
                event.event_id,
                event.tenant_id,
                detection_key.to_db_string(),
                episode_id,
                event.rule_id,
                event.rule_version,
                event.title,
                event.description,
                enum_to_db(&event.category)?,
                event.event_type,
                enum_to_db(&event.severity)?,
                enum_to_db(&event.status)?,
                event.first_seen,
                event.last_seen,
                event.event_count as i64,
                event.src_ip,
                event.dst_ip,
                event.username,
                event.asset_id,
                related,
                evidence,
                event.created_at,
                event.updated_at,
            ],
        )
        .map_err(db_err)?;
    if rows == 0 {
        return Ok(CreateOutcome::AlreadyExists {
            event_id: event.event_id.clone(),
        });
    }
    Ok(CreateOutcome::Created {
        event_id: event.event_id.clone(),
    })
}

fn update_event(
    conn: &Connection,
    update: &SecurityEventUpdate,
) -> Result<UpdateOutcome, RepositoryError> {
    // Read-modify-write inside a transaction: monotonic merge, never regress.
    let existing = conn
        .query_row(
            "SELECT event_id, last_seen, event_count, related_event_ids_json FROM security_events
             WHERE tenant_id = ?1 AND detection_key = ?2 AND episode_id = ?3",
            rusqlite::params![
                update.detection_key.tenant_id,
                update.detection_key.to_db_string(),
                update.episode_id,
            ],
            |r| {
                let ids_json: String = r.get(3)?;
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    ids_json,
                ))
            },
        )
        .optional()
        .map_err(db_err)?;

    let Some((event_id, old_last_seen, old_count, ids_json)) = existing else {
        return Ok(UpdateOutcome::NotFound);
    };

    let old_ids: Vec<String> =
        serde_json::from_str(&ids_json).map_err(|_| RepositoryError::SerializationError)?;
    let merged_ids = merge_related_ids(&old_ids, &update.related_event_ids);
    let merged_json =
        serde_json::to_string(&merged_ids).map_err(|_| RepositoryError::SerializationError)?;
    let evidence =
        serde_json::to_string(&update.evidence).map_err(|_| RepositoryError::SerializationError)?;

    let last_seen = update.last_seen.max(old_last_seen);
    let event_count = (update.event_count as i64).max(old_count);

    conn.execute(
        "UPDATE security_events SET last_seen = ?1, event_count = ?2, evidence_json = ?3,
            related_event_ids_json = ?4, updated_at = ?5
         WHERE tenant_id = ?6 AND detection_key = ?7 AND episode_id = ?8",
        rusqlite::params![
            last_seen,
            event_count,
            evidence,
            merged_json,
            update.updated_at,
            update.detection_key.tenant_id,
            update.detection_key.to_db_string(),
            update.episode_id,
        ],
    )
    .map_err(db_err)?;

    Ok(UpdateOutcome::Updated { event_id })
}

fn select_by_event_id(
    conn: &Connection,
    tenant_id: &str,
    event_id: &str,
) -> Result<Option<SecurityEvent>, RepositoryError> {
    conn.query_row(
        "SELECT * FROM security_events WHERE tenant_id = ?1 AND event_id = ?2",
        rusqlite::params![tenant_id, event_id],
        row_to_event,
    )
    .optional()
    .map_err(db_err)
}

fn select_by_episode(
    conn: &Connection,
    tenant_id: &str,
    detection_key: &DetectionKey,
    episode_id: &str,
) -> Result<Option<SecurityEvent>, RepositoryError> {
    conn.query_row(
        "SELECT * FROM security_events WHERE tenant_id = ?1 AND detection_key = ?2 AND episode_id = ?3",
        rusqlite::params![tenant_id, detection_key.to_db_string(), episode_id],
        row_to_event,
    )
    .optional()
    .map_err(db_err)
}

fn list_by_tenant(
    conn: &Connection,
    tenant_id: &str,
    limit: u32,
) -> Result<Vec<SecurityEvent>, RepositoryError> {
    let mut stmt = conn
        .prepare(
            "SELECT * FROM security_events WHERE tenant_id = ?1 ORDER BY last_seen DESC LIMIT ?2",
        )
        .map_err(db_err)?;
    let rows = stmt
        .query_map(rusqlite::params![tenant_id, limit as i64], row_to_event)
        .map_err(db_err)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(db_err)?);
    }
    Ok(out)
}

/// Atomically transition a status: read current status, validate the transition,
/// conditionally update (compare-and-swap on the current status), and write the
/// action history — all in one transaction.
fn transition_status(
    conn: &mut Connection,
    tenant_id: &str,
    event_id: &str,
    to: Status,
    actor_id: &str,
    comment: Option<&str>,
    now: i64,
) -> Result<TransitionOutcome, RepositoryError> {
    let tx = conn.transaction().map_err(db_err)?;

    let from: Option<String> = tx
        .query_row(
            "SELECT status FROM security_events WHERE tenant_id = ?1 AND event_id = ?2",
            rusqlite::params![tenant_id, event_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(db_err)?;

    let Some(from_str) = from else {
        return Ok(TransitionOutcome::NotFound);
    };
    let from_status = enum_from_db::<Status>(&from_str)?;

    if !from_status.can_transition_to(to) {
        return Ok(TransitionOutcome::Conflict);
    }

    // Compare-and-swap on the current status — a concurrent transition makes
    // this update affect 0 rows, surfacing as Conflict instead of overwriting.
    let updated = tx
        .execute(
            "UPDATE security_events SET status = ?1, updated_at = ?2
             WHERE tenant_id = ?3 AND event_id = ?4 AND status = ?5",
            rusqlite::params![enum_to_db(&to)?, now, tenant_id, event_id, from_str],
        )
        .map_err(db_err)?;
    if updated == 0 {
        return Ok(TransitionOutcome::Conflict);
    }

    tx.execute(
        "INSERT INTO security_event_actions
            (id, tenant_id, security_event_id, action, from_status, to_status, actor_id, comment, created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        rusqlite::params![
            Uuid::now_v7().to_string(),
            tenant_id,
            event_id,
            action_name(to),
            from_str,
            enum_to_db(&to)?,
            actor_id,
            comment,
            now,
        ],
    )
    .map_err(db_err)?;

    tx.commit().map_err(db_err)?;
    Ok(TransitionOutcome::Transitioned { status: to })
}

fn action_name(to: Status) -> &'static str {
    match to {
        Status::Open => "open",
        Status::Acknowledged => "acknowledge",
        Status::Resolved => "resolve",
        Status::Closed => "close",
    }
}

fn list_filtered(
    conn: &Connection,
    tenant_id: &str,
    filter: &SecurityEventFilter,
) -> Result<ListPage<SecurityEvent>, RepositoryError> {
    let mut where_clauses = vec!["tenant_id = ?".to_string()];
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(tenant_id.to_string())];

    if let Some(s) = &filter.status {
        where_clauses.push("status = ?".to_string());
        params.push(Box::new(enum_to_db(s)?));
    }
    if let Some(s) = &filter.severity {
        where_clauses.push("severity = ?".to_string());
        params.push(Box::new(enum_to_db(s)?));
    }
    if let Some(r) = &filter.rule_id {
        where_clauses.push("rule_id = ?".to_string());
        params.push(Box::new(r.clone()));
    }
    if let Some(e) = &filter.event_type {
        where_clauses.push("event_type = ?".to_string());
        params.push(Box::new(e.clone()));
    }
    if let Some(ip) = &filter.src_ip {
        where_clauses.push("src_ip = ?".to_string());
        params.push(Box::new(ip.clone()));
    }
    if let Some(u) = &filter.username {
        where_clauses.push("username = ?".to_string());
        params.push(Box::new(u.clone()));
    }
    if let Some(f) = filter.last_seen_from {
        where_clauses.push("last_seen >= ?".to_string());
        params.push(Box::new(f));
    }
    if let Some(t) = filter.last_seen_to {
        where_clauses.push("last_seen <= ?".to_string());
        params.push(Box::new(t));
    }

    let where_sql = where_clauses.join(" AND ");
    let order = match filter.sort {
        SortOrder::LastSeenDesc => "last_seen DESC, event_id DESC",
        SortOrder::LastSeenAsc => "last_seen ASC, event_id ASC",
    };

    let total: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM security_events WHERE {where_sql}"),
            rusqlite::params_from_iter(params.iter().map(|p| p.as_ref())),
            |r| r.get(0),
        )
        .map_err(db_err)?;

    let sql = format!(
        "SELECT * FROM security_events WHERE {where_sql} ORDER BY {order} LIMIT ? OFFSET ?"
    );
    params.push(Box::new(filter.limit as i64));
    params.push(Box::new(filter.offset as i64));

    let mut stmt = conn.prepare(&sql).map_err(db_err)?;
    let rows = stmt
        .query_map(
            rusqlite::params_from_iter(params.iter().map(|p| p.as_ref())),
            row_to_event,
        )
        .map_err(db_err)?;
    let mut items = Vec::new();
    for r in rows {
        items.push(r.map_err(db_err)?);
    }

    Ok(ListPage {
        items,
        total: total as u64,
    })
}

fn list_actions(
    conn: &Connection,
    tenant_id: &str,
    security_event_id: &str,
) -> Result<Vec<SecurityEventAction>, RepositoryError> {
    let mut stmt = conn
        .prepare(
            "SELECT id, tenant_id, security_event_id, action, from_status, to_status, actor_id, comment, created_at
             FROM security_event_actions
             WHERE tenant_id = ?1 AND security_event_id = ?2
             ORDER BY created_at ASC, id ASC",
        )
        .map_err(db_err)?;
    let rows = stmt
        .query_map(rusqlite::params![tenant_id, security_event_id], |r| {
            Ok(SecurityEventAction {
                id: r.get(0)?,
                tenant_id: r.get(1)?,
                security_event_id: r.get(2)?,
                action: r.get(3)?,
                from_status: enum_from_db::<Status>(&r.get::<_, String>(4)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                to_status: enum_from_db::<Status>(&r.get::<_, String>(5)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                actor_id: r.get(6)?,
                comment: r.get(7)?,
                created_at: r.get(8)?,
            })
        })
        .map_err(db_err)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(db_err)?);
    }
    Ok(out)
}

fn row_to_event(row: &rusqlite::Row) -> rusqlite::Result<SecurityEvent> {
    let related_json: String = row.get("related_event_ids_json")?;
    let evidence_json: String = row.get("evidence_json")?;
    let related = serde_json::from_str(&related_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let evidence = serde_json::from_str(&evidence_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    Ok(SecurityEvent {
        event_id: row.get("event_id")?,
        tenant_id: row.get("tenant_id")?,
        rule_id: row.get("rule_id")?,
        rule_version: row.get("rule_version")?,
        title: row.get("title")?,
        description: row.get("description")?,
        category: enum_from_db::<Category>(&row.get::<_, String>("category")?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        event_type: row.get("event_type")?,
        severity: enum_from_db::<Severity>(&row.get::<_, String>("severity")?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        status: enum_from_db::<Status>(&row.get::<_, String>("status")?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        first_seen: row.get("first_seen")?,
        last_seen: row.get("last_seen")?,
        event_count: row.get::<_, i64>("event_count")? as u64,
        src_ip: row.get("src_ip")?,
        dst_ip: row.get("dst_ip")?,
        username: row.get("username")?,
        asset_id: row.get("asset_id")?,
        related_event_ids: related,
        evidence,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
    })
}

/// Merge two related-event-id lists: bounded, deduplicated union (existing order
/// first, then new ids).
fn merge_related_ids(existing: &[String], incoming: &[String]) -> Vec<String> {
    let mut merged = existing.to_vec();
    for id in incoming {
        if !merged.contains(id) && merged.len() < MAX_RELATED_EVENT_IDS {
            merged.push(id.clone());
        }
    }
    merged
}

fn enum_to_db<T: Serialize>(v: &T) -> Result<String, RepositoryError> {
    serde_json::to_value(v)
        .ok()
        .and_then(|j| j.as_str().map(str::to_string))
        .ok_or(RepositoryError::SerializationError)
}

fn enum_from_db<T: DeserializeOwned>(s: &str) -> Result<T, RepositoryError> {
    serde_json::from_value(Value::String(s.to_string()))
        .map_err(|_| RepositoryError::SerializationError)
}

impl DetectionKey {
    /// Canonical DB string for this key (tenant is stored in its own column).
    fn to_db_string(&self) -> String {
        format!(
            "{}|{}|{}",
            self.rule_id, self.rule_version, self.group_values
        )
    }
}
