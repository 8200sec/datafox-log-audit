# DataFox Log Audit — product architecture

This document describes the DataFox Log Audit product and how it is layered on the
OpenObserve baseline. It is the reference for deciding **where** a change belongs.

## 1. What the product is

DataFox Log Audit is a log-audit product built by secondary development ("二开") on
[OpenObserve](https://openobserve.ai) `v1.0.1`. OpenObserve is a cloud-native
observability platform (logs, metrics, traces, RUM, LLM observability) with Parquet
columnar storage and an S3-native design. DataFox Log Audit inherits that ingestion,
storage, and query engine and adds its own audit-specific product surface.

**License:** GNU AGPL-3.0 (see `LICENSE`). AGPL is copyleft: if DataFox Log Audit is
modified and exposed over a network, the corresponding source of the modified
version must be offered to its users (AGPL §13). This is a hard constraint on how the
fork is distributed and deployed, not a code detail.

## 2. Layering model

```
┌────────────────────────────────────────────────────────────┐
│  DataFox Log Audit product surface (NEW, additive)          │
│  frontend views (web/src/views, web/src/components)         │
│  additive Rust modules (new workspace members)              │
├────────────────────────────────────────────────────────────┤
│  OpenObserve baseline v1.0.1 (UPSTREAM, keep in sync)       │
│  api / search / storage / db / infra / ingester / WAL / …   │
├────────────────────────────────────────────────────────────┤
│  External engines (dependencies, not our code)              │
│  DataFusion (openobserve fork) · Tantivy · SQLite · S3      │
└────────────────────────────────────────────────────────────┘
```

The rule of thumb: DataFox-specific behavior is **additive** — new modules, new
views, new plugins — and never edits the upstream core in place. This keeps upstream
merges cheap (see `docs/UPSTREAM_SYNC.md`).

## 3. Protected core (do not modify)

These six areas are upstream OpenObserve core and are off-limits without explicit
human approval. The paths are the canonical map of the constraint in `AGENTS.md`.

| Area | Crate / path | Role |
| --- | --- | --- |
| Search | `src/search/` | Tantivy-based full-text + aggregation search engine |
| Search service | `src/search_service/` | Query orchestration, gRPC, search jobs, file-list merging |
| Storage | `src/infra/src/storage/`, `src/org_storage/` | Parquet/S3 object storage and per-org storage abstraction |
| Metadata store | `src/db/` | SQLite-backed metadata (streams, schemas, orgs, users) |
| DataFusion | `datafusion*` git deps + `src/infra/src/table/`, `src/search_service/` | SQL query engine (openobserve fork) and its table/scan integration |
| WAL | `src/wal/` | Write-ahead log for ingestion durability |
| Compactor | `src/compaction/` | Background compaction of small Parquet files |
| Ingester | `src/ingester/` | Ingestion pipeline entry point |

## 4. Backend crate map (workspace members)

The Rust workspace (`Cargo.toml` `[workspace].members`) is the canonical crate list.
Key members and their roles:

- `src/api/*` — HTTP (axum) and gRPC (tonic) API surfaces: `http`, `grpc`,
  `ingest`, `management`, `search`, `pipelines`, `common`.
- `src/common` — shared types, `meta` (stream/organization/user models), cluster
  primitives.
- `src/config` — configuration, env handling (`.env` overrides process env).
- `src/infra` — infrastructure layer: `storage` (S3/local/etc.), `table`
  (DataFusion table providers), `cache`, `cluster`, `scheduler`, `file_list`,
  `dist_lock`, `db`.
- `src/ingester` + `src/wal` — ingestion durability path.
- `src/compaction` — compactor.
- `src/search` + `src/search_service` — search engine and query service.
- `src/flight` — Apache Arrow Flight service for distributed query/scan.
- `src/proto` — protobuf definitions (`tonic_prost_build`; requires `protoc`).
- `src/db` — metadata persistence (SQLite).
- `src/promql`, `src/promql_service`, `src/metrics_index` — metrics/PromQL.
- `src/mcp` — Model Context Protocol server.
- `src/jobs`, `src/scheduler` (in `infra`) — background jobs and triggers.
- `src/audit`, `src/schema`, `src/stream`, `src/transform`, `src/enrichment_data`,
  `src/synthetics`, `src/report_server`, `src/sourcemaps`, `src/usage_reporting`,
  `src/super_cluster_queue`, `src/tantivy_utils`, `src/web` — supporting subsystems.

The binary is `openobserve` (`name = "openobserve"` in the root `Cargo.toml`).

## 5. Frontend (`web/`)

- Vue 3 + TypeScript + Vite; i18n (`web/src/locales`), Pinia stores
  (`web/src/stores`), Vue Router (`web/src/router`), services (`web/src/services`).
- UI is built from the internal O2 component library (`web/src/lib`) — see the
  `ui-architect` skill; no bare HTML controls when an O2 equivalent exists.
- `web/dist/` is embedded into the `openobserve` binary at build time, so the UI
  must be built before the backend when shipping a combined binary.
- Dev mode runs separately: Vite dev server on `:8081` → backend API on `:5080`.

## 6. Data flow (high level)

1. Agents/apps POST data to the ingest API (`src/api/ingest`) or gRPC.
2. Ingester (`src/ingester`) writes to the WAL (`src/wal`) for durability.
3. Data is compacted (`src/compaction`) into columnar Parquet files in object
   storage (`src/infra/src/storage`).
4. Queries hit the search service (`src/search_service`), which plans over the file
   list and executes scans through DataFusion (`src/infra/src/table`) and Tantivy
   (`src/search`), optionally distributed via Arrow Flight (`src/flight`).
5. The Vue UI (`web/`) calls the management/search APIs (`src/api/*`).

## 7. Where to add DataFox features

- **New audit views / dashboards / reports** → `web/src/views`, `web/src/components`,
  `web/src/router`.
- **New backend endpoints** → a new `src/api/...` module or an additive handler;
  prefer new modules over editing existing ones.
- **New background processing** → a new job in `src/jobs` or a new workspace crate.
- **Anything touching the protected core** → stop and get explicit human approval
  first; prefer an extension point or a wrapper module instead.
