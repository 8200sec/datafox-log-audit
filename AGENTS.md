# DataFox Log Audit — agent guidance

DataFox Log Audit is a secondary-development ("二开") fork of
[OpenObserve](https://openobserve.ai), pinned to upstream `v1.0.1`. This file is the
entry point for AI coding agents and tools that read `AGENTS.md`; it layers the
DataFox baseline rules on top of the upstream conventions.

## Read first (in this order)

1. `CLAUDE.md` — upstream OpenObserve project rules (build workflow, Rust code
   organization, comment policy, PR conventions). These remain authoritative for
   any code that lives in upstream modules.
2. `docs/ARCHITECTURE.md` — product architecture and the **protected core**.
3. `docs/UPSTREAM_SYNC.md` — how this fork tracks and merges upstream.
4. `docs/BUILD.md` — the verified build and run commands for both ends.

## Baseline facts

| Item | Value |
| --- | --- |
| Upstream | `openobserve/openobserve` |
| Baseline tag | `v1.0.1` (commit `1c9840747421fe71f5ff12b6adf056e5847d99bf`) |
| License | GNU AGPL-3.0 (copyleft — see `LICENSE`) |
| Branch | `main` (the DataFox baseline; `upstream` remote = openobserve) |
| Rust toolchain | `nightly-2026-05-20` (pinned in `rust-toolchain.toml`) |
| Frontend | Vue 3 + TypeScript (Vite), `web/` |

## Hard rule — do NOT modify the protected core

OpenObserve's **Search, Storage, DataFusion, WAL, Compactor, and Ingester** core is
off-limits. Any change that edits files under these paths requires an explicit
human go-ahead first:

- Search — `src/search/`, `src/search_service/`
- Storage — `src/infra/src/storage/`, `src/org_storage/`, `src/db/` (metadata store)
- DataFusion — the `datafusion*` git dependencies and their integration in
  `src/infra/src/table/` and `src/search_service/`
- WAL — `src/wal/`
- Compactor — `src/compaction/`
- Ingester — `src/ingester/`

Business features for DataFox Log Audit belong in new, additive modules and in the
frontend (`web/`), not inside the core above.

## Development workflow

- Build with `cargo build` (debug). Never `--release` unless explicitly asked.
- Verify commands and environment prerequisites live in `docs/BUILD.md`; keep it in
  sync when you change anything about the toolchain or build steps.
- Before finishing a backend task: `cargo fmt --all` and the CI clippy command from
  `CLAUDE.md`.
- Do not start business-feature development unless the human asks; this baseline is
  documentation and verification only.

## Frontend conventions

The `web/` subtree has its own guidance: `web/AGENTS.md` plus the `ui-architect` and
`eslint-error-handling` skills (see `.claude/skills/`). Load them before writing any
Vue UI.
