# DataFox Log Audit — upstream sync strategy

How this fork tracks `openobserve/openobserve` and merges upstream changes without
breaking the DataFox-specific work.

## 1. Remote layout

| Remote | URL | Role |
| --- | --- | --- |
| `upstream` | `https://github.com/openobserve/openobserve.git` | Original OpenObserve (read-only tracking) |
| `origin` | *(the DataFox fork — set this up)* | DataFox's private fork (push target) |

Current baseline state:

- `main` branch points at upstream `v1.0.1`
  (`1c9840747421fe71f5ff12b6adf056e5847d99bf`).
- `upstream` remote is already added; `origin` still points at openobserve and must
  be repointed to the DataFox fork before pushing any work:

```shell
git remote set-url origin git@<your-git-host>:datafox/datafox-log-audit.git
```

## 2. Branch model

- `main` — the DataFox baseline + product code. Never rewritten; merged via PR.
- `upstream/*` — (optional) local read-only mirrors of upstream branches, used only
  for diffing and merging.

The protected core (see `docs/ARCHITECTURE.md` §3) makes merges low-risk: because we
never edit Search/Storage/DataFusion/WAL/Compactor/Ingester in place, upstream
changes to those areas merge cleanly. Conflicts are expected only where DataFox
touches shared seams (API registration, config, `Cargo.toml`, `web/`).

## 3. Fetch upstream

```shell
git fetch upstream --tags
```

This pulls new tags/branches without touching working tree. Do this before any merge.

## 4. Sync to a new upstream release

```shell
# 1. Ensure a clean tree.
git status

# 2. Fetch the target tag (e.g. v1.1.0).
git fetch upstream --tags
git checkout main
git pull  # or: git fetch origin && git reset --hard origin/main

# 3. Create a sync branch and merge the tag.
git checkout -b sync/upstream-v1.1.0
git merge upstream/v1.1.0
```

Resolve conflicts in this order of priority:

1. Never let a conflict resolution rewrite protected-core logic — take upstream's
   version for `src/search*`, `src/infra/src/storage`, `src/wal`,
   `src/compaction`, `src/ingester`, `src/db`, and DataFusion integration, then
   re-apply any DataFox wrapper on top.
2. For `Cargo.toml` / `Cargo.lock`: regenerate with `cargo update` and `cargo build`;
   do not hand-edit the lockfile.
3. For `web/package-lock.json` and `web/dist`: rebuild the UI (see `docs/BUILD.md`).
4. For shared seams (API routes, config keys, i18n keys): prefer upstream, then add
   DataFox additions back additively.

## 5. Verify after a merge

```shell
cargo fmt --all
cargo clippy --workspace --all-targets -- -W clippy::too_many_lines \
  -W clippy::cognitive_complexity -W clippy::excessive_nesting -D warnings
cargo build                                   # backend
(cd web && npm install && npm run build)      # frontend
```

Run the full verification steps from `docs/BUILD.md` before opening the merge PR.

## 6. Cherry-picking hotfixes

For a critical upstream fix without a full release merge:

```shell
git fetch upstream
git cherry-pick <upstream-commit-sha>
```

Same conflict rules as §4 apply. Prefer a full tag merge over a pile of cherry-picks.

## 7. Rules

- **Never commit upstream-vendor vendoring.** Upstream code stays upstream; only
  merge, never copy.
- **Do not rebase `main`** once it has shared history; use merge commits for sync.
- **Pin, don't float.** Record the baseline tag in `AGENTS.md` and this file when you
  advance it, so the "current upstream" is always reproducible.
- **AGPL §13** — every merge that ships over a network must keep the modified source
  available to users. This is automatic if `origin` (the fork) is reachable, but keep
  it in mind for private deployments.
