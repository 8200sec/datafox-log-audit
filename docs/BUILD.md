# DataFox Log Audit — build & run commands

Verified commands for building and running the Rust backend and the Vue frontend on
this baseline (`openobserve` `v1.0.1`). Environment is macOS (Apple Silicon,
`arm64`). All paths are relative to the repository root unless noted.

## 0. Environment prerequisites

| Tool | Version (verified) | How installed |
| --- | --- | --- |
| Rust | pinned `nightly-2026-05-20` (rustc `1.97.0-nightly`) | `rustup` (see below) |
| Cargo | `1.97.0-nightly` | via `rustup` |
| protoc | `25.3` (≥ 3.15 required) | prebuilt binary in `tools/` (see below) |
| Node.js | `24.13.0` (≥ 20 required) | system |
| npm | `11.6.2` (≥ 10 required) | with Node |

### Rust toolchain

```shell
# Install rustup (once), then the pinned toolchain from rust-toolchain.toml:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh
sh /tmp/rustup-init.sh -y --profile minimal
source "$HOME/.cargo/env"
rustup toolchain install nightly-2026-05-20 --component rustfmt,clippy,llvm-tools
```

`rust-toolchain.toml` pins `nightly-2026-05-20`; running any `cargo`/`rustc` command
inside the repo auto-selects it.

### protoc

The build compiles `src/proto` with `tonic_prost_build`, which invokes `protoc`.
`protoc` is not installed system-wide on this machine, so a prebuilt copy lives in
`tools/` (not committed). Recreate it:

```shell
mkdir -p tools && cd tools
curl -sSL -o protoc.zip \
  https://github.com/protocolbuffers/protobuf/releases/download/v25.3/protoc-25.3-osx-aarch_64.zip
unzip -o protoc.zip && rm protoc.zip
cd ..
```

Every backend build/run needs:

```shell
export PATH="$PWD/tools/bin:$PATH"          # puts protoc on PATH
export PROTOC_INCLUDE="$PWD/tools/include"  # well-known types include root
```

## 1. Backend (Rust)

```shell
source "$HOME/.cargo/env"
export PATH="$PWD/tools/bin:$PATH"
export PROTOC_INCLUDE="$PWD/tools/include"
cargo build            # debug build — CLAUDE.md forbids --release unless asked
```

Run the server (first run seeds the admin user via env vars):

```shell
ZO_ROOT_USER_EMAIL="root@example.com" ZO_ROOT_USER_PASSWORD="Complexpass#123" \
  cargo run
```

The API server listens on port `5080`. `.env` in the repo root overrides process
env — check it before running.

> **Verified ✅** (`cargo build` finished in ~35 min; binary at
> `target/debug/openobserve`, ~1.2 GB; server starts and answers on `:5080`).
>
> The first build git-clones the git dependencies declared in `Cargo.toml` into
> `~/.cargo/git` — `openobserve/datafusion`, `openobserve/vortex`,
> `openobserve/datafusion-functions-json`, `openobserve/promql-parser`,
> `openobserve/rmcp-openapi`, `openobserve/vector`, `openobserve/tantivy`,
> `openobserve/arrow-rs-object-store`, and `mattsse/chromiumoxide`. Once cached, the
> build is offline. `CARGO_NET_GIT_FETCH_WITH_CLI=true` routes cargo's git fetches
> through the system `git` (more reliable than libgit2 on macOS); keep it set if
> GitHub is intermittently unreachable (DNS pollution → `SSL_ERROR_SYSCALL`) — the
> fetch may otherwise need retries until a network window opens.

## 2. Frontend (Vue 3 + Vite) — verified ✅

```shell
cd web
npm install
npm run build      # = type-check (vue-tsc) + vite build → web/dist/
```

Before the first dev run, point the UI at the backend. Without this the UI falls
back to same-origin (`:8081`) and login/API calls fail, because Vite does **not**
proxy to the backend — the UI calls the backend directly (cross-origin; the
backend's CORS allows it):

```shell
cd web
printf 'VITE_OPENOBSERVE_ENDPOINT=http://localhost:5080\n' > .env   # gitignored
```

Run the dev server (Vite on `:8081`, base `/web/`):

```shell
cd web
npm run dev        # → http://localhost:8081/web/
```

Login with the admin seeded by the backend's `ZO_ROOT_USER_EMAIL` /
`ZO_ROOT_USER_PASSWORD` (see §1).

### Environment workarounds required on this machine

These are needed here and are worth pinning in CI/dev setup:

1. **npm cache is root-owned** (`~/.npm/_cacache` contains root-owned files, an old
   npm bug). Work around with a private cache instead of `sudo chown`:

   ```shell
   npm install --cache /tmp/datafox-npm-cache
   ```

2. **Cypress binary download** fails (writes to `~/Library/Caches/Cypress`).
   Cypress is only used for e2e tests, not for build/dev. Skip its binary:

   ```shell
   CYPRESS_INSTALL_BINARY=0 npm install
   ```

3. **Vite build OOM**: the default Node heap (4 GB) is too small for this bundle.
   Raise it:

   ```shell
   NODE_OPTIONS="--max-old-space-size=8192" npm run build
   ```

4. **AI data-source cards content fetch**: `vite.config.ts` clones
   `openobserve/o2-datasource` before build. When GitHub is unreachable, set
   `DS_CONTENT_STRICT=0` so the build degrades gracefully (AI cards fall back to a
   basic snippet) instead of failing:

   ```shell
   DS_CONTENT_STRICT=0 NODE_OPTIONS="--max-old-space-size=8192" npm run build
   ```

   The dev server is lenient by default and does not need this flag.

### Combined command (one-shot frontend build)

```shell
cd web && CYPRESS_INSTALL_BINARY=0 npm install --cache /tmp/datafox-npm-cache \
  && DS_CONTENT_STRICT=0 NODE_OPTIONS="--max-old-space-size=8192" npm run build
```

## 3. Full local run (dev)

Two terminals:

```shell
# terminal 1 — backend
source "$HOME/.cargo/env"
export PATH="$PWD/tools/bin:$PATH" PROTOC_INCLUDE="$PWD/tools/include"
ZO_ROOT_USER_EMAIL="root@example.com" ZO_ROOT_USER_PASSWORD="Complexpass#123" cargo run

# terminal 2 — frontend (after: cd web && npm install)
cd web && npm run dev     # http://localhost:8081/web/  →  API http://localhost:5080
```

## 4. Checks before finishing a backend change

```shell
cargo fmt --all
cargo clippy --workspace --all-targets -- -W clippy::too_many_lines \
  -W clippy::cognitive_complexity -W clippy::excessive_nesting -D warnings
```

Frontend lint/type checks (see `web/package.json` scripts):

```shell
cd web && npm run type-check:app && npm run lint:ci
```

## 5. Notes

- `web/dist/` is embedded into the `openobserve` binary, so rebuild the UI before
  building the backend when shipping a combined binary (`CONTRIBUTING.md`).
- `tools/` and `/tmp` caches are local-only; do not commit `tools/` or `node_modules`.
