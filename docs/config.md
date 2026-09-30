# Configuration reference

All Cite settings use the `CITE_` prefix (optional `cite.toml` overrides). Bad config fails startup with a clear message.

Compose-level settings live in `.env` (copy `.env.example`). `.env` is gitignored and also holds the GitHub PAT.

## Compose / `.env`

| Var | Default | Notes |
|---|---|---|
| `CITE_REPO` | — | **required**, `owner/name` |
| `CITE_GITHUB_TOKEN` | — | **required**, PAT with `contents:read`; passed to the manager only |
| `CITE_BRANCH` | `main` | |
| `CITE_POLL_INTERVAL` | `5m` | `1m`…`1d`, or `off` |
| `CITE_VERSION` | `0.1.0` | Image tag shared by manager + executor |
| `CITE_NODE` | `22` | `22` or `24` — selects image pair |
| `CITE_PORT` | `8080` | Host published port (container always `:8080`) |
| `CITE_BIND` | `0.0.0.0` | Host bind address |
| `CITE_MANAGER_MEM` / `_CPUS` / `_PIDS` | `2g` / `2.0` / `2048` | Compose limits |
| `CITE_EXECUTOR_MEM` / `_CPUS` / `_PIDS` | `512m` / `1.0` / `256` | Compose limits |

## Path layout (both services)

| Var | Default | Notes |
|---|---|---|
| `CITE_DATA_DIR` | `/var/lib/cite` | Logical root (Compose mounts subpaths beneath it) |
| `CITE_RELEASES_DIR` | `$CITE_DATA_DIR/releases` | Built slots `blue` / `green` |
| `CITE_CONTROL_DIR` | `$CITE_DATA_DIR/control` | Manager → executor (`desired.json`) |
| `CITE_STATUS_DIR` | `$CITE_DATA_DIR/status` | Executor → manager |
| `CITE_STATE_DIR` | `$CITE_DATA_DIR/state` | Manager-private (not mounted into executor) |
| `CITE_WORK_DIR` | `/var/lib/cite-work` | Manager-only build scratch |
| `CITE_CACHE_DIR` | `/var/lib/cite-cache` | Manager-only package cache |
| `CITE_SOCKET` | `/run/cite/manager.sock` | Root-only CLI control socket (tmpfs) |

## Manager

| Var | Default | Notes |
|---|---|---|
| `CITE_GITHUB_TOKEN` | — | PAT; set through Compose from `.env` |
| `CITE_GITHUB_TOKEN_FILE` | unset | Optional fallback: path to a file holding the PAT, re-read on every poll so it can be rotated without a restart |
| `CITE_MIN_POLL` | `60s` | Floor for poll interval |
| `CITE_RENDERING` | `auto` | `auto\|static\|ssr` |
| `CITE_FRAMEWORK` | `auto` | Preset key |
| `CITE_ROOT_DIR` | `.` | Monorepo subdir |
| `CITE_PACKAGE_MANAGER` | `auto` | `npm\|pnpm\|bun` |
| `CITE_INSTALL_COMMAND` / `CITE_BUILD_COMMAND` | preset | Shell strings (manager-side) |
| `CITE_OUTPUT_DIR` | preset | Static output or SSR app root |
| `CITE_START_COMMAND` | preset | SSR argv-only |
| `CITE_PRUNE` | `true` (ssr) | Prod prune before pack |
| `CITE_HEALTH_PATH` | `/` | |
| `CITE_HEALTH_TIMEOUT` | `60s` | |
| `CITE_SPA_FALLBACK` | preset | e.g. `index.html` |
| `CITE_WARM_GRACE` | `24h` | Previous release keep-alive after cutover |
| `CITE_WATCH` | `10m` | Post-switch auto-fallback window |
| `CITE_BUILD_TIMEOUT` | `15m` | |
| `CITE_BUILD_CACHE` | `on` | |
| `CITE_CACHE_MAX_BYTES` | `2GB` | |
| `CITE_MAX_SOURCE_BYTES` / `CITE_MAX_WORK_BYTES` / `CITE_MAX_RELEASE_BYTES` | `2GB` / `4GB` / `1.5GB` | |
| `CITE_MIN_FREE_BYTES` | `2GB` | Refuse to build below this |
| `CITE_BUILD_ENV_FILE` | `/run/cite/build.env` | Build-time env file; read if present and overrides container env |
| `CITE_GITHUB_API_URL` | `https://api.github.com` | Override for mocks |
| `RUST_LOG` | `info` | JSON logs |

## Executor

| Var | Default | Notes |
|---|---|---|
| `CITE_LISTEN` | `0.0.0.0:8080` | |
| `CITE_PORT_BASE` | `3001` | Loopback: blue=base, green=base+1 |
| `CITE_TRUSTED_PROXIES` | empty | CIDRs allowed to set `X-Forwarded-*` |
| `CITE_ALLOWED_HOSTS` | empty | Empty = any |
| `CITE_MAX_BODY` | `100MB` | |
| `CITE_STATIC_HEADERS` | defaults | Extra/override static headers |
| `CITE_RUNTIME_ENV_FILE` | `/run/cite/runtime.env` | Runtime env file; read if present and overrides container env |
| runtime env | — | Container env not prefixed `CITE_` (see below) goes to the site process |

## Site environment variables

| File | Compose `env_file` on | Reaches |
|---|---|---|
| `build.env` (optional) | manager | install and build commands |
| `runtime.env` (optional) | executor | the SSR process |

Both files are optional (`required: false`). The manager and executor pass every container environment variable that is not prefixed `CITE_` and is not a host variable (`PATH`, `HOME`, `HOSTNAME`, `TERM`, `RUST_LOG`, `SSL_CERT_FILE`, `NODE_VERSION`, `YARN_VERSION`) to the build or SSR child, and redact their values in logs. `CITE_BUILD_ENV_FILE` and `CITE_RUNTIME_ENV_FILE` are read as well and win on conflict.

Builds run with a cleared environment plus these variables, so `CITE_GITHUB_TOKEN` never reaches build code. The executor is never given the PAT. Do not put the PAT in `build.env` or `runtime.env`.

## Executor image

`docker-compose.yml` runs `cite-executor-node`. For Bun or static-only sites, add a `docker-compose.override.yml` next to it (Compose loads it automatically):

```yaml
services:
  executor:
    image: ghcr.io/seggys116/cite-executor-static:${CITE_VERSION:-0.1.0}
```

Use `cite-executor-bun` for Bun sites. Both images set `CITE_RUNTIME` themselves.
