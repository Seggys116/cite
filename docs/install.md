# Install

## Requirements

| Component | Minimum | Notes |
|---|---|---|
| Docker Engine | **26.0+** | Named volume **subpath** mounts |
| Docker Compose | **v2.26+** | `volume.subpath` and optional `env_file` (`required: false`) |
| Disk | See sizing below | Shared volume holds **at most two** built sites |
| GitHub PAT | `contents:read` on the target repo | Set as `CITE_GITHUB_TOKEN` in `.env`; passed to the manager only |

Confirm:

```bash
docker version
docker compose version
docker compose -f docker-compose.yml config -q
```

## Disk sizing

| Volume | Suggested size | Contents |
|---|---|---|
| `cite_data` | **≥ 2×** largest release + 50 MB | `releases/{blue,green}`, `control/`, `status/`, `state/` only |
| `cite_work` | **≥** `CITE_MAX_WORK_BYTES` (default 4 GB) | Build scratch; empty between builds |
| `cite_cache` | **≥** `CITE_CACHE_MAX_BYTES` (default 2 GB) | npm/pnpm/bun caches |

Defaults refuse to build when free space drops below `CITE_MIN_FREE_BYTES` (2 GB). Plan **~8–12 GB** free for a typical SSR Node site.

### Subpath mounts

Compose mounts **subpaths** of `cite_data` so each container only sees what it needs:

| Subpath | Manager | Executor |
|---|---|---|
| `releases/` | rw | **ro** |
| `control/` | rw | **ro** |
| `status/` | **ro** | rw |
| `state/` | rw | — |

`cite_work` and `cite_cache` are manager-only volumes.

On every start, a one-shot `init` service (the manager image, `CHOWN` and `FOWNER` only, no network) creates the subpaths inside the named volume with the right owners before the manager and executor start; Docker refuses to mount a subpath that does not exist. If an older Engine rejects `volume.subpath`, upgrade Compose/Engine before proceeding.

## Production install

```bash
git clone https://github.com/seggys116/cite.git && cd cite
cp .env.example .env
$EDITOR .env                 # set CITE_REPO and CITE_GITHUB_TOKEN; optional CITE_BRANCH / CITE_NODE
chmod 600 .env
docker compose pull
docker compose up -d
curl -fsS "http://127.0.0.1:${CITE_PORT:-8080}/" || true
docker compose exec manager cite status
```

Images:

- `ghcr.io/seggys116/cite-manager:${CITE_VERSION}-node${CITE_NODE}`
- `ghcr.io/seggys116/cite-executor-node:${CITE_VERSION}-node${CITE_NODE}`

Default host port is **8080** (container listens on 8080). Set `CITE_PORT=80` if you want host port 80.

`.env` is gitignored. It holds the PAT, so keep it out of backups and shared shells. Site build-time and runtime variables go in optional `build.env` and `runtime.env` files; see [config.md](config.md).

## Development install

```bash
cp .env.example .env    # set CITE_REPO and CITE_GITHUB_TOKEN
docker compose -f docker-compose.dev.yml up --build
```
