# Cite

Tiny autonomous self-hosted deploy stack for **one site**. Two containers share a volume: the **manager** watches a GitHub branch and builds, the **executor** serves with blue-green switching. No dashboard, no database, no Docker socket.

## Quickstart

```bash
git clone https://github.com/seggys116/cite.git
cd cite
cp .env.example .env
# edit .env: set CITE_REPO=owner/name and CITE_GITHUB_TOKEN=<PAT with contents:read>
docker compose up -d
# site listens on http://127.0.0.1:8080 (override with CITE_PORT / CITE_BIND)
docker compose exec manager cite status
```

Requirements: **Docker Engine 26+** and **Compose v2.26+**. See [docs/install.md](docs/install.md).

## What you get

| Piece | Role |
|---|---|
| `manager` | Poll GitHub, fetch tarball, build as uid 10002, promote into `blue`/`green` |
| `executor` | Shell-less HTTP server + SSR supervisor; atomic slot switch |
| Shared volume | At most two built releases + tiny JSON control/status/state files |

## Local development

```bash
cp .env.example .env    # set CITE_REPO and CITE_GITHUB_TOKEN
docker compose -f docker-compose.dev.yml up --build
# optional mock GitHub profile (see docs/troubleshooting.md):
docker compose -f docker-compose.dev.yml --profile mock up --build
./scripts/smoke.sh                 # cargo build manager + executor (debug)
./scripts/assert-compose.sh
```

## Docs

- [Install & disk sizing](docs/install.md)
- [Configuration reference](docs/config.md)
- [How blue-green works](docs/how-it-works.md)
- [Hardening](docs/hardening.md)
- [Threat model](docs/threat-model.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Multiple sites](docs/multi-site.md)
- [HTTPS in front](docs/https.md)
- [SECURITY](SECURITY.md)

## Licence

MIT. Copyright (c) 2026 Zak Noble-Clarke.
