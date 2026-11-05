<div align="center">

<img src="./.github/assets/hero.svg" alt="Cite: blue/green edge for self-hosted sites, one connector per node, one dashboard for all of them" width="880">

**Self-hosted blue/green deploys for one site, or for a fleet of nodes behind one console.**

[![CI](https://github.com/seggys116/cite/actions/workflows/ci.yml/badge.svg)](https://github.com/seggys116/cite/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-ce422b.svg)](./LICENSE)
[![Docker 26+](https://img.shields.io/badge/docker-26%2B-2496ed.svg)](https://docs.docker.com/engine/)
![Platforms](https://img.shields.io/badge/platforms-Linux-30363d.svg)

[Modes](#two-modes) · [How it works](#how-it-works) · [Single site](#quickstart-single-site) · [Node](#quickstart-node) · [Dashboard](#dashboard) · [Security](#security) · [Docs](#docs)

<img src="./.github/assets/divider.svg" alt="" width="880">

</div>

<br>

> Cite builds a site from a GitHub branch into an idle slot, checks that it is healthy, and only then points traffic at it.
> A bad build never receives a request. In node mode the same idea runs behind HAProxy, with a firewall, maintenance pages
> and traffic analytics managed from one console.

<table>
<tr>
<td width="25%" valign="top"><b>Blue/green switch</b><br><sub>The new release is built and health-checked in the idle slot. Traffic moves by changing one entry in a map, with no proxy reload.</sub></td>
<td width="25%" valign="top"><b>Edge firewall</b><br><sub>Path, method, user agent, address and host rules that deny, silently drop or tarpit. Four presets cover common probes.</sub></td>
<td width="25%" valign="top"><b>Analytics</b><br><sub>Requests, status classes, latency percentiles and top paths from HAProxy's own logs, held in bounded memory with set retention.</sub></td>
<td width="25%" valign="top"><b>Many nodes, one console</b><br><sub>A connector on each node exposes an authenticated API. The dashboard talks to all of them and can replicate a site to every node.</sub></td>
</tr>
</table>

## Two modes

| | Single-site mode | Node mode |
|---|---|---|
| Compose file | `docker-compose.yml` | `docker-compose.node.yml`, optionally with `docker-compose.orchestrator.yml` |
| Sites | One, from one GitHub repo | Many, routed by host name and optional path regex |
| Components | `manager` and `executor` sharing a volume | HAProxy and the connector, plus a manager and executor per site when orchestration is on |
| Control | `docker compose exec manager cite status` | Connector API on port 7443, driven by the dashboard |
| Docker socket | Never mounted | Only with the orchestrator overlay, through a filtering proxy |

Single-site mode is two containers, no dashboard, no database and no Docker socket. Node mode adds those pieces and the trade-offs that come with them. [Security model](docs/security-model.md) lists what changes.

<p align="center"><img src="./.github/assets/divider.svg" alt="" width="880"></p>

## How it works

In single-site mode the manager polls a GitHub branch, downloads the tarball and builds it as an unprivileged user. It writes the result into the idle slot, and the executor switches to it atomically once it is healthy.

In node mode HAProxy sits in front. The connector renders `haproxy.cfg` from a JSON model, writes two map files, and receives HAProxy's logs over UDP. A request is checked against the firewall, then against the maintenance map, then routed to the backend named in `active.map`.

<p align="center"><img src="./.github/assets/flow.svg" alt="Clients reach HAProxy, which applies the firewall and routes through active.map to the live blue slot while the green slot stands by; the connector manages config and receives logs" width="880"></p>

Deploying to a site stages the new targets in the idle slot, which is a config change and reloads HAProxy once. Switching traffic afterwards, and toggling maintenance mode, are runtime map updates that need no reload. [Firewall and maintenance](docs/firewall.md) explains the mechanism.

<p align="center"><img src="./.github/assets/divider.svg" alt="" width="880"></p>

## Topology

<p align="center"><img src="./.github/assets/topology.svg" alt="The dashboard connects over TLS with a token and TOTP to the connector on each node; each node runs a connector, HAProxy and its blue/green sites" width="880"></p>

Each node is independent. A node keeps serving if the dashboard is offline, because HAProxy reads its config and maps from disk.

<p align="center"><img src="./.github/assets/divider.svg" alt="" width="880"></p>

## Quickstart: single site

```bash
git clone https://github.com/seggys116/cite.git
cd cite
cp .env.example .env
# edit .env: set CITE_REPO=owner/name and CITE_GITHUB_TOKEN=<PAT with contents:read>
docker compose up -d
# site listens on http://127.0.0.1:8080 (override with CITE_PORT / CITE_BIND)
docker compose exec manager cite status
```

Requirements: Docker Engine 26+ and Compose v2.26+. See [docs/install.md](docs/install.md).

Images are published to `ghcr.io/seggys116` (used by `docker-compose.yml`) and mirrored to Docker Hub as `docker.io/seggy116`. Rust sites use a separate image pair, `cite-manager-rust` and `cite-executor-rust`; see [docs/sites.md](docs/sites.md#rust).

| Piece | Role |
|---|---|
| `manager` | Poll GitHub, fetch tarball, build as uid 10002, promote into `blue`/`green` |
| `executor` | Shell-less HTTP server and SSR supervisor; atomic slot switch |
| Shared volume | At most two built releases and tiny JSON control, status and state files |

<p align="center"><img src="./.github/assets/divider.svg" alt="" width="880"></p>

## Quickstart: node

Two values in `.env` are required, and compose refuses to start without them:

| Variable | Meaning |
|---|---|
| `CITE_CONNECTOR_ALLOW` | Addresses or CIDRs allowed to reach the connector API, comma or space separated. `0.0.0.0/0` is refused unless the list also contains `allow-all`. |
| `CITE_CONNECTOR_BIND` | Host IP the connector port is published on. |

```bash
git clone https://github.com/seggys116/cite.git
cd cite
cat >> .env <<'EOF'
CITE_CONNECTOR_ALLOW=203.0.113.10
CITE_CONNECTOR_BIND=203.0.113.20
EOF
docker compose -f docker-compose.node.yml run --rm connector init
docker compose -f docker-compose.node.yml up -d
```

`init` creates the login and the node's TLS certificate authority. It prints the username (default `admin`), a 24-character password and a TOTP key with a QR code, then the CA certificate path and its SHA-256 fingerprint. They are shown once. The connector refuses to start its API until `init` has run.

HAProxy publishes ports 80 and 443 (`CITE_HTTP_PORT`, `CITE_HTTPS_PORT`, `CITE_PUBLIC_BIND`). The connector API listens on 7443 (`CITE_CONNECTOR_PORT`). `docker compose -f docker-compose.node.yml ps` shows the connector as healthy once it is up.

To let the connector build and run sites from GitHub itself, add the orchestrator overlay:

```bash
docker compose -f docker-compose.node.yml -f docker-compose.orchestrator.yml up -d
```

Without it, a site routes to upstream addresses you run yourself. [Running a node](docs/node.md) covers every setting, and [Orchestrator](docs/orchestrator.md) covers what the overlay changes.

<p align="center"><img src="./.github/assets/divider.svg" alt="" width="880"></p>

## Dashboard

The dashboard is a browser console with seven views: Overview, Nodes, Sites, Traffic, Firewall, Maintenance and Settings. A node switcher scopes every view to one node or to all of them. Signing in takes a username, a password and a six-digit authenticator code. A node is added with a name, its connector URL and a connector API token.

```bash
docker compose -f docker-compose.dashboard.yml up -d
docker compose -f docker-compose.dashboard.yml logs dashboard
```

Open `http://127.0.0.1:8088` and enter the one-time setup token from the log to create the first account.

The console source is in `crates/cite-dashboard/web`. [Dashboard](docs/dashboard.md) describes each view and the API the console uses.

## Adding a site

Open Sites, then Create site. The form asks for:

| Field | Notes |
|---|---|
| Hosts | One to 64 host names, exact or `*.example.com`. Requests with a matching `Host` header go to this site. |
| Path regex | Optional. When set, the site only receives paths that match, so an API can share a host with a front end. |
| Blue and green targets | `host:port` upstreams per slot. At least one blue target is needed. |
| Health check path | Must start with `/`. Defaults are every 2000 ms, healthy after 2 passes and down after 3 failures. |
| Nodes | Selected nodes, or Replicate to all nodes. |

A later deploy writes new targets into the idle slot, waits up to 60 seconds for every target to pass its health check, then flips the active slot. If a check fails the active slot is untouched and the attempt is recorded as `failed`. Roll back from the site page, which returns traffic to the previous slot.

<p align="center"><img src="./.github/assets/divider.svg" alt="" width="880"></p>

## Firewall and maintenance

Rules run in list order before routing. Each has an action: `deny` answers 403, `drop` closes the connection without a reply, and `tarpit` holds the request for 5 seconds before failing it. Matchers cover path regex, path prefix, method, user agent regex, client CIDR and host, and a rule can be limited to one site.

Four presets add ready-made rules: `sensitive-files`, `cms-probes`, `scanners` and `odd-methods`. A per-IP limit of 600 requests per 10 seconds applies by default and answers 429.

Maintenance mode serves an HTML page with status 503 by default for one site while leaving the others alone. Custom pages can use any status from 400 to 599. See [docs/firewall.md](docs/firewall.md).

## Analytics and retention

HAProxy sends one log line per request to the connector. The connector keeps counters and a bounded list of recent requests, saves a snapshot to `analytics.json` every 60 seconds and restores it on restart.

| Setting | Default |
|---|---|
| Recent requests kept | 5000 |
| Per-minute history | 48 hours |
| Per-hour history | 90 days |
| Audit log | 365 days |
| Store client IPs and user agents | on |

Turning off client IPs or user agents also erases what was collected. Query strings are never stored, only their length. See [docs/analytics.md](docs/analytics.md).

<p align="center"><img src="./.github/assets/divider.svg" alt="" width="880"></p>

## Security

Single-site mode keeps its original posture: no Docker socket, a shell-less executor, builds as an unprivileged user and a read-only root filesystem. See [hardening](docs/hardening.md) and the [threat model](docs/threat-model.md).

In node mode, the connector API is reached in this order: source address allowlist, TLS, then a bearer token. Logging in needs a password and a TOTP code, and failed logins are rate limited. API tokens and sessions are stored as SHA-256 hashes. Every configuration change is validated before it is rendered, and the rendered file is checked with `haproxy -c` before HAProxy loads it (unless `CITE_HAPROXY_VALIDATE` is set to false).

The orchestrator overlay gives the connector access to the Docker API through a filtering proxy. The proxy limits which endpoints are reachable but cannot stop a client that may create containers from asking for privileged ones, so a compromised connector is close to host root. The [security model](docs/security-model.md) states this and the other limits plainly.

## Requirements

| Component | Minimum |
|---|---|
| Docker Engine | 26.0 (named volume subpath mounts, Engine API 1.45) |
| Docker Compose | v2.26 |
| Host | Linux. The connector reads `/proc` of the HAProxy container to signal reloads. |
| GitHub token | `contents:read` on each repo built (single-site mode, and orchestrated sites) |

## Local development

```bash
cp .env.example .env    # set CITE_REPO and CITE_GITHUB_TOKEN
docker compose -f docker-compose.dev.yml up --build
# optional mock GitHub profile (see docs/troubleshooting.md):
docker compose -f docker-compose.dev.yml --profile mock up --build
./scripts/smoke.sh                 # cargo build manager + executor (debug)
./scripts/assert-compose.sh
```

<p align="center"><img src="./.github/assets/divider.svg" alt="" width="880"></p>

## Docs

| Single-site mode | Node mode |
|---|---|
| [Install and disk sizing](docs/install.md) | [Running a node](docs/node.md) |
| [Configuration reference](docs/config.md) | [Dashboard](docs/dashboard.md) |
| [How blue-green works](docs/how-it-works.md) | [Firewall and maintenance](docs/firewall.md) |
| [Hardening](docs/hardening.md) | [Analytics and retention](docs/analytics.md) |
| [Threat model](docs/threat-model.md) | [Orchestrator](docs/orchestrator.md) |
| [Troubleshooting](docs/troubleshooting.md) | [Connector API](docs/node-api.md) |
| [Multiple sites](docs/multi-site.md) | [Security model](docs/security-model.md) |
| [Running real sites](docs/sites.md) | |
| [HTTPS in front](docs/https.md) | |

[SECURITY](SECURITY.md) describes how to report a vulnerability.

<br>

<p align="center"><sub>MIT licensed &middot; &copy; 2026 Zak Noble-Clarke</sub></p>
