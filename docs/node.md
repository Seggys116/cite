# Running a node

This page covers installing, configuring and operating one Cite node: HAProxy plus the connector, started from `docker-compose.node.yml`.

## What runs

| Service | Image | Role |
|---|---|---|
| `init` | `ghcr.io/seggys116/cite-connector:${CITE_VERSION:-0.2.0}` | One-shot. Creates `/conf/haproxy`, `/conf/certs` and `/conf/state` in the `cite_conf` volume owned by uid 10001, and sets the owner and mode of the `cite_run` volume at `/run/cite`, then exits. No network. |
| `haproxy` | `docker.io/library/haproxy:3.0-bookworm` | Public listener on ports 80 and 443. Reads its config from the `haproxy` and `certs` subpaths of `cite_conf`, mounted read-only. It cannot see the connector's credentials, tokens, secrets or TLS keys. |
| `connector` | `ghcr.io/seggys116/cite-connector:${CITE_VERSION:-0.2.0}` | Authenticated API on 7443, renders the HAProxy config, receives HAProxy's logs, runs the optional orchestrator. |

The two containers do not share a process namespace. They share one small volume, `cite_run`, mounted at `/run/cite` in both, which holds three unix sockets: HAProxy's admin socket (`admin.sock`), the master CLI (`master.sock`, from `-S /run/cite/master.sock,level,admin` on the HAProxy command) and the log datagram socket the connector binds (`log.sock`). The directory is owned by uid 10001 with mode 0750, the admin and log sockets are mode 0600, and no admin listener exists on any network. The connector reloads HAProxy by connecting to the master socket, sending `reload` and reading the reply: `Success=1` or `Success=0` followed by the loader output. It then checks that `show info` on the admin socket reports a new pid. A config counts as applied only after that check passes, so a refused or unconfirmed reload is retried on the next apply and fails the change that caused it. If the master CLI is unreachable (HAProxy is not up yet at first boot), applying a config still succeeds with `reloaded` false and the reason in the status `last_error`. Both containers run as uid 10001 with a read-only root filesystem, `no-new-privileges` and all capabilities dropped.

Two networks exist. `public` is a normal bridge. `cite_edge` is internal, so containers on it have no route out, and HAProxy is on it. Orchestrated executors normally sit on a network of their own per site and slot, which the connector creates and HAProxy joins; `cite_edge` is only used when that is switched off (see [Orchestrator](orchestrator.md#site-isolation)). The connector stays on `public` only because Docker cannot publish ports from an internal-only network; it is not on `cite_edge`. The orchestrator overlay adds a third, internal network, `docker_api`, between the connector and the Docker proxy.

## First start

Set the two required values in `.env`. Compose stops with a message if either is missing.

| Variable | Meaning |
|---|---|
| `CITE_CONNECTOR_ALLOW` | Source addresses allowed to connect to the API. Single addresses and CIDRs, separated by commas or spaces, up to 1024 entries. A list that includes `0.0.0.0/0` or `::/0` is rejected unless it also contains the token `allow-all`. |
| `CITE_CONNECTOR_BIND` | Host IP to publish the connector port on. Use a private interface address where you can. |

```bash
docker compose -f docker-compose.node.yml run --rm --no-deps init
docker compose -f docker-compose.node.yml run --rm --no-deps connector init
docker compose -f docker-compose.node.yml up -d
docker compose -f docker-compose.node.yml ps
```

A connection to a published port reaches the container from its network's gateway, not from `127.0.0.1`, on Linux as well as Docker Desktop. When `--allow` contains a loopback address, `scripts/setup.sh` therefore adds each stack's gateway address to that stack's allowlist, so a console on the same host works. Binding the port to `127.0.0.1` keeps it reachable from this host only.

The first command runs the compose `init` service, which fixes the ownership of the volumes. The second runs the connector's `init` subcommand. `scripts/setup.sh --mode node` runs the same steps, writes `.env` for you and keeps its own update, status, logs and uninstall commands; see the [README](../README.md#quickstart-node).

`init` writes `credentials.json` and the TLS material, then prints the following once:

| Item | Detail |
|---|---|
| Username | `admin` unless you choose another: 3 to 32 characters of `a-z`, `0-9`, `.`, `_`, `-`. |
| Password | 24 random characters. |
| TOTP key | Base32 key, `otpauth://` URI and a QR code. Codes are six digits with a 30 second step. |
| CA certificate | Path and SHA-256 fingerprint of the node's certificate authority. |

Save all of it. It cannot be shown again. `init` refuses to run when credentials exist and tells you to pass `--force` or use `reset-credentials`. A reset issues new credentials and revokes every API token. `reset-credentials` and `init --force` write a new generation number into `credentials.json` and `tokens.json`. A running connector notices the change on its next request, adopts the new credentials, drops the old API tokens and signs out every session, so no restart is needed. The CLI and the running connector take the same file lock (`auth.lock` in the data directory) around every credential and token write, and a connector write that started from older state is refused, so a reset cannot be undone by a request that was in flight.

The connector API will not start without credentials, but it still writes the HAProxy config first so HAProxy can boot.

## Connector settings

The compose file passes only `CITE_CONNECTOR_ALLOW`, `CITE_CONNECTOR_LISTEN` and `RUST_LOG` into the connector. To set any other variable in the table, add it under `environment:` for the `connector` service in an override file.

```yaml
# docker-compose.override.yml
services:
  connector:
    environment:
      CITE_NODE_NAME: edge-fra-1
      CITE_CONNECTOR_SANS: edge.example.com,203.0.113.20
```

Compose reads `docker-compose.override.yml` automatically only when you run `docker compose` without `-f`. With `-f docker-compose.node.yml`, add `-f docker-compose.override.yml` yourself.

| Variable | Default | Meaning |
|---|---|---|
| `CITE_CONNECTOR_ALLOW` | none, required | Source allowlist, as above. |
| `CITE_CONNECTOR_LISTEN` | `0.0.0.0:7443` | Address the API binds inside the container. Compose sets the same value. |
| `CITE_CONNECTOR_DATA` | `/conf` | Data directory. |
| `CITE_NODE_NAME` | `HOSTNAME`, else `node` | Name shown in the API and used in certificates and the TOTP account. Letters, digits, `-`, `_`, `.`, up to 64 characters. Inside a container `HOSTNAME` is usually the container id, so set a name. |
| `CITE_CONNECTOR_TLS` | `true` | Serve the API over TLS. When false the connector logs a warning and expects a trusted tunnel. |
| `CITE_CONNECTOR_SANS` | empty | Extra host names or IPs for the server certificate, comma separated, up to 32. The certificate always covers `localhost`, `127.0.0.1`, `::1` and the node name. |
| `CITE_SESSION_TTL` | `28800` (8 hours) | Session lifetime in seconds, from 60 to 2592000. Sessions also expire after 30 minutes idle. |
| `CITE_HAPROXY_RUNTIME` | `haproxy:9999` | Where the connector reaches HAProxy's admin socket: `host:port`, or `unix:/path` for a unix socket. Compose sets `unix:/run/cite/admin.sock`, and the rendered config then declares `stats socket unix@/run/cite/admin.sock` with mode 600. |
| `CITE_HAPROXY_MASTER` | next to the runtime address | Where the connector reaches HAProxy's master CLI, used for reloads. Defaults to port `9998` on the runtime host, or `master.sock` beside a unix runtime socket. Compose sets `unix:/run/cite/master.sock`. It must match the `-S` socket in the `haproxy` command in `docker-compose.node.yml`. |
| `CITE_HAPROXY_BIN` | `haproxy` | Binary used for `haproxy -c` validation. |
| `CITE_HAPROXY_VALIDATE` | `true` | Run `haproxy -c` on a staged copy before installing a config. |
| `CITE_LOG_LISTEN` | `0.0.0.0:5140` | Where the log sink binds: a UDP `host:port`, or `unix:/path` for a unix datagram socket (any stale socket file is replaced and the new one is mode 0600). Compose sets `unix:/run/cite/log.sock`. The receive buffer is raised to 4 MiB so bursts are not dropped. |
| `CITE_LOG_ADDR` | `connector:5140`, or the `CITE_LOG_LISTEN` path for a unix listener | Address HAProxy sends logs to. For a UDP sink it must be an IP literal because HAProxy does not resolve names there; for a unix sink it is the socket path. Compose sets `/run/cite/log.sock`. |
| `CITE_ANALYTICS_DB` | `<data dir>/analytics/analytics.db` | Absolute path of the SQLite analytics database. See [analytics](analytics.md). |
| `CITE_ANALYTICS_MAX_BYTES` | unset | Optional size cap for the analytics database, 8 MiB to 1 TiB. Unset keeps everything until its retention age; when set, the oldest rows are removed first. |
| `CITE_DOCKER_HOST` | unset | Enables the orchestrator. The overlay sets `http://dockerproxy:2375`. |
| `CITE_HAPROXY_CONTAINER` | `cite-node-haproxy` | Name of the HAProxy container, which the connector attaches to each stack's network. The overlay sets it. An empty value turns per-stack networks off. |
| `CITE_EDGE_NETWORK` | `cite_edge` | Shared network that executors join when per-stack networks are off. |
| `CITE_STACK_VERSION` | the connector's version | Image tag used for orchestrated stacks. |
| `CITE_REGISTRY` | `ghcr.io/seggys116` | Registry prefix for orchestrated stack images. |
| `CITE_DEPLOY_BUILD_TIMEOUT` | `600` | Seconds a deploy or switch waits for a repo-built slot to become healthy. 60 to 3600. Upstream-only sites keep the 60 second health wait. |
| `CITE_STACK_GITHUB_API_URL` | unset (managers use `https://api.github.com`) | GitHub API base URL passed to every orchestrated manager as `CITE_GITHUB_API_URL`, for GitHub Enterprise Server. An `http` or `https` URL of at most 200 characters, with no user name, query or fragment. The Docker proxy must have the same value in `CITE_PROXY_GITHUB_API_URL`, or it refuses to create the managers. The overlay sets both from `CITE_GITHUB_API_URL` in `.env`. See [Orchestrator](orchestrator.md#github-enterprise-server-and-the-api-url). |
| `RUST_LOG` | `info` | Log level. |

Boolean values accept `1`, `true`, `yes`, `on`, `0`, `false`, `no`, `off`. The connector refuses to start on a malformed value.

## Compose settings

| Variable | Default | Meaning |
|---|---|---|
| `CITE_VERSION` | `0.2.0` | Connector image tag. |
| `CITE_HTTP_PORT` | `80` | Host port for HTTP. |
| `CITE_HTTPS_PORT` | `443` | Host port for HTTPS. |
| `CITE_PUBLIC_BIND` | `0.0.0.0` | Host IP for the two public ports. |
| `CITE_CONNECTOR_PORT` | `7443` | Host port for the connector API. |
| `CITE_HAPROXY_MEM`, `CITE_HAPROXY_CPUS`, `CITE_HAPROXY_PIDS` | `1g`, `2.0`, `512` | HAProxy limits. |
| `CITE_CONNECTOR_MEM`, `CITE_CONNECTOR_CPUS`, `CITE_CONNECTOR_PIDS` | `512m`, `1.0`, `256` | Connector limits. |

HAProxy binds HTTPS only when `settings.https_port` is set in the node's configuration and the directory `/conf/certs` exists. The bind loads every certificate in that directory and requires TLS 1.2 or newer.

## What is stored

Everything lives in the `cite_conf` volume, mounted at `/conf`.

| Path | Mode | Contents |
|---|---|---|
| `edge.json` | 0600 | The node's configuration: sites, maintenance pages, firewall rules, settings. |
| `credentials.json` | 0600 | Username, Argon2id password hash, TOTP secret. |
| `tokens.json` | 0600 | API token hashes, names and last-used times. At most 64 tokens. |
| `secrets.json` | 0600 | GitHub tokens for orchestrated sites. |
| `audit.jsonl`, `audit.jsonl.1` | 0600 | Audit log of changes and logins. |
| `analytics/analytics.db` | 0600 | SQLite analytics database, with its `-wal` and `-shm` files. An old `analytics.json` is imported once and then deleted. |
| `tls/` | 0700 | `ca.pem`, `ca.key`, `server.pem` and the server key. |
| `haproxy/haproxy.cfg` | 0644 | Rendered config. Overwritten on every change, do not edit it. |
| `haproxy/maps/active.map`, `maint.map` | 0644 | Active slot and maintenance flag per site. `active.map` also carries `<host>@<run>` keys that route runs of four or more plain sites (exact hosts, no path regex) with one lookup. |
| `haproxy/pages/` | 0644 | Maintenance pages, including `_default.html`. |

Back up the volume to keep sites, rules and credentials. Treat the backup as a secret.

## Operating it

| Task | Command or call |
|---|---|
| Logs | `docker compose -f docker-compose.node.yml logs -f connector` |
| Health | `docker compose -f docker-compose.node.yml ps` (the connector runs `cite-connector healthcheck` every 30 seconds) |
| View the rendered config | `GET /api/v1/haproxy/config` |
| Force a reload | `POST /api/v1/haproxy/reload` (reloads even when the config is unchanged) |
| Lost the password or TOTP device | `docker compose -f docker-compose.node.yml run --rm --no-deps connector reset-credentials`. The running connector picks up the new credentials on its next request, so no restart is needed |
| Update | Set `CITE_VERSION`, `docker compose -f docker-compose.node.yml pull`, then `up -d` |

The healthcheck requests `/api/v1/healthz` over the container's loopback address. The connector admits loopback peers for `/healthz` only, so the check works whatever the allowlist says.

Every change is validated and dry-rendered before it is stored. If `haproxy -c` rejects the rendered config, it cannot be installed, or a running HAProxy refuses to load it, the change is refused and the previous stored configuration is restored and loaded again. After a reload signal the connector waits up to five seconds for a new HAProxy worker. If none appears, `GET /api/v1/node` reports `haproxy.last_reload_ok` as false with the reason in `haproxy.last_error`.

After a connector restart the idle stack of each orchestrated site is stopped once its active slot passes health checks, since the drain timers do not survive a restart.

See [Connector API](node-api.md) for every route, [Orchestrator](orchestrator.md) to build sites from GitHub, and [Security model](security-model.md) for what the node exposes.
