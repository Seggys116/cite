# Running a node

This page covers installing, configuring and operating one Cite node: HAProxy plus the connector, started from `docker-compose.node.yml`.

## What runs

| Service | Image | Role |
|---|---|---|
| `init` | `ghcr.io/seggys116/cite-connector:${CITE_VERSION:-0.2.0}` | One-shot. Creates `/conf/haproxy` and `/conf/state` in the `cite_conf` volume owned by uid 10001, then exits. No network. |
| `haproxy` | `docker.io/library/haproxy:3.0-bookworm` | Public listener on ports 80 and 443. Reads its config from `cite_conf` mounted read-only. |
| `connector` | `ghcr.io/seggys116/cite-connector:${CITE_VERSION:-0.2.0}` | Authenticated API on 7443, renders the HAProxy config, receives HAProxy's logs, runs the optional orchestrator. |

The connector joins HAProxy's process namespace (`pid: service:haproxy`). That is how it finds the HAProxy master process and sends it `SIGUSR2` to reload. Both containers run as uid 10001 with a read-only root filesystem, `no-new-privileges` and all capabilities dropped.

Two networks exist. `public` is a normal bridge. `cite_edge` is internal, so containers on it have no route out. HAProxy and the connector are on both. Orchestrated site executors are on `cite_edge` only.

## First start

Set the two required values in `.env`. Compose stops with a message if either is missing.

| Variable | Meaning |
|---|---|
| `CITE_CONNECTOR_ALLOW` | Source addresses allowed to connect to the API. Single addresses and CIDRs, separated by commas or spaces, up to 1024 entries. A list that includes `0.0.0.0/0` or `::/0` is rejected unless it also contains the token `allow-all`. |
| `CITE_CONNECTOR_BIND` | Host IP to publish the connector port on. Use a private interface address where you can. |

```bash
docker compose -f docker-compose.node.yml run --rm connector init
docker compose -f docker-compose.node.yml up -d
docker compose -f docker-compose.node.yml ps
```

`init` writes `credentials.json` and the TLS material, then prints the following once:

| Item | Detail |
|---|---|
| Username | `admin` unless you choose another: 3 to 32 characters of `a-z`, `0-9`, `.`, `_`, `-`. |
| Password | 24 random characters. |
| TOTP key | Base32 key, `otpauth://` URI and a QR code. Codes are six digits with a 30 second step. |
| CA certificate | Path and SHA-256 fingerprint of the node's certificate authority. |

Save all of it. It cannot be shown again. `init` refuses to run when credentials exist and tells you to pass `--force` or use `reset-credentials`. A reset issues new credentials and revokes every API token.

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
| `CITE_HAPROXY_RUNTIME` | `haproxy:9999` | Address of HAProxy's runtime socket. |
| `CITE_HAPROXY_BIN` | `haproxy` | Binary used for `haproxy -c` validation. |
| `CITE_HAPROXY_VALIDATE` | `true` | Run `haproxy -c` on a staged copy before installing a config. |
| `CITE_LOG_LISTEN` | `0.0.0.0:5140` | UDP address the log sink binds. |
| `CITE_LOG_ADDR` | `connector:5140` | Address HAProxy sends logs to. |
| `CITE_DOCKER_HOST` | unset | Enables the orchestrator. The overlay sets `tcp://socketproxy:2375`. |
| `CITE_EDGE_NETWORK` | `cite_edge` | Network that orchestrated executors join. |
| `CITE_STACK_VERSION` | the connector's version | Image tag used for orchestrated stacks. |
| `CITE_REGISTRY` | `ghcr.io/seggys116` | Registry prefix for orchestrated stack images. |
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
| `analytics.json` | 0600 | Analytics snapshot. |
| `tls/` | 0700 | `ca.pem`, `ca.key`, `server.pem` and the server key. |
| `haproxy/haproxy.cfg` | 0644 | Rendered config. Overwritten on every change, do not edit it. |
| `haproxy/maps/active.map`, `maint.map` | 0644 | Active slot and maintenance flag per site. |
| `haproxy/pages/` | 0644 | Maintenance pages, including `_default.html`. |

Back up the volume to keep sites, rules and credentials. Treat the backup as a secret.

## Operating it

| Task | Command or call |
|---|---|
| Logs | `docker compose -f docker-compose.node.yml logs -f connector` |
| Health | `docker compose -f docker-compose.node.yml ps` (the connector runs `cite-connector healthcheck` every 30 seconds) |
| View the rendered config | `GET /api/v1/haproxy/config` |
| Force a reload | `POST /api/v1/haproxy/reload` |
| Lost the password or TOTP device | Run the connector's `reset-credentials` subcommand the same way as `init`, then restart the connector |
| Update | Set `CITE_VERSION`, `docker compose -f docker-compose.node.yml pull`, then `up -d` |

The healthcheck requests `/api/v1/healthz` over the container's loopback address. The connector admits loopback peers for `/healthz` only, so the check works whatever the allowlist says.

Every change is validated and dry-rendered before it is stored. If `haproxy -c` rejects the rendered config, or it cannot be installed, the change is refused and the previous stored configuration is restored. After a reload signal the connector waits up to five seconds for a new HAProxy worker. If none appears, `GET /api/v1/node` reports `haproxy.last_reload_ok` as false with the reason in `haproxy.last_error`.

See [Connector API](node-api.md) for every route, [Orchestrator](orchestrator.md) to build sites from GitHub, and [Security model](security-model.md) for what the node exposes.
