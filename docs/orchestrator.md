# Orchestrator

This page covers the optional orchestrator: how a node's connector builds and runs sites from GitHub through the Docker API, what it creates, and what it costs in privilege.

## Enabling it

```bash
docker compose -f docker-compose.node.yml -f docker-compose.orchestrator.yml up -d
```

The overlay adds a `socketproxy` service (`docker.io/tecnativa/docker-socket-proxy:0.3.0`) and an internal network `docker_api`. It sets `CITE_DOCKER_HOST=tcp://socketproxy:2375` on the connector and attaches the connector to `docker_api`. The proxy is the only container that mounts `/var/run/docker.sock`, read-only.

`CITE_DOCKER_HOST` is what switches the orchestrator on. It accepts a bare `tcp://host:port` or `http://host:port`. Unix sockets, paths and query strings are rejected. At start the connector pings the Docker API and logs a warning if it cannot reach it. It keeps running, and deploys that need Docker fail until the API answers.

Without the overlay, the connector runs no containers. A site can then only route to upstream addresses you provide in its blue and green targets, and creating or updating a site with a `source` is refused.

## Socket proxy scope

| Allowed | Denied |
|---|---|
| `CONTAINERS`, `NETWORKS`, `VOLUMES`, `IMAGES`, and `POST` (so those can be created and changed) | `EXEC`, `BUILD`, `COMMIT`, `SERVICES`, `SWARM`, `SECRETS`, `CONFIGS`, `DISTRIBUTION`, `PLUGINS`, `SYSTEM`, `AUTH`, `INFO`, `EVENTS`, `NODES`, `SESSION`, `TASKS` |

The proxy limits which API endpoints the connector can call. It does not look inside a request. A client that may create containers can still ask for a privileged container or a bind mount of the host's root. Read [Security model](security-model.md) before enabling this on a node that holds anything you care about.

The connector uses Docker Engine API v1.45, which is why Docker Engine 26 or newer is required.

## What a site stack is

A site with a `source` gets one stack per slot, created when the slot is first used. Names use the site id and slot: for site `shop` in the blue slot, `cite-shop-blue-manager`, `cite-shop-blue-executor`, `cite-shop-blue-init`, volumes `cite-shop-blue-data`, `-work` and `-cache`, and network `cite-shop-blue-egress`.

| Container | Role | Network | Limits |
|---|---|---|---|
| `init` | Lays out the data volume, then exits | none | 128 MiB, 64 pids, caps `CHOWN` and `FOWNER` only |
| `manager` | Polls the repo, builds, promotes into the stack's own volume | `cite-<id>-<slot>-egress`, its own network | 2 GiB, 2 CPUs, 2048 pids |
| `executor` | Serves the built site on port 8080 | `cite_edge` (internal), alias `cite-<id>-<slot>-executor` | 1 GiB, 1 CPU, 256 pids, runs as 65532 |

Both long-running containers have `ReadonlyRootfs`, `no-new-privileges`, all capabilities dropped (the manager gets back `CHOWN`, `SETUID`, `SETGID` and `DAC_READ_SEARCH` to build as an unprivileged user), an init process, a health check every 30 seconds and a 10 MiB by 3 file log cap. They mount only their own named volumes, with subpath mounts matching single-site mode: the executor sees releases and control read-only. No host paths are mounted.

HAProxy reaches the executor at `cite-<id>-<slot>-executor:8080` over `cite_edge`. The connector writes that address into the slot's targets.

These specifications mirror the `manager` and `executor` services in `docker-compose.yml`, so the single-site hardening in [Hardening](hardening.md) applies to each stack.

## Source settings

The `source` object on a site:

| Field | Default | Notes |
|---|---|---|
| `repo` | required | `owner/name`. |
| `branch` | `main` | Git branch to build. A deploy can override it with a ref. |
| `runtime` | `node` | One of `node`, `bun`, `static`, `rust`. |
| `node_major` | `22` | `22` or `24`. Ignored by the `rust` runtime. |
| `poll_interval` | `5m` | How often the manager checks GitHub. Minimum 60 seconds. |
| `secret` | none | Set by the connector. A value sent by a client is discarded. |

Images come from `CITE_REGISTRY` (default `ghcr.io/seggys116`) at tag `CITE_STACK_VERSION`:

| Runtime | Manager image | Executor image |
|---|---|---|
| `node` | `cite-manager:<version>-node<major>` | `cite-executor-node:<version>-node<major>` |
| `bun` | `cite-manager:<version>-node<major>` | `cite-executor-bun:<version>` |
| `static` | `cite-manager:<version>-node<major>` | `cite-executor-static:<version>` |
| `rust` | `cite-manager-rust:<version>` | `cite-executor-rust:<version>` |

Images are pulled only when they are not present locally; a pull can take up to 10 minutes before it times out.

## GitHub token

The token is supplied when the site is created. The connector stores it in `secrets.json` (mode 0600, up to 512 secrets, 16 KiB each) under a name it chooses from the site id, and records only that name in the site. It reaches the manager as `CITE_GITHUB_TOKEN` in the container's environment. It is not in container labels or in `edge.json`. Anyone who can inspect containers through the Docker API can read it, including the connector.

## Lifecycle

| Event | What happens |
|---|---|
| Create | Pulls images, creates volumes and the egress network, runs `init`, starts the manager and executor, sets the slot's target, applies the HAProxy config and waits up to 30 seconds for health. An unhealthy site is still created and an audit entry is written. If the stack fails to start, the stored secret is dropped and no site is created. If HAProxy rejects the new config, the stack and secret are removed. |
| Deploy | Starts the idle slot's stack, writes its target, waits up to 60 seconds for health, switches. A failed start or health check stops only the idle stack and records a `failed` deployment. |
| Switch, rollback | Restart the target slot's stack if it was stopped, check health, flip. |
| After a switch | The previous slot's stack stays up for a 30 second drain delay, then the executor and manager are stopped (the executor first). Volumes are kept so a rollback is fast. If the site has moved back in the meantime, nothing is stopped. |
| Update | Replaces the site's fields and keeps history and the stored secret. |
| Delete | Removes the site from HAProxy, then removes its stacks and deletes volumes and the stored secret. |

The connector compares each running container's image and environment with what it wants. A changed branch or token recreates only the manager. Containers it did not create are never adopted or removed: a name clash is reported as a conflict.

Deployment history keeps the last 50 entries per site.

## Resource planning

Each active stack holds up to 3 GiB of memory limit and a data, work and cache volume. Sizing for those volumes is the same as in [Install](install.md#disk-sizing). A stopped standby stack frees its memory but keeps its volumes.
