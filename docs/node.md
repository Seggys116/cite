# Running a node

This page covers installing, configuring and operating one Cite node: HAProxy plus the connector, started from `docker-compose.node.yml`.

## What runs

| Service | Image | Role |
|---|---|---|
| `init` | `ghcr.io/seggys116/cite-connector:${CITE_VERSION:-0.4.1}` | One-shot. Creates `/conf/haproxy`, `/conf/certs` and `/conf/state` in the `cite_conf` volume owned by uid 10001, and sets the owner and mode of the `cite_run` volume at `/run/cite`, then exits. No network. |
| `haproxy` | `docker.io/library/haproxy:3.2-bookworm` | Public listener on ports 80 and 443. Reads its config from the `haproxy` and `certs` subpaths of `cite_conf`, mounted read-only. It cannot see the connector's credentials, tokens, secrets or TLS keys. |
| `connector` | `ghcr.io/seggys116/cite-connector:${CITE_VERSION:-0.4.1}` | Authenticated API on 7443, renders the HAProxy config, receives HAProxy's logs, runs the optional orchestrator. |

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

HAProxy needs a config file to start, and only the connector writes the real one. The `init` service therefore also writes a small bootstrap `/conf/haproxy/haproxy.cfg` when none exists (owner 10001, mode 0640): one frontend on port 80 that answers 404 "no sites configured yet". HAProxy starts and stays up on it, and the connector's first apply replaces the file and reloads HAProxy through the master socket like any other change. A node that already has a `haproxy.cfg` keeps it. `init` also creates any of `/conf/haproxy`, `/conf/certs` and `/conf/state` that a volume from an older release lacks, because HAProxy mounts them by subpath and cannot be created without them.

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
| `CITE_CERTS_MODE` | `0600` | File mode of uploaded certificate files, `0600` or `0640`. See [Certificates](#certificates). |
| `CITE_LOG_LISTEN` | `127.0.0.1:5140` | Where the log sink binds: a UDP `host:port`, or `unix:/path` for a unix datagram socket (any stale socket file is replaced and the new one is mode 0600). Compose sets `unix:/run/cite/log.sock`. The default is loopback-only because any host that can reach a UDP sink can forge log lines; bind a wider address only on a network you trust. The receive buffer is raised to 4 MiB so bursts are not dropped. |
| `CITE_LOG_ADDR` | `connector:5140`, or the `CITE_LOG_LISTEN` path for a unix listener | Address HAProxy sends logs to. For a UDP sink it must be an IP literal because HAProxy does not resolve names there; for a unix sink it is the socket path. Compose sets `/run/cite/log.sock`. |
| `CITE_ANALYTICS_DB` | `<data dir>/analytics/analytics.db` | Absolute path of the SQLite analytics database. See [analytics](analytics.md). |
| `CITE_ANALYTICS_MAX_BYTES` | unset | Optional size cap for the analytics database, 8 MiB to 1 TiB. Unset keeps everything until its retention age; when set, the oldest rows are removed first. |
| `CITE_DOCKER_HOST` | unset | Enables the orchestrator. The overlay sets `http://dockerproxy:2375`. |
| `CITE_HAPROXY_CONTAINER` | `cite-node-haproxy` | Name of the HAProxy container, which the connector attaches to each stack's network. The overlay sets it. An empty value turns per-stack networks off. |
| `CITE_EDGE_NETWORK` | `cite_edge` | Shared network that executors join when per-stack networks are off. |
| `CITE_STACK_VERSION` | the connector's version | Image tag used for orchestrated stacks. |
| `CITE_REGISTRY` | `ghcr.io/seggys116` | Registry prefix for orchestrated stack images. |
| `CITE_DEPLOY_BUILD_TIMEOUT` | `600` | Seconds a deploy or switch waits for a repo-built slot to become healthy. 60 to 3600. Upstream-only sites keep the 60 second health wait. |
| `CITE_DOPPLER_TOKEN` | unset | Node-wide Doppler token for sites bound to a Doppler config without a token of their own. Same rules and handling as `CITE_GITHUB_TOKEN`: 1 to 512 printable ASCII characters, held in memory only, never written to disk or shown. See [Doppler](#doppler). |
| `CITE_DOPPLER_TOKEN_FILE` | unset | Path of a file holding the Doppler token, for secret mounts. `CITE_DOPPLER_TOKEN` wins when both are set. |
| `CITE_DOPPLER_POLL_SECS` | `300` | Seconds between Doppler syncs of each bound site. 60 to 86400. |
| `CITE_STACK_GITHUB_API_URL` | unset (managers use `https://api.github.com`) | GitHub API base URL passed to every orchestrated manager as `CITE_GITHUB_API_URL`, for GitHub Enterprise Server. An `http` or `https` URL of at most 200 characters, with no user name, query or fragment. The Docker proxy must have the same value in `CITE_PROXY_GITHUB_API_URL`, or it refuses to create the managers. The overlay sets both from `CITE_GITHUB_API_URL` in `.env`. See [Orchestrator](orchestrator.md#github-enterprise-server-and-the-api-url). |
| `RUST_LOG` | `info` | Log level. |

Boolean values accept `1`, `true`, `yes`, `on`, `0`, `false`, `no`, `off`. The connector refuses to start on a malformed value.

## Compose settings

| Variable | Default | Meaning |
|---|---|---|
| `CITE_VERSION` | `0.4.1` | Connector image tag. |
| `CITE_HTTP_PORT` | `80` | Host port for HTTP. |
| `CITE_HTTPS_PORT` | `443` | Host port for HTTPS. |
| `CITE_PUBLIC_BIND` | `0.0.0.0` | Host IP for the two public ports. |
| `CITE_CONNECTOR_PORT` | `7443` | Host port for the connector API. |
| `CITE_HAPROXY_MEM`, `CITE_HAPROXY_CPUS`, `CITE_HAPROXY_PIDS` | `1g`, `2.0`, `512` | HAProxy limits. |
| `CITE_CONNECTOR_MEM`, `CITE_CONNECTOR_CPUS`, `CITE_CONNECTOR_PIDS` | `512m`, `1.0`, `256` | Connector limits. |

HAProxy binds HTTPS only when `settings.https_port` is set in the node's configuration and `/conf/certs` holds at least one certificate. The bind loads every certificate in that directory and requires TLS 1.2 or newer. See [Certificates](#certificates).

## Certificates

Upload the certificates for your sites through the API (`/api/v1/certificates`, see [Connector API](node-api.md#certificates)) or the console; nothing needs to be copied into the volume by hand.

1. Upload a certificate chain and its unencrypted private key. The connector checks them, stores one combined PEM file per certificate, renders the config, runs `haproxy -c` and reloads HAProxy.
2. Turn HTTPS on by setting `https_port` in the node settings: `PUT /api/v1/settings` with the settings object from `GET /api/v1/settings` and `"https_port": 443`. The container listens on 443 whatever the host port is (`CITE_HTTPS_PORT` only maps the host side). Uploading a certificate never changes settings; when `https_port` is unset the upload answers with a `warning` saying so.
3. Renew with `PUT /api/v1/certificates/{id}`: the same id and name stay, the files and HAProxy are updated together, and no site config changes.

You do not have to make or upload certificates by hand: the node can issue them itself, see [Issuing certificates on the node](#issuing-certificates-on-the-node).

HAProxy picks the certificate for a connection by the SNI name the client sends, comparing it with each certificate's subject and alternative names, wildcards included. A client that sends no SNI, or a name no certificate matches, gets the first certificate in the directory (sorted by file name, which is the order of upload) and will usually see a name mismatch. `GET /api/v1/certificates` shows which configured site hosts are covered by some certificate so a gap is visible before a browser finds it. Each site host needs a certificate whose names match it; one certificate can cover many hosts.

If you delete every certificate the connector stops rendering the HTTPS bind, because HAProxy refuses `ssl crt` on an empty directory. HTTP keeps working, `https_port` stays set, and the bind comes back with the next upload.

### Automatic certificates and Cloudflare

Cloudflare reaches your node in one of three ways, set in its SSL/TLS mode for the zone:

| Cloudflare mode | Cloudflare to node | What the node needs |
|---|---|---|
| Flexible | http on port 80 | Nothing. Mark the site `access.tls: "flexible"`. |
| Full | https on port 443, any certificate accepted (self-signed included) | Something listening on 443. The node makes a self-signed certificate for you (or make one for chosen names with `POST /api/v1/certificates/generate`). |
| Full (strict) | https on port 443, a certificate Cloudflare trusts | A Cloudflare Origin CA or Let's Encrypt certificate. The node issues and renews either one itself (`POST /api/v1/certificates/origin-ca` or `/acme`), or you upload one. The automatic and generated self-signed ones fail here. |

Without a certificate and a TLS bind, Full mode ends in a Cloudflare 521 because nothing answers on 443. To prevent that, a node with at least one site that has `access.cloudflare_only` or `access.tls: "flexible"` binds the TLS port by itself and keeps an automatic certificate for every site host that no uploaded or hand-placed certificate covers:

- Port: `settings.https_port` if you set it, otherwise 443. `GET /api/v1/certificates` shows the configured value as `https_port` and the one in use as `https_effective_port`. The setting in `edge.json` is never changed by this.
- Certificate: self-signed ECDSA P-256, valid ten years, named by the uncovered hosts of one site (the first is the common name). It is stored like an upload, as `auto-<site id>.pem` in `/conf/certs` (mode `CITE_CERTS_MODE`), and listed with `source: "auto"`, the id `auto:<site id>` and a `warning` that explains it. Browsers do not trust it.
- It is rewritten only when the site's host set or the coverage by other certificates changes (or 30 days before it expires), and removed when the site is deleted, no longer needs it, or an uploaded certificate covers all its hosts. Uploaded certificates always take precedence. It does not count toward the limit of 64 certificates, cannot be replaced or deleted through the API (400, "automatic certificates are managed by the node"), and its key is never returned or logged.
- A file you place by hand under an `auto-` name without the node's marker is left alone; no automatic certificate is made for that site.
- Only Cloudflare-aware sites are affected. Automatic certificates are made for their hosts alone, never for other sites on the node. While the TLS port is the automatic one, a redirect to the node's own HTTPS (force-https and the www or apex helpers) applies only to those sites, so visitors of other sites are not sent to a self-signed certificate. Set `https_port` yourself to have such redirects apply to every site.
- To turn the automatic listener off (for example with host networking, where another service already holds 443 and every reload would fail), set `"https_port": 0` in the node settings. The node then never binds a TLS port on its own and makes no automatic certificates; an Origin CA or uploaded certificate is not served until you set a real `https_port`. `https_effective_port` reads `null`.
- A node with no such site and no `https_port` is unchanged: HTTP only, no automatic certificates. An explicit `https_port` on such a node binds as before and needs an uploaded certificate.
- A change that makes HAProxy refuse the config (a failed `haproxy -c`, or a reload that cannot bind the port) is rolled back, the automatic files with it, and port 80 keeps serving the previous configuration. A bind failure is reported as "HAProxy could not bind the HTTPS port".

For Flexible sites, requests that arrive over TLS on 443 are served like any other; Cloudflare still decides the scheme (`X-Forwarded-Proto` is handled as before) and no redirect is added.

### Issuing certificates on the node

Three routes make a certificate on the node and store it exactly like an upload (same checks, same `<id>.pem` file, `haproxy -c` and reload with rollback, replaceable and deletable). The private key is ECDSA P-256, generated on the node, and never leaves it. Details and JSON shapes are in [Connector API](node-api.md#issuing-certificates).

| Route | Gives you | Cloudflare token needs | Renewed by the node |
|---|---|---|---|
| `POST /api/v1/certificates/generate` | Self-signed, for any names and IPs. Fine for Cloudflare Full (not strict). | No token | No (default 825 days, at most 3650) |
| `POST /api/v1/certificates/origin-ca` | Cloudflare Origin CA certificate, trusted by Cloudflare only. Right for Full (strict) behind the proxy. | Zone, SSL and Certificates, Edit (or a legacy Origin CA key, `v1.0-...`) | Yes, when the token is stored (`remember_token: true`) |
| `POST /api/v1/certificates/acme` | Let's Encrypt certificate, trusted by browsers, wildcards included, via a DNS-01 challenge in Cloudflare DNS. | Zone, DNS, Edit and Zone, Zone, Read on the zones of the hosts | Yes, always |

Create the token in the Cloudflare dashboard under My Profile, API Tokens, with only those permissions and only the zones you need.

**The token is stored on the node when renewal needs it.** An ACME certificate always stores it (renewal needs a new DNS challenge), and an Origin CA certificate stores it when you ask with `remember_token`. It goes into `secrets.json` (mode 0600) as the secret `cloudflare-token:<certificate id>`, one per certificate, so issuing a second certificate with a differently scoped token never replaces the first one's and each certificate renews with its own; certificates marked before this change fall back to the old single `cloudflare-token` secret. The API only ever reports whether a token is stored, never its value, and it is kept out of logs, errors and the audit log. Anyone who can read the `cite_conf` volume can read it, so scope the token narrowly. To stop renewals, delete the certificate (which also removes its token). A renewal never overwrites a certificate you replaced by hand while it ran; it is dropped and audited as `certificates.renew_skipped`.

ACME orders run in the background because they take up to a few minutes: the route answers 202 with a job id, and `GET /api/v1/certificates/acme` lists the jobs and the managed certificates. The challenge TXT records the node creates are removed afterwards, also when the order fails. The ACME account key is made on first use and kept in `/conf/acme-account.pem` (mode 0600). Use `"staging": true` to try the flow against the Let's Encrypt staging CA first; its certificates are not trusted by browsers.

Managed certificates (Origin CA and ACME) are renewed by the node 30 days before they expire (at two thirds of the lifetime for certificates shorter than 90 days), in place under the same id and name, with the usual reload and rollback. Failures are retried with a growing delay (one hour, doubling, at most a day) and shown in the job list. Uploading a certificate over a managed one with `PUT` turns renewal off for it.

At most one Origin CA or ACME operation runs at a time and at most 10 start per hour; more answers 429. The node only connects to `api.cloudflare.com` and the Let's Encrypt ACME hosts, over https, without following redirects.

### Files and permissions

Certificates live in `/conf/certs`, one file per certificate named `<id>.pem`, where the id is generated by the connector. The user-chosen name is stored only inside the file, never in a path. A file holds three comment lines (format marker, name, creation time), the certificate chain and the key, in the single-file layout HAProxy reads. The directory is mode 0750 and each file 0600, written atomically (a temporary file in the same directory, then a rename), so HAProxy never reads a half-written file and a failed write leaves the old file in place.

The compose file mounts `certs` into the HAProxy container read-only, and HAProxy and the connector both run as uid 10001, so HAProxy can read a 0600 file the connector wrote and nothing else is needed. The `init` service already creates `/conf/certs` with owner 10001 and mode 0750 on a new volume, and the connector creates and repairs the directory itself at start and on every change, which also covers volumes made by an older `init`. If you run HAProxy as a different user in your own deployment, set `CITE_CERTS_MODE=0640` and give HAProxy's group read access to the directory and its files (for example by running both under a shared group id); a file HAProxy cannot read is caught by the reload, not by `haproxy -c` (that check runs as the connector's user, which can read it), so the reload is refused, the upload is rolled back and the running HAProxy keeps its old certificates.

HAProxy loads every file in the directory except hidden files and the sidecars ending in `.issuer`, `.ocsp`, `.sctl` or `.key`. The connector counts the regular files and the symlinks that resolve to a regular file (a dangling link, a link to a directory, a directory, a FIFO or a socket is not counted, so it cannot switch the HTTPS bind on with nothing loadable), turns the HTTPS bind on while there is at least one, and includes all of them in the digest that decides whether HAProxy needs a reload. For a regular file the digest covers its name and content (name, size and modification time above 256 KiB). For a symlink it covers the name and the target's size, modification time, device and inode, taken with a stat only: the connector never reads a file through a symlink, so a renewal that retargets or rewrites the link's target (the certbot `live/` layout) triggers a reload on the next apply or `POST /haproxy/reload`, but the certificate is not shown in `GET /certificates` and nothing about the target is echoed. A key kept in a separate `<name>.key` file next to a certificate is not counted, but its size and modification time are part of that certificate's digest, so replacing only the key file also triggers a reload; the key is never read. It removes leftover `.<id>.pem.tmp.*` files from an interrupted write when it starts and before each change.

### Hand-placed certificates and upgrading

Certificates you copied into `/conf/certs` yourself before this feature keep working: the HTTPS bind stays on as long as the directory holds any such file, and editing one triggers a reload on the next apply or `POST /haproxy/reload`. They appear in `GET /certificates` as read-only entries with `source: "manual"` and an id of the form `file:<name>` when they parse. The API cannot replace or delete them (404); do that on the volume and reload. Uploaded certificates have `source: "api"`. Moving a manual certificate under API management means uploading it and then removing the file. An uploaded file that cannot be parsed is listed with a `warning` instead of being hidden; it can be replaced or deleted by id, and it counts toward the 64 certificate limit.

If HAProxy is not running when you upload, replace or delete, the change is stored and audited with `haproxy=unreachable`, and the response carries a warning; the files are served after the next successful reload. A running HAProxy that rejects or does not load the change gets it rolled back.

### Changes that need a running HAProxy

Most changes are accepted while HAProxy is down and applied at its next reload; such a change is audited as `config.pending`. A change that adds or alters a protection is different, because success would otherwise report a protection that is not live. These are refused with 503 (400 if HAProxy refuses the config) and rolled back unless a running HAProxy confirms it loaded the change: turning on or changing a site's `cloudflare_only`, `zone_lock` or `bots` policy, changing `cloudflare_ranges`, adding or editing an enabled blocking rule or a rule with a secret header, and rotating a zone secret (the old secret is kept). Removing a protection and unrelated changes keep the tolerant behaviour. The rollback is audited as `config.rollback` (or `zone_secret.rollback`).

## Zone lock

A site with `access.zone_lock` only answers requests that carry the site's secret in the `x-cite-origin-secret` header, which a Cloudflare Transform Rule adds for the zone. The connector generates the secret per site on this node (`POST /api/v1/sites/{id}/zone-secret` returns it once), keeps it in `zone-secrets.json` (mode 0600) and injects the matching rule only into the rendered HAProxy config, never into `edge.json`. Only a fingerprint is shown afterwards.

Each node generates its own secrets. A hostname that is load-balanced across several nodes through one Cloudflare Transform Rule can therefore carry only one value, so only one of those nodes accepts it. Either point each node's hostname at its own Transform Rule value, or do not use the zone lock on a hostname served by more than one node.

## Doppler

A site built from a repository can take its build and runtime variables from a [Doppler](https://www.doppler.com) project and config. The node pulls the secrets, keeps them current and redeploys the site when they change. It needs the orchestrator, and the node lists the capability `doppler` only when the orchestrator is on.

**Token.** Set `CITE_DOPPLER_TOKEN` (or `CITE_DOPPLER_TOKEN_FILE`) on the connector once; the orchestrator overlay passes both, and `CITE_DOPPLER_POLL_SECS`, from `.env`. A site can carry its own token instead, sent with its binding and stored in `secrets.json` as `site-<id>.doppler-token`; it wins over the node token. A site with neither cannot be bound ("No Doppler token: set CITE_DOPPLER_TOKEN on the connector or pass a token for this site"). Listing projects and configs uses the node token, so use a personal or CLI token there; a service token scoped to one config works for a site but cannot list projects. `GET /api/v1/node` reports `doppler: {configured, source}` (`env`, `file` or `none`), never the value.

**Binding with a service token only (simplest).** In Doppler, open the project, pick the config the site should read (for example `prd`), then Access > Service Tokens > Generate, give it read access and copy the token (it starts with `dp.st.`). In the site's Doppler settings, paste that token, leave the project and config empty, choose build, runtime or both, and save. A service token is scoped to exactly one project and config, so the node needs nothing else: it downloads that config without naming it, and the binding status shows no project or config. No node token is needed for this. The token is stored and handled like any other site token below; pasting a new one re-syncs, and removing the binding deletes it. A token-only binding is refused when the site has no `dp.st.` token (a personal or CLI token reads every project, so it cannot stand in for the names), and setting only one of project and config is refused.

**What is synced.** Binding a site names a project, a config (or neither, with a service token) and whether the values feed the build variables, the runtime variables or both. The node downloads the config as JSON from `https://api.doppler.com` only (https, no redirects, 15 second timeout, 4 MiB response cap, the token sent as `Authorization: Bearer`). It drops Doppler's own `DOPPLER_*` variables and every name the target refuses, under the same rules as a variable set by hand: a build variable may not be a name the build manager reserves, a runtime variable may not be `PORT`, `NODE_ENV`, `HOST`, `HOSTNAME` or `NITRO_HOST`, and values over 4096 bytes or with control characters are left out. The binding status counts and names what was skipped and why, never a value. The filtered values are stored as `site-<id>.doppler-build` and `site-<id>.doppler-runtime` in `secrets.json`; they never reach `edge.json`, labels, the audit log or the connector log.

**Merge rule.** At every deploy the Doppler values form the base and the variables you set by hand (`PATCH /sites/{id}/build-env` and `runtime-env`) override them, name by name. Manual variables are never changed by a sync.

**Automatic redeploy.** A background task syncs every bound site every `CITE_DOPPLER_POLL_SECS` seconds (with a little random delay, two sites at a time, each site on its own so one failure does not stop the rest). It hashes the filtered build and runtime maps separately (SHA-256 over the sorted JSON), and only when a hash changed does it store the new values, audit `site.doppler.sync` with the site and the counts, and start a deploy of the site with the note `doppler sync` without waiting for it. If a deploy or another operation is already running on the site, the redeploy waits and starts when that one has finished, so two never overlap. Binding a site always redeploys it once the first sync succeeds. A failed sync keeps the last good values, shows the error in the status and is retried after one minute, then two, four and so on up to the poll interval or an hour; a 429 from Doppler is not retried before its `Retry-After`. Sync state is kept in memory: after a restart each bound site is synced once, and only a change redeploys it.

**Removing a binding** deletes the binding, the site's Doppler token and the synced values; manual variables stay. It does not redeploy: the running site keeps the old values until its next deploy, and the status says so.

**Limits.** A build or runtime environment holds at most 128 variables and 24 KiB of JSON, counting the Doppler values and the manual ones together. A sync that would go over is refused and keeps the previous values; a manual change that would go over is refused as well.

## Persistent volumes and outbound access

Both need the orchestrator; the node lists the capabilities `volumes` and `outbound` only when it is on.

**Volumes.** A site that runs a server (node, bun, Rust SSR, or a start command) can keep files across deploys in up to 8 named volumes, each with a mount path such as `/data`. Both slots mount the same volume, so data survives deploys, rollbacks and slot switches. Edit the list with the site; it takes effect on the next deploy. Removing a volume from the list keeps its data until you delete it with `DELETE /api/v1/sites/{id}/volumes/{name}` (after a redeploy), and deleting a site keeps its volumes unless the delete asks for `purge_volumes=true`. Back volumes up like any Docker volume (`docker run --rm -v cite-vol-<id>_<name>:/v ...`). Rules and the ownership step are in [Orchestrator](orchestrator.md#persistent-volumes).

**Outbound access.** Every site has `outbound`, on by default, which lets server-side code call external APIs. By default (`CITE_STACK_EGRESS_MODE=filtered`) that means the public internet only: each outbound stack gets a small egress proxy, and private, internal, Docker, host and cloud metadata addresses are blocked, as are the mail ports unless the site turns `block_mail` off. Server code reaches the internet through the `HTTP_PROXY` and `HTTPS_PROXY` variables the executor sets (Node fetch, Bun, curl, axios, undici, reqwest and requests honour them); a client that ignores them has no route out. Per site, `outbound_rules` adds allowed or denied destinations or switches to an allowlist. To let every site reach a LAN service, list its range in `CITE_STACK_EGRESS_ALLOW_CIDRS`; to block destinations for every site, use `CITE_STACK_EGRESS_DENY_CIDRS` and `CITE_STACK_EGRESS_DENY_HOSTS`. `CITE_STACK_EGRESS_MODE=open` restores the unfiltered bridge, and `off` forbids outbound access for every site (`GET /api/v1/node` reports `egress_mode` and `executor_egress`; the older `CITE_STACK_EXECUTOR_EGRESS=false` still means `off`). Turn `outbound` off per site for code that never needs the internet. See [Hardening](hardening.md#executor-egress) for exactly what is blocked. The single-site compose stack keeps executors without egress; add `docker-compose.egress.yml` there to give its executor a route out.

## Upgrading from an older release

The firewall grammar is stricter than before: regexes are checked for patterns HAProxy can never match or that match too much (for example a leading `.*`, as in `.*bot.*`). At start the connector reads `edge.json` and repairs what it can:

- Only the known old regex strings of the stock presets (`preset-sensitive-files-*`, `preset-cms-probes-*` and the like) are rewritten, field by field, to the current ones. Anything you edited in those rules is kept, as are the `enabled` flag and site scope.
- Any other rule whose regex is now refused is switched off and kept in the file so you can fix it and turn it on again.

When something changed and the result validates, the connector first copies the original to `edge.json.pre-migration` (mode 0600, written once and never overwritten), then writes the repaired `edge.json` atomically, logs one warning per rule and records a `config.migrated` audit entry with the counts and the rule ids (never the regex text). If the repaired configuration does not validate, nothing is written. Starting again changes nothing further. Only the server start migrates; `init` and `reset-credentials` read `edge.json` without changing it, so they are safe to run while the server is up.

The backup holds the values from before the migration, including any firewall header-secret values, and the connector never removes it. Check the result, then delete it.

One case is not repaired: a site whose `path_regex` is refused. The connector will not guess a site's routing, so it stops with an error naming the site and the field. Edit that site's `path_regex` in `edge.json` (or remove the site) and start again; `edge.json.pre-migration` holds the original if you need it.

**If the connector will not start.** `docker compose logs connector` shows the reason as a line starting `error:`. When `edge.json` is refused (for example a site `path_regex` that cannot be repaired) the connector exits before it writes anything, and HAProxy keeps serving the `haproxy.cfg` it already has, so running sites stay up. To recover, edit `/conf/edge.json` in the `cite_conf` volume (for example `docker run --rm -u 10001 -v cite-node_cite_conf:/conf alpine vi /conf/edge.json`), fix or remove the `path_regex` of the site named in the error, and restart the connector. If a migration had already run, `edge.json.pre-migration` next to it holds the file as it was before; copy it back over `edge.json` to undo the migration, then fix the one site.

Applying a preset again (`POST /api/v1/firewall/presets/{name}/apply`) refreshes any rule with the same id to the current definition instead of skipping it, again keeping `enabled` and the site scope.

## What is stored

Everything lives in the `cite_conf` volume, mounted at `/conf`.

| Path | Mode | Contents |
|---|---|---|
| `edge.json` | 0600 | The node's configuration: sites, maintenance pages, firewall rules, settings. |
| `edge.json.pre-migration` | 0600 | Only after an upgrade that rewrote `edge.json`: the original, written once and never removed. It holds the pre-migration header-secret values; delete it after checking the migration. |
| `credentials.json` | 0600 | Username, Argon2id password hash, TOTP secret. |
| `tokens.json` | 0600 | API token ids, Argon2id hashes, names and last-used times. At most 64 tokens. |
| `secrets.json` | 0600 | GitHub tokens for orchestrated sites, their build and runtime variables, per-site Doppler tokens and the synced Doppler values. |
| `zone-secrets.json` | 0600 | One Cloudflare zone-lock secret per locked site. Not part of `edge.json` or any backup the API produces; the secrets reach `haproxy/haproxy.cfg`, which HAProxy reads. |
| `audit.jsonl`, `audit.jsonl.1` | 0600 | Audit log of changes and logins. |
| `analytics/analytics.db` | 0600 | SQLite analytics database, with its `-wal` and `-shm` files. An old `analytics.json` is imported once and then deleted. |
| `tls/` | 0700 | `ca.pem`, `ca.key`, `server.pem` and the server key. |
| `certs/` | 0750 | Uploaded certificates, one `<id>.pem` file each (0600, or 0640 with `CITE_CERTS_MODE`) holding the chain and the private key. |
| `haproxy/haproxy.cfg` | 0644 | Rendered config. Overwritten on every change, do not edit it. |
| `haproxy/maps/cloudflare.lst` | 0644 | One CIDR per line: the Cloudflare ranges, written when a site depends on them. |
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
