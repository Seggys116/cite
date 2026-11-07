# Orchestrator

This page covers the optional orchestrator: how a node's connector builds and runs sites from GitHub through the Docker API, what it creates, and what it costs in privilege.

## Enabling it

```bash
docker compose -f docker-compose.node.yml -f docker-compose.orchestrator.yml up -d
```

Set `DOCKER_GID` in `.env` first: it is the numeric group id that owns `/var/run/docker.sock` on the host (`stat -c %g /var/run/docker.sock`). Compose refuses to start the overlay without it. The proxy runs as uid 10001 and gets that group through `group_add`, so it can open the socket without running as root. `scripts/setup.sh --orchestrator` writes `DOCKER_GID` for you.

The overlay adds a `dockerproxy` service (`ghcr.io/seggys116/cite-dockerproxy`) and an internal network `docker_api`. It sets `CITE_DOCKER_HOST=http://dockerproxy:2375` and `CITE_HAPROXY_CONTAINER=cite-node-haproxy` on the connector and attaches the connector to `docker_api`. The proxy is the only container that mounts `/var/run/docker.sock`. The mount is marked read-only, but that does not limit the API: a read-only bind of a unix socket still lets a client send any request. The restriction comes from the proxy's filter, described below. `docker-compose.node.yml` names the HAProxy container `cite-node-haproxy` so the connector and the proxy can refer to it.

`CITE_DOCKER_HOST` is what switches the orchestrator on. It accepts a bare `tcp://host:port` or `http://host:port`. Unix sockets, paths and query strings are rejected. At start the connector pings the Docker API and logs a warning if it cannot reach it. It keeps running, and deploys that need Docker fail until the API answers.

Without the overlay, the connector runs no containers. A site can then only route to upstream addresses you provide in its blue and green targets, and creating or updating a site with a `source` is refused.

## The Docker proxy

`cite-dockerproxy` is a purpose-built filter that sits between the connector and the Docker Engine socket. It is deny-by-default: it forwards only the calls the orchestrator makes, and only when the request body and query match what the orchestrator would send. Everything else gets `403 {"message":"denied"}` and a log line with the method, the normalised path and the reason. Request bodies are never logged.

A generic socket proxy filters by URL prefix, so allowing container creation allows every body under `/containers/`, including a privileged container with the host's root bind-mounted. Volume creation with bind driver options, image pulls from any registry, and attaching any container to any network are open in the same way. This proxy closes those paths by validating what is inside the request.

JSON bodies are parsed strictly: a duplicate object key at any depth, or two keys that differ only in case, is rejected, because the Docker daemon and the proxy could otherwise read different values. A validated body is then re-encoded and the re-encoded bytes are what the daemon receives, so it decodes exactly what was checked.

| Allowed | Conditions |
|---|---|
| `GET /_ping` | None. |
| `POST /images/create` | Only `fromImage` and `tag`. The image must be one of the Cite images under the configured registry with a matching tag form (`x.y.z-node22` or `x.y.z-node24` for the node images, `x.y.z` for the others). |
| `GET /images/{ref}/json` | The same image references. |
| `POST /volumes/create` | Body keys `Name` and `Labels` only (so no `Driver` or `DriverOpts`). The name must be `cite-<id>-<slot>-(data\|work\|cache)` and the labels must be exactly the four `cite.*` labels, consistent with the name. |
| `GET` and `DELETE /volumes/{name}` | Same name pattern. Delete first inspects the volume and requires `cite.managed=true`. |
| `POST /networks/create` | Body keys `Name`, `Driver` (`bridge` or absent), `Internal` and `Labels` only. Names are `cite-<id>-<slot>-net` and `cite-<id>-<slot>-xnet` (both must be internal) or `cite-<id>-<slot>-egress` (must not be), plus the node's egress bridge named by `CITE_STACK_EGRESS_BRIDGE` (must not be internal, labels exactly `cite.managed=true` and `cite.role=egress-bridge`). |
| `GET` and `DELETE /networks/{name}` | Same name patterns; the egress bridge may be inspected but never deleted. Delete requires `cite.managed=true`. |
| `POST /networks/{name}/connect` and `disconnect` | Only the per-stack `-net` networks, only for the HAProxy container, and only when the network carries `cite.managed=true`. |
| `POST /containers/create?name=` | The name must be `cite-<id>-<slot>-(manager\|executor\|init\|egress-proxy)`. The body is compared structurally with the exact specification the orchestrator builds for that role. See below. |
| `POST /containers/{name}/start`, `stop`, `restart`, `wait` | Name pattern, `cite.managed=true` on the container, and only the query parameters the orchestrator uses. |
| `GET /containers/{name}/json` | Name pattern. |
| `GET /containers/{name}/logs` | Name pattern and `cite.managed=true` on the container. Query keys are limited to `stdout`, `stderr` (at least one, value `1` or `true`), `tail` (required, a whole number from 1 to 1000, never `all`), `since` (digits with an optional fraction, at most 20 characters) and `timestamps` (`0`, `1`, `true` or `false`). `follow`, `until`, `details` and any other key are refused. The response is passed through but cut off at 4 MiB. |
| `DELETE /containers/{name}` | Name pattern, `cite.managed=true`, optional `force`. |
| `GET /containers/json` | The `filters` parameter must pin `cite.managed=true`. |

A container create body is rebuilt by the proxy from the site id, slot and role in the name, and the request must equal it. Only a few values are free, and each is checked: the image (registry, image name for the role, tag form), the environment (a fixed list of keys, fixed values for paths, validated values for repo, branch, poll interval, node major and token, and the GitHub API URL only when it equals the proxy's own setting), the memory, CPU and pids limits (positive and under a per-role cap), and the network (`none` for init, the stack's own egress network for the manager, the stack's own network or the configured edge network for the executor). Any other key or value is rejected, which covers `Privileged`, `Binds`, `Devices`, `PidMode`, `IpcMode`, `UsernsMode`, `CapAdd` beyond the fixed sets, other users, other mounts, `Sysctls`, `VolumesFrom`, port bindings and the rest. Mounts are volumes only, named after the same stack, with the exact subpaths and read-only flags.

The manager environment is a closed list of at most 32 entries, each key at most once. Besides the fixed values (`CITE_DATA_DIR`, `CITE_RELEASES_DIR`, `CITE_CONTROL_DIR`, `CITE_STATUS_DIR`, `CITE_STATE_DIR`, `CITE_WORK_DIR`, `CITE_CACHE_DIR`, `CITE_SOCKET`, `RUST_LOG`) these keys carry validated values:

| Key | Accepted value |
|---|---|
| `CITE_REPO` | `owner/name`, each part letters, digits, `.`, `_`, `-`, at most 100 characters. |
| `CITE_BRANCH` | Letters, digits, `.`, `_`, `-`, `/`, at most 100 characters, no leading `-`, no `..`. |
| `CITE_POLL_INTERVAL` | Letters and digits, at most 16 characters. |
| `CITE_NODE` | `22` or `24`. |
| `CITE_GITHUB_TOKEN` | 1 to 512 printable ASCII characters without spaces. |
| `CITE_GITHUB_API_URL` | Exactly the proxy's `CITE_PROXY_GITHUB_API_URL`. |
| `CITE_ROOT_DIR`, `CITE_OUTPUT_DIR`, `CITE_SPA_FALLBACK` | A relative path of at most 255 bytes from `A-Za-z0-9._/-`, with no `..` segment and no leading `/`. |
| `CITE_PACKAGE_MANAGER` | `npm`, `pnpm`, `yarn` or `bun`. |
| `CITE_RENDERING` | `static` or `ssr`. |
| `CITE_FRAMEWORK` | 1 to 32 characters from `a-z0-9-`. |
| `CITE_PRUNE` | `true` or `false`. |
| `CITE_INSTALL_COMMAND`, `CITE_BUILD_COMMAND` | 1 to 1024 bytes with no control characters (so no newline or NUL). The manager runs them with `sh -c` inside the sandboxed build helper, so shell syntax is allowed here by design. |
| `CITE_START_COMMAND` | 1 to 1024 bytes with no control characters. It is split with shell-like quoting and must not contain a semicolon, pipe, ampersand, angle bracket, backtick or dollar sign anywhere, or a parenthesis, brace, `*`, `?`, `~`, `!`, `#` or backslash outside quotes. The first word must not be a package manager or shell (`npm`, `npx`, `pnpm`, `yarn`, `corepack`, `cargo`, `rustc`, `sh`, `bash`, `env`), also when given as a path. |
| `CITE_FORGE` | Exactly the proxy's `CITE_STACK_FORGE`. |
| `CITE_FORGE_API_URL` | Exactly the proxy's `CITE_STACK_FORGE_API_URL`. |
| `CITE_DEPLOY_ID` | Exactly 26 characters from `0-9A-Z`. |
| `CITE_BUILD_ENV_JSON` | A JSON object of at most 24 KiB and 128 keys, with no duplicate keys. Keys match `[A-Z_][A-Z0-9_]{0,63}`, do not start with `CITE_`, and are not `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `NODE_OPTIONS`, `NODE_EXTRA_CA_CERTS`, `HOME`, `PATH`, `TMPDIR`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `ALL_PROXY`, `PNPM_HOME`, or start with `XDG_`, `GIT_` or `npm_config_` (compared without regard to case). Values are strings of at most 4096 bytes without control characters. |

The executor environment is likewise closed: its fixed values, `CITE_NODE`, and `CITE_RUNTIME_ENV_JSON`, which follows the same rules as `CITE_BUILD_ENV_JSON` and also refuses `PORT`, `NODE_ENV`, `HOST`, `HOSTNAME` and `NITRO_HOST`, the names the executor sets itself. A filtered executor (see [Outbound network access](#outbound-network-access)) must also carry `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy` and `https_proxy`, each exactly `http://cite-<id>-<slot>-egress-proxy:3128` for its own stack, `NO_PROXY=localhost,127.0.0.1` and `NODE_USE_ENV_PROXY=1`; any other executor must carry none of them. `NODE_USE_ENV_PROXY` is refused in the owner's variables like the proxy names.

The egress proxy environment holds only `CITE_EGRESS_*` keys: the node lists (`CITE_EGRESS_ALLOW_CIDRS`, `CITE_EGRESS_DENY_CIDRS`, `CITE_EGRESS_DENY_HOSTS`, `CITE_EGRESS_ALLOW_PORTS`) must each be present exactly when the proxy's own `CITE_STACK_EGRESS_*` setting is non-empty, with exactly that value, so a create body cannot widen or drop them; `CITE_EGRESS_MODE` (`public` or `allowlist`) and `CITE_EGRESS_BLOCK_MAIL` (`true` or `false`) are required; `CITE_EGRESS_ALLOW` and `CITE_EGRESS_DENY` are optional comma lists of at most 64 distinct IPs, CIDRs or lowercase host names (a leading `.` adds subdomains), and allowlist mode needs `CITE_EGRESS_ALLOW`. The rest of the body is fixed: image `cite-egress:<x.y.z>`, user 65532, read-only root, all capabilities dropped, no mounts, 64 MiB, 0.25 CPU, 128 pids, no health check, network mode `cite-<id>-<slot>-xnet` and exactly two endpoints, that xnet and the egress bridge, with no aliases. The proxy refuses an egress proxy create unless its mode is `filtered`.

Anything else is refused, including `CITE_BUILD_UID`, `CITE_BUILD_GID`, `CITE_DEV_SAME_USER`, `CITE_BUILD_ENV_FILE`, the `CITE_MAX_*` limits, `CITE_BUILD_TIMEOUT`, any other directory key and per-site API URLs. With every key at its longest value and a 24 KiB build environment escaped twice, a create body still fits the 64 KiB body cap.

The proxy also refuses, before any matching: request targets that are not origin-form, percent-encoding in paths, `.` and `..` segments, empty segments, backslashes and NUL bytes, API versions outside 1.45 to 1.99, duplicate query keys, any `Upgrade` or `Connection: upgrade` (so no attach, exec or hijack), any `Transfer-Encoding`, a body on a request that should have none, a body over 64 KiB, and a body without `Content-Type: application/json`. Client headers are not forwarded; the proxy builds its own request to the engine, so request smuggling toward Docker is not possible. Responses are streamed back (image pull progress) with a per-route deadline. Connections are capped (`CITE_PROXY_MAX_CONNS`, default 64) and request headers must arrive within 10 seconds.

Proxy settings, all on the `dockerproxy` service:

| Variable | Default | Meaning |
|---|---|---|
| `CITE_PROXY_LISTEN` | `0.0.0.0:2375` | Listen address. Keep it on the internal `docker_api` network. |
| `CITE_PROXY_SOCKET` | `/var/run/docker.sock` | Engine socket. |
| `CITE_PROXY_REGISTRY` | `ghcr.io/seggys116` | Registry prefix images must come from. Keep it equal to the connector's `CITE_REGISTRY`. |
| `CITE_PROXY_HAPROXY_CONTAINER` | `cite-node-haproxy` | Container the proxy lets the connector attach to stack networks. |
| `CITE_PROXY_EDGE_NETWORK` | `cite_edge` | Shared network executors may join when per-stack networks are off. |
| `CITE_PROXY_MAX_CONNS` | `64` | Concurrent connections. |
| `CITE_PROXY_GITHUB_API_URL` | unset | The one GitHub API URL a manager may be given. Unset means a manager create body must not carry `CITE_GITHUB_API_URL` at all. |
| `CITE_STACK_FORGE` | unset | `github`, `gitlab` or `gitea`: the kind of forge the one `CITE_STACK_FORGE_API_URL` belongs to. Must be set together with the URL. Unset means a manager create body must not carry `CITE_FORGE` or `CITE_FORGE_API_URL`. |
| `CITE_STACK_FORGE_API_URL` | unset | The one forge API URL a manager may be given as `CITE_FORGE_API_URL`. `https` only, with the same shape rules as the GitHub API URL. |
| `CITE_STACK_MAX_MEM` | `16g` | Largest `Memory` a manager or executor create body may ask for. A whole number with an optional `k`, `m`, `g` or `t` suffix (powers of 1024, optionally followed by `b` or `ib`). Between `256m` and `1t`. |
| `CITE_STACK_MAX_CPUS` | `8` | Largest `NanoCpus` (as a CPU count such as `4` or `0.5`, at most nine decimals) a manager or executor create body may ask for. Between `0.25` and `1024`. |
| `CITE_STACK_EGRESS_MODE` | `filtered` | How executors of outbound sites reach the internet (see [Outbound network access](#outbound-network-access)): `filtered` (through the stack's egress proxy only), `open` (the stack's egress bridge directly) or `off`. When unset, the older `CITE_STACK_EXECUTOR_EGRESS` is read instead: `true`/`1` means `filtered`, `false`/`0` means `off`. The overlay passes the same values to the connector, which refuses an outbound site before touching its stack when the mode is `off` and reports `egress_mode` and `executor_egress` in `GET /api/v1/node`. |
| `CITE_STACK_EGRESS_BRIDGE` | `cite-egress` | The normal bridge network the connector creates once per node and attaches every egress proxy to. Nothing else joins it. |
| `CITE_STACK_EGRESS_ALLOW_CIDRS` | empty | Filtered mode: comma list of IPs or CIDRs every site may reach even though they are private or reserved, for example a LAN database at `192.168.10.0/24`. |
| `CITE_STACK_EGRESS_DENY_CIDRS` | empty | Filtered mode: public ranges no site may reach. A site allow entry never overrides it. |
| `CITE_NODE_PUBLIC_IPS` | empty | Filtered mode: the node's own public IPs, added to the deny list of every egress proxy so sites cannot reach host services through the public address. Set it on every internet-facing node; set it on both the connector and the Docker proxy (the orchestrator overlay passes it to both). |
| `CITE_STACK_EGRESS_DENY_HOSTS` | empty | Filtered mode: host names no site may reach, each also covering its subdomains. A site allow entry never overrides it. |
| `CITE_STACK_EGRESS_ALLOW_PORTS` | empty (every port) | Filtered mode: comma list of ports or ranges (`80,443,8000-8100`) a site may connect to. Mail ports 25, 465 and 587 stay refused for sites whose `block_mail` is on (the default) even when listed. |

Persistent site volumes add these rules (see [Persistent volumes](#persistent-volumes)). `POST /volumes/create` also accepts a `cite-vol-<id>_<name>` volume whose labels are exactly `cite.managed=true`, `cite.site=<id>` and `cite.volume=<name>`; no driver or options. `GET` and `DELETE /volumes/<name>` accept those names, and `DELETE` still requires the `cite.managed` label on the existing volume. `GET /volumes` is allowed only with a `filters` label list that contains `cite.managed=true`. An executor create body may carry, after its three fixed mounts, at most 8 extra entries of `Type` `volume` whose `Source` is `cite-vol-<its own site>_<name>`, `ReadOnly` false, with no `VolumeOptions`, bind, tmpfs or driver settings; each `Target` follows the mount path rule below and no two may repeat or nest. An init create body may carry the same volumes at exactly `/vols/<name>`, and its script must be the fixed layout script followed by the fixed ownership step for exactly those names.

Because the stack version becomes an image tag, `CITE_STACK_VERSION` must be a plain `x.y.z` version. The overlay passes it from `.env` to the connector; when it is unset the connector uses its own version. The connector uses Docker Engine API v1.45, which is why Docker Engine 26 or newer is required.

## What a site stack is

A site with a `source` gets one stack per slot, created when the slot is first used. Names use the site id and slot: for site `shop` in the blue slot, `cite-shop-blue-manager`, `cite-shop-blue-executor`, `cite-shop-blue-init`, volumes `cite-shop-blue-data`, `-work` and `-cache`, and networks `cite-shop-blue-egress` and `cite-shop-blue-net`. An outbound server site on a filtered node also gets `cite-shop-blue-egress-proxy` and the internal network `cite-shop-blue-xnet`.

| Container | Role | Network | Limits |
|---|---|---|---|
| `init` | Lays out the data volume, then exits | none | 128 MiB, 64 pids, caps `CHOWN` and `FOWNER` only |
| `manager` | Polls the repo, builds, promotes into the stack's own volume | `cite-<id>-<slot>-egress`, its own network | 2 GiB, 2 CPUs, 2048 pids |
| `executor` | Serves the built site on port 8080 | `cite-<id>-<slot>-net` (internal), alias `cite-<id>-<slot>-executor`; when the site is outbound also `cite-<id>-<slot>-xnet` (filtered) or `cite-<id>-<slot>-egress` (open) | 1 GiB, 1 CPU, 256 pids, runs as 65532 |
| `egress-proxy` | Forwards the executor's HTTP and HTTPS requests to public destinations only | `cite-<id>-<slot>-xnet` (internal) and the node's egress bridge | 64 MiB, 0.25 CPU, 128 pids, runs as 65532, no mounts |

Both long-running containers have `ReadonlyRootfs`, `no-new-privileges`, all capabilities dropped (the manager gets back `CHOWN`, `SETUID`, `SETGID` and `DAC_READ_SEARCH` to build as an unprivileged user), an init process, a health check every 30 seconds and a 10 MiB by 3 file log cap. They mount only their own named volumes, with subpath mounts matching single-site mode: the executor sees releases and control read-only. No host paths are mounted.

These specifications mirror the `manager` and `executor` services in `docker-compose.yml`, so the single-site hardening in [Hardening](hardening.md) applies to each stack.

## Site isolation

Each stack gets its own internal network, `cite-<id>-<slot>-net`, and its executor is the only container on it besides HAProxy. The connector creates the network, then asks Docker (through the proxy) to connect the HAProxy container, named by `CITE_HAPROXY_CONTAINER` (default `cite-node-haproxy`). HAProxy reaches the executor at `cite-<id>-<slot>-executor:8080` over that network, and the connector writes the address into the slot's targets. Because the network is internal and unshared, site A's code cannot reach site B's executor, neither HAProxy's admin sockets nor the connector can be reached from an executor, and an executor whose site has `outbound` off has no route out (see [Outbound network access](#outbound-network-access)).

On stop, HAProxy is disconnected from the stack's network. The network itself stays so the stopped executor can start again. Removing a stack disconnects HAProxy and deletes both networks. If HAProxy is recreated, it loses its attachments; the connector re-attaches it to every running stack's network when it starts, before it waits for any site to turn healthy, and again the first time it uses the orchestrator. A container, volume or network that already has the expected name but lacks the `cite.managed=true` label is never adopted, changed or deleted; the connector reports a conflict.

If `CITE_HAPROXY_CONTAINER` is set to an empty value, per-stack networks are off and executors join the shared `cite_edge` network as before. That mode is weaker: all executors on the node can reach each other directly, so one site's code can talk to another site's executor. Use it only for a node whose sites you fully trust. Stacks created in that mode move to their own network the next time they are ensured, because the executor is recreated when its network differs.

The manager keeps its own `cite-<id>-<slot>-egress` network so it can reach GitHub and the package registries. That network is not shared with other stacks and is not filtered: builds still fetch from wherever the package manager points. In filtered mode the executor never joins it.

## Outbound network access

A site's `outbound` flag (default `true`; sites saved before 0.4.1 read as `true`) lets server-side code make outbound requests, for example to the App Store, GitHub or a payment API. Static sites (`static` runtime or `rendering: static`) ignore it. How an outbound executor reaches the internet depends on the node's `CITE_STACK_EGRESS_MODE`:

- `filtered` (default): the executor joins its internal `cite-<id>-<slot>-net` network as before plus `cite-<id>-<slot>-xnet`, an internal network whose only other member is the stack's egress proxy `cite-<id>-<slot>-egress-proxy`. Neither network has a gateway, so the executor has no route anywhere; the only thing it can reach outside its stack is the proxy on port 3128. The proxy also sits on the node's egress bridge (`CITE_STACK_EGRESS_BRIDGE`, default `cite-egress`, which holds only egress proxies) and forwards HTTP and HTTPS (`CONNECT`) requests to public destinations. It resolves each host itself, checks every address, and connects only to an address that passed, so a name cannot be rebound to a private address between the check and the connection. The executor gets `HTTP_PROXY`, `HTTPS_PROXY`, their lowercase forms, `NO_PROXY=localhost,127.0.0.1` and `NODE_USE_ENV_PROXY=1`, and passes them to the app.
- `open`: the executor joins its stack's `cite-<id>-<slot>-egress` bridge directly, the same network its manager uses, with no filtering. This is the behaviour before filtered mode existed.
- `off`: no executor gets an outbound network, and the connector refuses to deploy a site with `outbound` on ("outbound network access is off on this node").

The xnet is a separate network on purpose: the manager's egress bridge must keep its gateway for builds, so making that network internal would cut the manager off, and sharing it would give the executor a direct route again.

Nothing changes for HAProxy in any mode: the executor's alias exists only on the internal network, HAProxy is attached only to that network, and the slot target stays `cite-<id>-<slot>-executor:8080`. The executor publishes no ports. With per-stack networks off (`CITE_HAPROXY_CONTAINER` empty) the executor joins `cite_edge` and its xnet (filtered) or egress bridge (open).

With `outbound: false` the executor is on the internal network only and has no route out, and no egress proxy is created. A change of the flag, the site's `outbound_rules` or the node mode takes effect on the next deploy: until then the site status reports the settings as not current. The connector compares the executor's networks and the egress proxy's image, networks and `CITE_EGRESS_*` environment with what it wants; the next deploy recreates the egress proxy when only its rules changed, starts it before the executor, and removes it and the xnet when the site no longer needs them. Removing or stopping a stack removes or stops its egress proxy too. The egress bridge outlives every stack.

The proxy accepts each executor variant only in the matching mode and only for the stack's own networks. Keep `CITE_STACK_EGRESS_MODE` and the `CITE_STACK_EGRESS_*` lists equal on the proxy and the connector; a mismatch shows as a proxy refusal naming the setting. See [Hardening](hardening.md#executor-egress) for what filtered mode blocks.

## Persistent volumes

A site whose runtime runs a server (`node`, `bun`, `rust` with SSR, or any site with a `start_command`) can declare up to 8 named volumes in `volumes: [{ "name": "data", "mount_path": "/data" }]`. A static site with volumes is refused with 400. Rules, checked on create and update (a stored site is never judged when the config loads, but its volumes are checked again before a deploy):

- `name` matches `^[a-z0-9][a-z0-9-]{0,30}$` and is unique in the site.
- `mount_path` is absolute and normalised: 2 to 255 characters of letters, digits, `.`, `_`, `-` and `/`, no trailing slash, no empty, `.` or `..` segment.
- No two mount paths are equal or nested.
- A mount path may not equal, sit under or contain any path the executor or the system uses: `/var/lib/cite` (releases, control and status), `/cite-executor`, `/nodejs`, `/tmp`, `/proc`, `/sys`, `/dev`, `/etc`, `/run`, `/var/run`, `/usr`, `/bin`, `/sbin`, `/lib`, `/lib32`, `/lib64`, `/libx32`, `/root` and `/boot`. So `/var` and `/` are refused too.

Each volume is a Docker named volume `cite-vol-<id>_<name>` labelled `cite.managed=true`, `cite.site=<id>` and `cite.volume=<name>`. The underscore cannot occur in a site id, so one site can never name another site's volume. The volume carries no slot: both the blue and green executor mount it read-write at `mount_path`, so data survives deploys, rollbacks and slot switches. During a deploy both slots run at once and see the same files, so an application that writes must tolerate a second instance briefly (use SQLite WAL, file locks or a write-once layout). The manager never mounts site volumes.

Volumes are created before the new slot starts. The executor runs as uid 65532 on a read-only root, and a fresh volume is owned by root, so the existing one-shot `init` container (manager image, root, caps `CHOWN` and `FOWNER` only, no network) also mounts each site volume at `/vols/<name>`. When the volume root is not yet owned by 65532 it writes a `.cite-init` marker, runs `chown -R 65532:65532` and sets mode 0750; afterwards the step is skipped. The marker keeps the volume non-empty, so Docker never copies image content (and its owner) over it on first mount.

Changing the list takes effect on the next deploy; until then the site status shows the settings as not current. Removing a volume from the list stops mounting it but keeps its data. Delete the data with `DELETE /api/v1/sites/{id}/volumes/{name}`; it is refused with 409 while the volume is still declared and the site has a running container, or while a running slot still mounts it. Remove it from the list, redeploy, then delete. Deleting a site keeps its volumes unless the request carries `?purge_volumes=true`; volumes left over from an earlier list are reported by `GET /api/v1/sites/{id}/volumes` with `declared: false`. Sizes come from Docker's usage data when the engine reports it, and are `null` otherwise (the proxy does not open `/system/df`).

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
| `doppler` | none | `{project,config,build,runtime}`, set only through `PUT /sites/{id}/doppler`; `project` and `config` are both empty for a service-token binding. A value sent when creating a site is discarded, and `PUT /sites/{id}` keeps the stored one. See [Doppler](#doppler). |

Images come from `CITE_REGISTRY` (default `ghcr.io/seggys116`) at tag `CITE_STACK_VERSION`:

| Runtime | Manager image | Executor image |
|---|---|---|
| `node` | `cite-manager:<version>-node<major>` | `cite-executor-node:<version>-node<major>` |
| `bun` | `cite-manager:<version>-node<major>` | `cite-executor-bun:<version>` |
| `static` | `cite-manager:<version>-node<major>` | `cite-executor-static:<version>` |
| `rust` | `cite-manager-rust:<version>` | `cite-executor-rust:<version>` |

Images are pulled only when they are not present locally; a pull can take up to 10 minutes before it times out.

## GitHub token

There are two ways to give a site its GitHub token.

**1. On the connector, once for the node (recommended).** Set `CITE_GITHUB_TOKEN` in `.env` (as in the single-site stack). The orchestrator overlay passes it to the connector, which reads it at start and uses it for every site built from GitHub that has no token of its own. Use a fine-grained token with Contents:read, or a classic PAT with repo scope. `CITE_GITHUB_TOKEN_FILE` is the alternative for secret mounts: mount the file into the connector and set the variable to its path; the environment variable wins when both are set. Both follow the same rules as a per-site token (printable ASCII, up to 512 bytes), and an invalid value stops the connector at start with an error that never prints it. `GET /api/v1/node` reports `github.token_configured` and `github.source` (`env`, `file` or `none`), never the value.

**2. Per site.** Send a `github_token` string beside the site object in the `POST /api/v1/sites` body. It overrides the node token for that site. The connector stores it in `secrets.json` (mode 0600, up to 512 secrets, 32 KiB each) under a name it chooses from the site id, and records only that name in the site.

A site created with a `source` and neither token is refused with 400 ("No GitHub token: set CITE_GITHUB_TOKEN on the connector (or pass github_token for this site)"); the manager needs the token even for a public repository.

**What is stored where.** The node token is held in the connector's memory only. It is never written to `secrets.json`, `edge.json`, the audit log, status output, error messages or container labels. It reaches each manager as `CITE_GITHUB_TOKEN` in the container's environment, resolved whenever the connector creates the manager container (create, deploy, switch and rollback). Anyone who can inspect containers through the Docker API (`docker inspect`) or read the connector's environment can read it, including the connector.

**Rotating the node token.** Change `CITE_GITHUB_TOKEN` in `.env` and recreate the connector (`docker compose up -d connector`). Running managers keep the old token until their site's next deploy, switch or rollback, which recreates the manager with the new one; a startup reconcile does not recreate managers. To roll a site immediately, deploy it again. Per-site tokens are unaffected.

## Doppler

A site's build and runtime variables can come from a Doppler project and config. Set `CITE_DOPPLER_TOKEN` (or `CITE_DOPPLER_TOKEN_FILE`) in `.env`; the overlay passes it and `CITE_DOPPLER_POLL_SECS` (default 300 seconds, at least 60) to the connector, which holds the token in memory like the GitHub node token. A site can also carry its own Doppler token, stored in `secrets.json` as `site-<id>.doppler-token`. Bind a site with `PUT /api/v1/sites/{id}/doppler`. The connector syncs it at once and then on every poll, merges the Doppler values under the manual build and runtime variables, and redeploys the site when the synced values change; managers and executors receive the merged result through `CITE_BUILD_ENV_JSON` and `CITE_RUNTIME_ENV_JSON`, so the Docker proxy rules and limits above apply unchanged. Only the connector talks to Doppler, and only to `https://api.doppler.com`. See [Running a node](node.md#doppler) and [Connector API](node-api.md#doppler).

## GitHub Enterprise Server and the API URL

Managers talk to `https://api.github.com` unless told otherwise. To build from a GitHub Enterprise Server, or any GitHub-compatible API, set `CITE_GITHUB_API_URL` in `.env`. The overlay passes it to the connector as `CITE_STACK_GITHUB_API_URL` and to the proxy as `CITE_PROXY_GITHUB_API_URL`, and the connector hands it to every manager as `CITE_GITHUB_API_URL`.

```bash
CITE_GITHUB_API_URL=https://ghe.example.com/api/v3
```

The URL must be `http` or `https`, at most 200 characters, with a plain host (optionally a port) and a path of letters, digits and `. - _ ~ /`. User names, passwords, queries, fragments, percent-encoding and IPv6 literals are refused, by the connector at start and by the proxy at start. The manager sends the GitHub token to this URL, so the proxy does not trust the connector's choice: a manager create body may carry `CITE_GITHUB_API_URL` only with exactly the value of the proxy's own `CITE_PROXY_GITHUB_API_URL`. With none set, the key is denied. A compromised connector therefore cannot point a manager, and its token, at another host. Changing the value recreates the managers on their next ensure, because the connector compares each manager's environment with what it wants.

## Lifecycle

| Event | What happens |
|---|---|
| Create | Pulls images, creates volumes and the egress network, runs `init`, starts the manager and executor, sets the slot's target, applies the HAProxy config and waits up to 30 seconds for health. An unhealthy site is still created and an audit entry is written. If the stack fails to start, the stored secret is dropped and no site is created. If HAProxy rejects the new config, the stack and secret are removed. |
| Deploy | Starts the idle slot's stack, writes its target, waits for health, then switches. A repo-built slot gets the build wait, 600 seconds by default and set with `CITE_DEPLOY_BUILD_TIMEOUT` (60 to 3600). A failed start or health check stops only the idle stack and records a `failed` deployment. |
| Switch, rollback | Restart the target slot's stack if it was stopped, check health, flip. |
| After a switch | The previous slot's stack stays up for a 30 second drain delay, then the executor and manager are stopped (the executor first). Volumes are kept so a rollback is fast. If the site has moved back in the meantime, nothing is stopped. |
| Update | Replaces the site's fields and keeps history and the stored secret. |
| Delete | Removes the site from HAProxy, then removes its stacks and deletes the stack volumes and the stored secret. Persistent site volumes are kept unless the request asks for `?purge_volumes=true`. |

The connector compares each running container's image and environment with what it wants. A changed branch or token recreates only the manager. Containers it did not create are never adopted or removed: a name clash is reported as a conflict.

Deployment history keeps the last 50 entries per site.

## Live end to end check

`scripts/e2e-orchestrator.sh` runs the whole orchestrator against a real Docker daemon. After the onboarding, isolation, proxy-attack, restart and delete checks, a live phase starts the mock GitHub from `images/mock-github/Dockerfile`, sets `CITE_GITHUB_API_URL` for the proxy and connector, and creates a `static` site for the mock repository. It then checks that the manager built the site from the mock, that `curl -H 'Host: app.e2e.test'` against HAProxy returns the built page, that the stack containers and networks are as hardened as before, that a deploy of a second branch switches traffic and that a rollback restarts the drained slot on its own branch. Deleting the site must remove every container, volume, network and the stored token.

The managers sit on a per-stack bridge network, so the mock is published on the host and reached through it. On Docker Desktop the script binds the mock to `127.0.0.1` and uses `http://host.docker.internal:18090`. On Linux, `host.docker.internal` does not resolve inside the stacks and the orchestrator does not add `--add-host host.docker.internal:host-gateway` to them, so the script binds the mock to the `docker0` gateway address and uses that address as the API URL. If you point a real stack at a service on the Docker host, use the same approach.

The script needs these local images, tagged as the orchestrator asks for them (version `0.0.1` in CI): `cite-connector`, `cite-dockerproxy`, `cite-manager:<version>-node22`, `cite-executor-node:<version>-node22` and `cite-executor-static:<version>`, all under `ghcr.io/seggys116`, and `cite-mock-github:e2e` (override with `MOCK_IMAGE`). The mock cannot delete a file or rewind a branch, so the second version of the site is a push to a new `release` branch, deployed through `git_ref`.

## Resource planning

The proxy accepts any manager or executor `Memory` from 256 MiB up to `CITE_STACK_MAX_MEM` (default 16 GiB) and any `NanoCpus` from 0.25 up to `CITE_STACK_MAX_CPUS` (default 8 CPUs); `MemorySwap` must equal `Memory`. Values outside the range, or an unparsable setting, are refused (a bad setting stops the proxy at start). Init containers keep their fixed 256 MiB cap, and pid limits are unchanged.

Each active stack holds up to 3 GiB of memory limit and a data, work and cache volume. Sizing for those volumes is the same as in [Install](install.md#disk-sizing). A stopped standby stack frees its memory but keeps its volumes.

Disk is not limited per stack. The `docker-compose.yml` work and cache volumes are unbounded and the orchestrator mirrors that, because the proxy forbids `StorageOpt` and volume driver options, the only per-container ways to set a quota. To bound disk use, put Docker's data root on an XFS filesystem mounted with project quotas, or monitor `docker system df -v`. A site whose build fills the disk can fill the host. This is listed under residual risk in the [security model](security-model.md#the-orchestrator-overlay).
