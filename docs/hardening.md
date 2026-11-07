# Hardening

Cite's Compose defaults aim for a small attack surface. Verify a live stack with:

```bash
./scripts/assert-hardening.sh          # live container settings
./scripts/assert-shellless.sh --compose
./scripts/assert-compose.sh            # rendered config snapshot
```

## Container defaults (production)

| Control | Manager | Executor |
|---|---|---|
| `init: true` | yes | yes |
| `read_only: true` | yes | yes |
| `cap_drop: ALL` | yes | yes |
| `cap_add` | `CHOWN`, `SETUID`, `SETGID`, `DAC_READ_SEARCH` | none |
| `no-new-privileges` | yes | yes |
| User | root → drops to **10002** for builds | **65532** |
| Published ports | **none** | host `CITE_PORT` → 8080 |
| Docker socket | **never** | **never** |
| Egress | yes (GitHub + registries) | **denied by default** (single-site Compose); per site, on by default (orchestrator) |

In the single-site Compose stack, enable executor egress only when an SSR site must call external APIs:

```bash
docker compose -f docker-compose.yml -f docker-compose.egress.yml up -d
```

## Executor egress

With the orchestrator, each site has an `outbound` flag that is **on by default**, so server-side code can call external APIs. Static sites never get it. What an outbound site can reach is set per node by `CITE_STACK_EGRESS_MODE` (details in [Outbound network access](orchestrator.md#outbound-network-access)):

| Mode | What site code can reach |
|---|---|
| `filtered` (default) | The public internet only, through the stack's egress proxy. |
| `open` | Everything the stack's egress bridge can route to: the internet, the Docker host's gateway address (and any host service on it, including ports bound to `0.0.0.0`), other containers reachable from the bridge, every LAN or VPC range the host can reach, and the cloud metadata address unless you block it as below. |
| `off` | Nothing; sites with `outbound` on are refused at deploy time. |

In every mode site code cannot reach other sites' executors, HAProxy's sockets, the connector or the Docker proxy, and nothing can connect in to the executor because it publishes no ports.

### Filtered mode

The executor sits on two internal networks without a gateway: its own `-net` (shared only with HAProxy) and its `-xnet` (shared only with its egress proxy). It has no route to anything else, so the filter is enforced by the network layout rather than by asking the app to behave: code that ignores the proxy variables, opens raw sockets, or speaks another protocol simply cannot get out. The proxy (`cite-egress`, a static, shell-less, non-root binary on a read-only root with every capability dropped) accepts HTTP/1.1 `CONNECT` for HTTPS and plain `http://` requests, resolves the host itself, and connects only to an address it has just checked. It refuses:

- loopback, unspecified and `0.0.0.0/8`, private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), carrier-grade NAT `100.64.0.0/10`, link-local `169.254.0.0/16` (which covers cloud metadata at `169.254.169.254`), multicast, broadcast and the reserved `240.0.0.0/4`, the documentation and benchmark ranges, and the IPv6 equivalents: `::1`, `::`, unique local `fc00::/7`, link-local `fe80::/10`, multicast, documentation, and anything outside global unicast `2000::/3`;
- IPv6 forms that carry an IPv4 address (IPv4-mapped `::ffff:a.b.c.d`, IPv4-compatible `::a.b.c.d`, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`) when the embedded address is refused, and Teredo entirely;
- host names written as numbers (`2130706433`, `0x7f000001`, `0177.0.0.1`, `127.1`) and anything else that is not a plain DNS name, a dotted IPv4 address without leading zeros or a bracketed IPv6 address;
- ports 25, 465 and 587 (mail submission and relay), so a site cannot be turned into a spam relay, unless the site's `outbound_rules.block_mail` is `false`;
- every subnet the proxy container is directly attached to and every gateway in its routing table (read from `/proc/net/route` and `/proc/net/ipv6_route` at start), so neither the host's bridge address nor another stack's proxy is reachable even when a node or site rule opens private ranges;
- the addresses in `CITE_NODE_PUBLIC_IPS`.

The proxy cannot discover the node's public address by itself: it is an ordinary public address, so without `CITE_NODE_PUBLIC_IPS` a site can reach any host service listening on it (SSH, admin panels, anything bound to `0.0.0.0`). Set it on every internet-facing node, for example `CITE_NODE_PUBLIC_IPS=203.0.113.10,2001:db8::10`; the connector and the Docker proxy both add it to `CITE_EGRESS_DENY_CIDRS` of every egress proxy. The egress bridge is created with inter-container traffic off (`com.docker.network.bridge.enable_icc=false`); Docker cannot change that on an existing bridge, so on a node upgraded from 0.4.0 remove the `cite-egress` network once no egress proxy is attached and the next deploy recreates it.

A refusal is a `403 Forbidden` whose body names the reason, for example `destination is a private or internal address`. A plain `http://` request is sent upstream with `Connection: close` and the client connection closes after its response, so one connection carries exactly one request; a request with both `Content-Length` and `Transfer-Encoding`, or with a transfer coding other than `chunked`, gets `400`. The proxy logs the destination host and port and the verdict, never the path or query string. It allows 256 connections at a time and answers `503` past that, gives the DNS lookup and every connect attempt 10 seconds in total, caches lookups for 30 seconds (each use is checked again), waits at most 10 seconds for request headers, and closes a tunnel when nothing moves either way for 120 seconds.

Clients that honour the proxy variables work unchanged: Node `fetch` and `http` (Node 22.21 and newer, and 24, through `NODE_USE_ENV_PROXY=1`), Bun, curl, axios and undici configured to read the environment, Rust `reqwest`, Python `requests`. A client that ignores them cannot reach the internet in filtered mode; configure it to use `http://cite-<id>-<slot>-egress-proxy:3128` (the value of `HTTPS_PROXY`), or use `open` mode on a node whose sites you trust. Databases and other non-HTTP protocols cannot go through the proxy; reach them on a private address you allow (below) only if the client supports an HTTP `CONNECT` proxy, or use `open` mode.

Node settings, set on both the Docker proxy and the connector by the orchestrator overlay:

- `CITE_STACK_EGRESS_ALLOW_CIDRS`: private or reserved ranges every site may reach, for example a LAN database at `192.168.10.0/24`. An explicit CIDR is the only thing that opens loopback, link-local or metadata addresses, so do not list those unless you mean it.
- `CITE_STACK_EGRESS_DENY_CIDRS` and `CITE_STACK_EGRESS_DENY_HOSTS`: public ranges and host names (with their subdomains) no site may reach. These are a ceiling: no site rule can lift them. A deny range also matches the IPv4 address inside a NAT64, 6to4 or IPv4-compatible IPv6 address; write IPv4-mapped ranges as IPv4 (`::ffff:` entries are refused).
- `CITE_NODE_PUBLIC_IPS`: the node's own public IPs, added to the deny ceiling (above). The deny list and these together hold at most 64 entries.
- `CITE_STACK_EGRESS_ALLOW_PORTS`: the destination ports sites may use (`80,443,8000-8100`); empty means every port, less the mail ports for sites that block mail.

### Per-site outbound rules

Each site may carry `outbound_rules`, settable from the apps and through `POST` and `PUT /api/v1/sites`, enforced by its own egress proxy in filtered mode:

| Field | Default | Meaning |
|---|---|---|
| `mode` | `public` | `public`: any public destination, plus private ones named in `allow`. `allowlist`: only destinations named in `allow`; needs at least one entry. |
| `allow` | empty | Up to 64 IPs, CIDRs or host names. A name matches exactly; `.example.com` or `*.example.com` also matches every subdomain. A matching name may resolve to a private address (so a site can reach `db.lan`), but loopback, link-local and metadata addresses open only through an explicit CIDR entry, in either mode. A CIDR wider than `/8` (IPv4) or `/16` (IPv6), or one touching loopback, link-local, unspecified, NAT64 or 6to4 ranges, is refused on create and update unless a node `CITE_STACK_EGRESS_ALLOW_CIDRS` entry covers it. |
| `deny` | empty | Up to 64 IPs, CIDRs or host names, each name also covering its subdomains. Always refused; deny wins over allow. |
| `block_mail` | `true` | Refuses ports 25, 465 and 587. |

The order of precedence is: node deny lists, then the site's `deny`, then (in allowlist mode) the site's `allow`, then the address checks above, which only an allow entry or the node's allow ranges can relax. Changes take effect on the next deploy, which recreates the egress proxy; the executor keeps running if nothing else changed.

### Open and off

For isolation, turn `outbound` off on sites that do not need it, or set `CITE_STACK_EGRESS_MODE=off` so the Docker proxy refuses executor egress for every site on the node (the connector then refuses outbound sites with a clear error and `GET /api/v1/node` reports `egress_mode: "off"` and `executor_egress: false`). The older `CITE_STACK_EXECUTOR_EGRESS=false` still means `off`. In `open` mode add `DOCKER-USER` rules that drop traffic from the `cite-*-egress` bridges to the host and private ranges you do not want reached, and block the metadata address as described below. Filtered mode does not need those rules for executors, but managers still use their unfiltered egress bridge for builds.

## Host firewall

Publish only the executor port (`CITE_PORT`, default 8080). The manager has no published ports. On the host, allow inbound traffic to that port and drop the rest of the Docker-published range. Keep the Docker bridge from reaching cloud metadata (below) and from reaching the host's own admin ports.

## Resource limits

Production Compose caps each service so one site cannot exhaust the host:

| Service | Memory | CPUs | PIDs |
|---|---|---|---|
| manager | 2 GB | 2 | 2048 |
| executor | 1 GB | 1 | 256 |

Build wall-clock time is capped by `CITE_BUILD_TIMEOUT` (default 15 m). The executor also caps connections, header bytes, and body bytes.

## Rootless Docker / userns-remap

Prefer **rootless Docker** or userns-remap on the host so the manager's in-container root maps to an unprivileged host uid. Documented Compose caps still apply inside the user namespace.

## Cloud metadata IP (`169.254.169.254`)

Builds run arbitrary repo code. On cloud VMs, block the instance metadata endpoint from the Docker bridge so a hostile build cannot steal cloud credentials.

Example iptables (adjust bridge name; often `docker0` or `br-*`):

```bash
# Drop traffic from containers to the link-local metadata address.
sudo iptables -I DOCKER-USER -d 169.254.169.254 -j DROP
sudo iptables -I DOCKER-USER -d 169.254.0.0/16 -j DROP
```

nftables sketch:

```bash
sudo nft add rule ip filter forward ip daddr 169.254.169.254 drop
```

Also restrict cloud IAM / instance profiles to least privilege. Cite does not proxy metadata.

## Logging & the GitHub PAT

- Log driver: `json-file`, `max-size=10m`, `max-file=3`.
- The PAT is set as `CITE_GITHUB_TOKEN` in `.env` and passed to the **manager container's environment only**. It is visible to `docker inspect` on the host and to root inside the manager, so restrict who can run Docker on the host and keep `.env` mode `600`.
- It is not visible to the uid-10002 build process (builds run with a cleared environment and `/proc/1/environ` is unreadable to that uid), and the executor never receives it: `docker inspect` of the executor shows no PAT.
- For rotation without a restart, mount a file and set `CITE_GITHUB_TOKEN_FILE` to its path; it is re-read on every poll. The file must be a regular file readable only by its owner (mode `0400` or `0600`); Cite refuses a group- or world-readable token file, because the build uid could otherwise read a bind mount. Mount it under `/run/cite/` (a root-only tmpfs), for example `./github_token:/run/cite/github_token:ro`, so uid 10002 cannot reach it whatever its mode.
- Use a fine-grained PAT limited to the one repository with `contents:read`.

## Start binaries

The executor never runs a shell. A `node_modules/.bin` start binary is run by node, and a pnpm shim is read rather than executed: Cite takes the script its `exec node` line names and starts that.

- Both the `.bin` entry and the script it resolves to must sit inside the release's app directory after symlinks are followed; anything else is refused.
- The shim may pass no node options unless you list them in `CITE_BIN_NODE_FLAGS`, and options that run code or open a debug port are never allowed.
- Set `CITE_BIN_SHIMS=deny` to refuse shell-script bins altogether, for sites that start with `node server.js` or an npm-style JS bin.

## Executor shell-less

Executor images are distroless with no shell. `docker exec … sh` must fail.
