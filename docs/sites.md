# Running real sites

Notes from deploying production Next.js sites with Cite. Everything here uses a `docker-compose.override.yml` next to `docker-compose.yml`, which Compose loads automatically.

## Package managers

Cite installs with the package manager your repo uses: npm (`package-lock.json` or `npm-shrinkwrap.json`), pnpm (`pnpm-lock.yaml`), Yarn classic or Berry (`yarn.lock`, Berry when `.yarnrc.yml` exists or `packageManager` says `yarn@2+`) and Bun (`bun.lock` / `bun.lockb`). Installs are frozen when a lockfile exists.

Precedence: `CITE_PACKAGE_MANAGER`, then the `packageManager` field in `package.json`, then lockfiles in the order pnpm, yarn, bun, npm. When a repo has several lockfiles, the build log warns which one won and why. Setting `CITE_PACKAGE_MANAGER` changes both the install and the build commands of the framework preset, so you rarely need `CITE_BUILD_COMMAND`.

pnpm, Yarn and Corepack caches live on the `cite_cache` volume, so later builds reuse downloads.

## Sites that call external APIs

The executor has no outbound internet by default (`no_egress` network), so a compromised site cannot phone home. SSR code that calls external APIs (for example `fetch("https://api.github.com")`) needs egress:

```bash
docker compose -f docker-compose.yml -f docker-compose.egress.yml up -d
```

If you also attach the executor to your own network (a reverse proxy's, say), Docker may pick `no_egress` as the default route and outbound calls time out with `UND_ERR_CONNECT_TIMEOUT`. Give your network the gateway (Docker Engine 28+):

```yaml
services:
  executor:
    networks:
      no_egress: {}
      proxy:
        gw_priority: 1
networks:
  proxy:
    external: true
```

## Persistent data

Releases are read-only and replaced on every deploy, so anything a site writes at runtime must go to a volume mounted into the executor. The executor runs as uid 65532, so hand the volume to that user first:

```yaml
services:
  data-init:
    image: ghcr.io/seggys116/cite-manager:${CITE_VERSION}-node${CITE_NODE:-22}
    restart: "no"
    user: "0:0"
    read_only: true
    security_opt: [no-new-privileges:true]
    cap_drop: [ALL]
    cap_add: [CHOWN]
    entrypoint: ["/bin/sh", "-c"]
    command: ["chown -R 65532:65532 /data"]
    network_mode: none
    volumes:
      - { type: volume, source: site_data, target: /data }
  executor:
    environment:
      MY_SITE_DATA_DIR: /data
    volumes:
      - { type: volume, source: site_data, target: /data }
    depends_on:
      data-init: { condition: service_completed_successfully }
volumes:
  site_data:
```

To keep data from an existing deployment, declare the old volume instead: `site_data: { external: true, name: <existing volume name> }`. The recursive `chown` fixes files written by a previous container user (for example uid 1001).

## Next.js

- `output: 'standalone'` in `next.config.*` runs `.next/standalone/server.js`; otherwise Cite runs `next start` from `node_modules/.bin`, including the shell shim pnpm writes there (the executor has no shell, so Cite runs the script the shim points at with node). Keep `next` in `dependencies`, because SSR builds prune dev dependencies (`CITE_PRUNE=false` turns that off).
- Every SSR child is bound to loopback (`HOST`, `HOSTNAME` and `NITRO_HOST` are forced to `127.0.0.1`), so the blue and green ports are never reachable from other containers; only the executor's port is.
- ISR and on-demand revalidation try to write regenerated pages into `.next`, which is read-only in a release, so the site logs `EROFS`/`ENOENT` "Failed to update prerender cache" errors. Pages still serve, and the regenerated copy is kept in memory. To stop the errors, keep the cache in memory with a cache handler:

```js
// cache-handler.js
const cache = new Map();

module.exports = class CacheHandler {
  async get(key) {
    return cache.get(key) ?? null;
  }
  async set(key, data, ctx) {
    cache.set(key, { value: data, lastModified: Date.now(), tags: ctx.tags ?? [] });
  }
  async revalidateTag(tags) {
    const list = [tags].flat();
    for (const [key, entry] of cache) {
      if (entry.tags.some((tag) => list.includes(tag))) cache.delete(key);
    }
  }
  resetRequestCache() {}
};
```

```ts
// next.config.ts
const nextConfig = {
  cacheHandler: require.resolve("./cache-handler.js"),
  cacheMaxMemorySize: 0,
};
export default nextConfig;
```

## Rust

The rust images (`CITE_RUNTIME=rust`) require a `Cargo.toml`. Cite takes the binary name from `[[bin]]` when the manifest sets one, and from the package name when it does not. In a workspace, `CITE_ROOT_DIR` is the member that contains that binary; at the workspace root, Cite uses `default-members` or the first member.

When `Cargo.lock` is present the manager runs `cargo build --release --locked`. The binary must listen on `127.0.0.1` and the `PORT` variable Cite sets; blue and green are loopback ports. The published port is still the executor's 8080 (`CITE_PORT` / `CITE_BIND`), the same as Node.

Source is the GitHub tarball. Cite does not clone. `cargo` runs in the manager; the executor only runs the binary.

The release contains that binary, plus `public`, `static`, `assets`, and `templates` when those directories exist. `target/` is not packed. Registry data and build output stay on the `cite_cache` volume (`CARGO_HOME`, `CARGO_TARGET_DIR`).

```bash
docker compose -f docker-compose.yml -f docker-compose.rust.yml up -d
```

A Rust child is one process. Warm grace still keeps the previous binary. An open stream keeps that process until the stream ends, or until the later of `CITE_WARM_GRACE` and `CITE_DRAIN_MAX`.

## Access: Cloudflare only, Flexible SSL and bot policy

A site can be reachable only through the Cloudflare proxy, and can be put in a mode where Cloudflare terminates HTTPS and the origin needs no certificate. It can also refuse requests from known bots. All three live in the site's `access` object. A site without it behaves as before (open access, `tls` of `full`, `bots` of `allow`).

```json
"access": {"cloudflare_only": true, "tls": "flexible", "bots": "block_bad"}
```

| Field | Values | Effect |
|---|---|---|
| `cloudflare_only` | `false` (default), `true` | Connections whose TCP peer is not a Cloudflare address answer 403 before any backend is reached. |
| `tls` | `"full"` (default), `"flexible"` | `full` keeps today's behaviour. `flexible` means Cloudflare talks plain HTTP to the origin. |
| `bots` | `"allow"` (default), `"block_bad"`, `"block_all"` | Answers 403 to requests whose User-Agent names a bot. See [Bot policy](#bot-policy). |

### Cloudflare only

With `cloudflare_only` on, the edge compares the TCP peer address (`fc_src`) with the Cloudflare range list. A client cannot forge that address the way it can forge a header, so a request sent straight to your origin address is refused. The refusal is logged with the rule label `cloudflare-only`, which appears in the Traffic blocked-by-rule table.

For connections from Cloudflare the edge then takes the visitor's address from `CF-Connecting-IP`, so firewall rules, the per-IP rate limit and analytics see the visitor and not a Cloudflare edge. The header is honoured only when the peer is Cloudflare, it is present exactly once and its whole value is a single IP address. Otherwise the source address stays as it was. `CF-Connecting-IP`, `True-Client-IP`, `CF-Visitor`, `CF-Connecting-IPv6` and `CF-Pseudo-IPv4` are removed from requests that do not come from Cloudflare, so a backend never receives a spoofed copy. The per-IP rate limit counts IPv4 and IPv6 visitors alike.

The range list is built into the edge and was last copied from `cloudflare.com/ips-v4` and `ips-v6` on 2026-11-06. Cloudflare changes its ranges rarely but they do change, and a stale list would refuse real traffic. To override it, set `settings.cloudflare_ranges` to your own list of CIDRs. A non-empty list replaces the built-in one; an empty list (the default) uses it. A list holds at most 256 entries. Entries are stored as their masked network (`1.2.3.4/16` becomes `1.2.0.0/16`) and IPv4-mapped IPv6 entries (`::ffff:a.b.c.d`) become IPv4. Ranges wider than `/12` (IPv4) or `/28` (IPv6) are refused, as is any IPv6 range that overlaps `::ffff:0:0/96`, `::/96`, `2002::/16` or `64:ff9b::/96`, because HAProxy also tests IPv4 clients as mapped IPv6 addresses and such a range would make every IPv4 client look like Cloudflare. Cloudflare's own widest ranges are `/13` and `/29`. Changing the list reloads HAProxy.

An address allowlist proves that a request came through Cloudflare, not that it came through your Cloudflare zone: anyone's zone or Worker can connect from the same addresses, so another account can proxy to your origin if it learns its address. The fix is the [zone lock](#zone-lock-prove-the-request-came-through-your-cloudflare-zone) below, which works in both Full and Flexible mode. Keep the origin address private as well. For sensitive sites also prefer Full mode with Authenticated Origin Pulls (mutual TLS at Cloudflare), which the edge does not enforce yet and which is not available in Flexible mode.

This protects only the HTTP port of the edge. Anything that can reach a backend directly, or the node's other ports, is not covered, so also firewall the origin so that it accepts traffic from Cloudflare only where you can.

### Flexible SSL

In Flexible mode Cloudflare serves HTTPS to visitors and connects to your origin over plain HTTP on the edge's HTTP port, so the origin needs no certificate. The edge never redirects the site to HTTPS. For connections from Cloudflare it sets `X-Forwarded-Proto` from the value Cloudflare sent, but only if that value is exactly `https`; anything else, including a missing header, becomes `http`. Connections from any other peer keep the normal logic, which sets `X-Forwarded-Proto` from the connection itself.

Traffic between Cloudflare and the origin is unencrypted in this mode, so anyone on that path can read or change it. Use Flexible together with `cloudflare_only`, and do not use it for sensitive data (logins, payments, personal information) unless you use Cloudflare's Full or Full (strict) mode instead and give the origin a certificate. A site with `cloudflare_only` and `tls` of `full` works through the edge's HTTPS port exactly as an ordinary site does.

Because Cloudflare connects over plain HTTP, Flexible mode rules out Authenticated Origin Pulls, so on its own the address allowlist is the only proof that traffic came through Cloudflare; add the zone lock to prove it came through your zone. Flexible mode also needs the range list, to tell Cloudflare apart from other peers, even when `cloudflare_only` is off.

### Zone lock: prove the request came through your Cloudflare zone

All Cloudflare customers share the same edge addresses, so the address check cannot tell your zone from anyone else's. Cloudflare cannot tell the origin which zone a request is for, but you can add a secret header with one free Transform Rule, and the edge refuses requests without it.

1. Turn the lock on for the site: `"access": {"cloudflare_only": true, "zone_lock": true}`. `zone_lock` requires `cloudflare_only`. The node generates a secret for the site (32 to 128 characters from letters, digits, `-` and `_`) and shows it once, when the lock is enabled or rotated.
2. In Cloudflare, go to Rules > Transform Rules > Modify Request Header, create a rule that matches the site's hostname, and under Modify request header choose Set static: header name `X-Cite-Origin-Secret`, value the secret.

The secret is not part of the site or the rules JSON, so the API never returns it. The node keeps it in a node-local file (mode 0600) and adds the lock rule when it renders the config. A site with `zone_lock` on is never rendered without its lock: if the secret is missing, or no enabled zone-lock rule is present, rendering fails instead of leaving the site open. In the crate, `cite_edge::presets::with_zone_locks(cfg, secret_for)` returns a copy of the config with the rule added for each locked site (an error if a secret is missing), and `zone_lock_rule(site_id, secret)` builds the single rule:

```json
{"id": "zone-shop", "name": "Cloudflare zone lock", "enabled": true, "action": "deny",
 "label": "cloudflare-zone", "site": "shop",
 "matchers": {"header": {"name": "X-Cite-Origin-Secret", "equals": "<secret>", "negate": true, "secret": true}}}
```

The rule id is `zone-<site>` when that fits in 40 characters, otherwise `zone-` plus the first 26 characters of the site id and a short hash of the whole id, so two long site ids never collide. Ids starting with `zone-` are reserved: a rule of your own that reuses one is refused with an error that says so. The edge deletes `X-Cite-Origin-Secret` from every request on the node, not only those of the locked site, because Cloudflare sends it for the whole hostname. A request without the header, or with a different value, answers 403 and is recorded with the label `cloudflare-zone`, so it shows up in the Traffic blocked-by-rule table with its user agent and bot class like any other block. Once the check has passed the edge deletes `X-Cite-Origin-Secret` from the request, so the site's backend never sees the secret.

- To rotate the secret, rotate it from the console or desktop app, then paste the new value into the Cloudflare Transform Rule. The two changes cannot land at the same instant, so requests are refused with 403 in between; do them back to back.
- The secret is written into the rendered `haproxy.cfg` (HAProxy has to compare it), so protect that file and the node's secret file like a credential. It is redacted in the rule's debug output and in validation errors, and it is never put in a log or analytics label. The config hash changes when the secret changes, so a rotation reloads HAProxy.
- In Flexible mode the hop from Cloudflare to the origin is plain HTTP, so the secret crosses it in cleartext. Anyone who can read that path can learn it and replay it. In Full mode it travels over TLS. The lock raises the cost of a casual bypass in Flexible mode; it does not make that hop private.
- The lock is a shared secret, not a signature: anyone who learns it can reach the site by adding the header. Keep the origin address private as well, and combine the lock with `cloudflare_only`.

### Bot policy

`bots` controls what the edge does with requests from known bots, judged by the `User-Agent` header:

| Value | Effect |
|---|---|
| `allow` | The default. Nothing is blocked. |
| `block_bad` | Answers 403 to command-line tools, HTTP libraries and security scanners (`curl`, `wget`, `python-requests`, `sqlmap`, `nikto` and the rest of the lists in [Bot policy](firewall.md#bot-policy)). A request with no user agent at all is not blocked by this setting. |
| `block_all` | Also answers 403 to search engines, link-preview bots, SEO and AI crawlers and uptime monitors. |

Blocked requests still count in analytics: they are logged with the label `bots-bad` or `bots-all`, their user agent, and the bot class and score computed from it, exactly like firewall blocks. User-agent matching is advisory because clients choose their own header, so it stops honest tools and lazy scripts only. `block_all` also removes the site from search results and link previews; do not use it on a site that needs search traffic. The token lists are shared with the Traffic bot classifier, so they cannot drift apart.

Other per-site rules such as redirects (add or remove `www.`, force HTTPS), response headers and CORS are firewall rules scoped to the site; see [the firewall page](firewall.md#rules).

## Memory

After a deploy the previous release keeps running for `CITE_WARM_GRACE` (24 h by default) so rollback is instant, and the executor holds two SSR processes. An open stream (response body or WebSocket) keeps the previous process until it ends, or until the later of that grace and `CITE_DRAIN_MAX`. The default `CITE_EXECUTOR_MEM` is `1g`; raise it for heavy apps, or shorten `CITE_WARM_GRACE`. Raise `CITE_DRAIN_MAX` when a stream should outlive the grace.

## Upgrading to 0.1.4

- A `CITE_GITHUB_TOKEN_FILE` must now be owner-only (`chmod 600`); a group- or world-readable token file is refused. Prefer the `CITE_GITHUB_TOKEN` environment variable, or mount the file under `/run/cite/`.
- Rate limiting is on by default (see [config](config.md#abuse-protection)). Proxies on the same host or Docker network are trusted automatically; a proxy on a public address needs `CITE_TRUSTED_PROXIES`.
- `CITE_EXECUTOR_MEM` defaults to `1g`.

## Upgrading to 0.2.0

- Rust sites use `cite-manager-rust` and `cite-executor-rust` (compose overlay below).
- The app is a Cargo binary. It must listen on `127.0.0.1` and the `PORT` variable (blue/green loopback). The published port is still the executor's 8080 (`CITE_PORT` / `CITE_BIND`), same as Node.
- Source is still the GitHub tarball. Cite does not clone. cargo runs in the manager; the executor only runs the binary.
- The release contains the release binary (and `public`/`static`/`assets`/`templates` if present), not `target/`.
- Registry and build output are cached on the existing cache volume (`CARGO_HOME`, `CARGO_TARGET_DIR`).

```yaml
services:
  init:
    image: ghcr.io/seggys116/cite-manager-rust:${CITE_VERSION:-0.2.0}
  manager:
    image: ghcr.io/seggys116/cite-manager-rust:${CITE_VERSION:-0.2.0}
    environment:
      CITE_RUNTIME: rust
  executor:
    image: ghcr.io/seggys116/cite-executor-rust:${CITE_VERSION:-0.2.0}
    environment:
      CITE_RUNTIME: rust
```

That file is `docker-compose.rust.yml`. For a local build, `docker-compose.dev.yml` keeps its `build:` keys unless you also pass `docker-compose.dev.rust.yml`.
