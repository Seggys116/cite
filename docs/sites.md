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

- `output: 'standalone'` in `next.config.*` runs `.next/standalone/server.js`; otherwise Cite runs `next start` from `node_modules/.bin`. Keep `next` in `dependencies`, because SSR builds prune dev dependencies (`CITE_PRUNE=false` turns that off).
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

## Memory

After a deploy the previous release keeps running for `CITE_WARM_GRACE` (24 h by default) so rollback is instant, so the executor holds two SSR processes. The default `CITE_EXECUTOR_MEM` is `1g`; raise it for heavy apps, or shorten `CITE_WARM_GRACE`.

## Upgrading to 0.1.4

- A `CITE_GITHUB_TOKEN_FILE` must now be owner-only (`chmod 600`); a group- or world-readable token file is refused. Prefer the `CITE_GITHUB_TOKEN` environment variable, or mount the file under `/run/cite/`.
- Rate limiting is on by default (see [config](config.md#abuse-protection)). Proxies on the same host or Docker network are trusted automatically; a proxy on a public address needs `CITE_TRUSTED_PROXIES`.
- `CITE_EXECUTOR_MEM` defaults to `1g`.
