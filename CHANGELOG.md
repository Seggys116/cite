# Changelog

This file starts at 0.5.0. Earlier releases are on the [GitHub releases page](https://github.com/seggys116/cite/releases).

## 0.5.0 - 2026-11-20

This release adds managed databases and S3 storage for sites on a node with the orchestrator, and seals every node secret at rest.

### Upgrade notes

Read these before you update a node. The full procedure is in [Upgrading from an older release](docs/node.md#upgrading-from-an-older-release).

- **Back up the node key after the first start.** On its first start with write access, the connector seals its secret files (`secrets.json`, `credentials.json`, `alerts.json`, `zone-secrets.json`, `acme-account.pem`, `tls/ca.key`, `tls/server.key`) under a key. Unless you set `CITE_SECRETS_KEY` or `CITE_SECRETS_KEY_FILE`, it creates `/conf/secrets.key`. Export it and keep it off the node:

  ```bash
  docker compose -f docker-compose.node.yml run --rm --no-deps -T connector secrets export-key > cite-node.key
  ```

  Without the key, the sealed files and every backup are unreadable, and the connector refuses to start rather than create a new key.
- **Sealing is one-way.** A 0.4.x connector cannot read sealed files. Each file is first copied to `<name>.pre-seal` (mode 0600), and the next start that finds the file already sealed deletes the copy. Until that second start, the copies hold the plaintext. After it, going back means restoring a volume backup taken before the upgrade. Volume backups from before the upgrade hold plaintext secrets.
- **Update the dashboard and the desktop app before you attach databases to a site.** An older client cannot parse the new `data` field. The connector leaves `data` out of site responses unless the request carries `X-Cite-Client` with a version equal to or newer than the connector's. An older client sees sites without their data settings, and a write from it never removes them.
- **The data services need the orchestrator overlay.** Update the connector and the Docker proxy together (same `CITE_VERSION`) and run `up -d` with the overlay again; it now creates the `cite-backups` volume. `setup.sh update` fetches the new compose files. Sites without data are unchanged.
- **Raise Docker's address pools on nodes with many sites.** Each orchestrated site uses several Docker networks, and managed Postgres adds one more. Docker's default pools allow about 30, after which deploys fail with `all predefined address pools have been fully subnetted`. See [Docker address pools](docs/node.md#docker-address-pools).
- **Building from source needs Rust 1.100.**

**Tested upgrade.** `scripts/e2e-upgrade.sh` starts a node from the 0.4.1 compose files and images, creates an API token, an orchestrated site, a plain upstream site, a runtime variable, a per-site GitHub token, a site volume, a firewall rule and analytics traffic, then upgrades it in place the way `setup.sh update` does. Sites kept serving through the upgrade (no failed requests in a 0.1 s request loop); only the connector API restarts, for a few seconds. Afterwards the same password and authenticator code log in, the old API token works, the node CA fingerprint is unchanged, the site list is identical, and the variables, token, volume contents, firewall rule and analytics rows are all still there. The secrets are sealed, a redeploy runs on the 0.5.0 images, and Postgres can be enabled on the upgraded site.

**Downgrading is not supported once 0.5.0 has started.** A 0.4.1 connector put back on the same volumes fails to start: it reads the sealed `credentials.json` as plain JSON, and once a site has data attached it also rejects the `data` field in `edge.json`. Nothing is damaged, and starting 0.5.0 again recovers fully. To go back for good, restore volume backups taken before the upgrade.

### Site data services

These need node mode with the orchestrator. See [Site data services](docs/data.md).

- Managed Postgres per site, either dedicated (one container per site) or on a shared instance per node. Postgres 18 is the default and 17 can be selected.
- Database users at the owner, read and write, and read only levels, with password rotation that keeps the old login working until running containers have the new one.
- Env links that deliver URLs and secrets to the build or runtime environment, with presets for Generic, Prisma, Drizzle, Auth.js and Better Auth, and node-generated secrets.
- External Postgres databases, reached through TCP forwards in the site's egress proxy.
- S3 attachments for sites, and S3 backup targets for the node.
- Encrypted, versioned backups with labels, pins, grandfather-father-son retention, a prune preview, restore with a `pre_restore` backup taken first, and verified downloads.
- Conversion between dedicated and shared on the same node.
- Staged transfer of a database from one node to another, verified by comparing row counts table by table. Live transfer is not in this release.
- A Data tab on site pages and a Databases page, in the dashboard and in the desktop app.

### Topology and node scope

- A Topology view in the dashboard and the desktop app draws how hosts reach sites through the nodes, with live load.
- A node switcher sets which nodes a page reads. Firewall, redirect and maintenance changes go only to the nodes you pick, and confirm buttons name their target.
- Pages are compared across nodes, with a `differs` marker and a "Bring nodes in line" action that lists every change before writing anything.
- Site pages show live targets per slot and which nodes hold the site.

See [Dashboard](docs/dashboard.md) and [Desktop app](docs/desktop.md).

### Security

- All node secrets are sealed at rest with ChaCha20-Poly1305, including the TLS private keys. New commands: `cite-connector secrets status`, `secrets export-key` and `secrets rotate-key`, and `cite-connector backup decrypt` for opening a backup file outside the node. See [Security model](docs/security-model.md#secrets-at-rest).
- The Docker proxy validates the data containers, volumes and networks, and refuses them all when `CITE_DATA=false`.
- The Postgres superuser never runs SQL inside a site database. Work in a tenant database runs as a per-database job login that can log in only while a job runs.
- A freeze locks the site's database logins, so open connections cannot switch read-only off.
- Transfer manifests are restricted: a link in an imported manifest can only read from a user or generated secret the import creates, or match a link the target already has.
- `CITE_DATA_S3_ALLOW_PRIVATE` opens only RFC 1918, IPv6 ULA and CGNAT ranges for backup targets. Loopback, link-local and metadata addresses stay refused.
- S3 attachment endpoints must use https.

### Fixes

- Orchestrated Bun sites now get `CITE_RUNTIME`.
- Promote waits up to 30 seconds for an executor that is still starting instead of calling it unresponsive.
- The executor sets a `Host` header on health checks that arrive without one, such as HAProxy's HTTP/1.0 check, which Bun's `req.url` handling needs.

### Platform

- The toolchain is Rust 1.100, and the minimum supported Rust version is now 1.100 (it was 1.88).
- Dependencies are at their latest major versions, including a patched SQLite (RUSTSEC-2026-0459).
- reqwest is 0.13 with ring and the bundled Mozilla roots, set up in the new `cite-tls` crate. The desktop app and the dashboard trust only the node's CA for node connections.
- Base image digests are refreshed. The manager image has Bun 1.4.5, and the Rust executor image uses distroless cc on Debian 13.
