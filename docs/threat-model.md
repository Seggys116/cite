# Threat model (abridged)

| Actor / asset | Threat | Mitigations |
|---|---|---|
| **Repo code at build time** (same container as the PAT) | Steal PAT, tamper with manager, persist | uid **10002** with all caps dropped; cleared build env (PAT is not in it) and `/proc/1/environ` unreadable to that uid; root-only control socket (`SO_PEERCRED`); read-only rootfs; limits + timeout; no `git`, no Docker socket |
| **Malicious build output** | Symlink/hardlink escape, specials, bombs | Pack via no-follow handles as 10002, then re-extract by the hardened manager into fresh inodes; size/count caps |
| **Malicious tarball** | Zip-slip, symlink escape, bombs | Hardened extractor + fuzzing |
| **RCE in the deployed site** | Shell, persist, pivot | Shell-less distroless executor; read-only rootfs; releases **ro**; non-root; caps dropped; no-new-privileges; pids/mem limits; egress denied by default; can write only `status/`; never receives the PAT |
| **Abusive visitors** | Floods, connection exhaustion | Per-client token-bucket rate limit, per-IP connection cap, timed bans dropped at accept, bounded tracking table, header and idle timeouts |
| **Forged `status/` files** | Mislead manager, exhaust it | No-follow, regular-file-only, size-capped reads; strict schema; control characters rejected; worst case false status, never code execution |
| **Visitor traffic** | Smuggling, Host/XFF spoofing, slowloris, traversal | Strict HTTP parsing, header policy, timeouts/limits, path containment |
| **Supply chain** | Bad deps/images/actions | `cargo deny` + audit, digest-pinned images, SHA-pinned Actions, Dependabot |
| **Host** | Container breakout | No socket, no privileged, minimal caps, default seccomp; prefer rootless / userns-remap |

## Where the GitHub PAT is exposed

The PAT is an environment variable (`CITE_GITHUB_TOKEN`) of the **manager container**, set from `.env` by Compose. Anyone who can do any of the following can read it:

- run `docker inspect` on the manager (any user with Docker access on the host, which is effectively root);
- read `.env` on the host;
- run code as root inside the manager container.

It is not visible to the uid-10002 build process or to the executor and the site it hosts. With `CITE_GITHUB_TOKEN_FILE`, that holds only for an owner-only file (Cite refuses group- or world-readable token files); mount it under `/run/cite/`. A compromised executor or site cannot obtain it; a compromise of the manager's root user or the Docker host can. Limit the blast radius with a fine-grained, read-only, single-repository PAT.

The package-manager and tool caches on `cite_cache` are shared across builds of the same repo, so a malicious commit can leave cached files that a later build uses even after the commit is reverted. That stays within the build uid and the same repository; clear the `cite_cache` volume after removing a malicious commit.

## Site visibility surfaces (0.4.0)

| Surface | Design | Residual risk |
|---|---|---|
| Build and install commands set per site | They run with `sh -c` in the sandboxed build helper (uid 10002, caps dropped, cleared environment, no PAT, no Docker socket), the same place a repo's own build scripts already run. Running them is the feature, so they are not filtered for shell syntax. The start command is validated and never goes through a shell. | Anyone who can edit a site can run code in that sandbox. Treat site edit rights like repo write rights. |
| Logs route (`GET /sites/{id}/logs`) | Read-only. The connector asks the Docker proxy for the logs of containers carrying `cite.managed=true` and the site's own name pattern, with a bounded `tail` (1 to 1000) and no `follow` on the Docker side; following is done by repeated polling. The output is cut at 4 MiB. | Logs are untrusted text produced by the repo's code and are shown as plain text. |
| Log redaction | The connector masks every stored secret for the site (GitHub token, build and runtime environment values, zone secret) before returning log text. | The redactor matches exact values of 4 or more characters only. A secret that a build script prints encoded (base64, URL-escaped, split across lines, reversed) or that is shorter than 4 characters is not masked. Do not print secrets in build scripts. |
| Build and runtime environment values | Stored in `secrets.json` (mode 0600), passed only to the manager that needs them, and never written to `edge.json`, container labels or API replies. After saving, only names are returned. | The values are visible to anyone with Docker access (`docker inspect` of the manager or executor) and to code running in the build or the site, which is the purpose of the variables. |
| Health report | The manager writes a small status record (phase, reason, timestamps) to the data volume and the connector reads it through the same no-follow, size-capped path as `status/` files. | The record is readable by anyone with Docker access to the volume. A forged record can only show a false status. The failure reason is derived from build output, so it can contain whatever the build printed, after redaction. |
| Cloudflare API token | Used only for the DNS-01 challenge and Origin CA calls. It is sent to Cloudflare over HTTPS, kept out of API replies and logs, and for Let's Encrypt it is stored in `secrets.json` (0600) so renewals can run unattended. | A node compromise yields a token that can edit DNS for the zones it covers. Create it scoped to the single zone with DNS edit only (or the Origin CA permission only), and rotate it if the node is lost. |
| ACME account key and stored tokens | Generated on the node, kept in `secrets.json` (0600), never returned. | Same as the node's other secrets: root on the host or Docker access to the config volume reads them. |
| Alert webhooks | Outbound requests from the connector, SSRF-guarded: the destination must resolve to a public address, redirects are not followed, the body is capped and the request has a short timeout. The webhook URL is treated as a secret and returned masked. | DNS rebinding between the check and the connect is narrowed by connecting to the resolved address, but an operator with a hostile resolver can still shape what the node reaches. Webhook bodies carry site names and failure reasons. |
| Per-site GitHub token | Validated against the forge before it replaces the old one; an invalid token is rolled back. Stored in `secrets.json`, set in the manager environment only. | Same exposure as the node PAT described above. |

The connector's secret files named in these rows (`secrets.json`, `alerts.json`, `zone-secrets.json`, `acme-account.pem`, `credentials.json` and the TLS keys) are also sealed under a node key; the mode 0600 still applies on top. That protects a copy of one file or an old volume snapshot, not someone who reads the whole `cite_conf` volume while the managed key sits on it. See [Secrets at rest](security-model.md#secrets-at-rest).

## Site data services

| Surface | Design | Residual risk |
|---|---|---|
| Site code against its own database | Per-database groups with fixed levels (owner, read and write, read only), no superuser rights, `scram-sha-256` only, per-user connection limit and statement and idle-in-transaction timeouts. The runtime user cannot change the schema. | A site that holds the owner credentials (a build running migrations) can change the schema, and a SQL injection in the app is as strong as the runtime user's level. |
| One site against another's database (shared instance) | `CONNECT` revoked from `PUBLIC` everywhere, a generated `pg_hba.conf` that admits each tenant's logins only to its database and only from its own `dbnet` subnet, and a final reject rule. A dedicated server is on the site's own network only. |
| Tenant code against the superuser | The superuser never connects to a tenant database, where functions, views and `ALTER DATABASE ... SET` are tenant-controlled. It works in the `postgres` maintenance database only; maintenance inside a tenant database (backup, restore, counts, regrant) runs as that database's non-superuser job login, which can log in only during a job. Restores run without superuser rights. | The job login inherits the owner group and bypasses row-level security, so tenant code that runs during a job has the owner's rights. Extensions only a superuser can create cannot be restored. | One Postgres process, memory, disk and connection slots for every tenant. A Postgres flaw or a noisy tenant reaches all of them. |
| Database credentials | Generated by the node, kept in the sealed secret store, delivered only through env links, never returned by any route. Rotation uses two logins so a password changes without cutting connections. | The values sit in container environments, so anyone with Docker access reads them, as with any variable. |
| A compromised connector against the Docker API | The proxy accepts only exact data bodies: fixed users, no host mounts, a single `staging/<site>` subpath of the backup volume, the site's own role tag, no published ports. | The proxy cannot tell tenants, so it lets `cite-pg-shared` join any `dbnet`. The connector also holds every database credential and can read every site's data. |
| Backups | Encrypted before they are stored, locally and in S3; plaintext only in a running job's staging directory. S3 targets are node-level, so app credentials cannot delete them. | Backup download returns the decrypted dump to any holder of a token. An S3 copy needs the node key to restore. |
| Node key | A 32-byte key, from the environment, a file or `/conf/secrets.key`; the connector refuses to start with sealed data and a missing or wrong key. | The managed key lives on the volume it protects. Use `CITE_SECRETS_KEY_FILE` on another mount for more, and keep an exported copy away from the node. Plaintext `.pre-seal` copies exist after an upgrade until the next start removes them. |
| External databases | Reached through a fixed-destination TCP forward of the site's egress proxy, with the same resolve, address and port checks as `CONNECT`. The URL is write-only. | `CITE_EGRESS_AUTO_ALLOW` makes allowlist mode accept the attached host names but never opens private addresses. `verify-full` cannot verify the host through a forward. |
| Transfers between nodes | Chunks are hashed one by one and as a whole, the target stores them sealed, the source is never dropped, and generated secrets travel only in the manifest over the nodes' TLS APIs. A manifest link may only read from a user or secret the import creates (or equal a link the target has); otherwise the import is refused. | The process that drives a transfer sees the manifest, secrets included, while it runs. |

## Trust boundaries

```text
Internet ──HTTP──► executor (shell-less) ──files──► cite_data
                      ▲
GitHub ──HTTPS──► manager (has shell) ──files──► cite_data
                      │
                      └── cite_work / cite_cache (manager only)
```

Manager and executor share **no network path**, only the volume.
