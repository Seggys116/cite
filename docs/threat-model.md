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

## Trust boundaries

```text
Internet ──HTTP──► executor (shell-less) ──files──► cite_data
                      ▲
GitHub ──HTTPS──► manager (has shell) ──files──► cite_data
                      │
                      └── cite_work / cite_cache (manager only)
```

Manager and executor share **no network path**, only the volume.
