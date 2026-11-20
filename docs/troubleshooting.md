# Troubleshooting

## `docker compose config` fails

- Ensure `.env` exists (`cp .env.example .env`) with `CITE_REPO=owner/name` and `CITE_GITHUB_TOKEN` set; Compose refuses to render without both.
- Upgrade to Engine **26+** and Compose **v2.26+** if `volume.subpath` or an optional `env_file` is rejected.

## Site returns 503

Executor starts without a release and serves 503 until the first successful deploy. Check:

```bash
docker compose logs manager --tail=200
docker compose exec manager cite status
```

## Deploy never starts

- PAT scopes / repo visibility, and that `CITE_GITHUB_TOKEN` is set in `.env` (`docker compose up -d` again after editing it)
- `CITE_GITHUB_API_URL` if using a mock
- Rate limits / 401s in manager logs (token redacted)

## Build fails, old site stays up

Expected: failed builds do not evict the live slot. Inspect `last_failed_sha`, `last_failed_phase` and `last_failed_reason` via `cite status`.

A failure reason starts with one line naming the step and the exact command, for example `install failed: exit status 1 (pnpm install --frozen-lockfile)` or `build failed: exit status 1 (pnpm run build)`, followed by the last 40 lines the command printed (stdout and stderr together, ANSI colours removed, each line cut at 300 characters, the token and build variable values masked). The same text is the deploy's failure note on the node and in the apps. The step is one of `fetch`, `install`, `build` (including the production prune and missing build output), `pack` and `start`. Common causes:

- `install failed` with a frozen-lockfile error: the lockfile does not match `package.json`, or Corepack ran a different pnpm or Yarn than the one that wrote it. Pin it with `"packageManager": "pnpm@<version>"` in `package.json`.
- `build failed` with `Cannot find module`: a package the build needs is missing from `package.json`.
- `static output_dir missing`: the build wrote somewhere else; set `CITE_OUTPUT_DIR`.
- `SSR start target missing`: the build did not write the server file, or the production prune removed a dev dependency it needs; move the package to `dependencies` or set `CITE_PRUNE=false`.

## Reading a site's status

The manager container prints one line of compact JSON from its Docker healthcheck, so `docker inspect --format '{{json .State.Health.Log}}' <manager>` shows the latest report in each entry's `Output`. The line is at most 3500 bytes (Docker keeps 4096). When it would be longer, `last_error` is cut first (its first line and its last lines are kept with a `...` line between), then `detected`, then optional fields are dropped. The exit code is unchanged: healthy whenever the manager answers its control socket.

| Field | Meaning |
|---|---|
| `v` | Report version, currently `1` |
| `phase` | `fetching`, `building`, `packing`, `promoting`, `idle` or `failed` (see below) |
| `since` | When the manager entered `phase` |
| `sha` | Commit being handled; absent when `idle` |
| `deploy` | `id`, `result` (`live` or `failed`) and, for a failure, `phase` of the last attempt started by `CITE_DEPLOY_ID` |
| `head_sha` | Newest branch head the manager has seen |
| `live_sha` | Commit currently deployed |
| `last_build_secs` | Duration of the last attempt since the manager started |
| `last_failed_sha` | Commit that failed and is not retried |
| `last_error` | Why the last attempt failed: the step and command, then the command's last output lines, with the token and build variable values masked |
| `failed_phase` | The step `last_error` comes from: `fetch`, `install`, `build`, `pack` or `start` |
| `token` | `ok`, `invalid`, or `unknown` before GitHub has answered |
| `token_expires_at` | Token expiry when GitHub reports one |
| `detected` | What the build uses: `framework`, `package_manager`, `rendering`, `node`, `install_command`, `build_command`, `output_dir` (static) or `start` (SSR), `confidence` (`high`, `medium`, `low`) and `notes` on anything detection assumed |
| `executor` | `active` slot and the `blue` and `green` slot states from `status/executor.json` |

Phases: `fetching` downloads the source for the commit; `building` extracts it and runs install and build; `packing` seals the output into a release; `promoting` starts it in the free slot and runs the health gate; `idle` means nothing is running and the last attempt succeeded or none ran; `failed` means the last attempt failed and `last_error` says why. `detected` stays after the attempt ends so a failure shows which commands ran.

## Health gate fails

Candidate never goes live; previous remains. The failure reason starts with `start failed:` and says what happened, followed by the server's last output lines:

- `the server process exited with code 1 before it listened on port N`: the server crashed at startup; its own error is in the lines below (a missing module, a missing environment variable, a database it cannot reach).
- `the server process did not answer / on port N with a status below 500 within 60s`: the server must listen on the `PORT` it is given (and `127.0.0.1` or all interfaces); a port hard-coded in the code or a `-p` flag in a custom start command breaks this. A slow start needs a longer `CITE_HEALTH_TIMEOUT`, and a server whose `/` fails needs `CITE_HEALTH_PATH`.
- `the server process could not be started`: the start file or interpreter is missing; for `bun` start commands set `CITE_RUNTIME=bun`.

`status/executor.json` `last_result` holds the same reason and the log tail.

## Cannot `docker exec` a shell into executor

Expected: the image is shell-less. Use `cite status` / Compose logs instead.

## Executor needs outbound HTTP

Default egress is denied. Attach the override:

```bash
docker compose -f docker-compose.yml -f docker-compose.egress.yml up -d
```

## Manager has no published ports

Expected. Operate with `docker compose exec manager cite …`.

## Subpath mount / empty releases

Engine must support volume subpaths. Confirm with `docker compose config`, Engine 26+ and Compose v2.26+.

## Site env vars missing in the build or SSR process

Put build-time variables in `build.env` and runtime variables in `runtime.env` next to `docker-compose.yml`, then `docker compose up -d`. Variables prefixed `CITE_` and host variables (`PATH`, `HOME`, ...) are not forwarded. See [config.md](config.md).

## Node: the connector will not start with `sealed secrets found`

The connector seals its secret files under a node key and refuses to start when it cannot open them. `docker compose -f docker-compose.node.yml logs connector` shows one of:

- `sealed secrets found (<file>, key <id>) but no key: restore /conf/secrets.key or set CITE_SECRETS_KEY_FILE`: the managed key is gone and none is configured. Put the exported key back as `/conf/secrets.key` (mode 0600), or mount it and set `CITE_SECRETS_KEY_FILE`. The connector never makes a new key over sealed data.
- `<file> is sealed under key <id>, but this node has key <id>`: the key in use is not the one that sealed the file, for example after a restore of an older `cite_conf` or a changed `CITE_SECRETS_KEY_FILE`. Supply the key with the first id. After a rotation, put the old key in `CITE_SECRETS_KEY_PREVIOUS_FILE` and restart.
- `CITE_SECRETS_KEY: the secrets key must look like cite-key-v1:<43 characters of base64url>` (or the same for `CITE_SECRETS_KEY_FILE`): the value is not a key. The error never prints the value.

`docker compose -f docker-compose.node.yml run --rm --no-deps connector secrets status` shows which key the node has, where it comes from, and the state of each file (absent, plaintext, sealed under which key, unreadable). `<name>.pre-seal` files are the plaintext copies made when a file was first sealed; see [Upgrading](node.md#secrets-are-sealed-site-data-services-release). If you lost the key and have an older volume backup, restore that backup and its key together.

## Node: data routes answer 404, or the Data tab is missing

- `data services are not enabled on this node`: the connector has no Docker access or no `CITE_DATA_BACKUP_DIR`. Start the node with the orchestrator overlay.
- The `data-*` capabilities are listed only while the data service is running, so a node whose data service failed to start shows no Data tab and no Databases view. The connector log says why (`data services are off`).
- A static site has no Data tab and cannot enable Postgres; the site needs a repository build with a server runtime.
- A console that predates data services shows no Data tab and, through an older connector, sees sites without a `data` field. Update the dashboard or desktop app; see [Upgrading](node.md#data-services-and-older-clients).
- Docker proxy refusals that name `data services are off on this node (CITE_PROXY_DATA=false)`: set `CITE_DATA=true` in `.env` and recreate the proxy.

## Node: a deploy says `the database of <id> is not ready`

The deploy checks the site's Postgres before it changes any container and stops, with the running slot untouched, when the database does not become healthy within 120 seconds. The reason follows the message. Look at the database container's logs (`cite-<id>-db`, or `cite-pg-shared` for shared mode) and its health in the site's Data tab. The Databases page has a Restart action for the shared instance.

## Node: a database job failed

Jobs report as `the <op> job failed (exit <n>): <last lines>`; the lines are redacted. Exit 2 means the job refused its input, 3 means the shared server rejected the generated `pg_hba.conf` (the previous file was restored). A job also fails after `CITE_DATA_JOB_TIMEOUT` seconds. `GET /api/v1/data/jobs/{job}` gives the state, step and error of a job started by a data route; the connector keeps the last 200. `two data jobs are already running; try again shortly` (429) means the node's two job slots are busy. `not enough space` (507) is an import that needs twice the dump plus 1 GiB on the backup volume.

## Node: a site cannot connect to its database

- The connection string comes from an env link, and links apply at the next deploy. A new, rotated or converted credential reaches a running container only after a deploy (`redeploy_needed`).
- `no pg_hba.conf entry` or `rejected` from the shared instance: the instance allows a tenant only from its own `dbnet` subnet. The connector writes each tenant's subnet into `pg_hba.conf` at startup, whenever a `dbnet`, the admin network or the shared container is recreated, and when the instance or a shared tenant changes. A disabled user cannot log in, and neither can any user of a database that is frozen or being restored: those logins are `NOLOGIN` and carry the role comment `cite:locked` until the freeze or restore ends. Do not edit these comments.
- A user that was rotated keeps working on its old login until the next deploy replaced the containers (or 7 days); then the old login is retired. A container that still carries the old password after that has not been redeployed.
- Check the user's level. A read-only user cannot write and a read and write user cannot change the schema.

## Node: backup, restore and S3 problems

- `the active slot is not running; start the site first`: a backup of an external database runs through the site's own network and needs a running executor.
- A restore fails with `the dump creates an extension that only a superuser can create`: restores run without superuser rights, so only trusted extensions (for example `pgcrypto`, `citext`, `hstore`) can be restored.- A backup of an external database fails when the URL points at a pooler that rejects the `options` startup parameter (pgbouncer in some modes): the backup job pins `search_path` that way. Attach the database directly for backups.
- `the backup comes from Postgres <n>, newer than this database`: a restore or import refuses a dump from a newer major than its target.
- A backup stays `running` after a connector restart: the connector marks it `failed` at start with the note `interrupted by a connector restart`. Start a new one.
- A failed scheduled backup raises the `backup_failed` alert and is not retried until the next slot.
- `the backup does not match its recorded checksum`, or `the backup is damaged: chunk <n> failed authentication`: the file was altered or truncated, or it is being opened under another backup id. A backup sealed under a key this node does not hold reports the key ids, as for the secret files above.
- `POST /api/v1/data/targets/{id}/test` returns `{ok:false,error}` where `error` is one of `auth_failed`, `bucket_missing`, `unreachable`, `tls_error`, `refused_address`, `http_<status>` or `request_failed`; the server's own message is only in the connector's debug log. `refused_address` means the endpoint is a loopback, link-local or other reserved address, a private address while `CITE_DATA_S3_ALLOW_PRIVATE` is not `true`, or plain http to anything but an RFC 1918, ULA or CGNAT address.
- A backup whose S3 object could not be deleted stays listed with a `delete_error` on its S3 copy, and the scheduler retries.

## Node: an external database is unreachable

- `outbound access is switched off ...` or `this site has outbound access switched off`: switch the site's `outbound` flag on, and check `CITE_STACK_EGRESS_MODE` is not `off`.
- `the node's CITE_STACK_EGRESS_ALLOW_PORTS does not include <port>`: add the port.
- The egress proxy's log shows `verdict=denied` with a reason. A private or internal address needs an explicit rule: the host name or range in the site's `outbound_rules.allow`, or a range in the node's `CITE_STACK_EGRESS_ALLOW_CIDRS`. `CITE_EGRESS_AUTO_ALLOW` never opens one. In allowlist mode an IP-address host needs its own `allow` entry.
- `sslmode=verify-full` fails on a filtered node because the client verifies the proxy's name. Use `require` or `verify-ca`, or link the `tls_servername` field into a driver option that sets the server name.
- A forward port moves when attachments are added or renamed, because ports follow the sorted names. Redeploy so the new URLs and the proxy's forwards agree.

## Node: env link problems

- A link request answers 409 with a list of conflicts: those variables are already set by hand or linked to another source. Resend with `override: true` to replace the manual ones, or remove the link first.
- `PATCH` of a build or runtime variable answers 400 `<var> is linked from ...; remove the link first`.
- A linked variable that is also in Doppler is shadowed by the link; `GET /sites/{id}/data` lists it under `shadowed`.
- `... would be <n> characters; the limit is 4096` or an environment over 128 variables or 24 KiB: the merged environment must fit the same limits as any site.

## Reset local data

```bash
docker compose down -v
docker compose up -d
```
