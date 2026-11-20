# Site data services

This page covers the databases and storage a node can run or attach for a site: managed Postgres, external Postgres, S3 attachments, generated secrets, the env links that deliver them, backups, and moving data between modes and nodes. It needs the [orchestrator](orchestrator.md). Routes are in [Connector API](node-api.md#site-data-services); the console views are in [Dashboard](dashboard.md#data-and-databases) and [Desktop app](desktop.md#data-and-databases).

## Requirements

- The orchestrator overlay. It mounts the `cite-backups` volume into the connector at `/backups` and sets `CITE_DATA_BACKUP_DIR`. The connector runs data services only when it has both Docker access and that variable; otherwise the data routes answer 404 `data services are not enabled on this node`, and `GET /api/v1/data` reports `enabled: false`.
- `CITE_DATA=false` in `.env` makes the Docker proxy refuse every data container, volume and network (`CITE_PROXY_DATA`). The default is `true`.
- A site built from a repository with a server runtime. A static site cannot have data services.
- For external Postgres and S3 attachments: the site's `outbound` flag on and the node's `CITE_STACK_EGRESS_MODE` not `off`.
- The images `cite-postgres:<version>-pg17` and `-pg18`, pulled from the node's registry like the other Cite images. Each is the digest-pinned official `postgres:<major>-alpine` image plus the `cite-pg-job` maintenance script.

A node with the orchestrator lists the capabilities `data-postgres`, `data-shared`, `data-external`, `data-s3`, `data-backups`, `data-links` and `data-transfer` in `GET /api/v1/node` only while the data service is running; without it none of them is listed, and `GET /api/v1/data` reports `enabled: false`.

## Modes

| Mode | What runs | Where the site connects |
|---|---|---|
| Dedicated | One Postgres container for the site: `cite-<id>-db`, volume `cite-<id>-db-data`, internal network `cite-<id>-dbnet`. Blue and green share it. | `cite-<id>-db:5432` |
| Shared | One Postgres container for the node, `cite-pg-shared`, with databases and roles per site. It joins each tenant's `cite-<id>-dbnet`. | `cite-pg-shared:5432` |
| External | Nothing runs on the node. The site's URL is stored and, on a filtered node, reached through a TCP forward of the site's egress proxy. | See [External Postgres](#external-postgres) |

Dedicated and shared are the two managed modes. A site picks one when it enables Postgres and can change it later with a [conversion](#converting-between-dedicated-and-shared).

| | Dedicated | Shared |
|---|---|---|
| Isolation | Own process, volume and network. | Separate database and roles per site inside one process. Access is limited by `pg_hba.conf` (see [Security model](security-model.md#site-data-services)). |
| Resources | Per site: memory 256 to 65,536 MiB (default 512), one CPU, `max_connections` 10 to 1000 (default 100). The Docker proxy also caps memory and CPU at `CITE_STACK_MAX_MEM` and `CITE_STACK_MAX_CPUS`. | Per node: memory 256 to 65,536 MiB (default 1024), 0.25 to 64 CPUs (default 1), `max_connections` 10 to 1000 (default 200). Every tenant shares them. |
| Noisy neighbour | None. | CPU, memory, I/O and connection slots are shared. |
| Postgres major | 17 or 18, chosen per site (default 18). | The instance's major; fixed once the instance exists. |
| Failure | Affects this site. | A crash or full disk of the instance affects every tenant. |
| Restart or resize | Per site. | Changing the settings recreates the container and disconnects every tenant. |
| Backups | Per database. | Per database, plus an optional whole-instance backup. |
| Setup | Enable Postgres on the site. | Enable the shared instance once on the node (`PUT /data/shared`), then enable Postgres on the site with mode `shared`. |

The major of a database is fixed when it is created. A shared database follows the instance.

## Enabling Postgres

`PUT /api/v1/sites/{id}/data/postgres` with `{mode, major?, memory_mb?, max_connections?, preset?}` answers 202 with a job id. `GET /api/v1/data/jobs/{job}` shows its progress. The job creates the container, volume and network, starts the database, waits up to 120 seconds for it to be healthy, and creates the first database and its users:

- database `app`, users `app` (read and write) and `migrate` (owner);
- the env links `DATABASE_URL` (runtime, from `app`) and `MIGRATION_DATABASE_URL` (build, from `migrate`). With `preset: "generic"` the runtime links also include `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD` and `PGSSLMODE`. A link whose variable is already set by hand is skipped and reported.

Nothing reaches a running container until the next deploy. A deploy first makes sure the database is running and aborts when it is not (`the database of <id> is not ready: <reason>; the running slot was not changed`).

`PUT` on an enabled site updates its resources (dedicated only). `DELETE /sites/{id}/data/postgres` turns Postgres off: dedicated removes the container and network and keeps the volume, shared disables the logins and removes the site's access rules and keeps the databases. Add `?purge=true` to delete the volume or databases, the credentials and the backups. Turning Postgres off also removes every link that reads from it and answers `redeploy_needed` when it removed any.

Deleting a site keeps its data unless the request carries `?purge_data=true`. Kept data is listed as left behind by `GET /api/v1/data/orphans`, and a new site with the same id picks it up again. `DELETE /data/orphans/{id}` purges it. A purge never deletes S3 copies of backups; the answer reports how many are left.

## Databases and users

A site has at most 4 databases and each has at most 8 users. Database and user names match `^[a-z][a-z0-9]{0,15}$`; `postgres`, `template0` and `template1` are reserved. Every database needs at least one user, and a site with Postgres needs at least one database.

Each user has a level. The levels are fixed presets; there are no free-form grants.

| Level | Can | Default statement timeout |
|---|---|---|
| Owner | Owns every object in the database and changes the schema. The login runs as the database's owner group, so objects belong to the group and not to the login. Use it for migrations. | None |
| Read and write | `SELECT`, `INSERT`, `UPDATE` and `DELETE` on tables and `USAGE`, `SELECT` and `UPDATE` on sequences, including objects the owner creates later. The level for the running app. | 30 seconds |
| Read only | `SELECT` on tables and sequences. | 30 seconds |

The grants cover the `public` schema. Other per-user settings are the connection limit (1 to 500, default 20), the statement timeout (0 to 3,600,000 ms, 0 meaning none) and the idle-in-transaction timeout (1,000 to 3,600,000 ms, default 60,000). The server also ends sessions that sit idle in a transaction for 300 seconds. A user can be disabled, which switches its logins off and ends its sessions, and enabled again. The last owner of a database cannot be deleted or demoted, and a user that a link reads from cannot be deleted. Deleting a database is refused while a link reads from it or while it has pinned backups, unless `purge=true`.

The site's roles are created without superuser, create-database, create-role, replication and row-security bypass rights. Authentication is `scram-sha-256` only. `sslmode=disable` appears in generated URLs: traffic stays on an internal network of the host, and TLS inside the node is not available in this release.

### Names inside Postgres

The names a site sees in its URLs are derived from the site id, so they are the same in both modes and on every node. The tag is the first 10 hex characters of the SHA-256 of `cite-pg-v1:<site id>`.

| Object | Name |
|---|---|
| Database, dedicated | `<db>` |
| Database, shared | `t<tag>_<db>` |
| Groups | `t<tag>_<db>_owner`, `_rw`, `_ro` and `_login` |
| Logins | `t<tag>_<db>_<user>_a` and `_b` |

The shared instance refuses a site whose tag equals another tenant's (409, `pick another site id`).

### Superuser and job logins

Owner-level logins are held by site code, so everything inside a tenant database (functions, views, `ALTER DATABASE ... SET`) is under the tenant's control. The superuser therefore never connects to a tenant database. Its sessions open only the `postgres` maintenance database, with `search_path` pinned to `pg_catalog,pg_temp` and qualified names, and do role, database and access-rule administration there. Work inside a tenant database (backing up a managed database, restoring, counting rows, re-applying grants, and the `REASSIGN OWNED` and `DROP OWNED` of a deleted user) runs as a job login of that database, `t<tag>_<db>_job`. It is not a superuser, but it bypasses row-level security and inherits the owner group, and it can log in only while a job runs: the superuser opens it with a fresh password for the job and closes it afterwards (`NOLOGIN`, no password). On the shared instance `pg_hba.conf` lets the superuser in only to the `postgres` database from the admin network, and lets each `<db>_job` login in to its database from the admin network. On a dedicated server the job login is kept to its own database by `CONNECT` grants.

### Passwords are never shown

No route returns a password, and there is no reveal action. A password is generated by the node (32 random bytes, 43 URL-safe characters), kept in the sealed secret store and delivered only where it is used: into the env of a deploy through a link, and into the environment of the one-shot job containers that create logins. External database URLs and S3 keys are write-only for the same reason. The connector redacts stored data secrets from the logs and job output it returns, including percent-encoded passwords and every rendered env value that carries a secret.

### Rotating a password without downtime

Every user is two Postgres logins, `a` and `b`. `POST /sites/{id}/data/postgres/databases/{db}/users/{user}/rotate` sets a new password on the idle login, makes it the active one and leaves the old login working. The next deploy gives running containers the new password. The old login is then switched off: when no running manager or executor still carries it, or after 7 days at the latest. A user that only has build links also waits 2 hours for builds that started before the rotation. A new rotation of the same user is refused with 409 until the previous one is finished. The answer says `redeploy_needed` when a link delivers the password to a running site.

## Env links

An env link names a variable, a target and a source. Nothing a data resource produces reaches the site unless a link says so.

| Part | Values |
|---|---|
| `var` | A variable name valid for the target, the same rules as `PATCH /sites/{id}/runtime-env` or `build-env`. A site has at most 64 links. A variable is linked once per target. |
| `target` | `runtime` (the executor), `build` (the manager), or `both` in a request, which stores one link for each. |
| `source` | `postgres` (database, user and a field), `external` (a name and a field), `s3` (a name and a field), `secret` (a generated secret), `site_url` (`https://<first host of the site>`). |

Fields of a Postgres source are `url`, `host`, `port`, `database`, `user`, `password` and `sslmode`. A managed `url` has the form `postgres://<login>:<password>@<host>:5432/<database>?sslmode=disable`, with the derived login and database names above. External sources add `tls_servername`. S3 fields are `endpoint`, `bucket`, `region`, `access_key_id`, `secret_access_key` and `path_style`. A rendered value is at most 4096 characters.

- A link whose variable is already set by hand for that target is refused with 409 and the list of conflicts, unless the request carries `"override": true`, which removes the manual variable in the same update.
- A Doppler variable of the same name is shadowed by the link; `GET /sites/{id}/data` lists such names under `shadowed`.
- `PATCH` of a linked variable on `build-env` or `runtime-env` is refused with 400 naming the link.
- A new link checks the merged environment against the same limits the Docker proxy applies at deploy time, so a link that would push the environment over 128 variables or 24 KiB is refused when it is created.
- Links take effect at the next deploy.

### Presets

`POST /sites/{id}/data/links/preset` creates the databases, users, generated secrets and links a framework usually needs, with `{preset, database?, runtime_user?, migrate_user?, auth_database?, override_manual?}`. The defaults are database `app`, runtime user `app` (read and write), migrate user `migrate` (owner) and, for Auth.js, database `auth`. A preset is refused when a user it needs exists with another level or a variable is already linked to another source. It answers 202 with a job id when it has to create databases or users and 200 otherwise.

| Preset | Runtime links | Build links | Also creates |
|---|---|---|---|
| `generic` | `DATABASE_URL`, `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD`, `PGSSLMODE` from the runtime user | `MIGRATION_DATABASE_URL` from the migrate user | |
| `prisma` | `DATABASE_URL` from the runtime user | `DATABASE_URL` and `DIRECT_URL` from the migrate user | |
| `drizzle` | `DATABASE_URL` from the runtime user | `DATABASE_URL` from the migrate user | |
| `authjs` | `AUTH_SECRET`, `AUTH_DATABASE_URL` (the `auth` database, runtime user) | `AUTH_MIGRATION_DATABASE_URL` (the `auth` database, migrate user) | Secret `auth-secret` |
| `better-auth` | `BETTER_AUTH_SECRET`, `BETTER_AUTH_URL` (the site URL), `DATABASE_URL` from the runtime user | `DATABASE_URL` from the migrate user | Secret `better-auth-secret` |

The `PG*` variables of the `generic` preset describe the site's own database. Some clients let them fill in fields of any connection string: Bun's `SQL`, for one, takes `PGDATABASE` over the database named in a URL. A site that also links a second database, such as an external one, should then pass that connection's fields explicitly, or use a preset without `PG*` variables.

## Generated secrets

A generated secret is a random value the node keeps, for variables such as `AUTH_SECRET`. A name matches `^[a-z][a-z0-9-]{0,30}$`; a site has at most 8. `POST /sites/{id}/data/secrets` takes `{name, bytes?, encoding?}`: 32 to 128 random bytes (default 32), encoded as `base64url` (default) or `hex`. The value is never returned. `POST .../secrets/{name}/rotate` replaces it and answers `redeploy_needed`; rotating a secret that signs sessions signs every user out. `DELETE` is refused while a link reads from it. A secret reaches the site only through a `secret` link.

## Migrations

Cite does not run a migration tool. It makes a credential available to the build, and the build command runs the tool.

When a build-target link reads from managed Postgres, the manager joins the site's `cite-<id>-dbnet` network for that build, and only then. The default `MIGRATION_DATABASE_URL` and the build links of the `prisma`, `drizzle`, `authjs` and `better-auth` presets give the build the owner-level user, so a build command such as `prisma migrate deploy` can change the schema. The running app gets the read and write user.

- A blue/green deploy builds the new slot while the old one serves. A migration therefore has to work for the old code too: add before you remove (expand, then contract).
- Build code, including install scripts of dependencies, holds the owner credentials while it runs. The alternative is to link an owner URL into the runtime environment and migrate at start. That gives the running process schema rights, so it is not the default.
- A build-target link to an external database uses the stored URL as it is; the manager has direct outbound access.

## Backups

Backups are per database, `pg:<db>` for managed ones and `ext:<name>` for external ones. Each is made by a one-shot job with `pg_dump -Fc -Z 6` and becomes an immutable numbered version.

| Property | Behaviour |
|---|---|
| Versions | Numbered per database from 1, never reused, even after a version is deleted. Only the label and the pin of a version can change. |
| Record | Id, version, trigger (`manual`, `scheduled`, `pre_restore`, `transfer` or `import`), label (at most 100 characters), pinned flag, plaintext size and SHA-256, server version, status (`running`, `ok` or `failed`), encryption (scheme `cite-stream-v1` and key id), and the local and S3 copies. A catalog holds at most 2000 records per database. |
| Labels and pins | `PATCH /sites/{id}/data/backups/{id}` with `{label?, pinned?}` (`label: null` clears it). A pinned version is never pruned and cannot be deleted until it is unpinned. |
| Encryption | Every dump is encrypted before it is kept, locally and in S3: 64 KiB chunks sealed with ChaCha20-Poly1305 under a data key of its own, which the node key wraps. Plaintext exists only in the job's staging directory while a job runs and is deleted afterwards, also on failure. |
| Where | The `cite-backups` volume, in `/backups/sites/<site>/<id>.cbk`. |
| Download | `GET .../backups/{id}/download` streams the decrypted dump (`application/octet-stream`, `X-Backup-Sha256`, byte ranges supported). It returns the data of a site in plain form, so it needs the same token as any other route and is audited. |
| Schedule | None by default. `PUT .../data/postgres/policy` sets `schedule: {every_hours, minute}` with `every_hours` one of 1, 2, 3, 4, 6, 8, 12 or 24. Slots are UTC: the hours that divide evenly by `every_hours`, at the given minute, with up to five minutes of random delay. A connector that was down at a slot makes one catch-up backup when it starts. A failed attempt is not retried until the next slot and raises the `backup_failed` alert. Schedules cover managed databases. |
| External databases | Manual backups only, while the active slot is running, and never restored into the external database (a version can be restored into a managed database). The backup pins the connection option `search_path` (`PGOPTIONS`) as a startup parameter, so a pooler that rejects the `options` startup parameter, such as pgbouncer in some modes, makes the backup fail. Point the backup at the database directly. |

### Retention

Retention is a grandfather-father-son rule applied separately to the copies on the node (`local`) and in S3. All times are UTC. The policy has `keep_all_hours` (default 24), `daily_days` (7), `weekly_weeks` (4), `monthly_months` (6) and `pre_restore_days` (7).

A version with status `ok` that has a copy in the tier is kept when the first of these holds:

1. it is pinned;
2. it is the newest version of its database;
3. it is younger than `keep_all_hours`;
4. it is a `pre_restore` version younger than `pre_restore_days`;
5. it is the newest version of one of the last `daily_days` calendar days, `weekly_weeks` ISO weeks (Monday start) or `monthly_months` calendar months.

Every other copy is deleted. A version is removed from the catalog when it has no copy left, and failed records are dropped after 30 days. `GET /sites/{id}/data/prune-preview` lists, per database and tier, what would be kept (with the reason) and what would be deleted; `POST .../data/prune` applies it and reports the count. The same rule runs daily at 03:17 UTC and after backups. `DELETE .../backups/{id}?from=local|s3|all` removes copies by hand.

### Restore

`POST /sites/{id}/data/backups/{id}/restore` with `{confirm, database?}` needs `confirm` to equal the site id. The target is the backup's own database unless `database` names another managed one. It answers 202 with a job id and the id of the `pre_restore` backup it took first; if that backup fails, the restore does not run. The restore then runs `pg_restore --clean --if-exists --exit-on-error --single-transaction --no-owner --no-acl --role=<owner group>` into the database as the database's job login, which is not a superuser (see [Superuser and job logins](#superuser-and-job-logins)), so a failed restore rolls back; it re-applies the privilege layout afterwards. While it runs, the site's logins for that database are locked (`NOLOGIN`) and their open sessions are ended, and they are given back afterwards. A dump that creates an extension only a superuser may create cannot be restored; trusted extensions such as `pgcrypto`, `citext` and `hstore` can. A dump made on a newer Postgres major than the target is refused. Because the restore ignores owners and grants, a dump restores into either mode, on any node, under any role names.

### S3 copies and targets

A backup destination is a node-level target, separate from the buckets a site uses, so credentials an app holds cannot delete backups. `POST /api/v1/data/targets` takes `{name, endpoint, bucket, region, path_style?, prefix?, encrypt?, access_key_id, secret_access_key}`: at most 16 targets, `prefix` defaults to `cite`, and `encrypt` cannot be `false`. The keys are write-only; on update, omitted keys keep the stored ones. `POST /data/targets/{id}/test` checks the credentials.

The endpoint must use https and name a public address, unless the node sets `CITE_DATA_S3_ALLOW_PRIVATE=true`, which opens exactly three private ranges for targets (for example MinIO on the host's network): RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), IPv6 ULA (fc00::/7) and CGNAT (100.64.0.0/10). Plain http is allowed only with the flag and only to an address in those ranges. Loopback, link-local (including the 169.254.169.254 metadata address), unspecified, multicast, broadcast, documentation and other reserved addresses, and their IPv4-mapped forms, stay refused with the flag on. `POST /data/targets/{id}/test` reports a fixed word in `error` (`auth_failed`, `bucket_missing`, `unreachable`, `tls_error`, `refused_address`, `http_<status>` or `request_failed`) and never the server's own text. The connector resolves the name, checks the address and connects to that address only, without following redirects or using proxies. It signs requests itself (SigV4); objects up to 64 MiB go in one request and larger ones as multipart uploads.

A site's policy names a target in `s3: {target, retention}`; scheduled backups are then pushed and pruned by their own retention. `POST .../backups/{id}/push` pushes one version, `push_s3: true` on a manual backup pushes it when done. A copy in S3 is encrypted with the node key like the local one. Restoring it, on this node or another, needs that key: see [Backing up the node key](#backing-up-the-node-key).

### Backing up the node key

Everything sealed on the node, including backups, is bound to the node key (see [Security model](security-model.md#secrets-at-rest)). Export it and keep it away from the node:

```bash
docker compose -f docker-compose.node.yml -f docker-compose.orchestrator.yml exec -T connector cite-connector secrets export-key > cite-node.key
```

Anywhere else, a backup file is decrypted with:

```bash
cite-connector backup decrypt --in <id>.cbk --out dump.pgdump --backup-id <id> --key-file cite-node.key
```

`--out` must not exist. The result is the custom-format dump that `pg_restore` reads. `--backup-id` is required because the file is bound to it.

## External Postgres

`PUT /sites/{id}/data/external/{name}` with `{url}` attaches a database: `postgres://user:password@host[:port]/database[?query]`. The name matches `^[a-z][a-z0-9-]{0,30}$` and a site has at most 4. The URL holds one host, which is a name or an IP address; a query may not set `host`, `hostaddr`, `port`, `user`, `password`, `dbname`, `service` or a file path option, because those would move the connection past the egress rules. The URL is stored sealed and never returned; the answer has the host, port, database, `sslmode`, the forward port and warnings. The node's `CITE_STACK_EGRESS_ALLOW_PORTS` must include the port.

On a node in `filtered` egress mode the app has no route out, so each attachment gets a TCP forward in the site's egress proxy:

- Forwards listen on ports 15432 to 15439, in the sorted order of the attachment names, so adding an attachment can move the ports of the ones after it. The connector writes them to the proxy as `CITE_EGRESS_FORWARDS=<listen>=<host>:<port>,...`. A forward goes to the one destination its environment names; a client cannot choose another.
- Each connection goes through the same resolve, check and connect step as an HTTP `CONNECT`, so rebinding protection, the internal-address refusal, the port list and the node deny lists apply.
- A forward closes a connection after 30 minutes without traffic (HTTP keeps 120 seconds), because pooled database connections sit idle.
- For runtime links the host and port of the URL become `cite-<id>-<slot>-egress-proxy` and the forward port; the rest of the URL, including the query, is kept and TLS runs end to end. In `open` mode and for build links the stored URL is used as it is.
- `sslmode=verify-full` fails through a forward, because the client checks the certificate against the proxy's name. The `tls_servername` field holds the real host name for drivers that accept a separate server name, and the answer carries a warning.

### Private addresses

A forward never opens a private address by itself. The proxy refuses destinations on private, internal and reserved ranges unless a rule opens them (see [Hardening](hardening.md#filtered-mode)). `CITE_EGRESS_AUTO_ALLOW`, which the connector sets from the attachments, carries the host names of external databases and S3 endpoints (IP literals are left out) and only satisfies `allowlist` mode: a site in allowlist mode needs no extra entry for them. It does not lift the private-address refusal, so a public name that resolves to `10.x` is still refused. To reach a database on a private address, list its host name or its range in the site's `outbound_rules.allow`, or its range in the node's `CITE_STACK_EGRESS_ALLOW_CIDRS`. A database given by IP address needs such an entry in allowlist mode too.

## S3 attachments

`PUT /sites/{id}/data/s3/{name}` with `{endpoint, bucket, region, path_style?, access_key_id?, secret_access_key?}` stores an S3-compatible bucket for the site to use. The endpoint is `https://host[:port]` with nothing after it and a lowercase host; plain http is refused, and so are loopback and private IP literals, like webhook destinations. The bucket is 3 to 63 characters of `a-z`, `0-9`, `.` and `-`, the region 1 to 32 of `a-z`, `0-9` and `-`. Both keys are required for a new attachment; an update may leave either out to keep the stored one. A site has at most 4. The keys are write-only and reach the app through `s3` links. The connector stores the settings and makes no request to the endpoint; the app's own traffic goes through the stack's egress rules, and the endpoint's host name is added to `CITE_EGRESS_AUTO_ALLOW`. `CITE_DATA_S3_ALLOW_PRIVATE` does not apply to attachments.

## Converting between dedicated and shared

`POST /sites/{id}/data/postgres/convert` with `{to, freeze?}` moves every database of the site to the other mode on the same node. It answers 202 with a session id, and `GET .../convert/{session}` shows its state. The steps are freeze, dump, restore into the new server with the same databases and users under new passwords, and a count of the rows of every table on both sides. The session then waits in `awaiting_cutover`.

- `freeze` is `maintenance` (default: the site serves its maintenance page), `read_only` or `none`; see [Freezing](#freezing).
- Shared as the target needs the shared instance running with the same Postgres major as the site's database.
- `POST .../cutover` is refused when the row counts differ. It switches the credentials and the stored mode, and ends a `maintenance` freeze. Containers pick up the new host and passwords at the next deploy. A `read_only` freeze stays on the retired source, with its logins locked.
- `POST .../abort` removes what the conversion made on the target and lifts the freeze.
- The old database is not dropped. It is listed as `retired` until `DELETE .../postgres/retired`, and a new conversion, turning Postgres off, or a purge is refused meanwhile.
- One conversion runs at a time per site.

## Moving a database to another node

A staged transfer copies one managed database from a source node to a target node. A console drives it, and the data goes from node to node through that console. The [dashboard](dashboard.md#moving-a-database-to-another-node) server runs it between two nodes it manages, so the data never passes through a browser, and the [desktop app](desktop.md#data-and-databases) runs it itself.

Prerequisites: the site exists on the target with managed Postgres enabled (either mode), and both nodes run data services. The target database must not exist, or the transfer must be started with `replace`, which takes a `pre_restore` backup of it first. The transfer moves data, not the site: deploy and route the site on the target yourself.

1. **Freeze.** The source takes one of the freeze choices below.
2. **Dump.** The source makes a backup version with trigger `transfer`, pinned so retention cannot remove it, counts the rows of every table and offers the dump in 8 MiB chunks.
3. **Copy.** The console reads the manifest and each chunk from the source and sends them to the target. Every chunk carries its SHA-256 in `X-Chunk-Sha256`, checked on arrival, and the target checks the whole dump against the manifest. A repeated chunk is accepted, so a copy can be resumed. The target stores each chunk sealed. A dump larger than 2 TiB is refused, and the target needs free space for twice the dump plus 1 GiB.
4. **Restore.** On commit the target assembles the dump as a backup version (trigger `import`), creates the database and the users named in the manifest with new passwords, creates the links that read from that database and the generated secrets they need, restores the data, and counts the rows of every table.
5. **Verify.** The console compares the two counts table by table. Cutover is refused unless they match, and mismatches are listed. With `auto_cutover` the console cuts over when they match.
6. **Cutover or rollback.** Cutover finishes both sessions: the target keeps the data and the source stays frozen. Rollback aborts the target (a replaced database comes back from its `pre_restore` backup, a created one is deleted) and lifts the freeze on the source.

After the commit the target site needs a deploy before containers see the new links (the commit answer has `redeploy_needed`). A variable already set by hand on the target blocks the links unless the transfer uses `override_manual`. The manifest comes from another node, so a link in it may only read from a user the import creates, from a generated secret the import actually writes, or be identical to a link the target already has. Any other link makes the import fail with 409, both when it is created and again at commit, with the offending links named.

The source database is never dropped, by a transfer or a conversion. It stays frozen until you delete it. Users keep their names, levels and limits but get new passwords on the target; no password is copied.

Generated secrets that the moved links use are carried in the manifest, so users of an auth library stay signed in after the move. The values travel over the two nodes' TLS connections through the process that runs the transfer, are held in memory there and wiped after the request, and are kept on the target only in its sealed secret store. A secret the target site already has keeps its own value. They are not written to the `transfers.json` of the dashboard or the desktop app. Fetching the manifest is audited with the number of secrets only.

A transfer survives a restart of either node or the console: each node keeps a durable session, and the console state is reloaded and marked `failed` if a step was running. Resume continues from what the nodes report. Steps that were running when a connector stopped are marked `failed` with a note, and an export can be retried from its freeze.

### Freezing

| Choice | Effect |
|---|---|
| `maintenance` | The site's maintenance flag is turned on for the copy, remembering whether it was already on. |
| `read_only` | The database gets `default_transaction_read_only = on`, every login of the site's users for that database is locked (`NOLOGIN`) and their open sessions are ended. The site stays up, but its database connections fail during the freeze, not only its writes. |
| `none` | Nothing is frozen; writes after the dump are not copied. The dashboard offers the first two. |

Locked logins are recorded in role comments: `cite:locked` on each login and `cite:frozen` on the database's `_login` group. Do not edit them; unfreeze, abort and the recovery after a connector restart give `LOGIN` back to exactly the marked logins. Abort lifts a freeze. A conversion cutover ends a maintenance freeze and leaves a read-only freeze on the retired source. A transfer cutover leaves the source frozen for good; a maintenance flag that the transfer turned on stays on the source until you turn it off.

## Limits

| Item | Limit |
|---|---|
| Databases per site, users per database | 4, 8 |
| External databases, S3 attachments, generated secrets, env links per site | 4, 4, 8, 64 |
| Backup targets per node | 16 |
| Backup records per database | 2000 |
| Concurrent data jobs per node | 2; a request that starts another answers 429 |
| One job per scope | One job container per site (and one for the shared instance) at a time |
| Job time limit | `CITE_DATA_JOB_TIMEOUT`, 60 to 86,400 seconds (default 21,600) |
| Job container | 512 MiB, one CPU, 64 pids |
| Egress forwards per proxy | 8, on ports 15432 to 15439 |
| `CITE_EGRESS_AUTO_ALLOW` names | 16 |
| Request bodies of the data routes | 64 KiB; transfer chunks 8 MiB |

## Not in this release

- Major upgrades. A database stays on the major it was created with. Restores and transfers accept dumps from the same or an older major and refuse newer ones.
- Live (near-zero-downtime) transfer. `mode: "live"` on an export answers 501.
- Transfer through S3 instead of the console.
- TLS inside the node. The `tls` setting is reserved and refused.
- Restoring a backup into an external database, and scheduled backups of external databases.
- Free-form grants and schemas other than `public`.
- Anything on a node without the orchestrator overlay.
