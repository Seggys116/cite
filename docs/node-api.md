# Connector API

JSON over HTTP, prefix `/api/v1`. Every route except `POST /auth/login` and `GET /healthz` needs `Authorization: Bearer <token>`, where the token is a session token from login or a long-lived API token. Requests from addresses outside the allowlist get a bare connection close.

Errors are `{"error":"message"}` with a matching status code. Bodies are capped at 1 MiB.

## Auth

| Route | Body | Response |
|---|---|---|
| `POST /auth/login` | `{username,password,totp}` | `{token,expires_at}` |
| `POST /auth/logout` | none | `{ok:true}` |
| `GET /auth/me` | none | `{username,kind:"session"\|"api",expires_at}` |
| `GET /tokens` | none | `[{id,name,created_at,last_used_at}]` |
| `POST /tokens` | `{name}` | `{id,name,token}` (token shown once) |
| `DELETE /tokens/{id}` | none | `{ok:true}` |

The three `/tokens` routes need a session token from login. An API token gets 403 on them.

## Node

| Route | Response |
|---|---|
| `GET /healthz` | `{ok:true}` |
| `GET /node` | `{name,version,uptime_secs,haproxy:{running,config_hash,last_reload_at,last_reload_ok,last_error},sites,firewall_rules,orchestrator:{enabled,reachable},analytics}` where `analytics` has the fields of `GET /analytics/stats`, or is `null` when the database cannot be read |
| `POST /haproxy/reload` | `{ok,config_hash,reloaded}` |
| `GET /haproxy/config` | `text/plain` rendered haproxy.cfg |
| `GET /haproxy/stats` | `{backends:[{name,status,sessions,bytes_in,bytes_out,servers:[{name,status,check}]}]}` |
| `GET /settings` / `PUT /settings` | `EdgeSettings` (retention, limits, rate limit) |
| `GET /audit?limit=` | `[{at,actor,action,detail}]` |

## Sites

| Route | Body | Response |
|---|---|---|
| `GET /sites` | none | `[Site]` |
| `POST /sites` | `Site` without `history`, plus an optional `github_token` | `Site` |
| `GET /sites/{id}` | none | `Site` plus `live:{blue:[{addr,status}],green:[...]}` |
| `PUT /sites/{id}` | `Site` | `Site` |
| `DELETE /sites/{id}` | none | `{ok:true}` |
| `POST /sites/{id}/deploy` | `{targets:[Target],note?}` | `Deployment` |
| `POST /sites/{id}/switch` | `{slot}` | `Deployment` |
| `POST /sites/{id}/rollback` | none | `Deployment` |
| `POST /sites/{id}/maintenance` | `{enabled,page_id?}` | `Site` |

`github_token` is used for a site with a `source`, which needs the orchestrator. It is stored in `secrets.json`, never in the site, and never returned. See [Orchestrator](orchestrator.md#github-token).

`PUT /sites/{id}` changes the name, hosts, `path_regex`, kind, health check and source. The active slot, both slots' targets and the maintenance flag are kept from the stored site, whatever the body says, so a stale copy of a site cannot undo a deploy. Those fields change only through `deploy`, `switch`, `rollback` and `maintenance`. `DELETE /sites/{id}` returns 409 naming the firewall rules while any rule is scoped to the site; delete or change those rules first.

Deploys, switches, rollbacks, site changes and every other change that touches the HAProxy config run to completion on the node even if the client disconnects or the 700 s request limit passes. Read the result afterwards from `GET /sites/{id}`. A change is refused, and the stored config restored, when a reachable HAProxy rejects the rendered config (400) or does not load it (400 for a refused reload, 503 for an unconfirmed one). When HAProxy cannot be reached at all the change is stored and applied on the next reload.

`POST /haproxy/reload` always asks HAProxy to reload, even when the config is unchanged, so renewed certificates are picked up and a failed reload can be retried. It returns 503 when HAProxy is unreachable or does not confirm a new worker.

`switch` and `rollback` start a stopped slot again on the git ref it last ran, not on the site's current branch.

`deploy` writes the targets into the idle slot, waits for every target to pass health checks (up to 60 s, or the build wait of 600 s by default for a site built from a repo), flips the active slot through the HAProxy runtime API, and records a `Deployment`. A failed health check leaves the active slot untouched and records `failed`.

## Maintenance pages

`GET /pages`, `POST /pages`, `GET /pages/{id}`, `PUT /pages/{id}`, `DELETE /pages/{id}` with `MaintenancePage` bodies. A page in use by a site cannot be deleted.

## Firewall

| Route | Response |
|---|---|
| `GET /firewall/rules` | `[FirewallRule]` |
| `POST /firewall/rules` | `FirewallRule` |
| `PUT /firewall/rules/{id}` | `FirewallRule` |
| `DELETE /firewall/rules/{id}` | `{ok:true}` |
| `GET /firewall/presets` | `[{name,title,description,rules:[FirewallRule]}]` |
| `POST /firewall/presets/{name}/apply` | `[FirewallRule]` added |

## Analytics

`summary`, `timeseries`, `bots` and `top` accept `window` (`15m`, `1h`, `24h`, `7d`, `30d`; the default is `1h`) and optional `site`. Every route needs the bearer token, and a session token and an API token are both accepted. Storage, retention, bot scoring and the export format are described in [Analytics](analytics.md).

| Route | Response |
|---|---|
| `GET /analytics/summary` | `{requests,bytes_in,bytes_out,blocked,errors_4xx,errors_5xx,avg_ms,p50_ms,p95_ms,p99_ms,status:{"2xx":n,...},methods:{GET:n},content_types:{...},sizes:[{le,count}],top_paths:[{key,count,bytes}],top_ips:[...],top_user_agents:[...],top_hosts:[...],top_blocked:[...]}` |
| `GET /analytics/timeseries` | `{step_secs,points:[{ts,requests,bytes_out,errors,blocked,avg_ms}]}` |
| `GET /analytics/requests?limit=&status=&method=&path=&ip=&blocked=&site=` | `[LogEvent]` newest first, `limit` 1 to 1000 (default 100) |
| `GET /analytics/bots?window=&site=` | `{total_requests,bot_requests,bot_share_pct,classes:[{key,count,bytes}],signals:[...],agents:[...],score_buckets:[...]}`. `classes` keys are `human`, `suspect`, `crawler`, `tool`, `bot`; `score_buckets` keys are `0-19`, `20-39`, `40-59`, `60-79`, `80-100`. |
| `GET /analytics/top?kind=&window=&site=&limit=` | `{items:[{key,count,bytes}]}`. `kind` is required: `paths`, `hosts`, `referers`, `agents`, `content_types`, `statuses`, `ips` or `languages`. `limit` 1 to 1000 (default 100). An unknown `kind` is a 400. |
| `GET /analytics/stats` | `{rows,db_bytes,oldest_ts_ms,newest_ts_ms,write_batches,write_errors,retention_days,archive_before_delete,max_bytes,ingest_stalls}`. The two timestamps are `null` for an empty database, and `max_bytes` is `null` when no size cap is set. `retention_days` 0 means rows are kept forever. `ingest_stalls` counts the times the log receiver waited on the database writer. |
| `GET /analytics/archives` | `{items:[{name,kind,bytes,created_ms,sha256,rows,from_ms,to_ms}],dir_bytes}`, newest first. `kind` is `archive` or `backup`; `from_ms` and `to_ms` are the oldest and newest request in the file, `null` for an empty backup. `dir_bytes` is everything in the archive directory. |
| `POST /analytics/backup` | No body. Writes a consistent copy of the database and returns its item. |
| `POST /analytics/cut` | `{before_ms \| before_days, archive?, dry_run?}` returns `{dry_run,cutoff_ms,rows,oldest_ms,archived_rows,files,archive}`. See below. |
| `POST /analytics/restore` | `{name, again?}` imports an archive and returns `{rows}`. A backup name is a 400. An archive that was already restored is a 409 unless `again` is `true`, which imports it a second time and duplicates its rows. A failed restore can be partially applied and leaves no marker. |
| `GET /analytics/archives/{name}` | The file, `application/gzip` or `application/vnd.sqlite3`, with `X-Archive-Sha256`. |
| `DELETE /analytics/archives/{name}` | `{ok:true}`; removes the file and its manifest entry. |
| `GET /analytics/export?kind=&top=&format=&from=&to=&site=&status_min=&status_max=&bot_class=&min_bot_score=&host=&path_prefix=&client_ip=&method=&limit=` | A streamed file download, not JSON. See below. |

### Export

| Parameter | Values |
|---|---|
| `kind` | `requests` (default), `hourly`, `bots`, `top` |
| `top` | Required with `kind=top`, rejected otherwise; the same names as `/analytics/top` |
| `format` | `csv` (default), `ndjson` |
| `from`, `to` | Milliseconds since the epoch or RFC 3339. `from` inclusive, `to` exclusive, `from` must be earlier |
| `site` | A site id |
| `status_min`, `status_max` | 100 to 599, inclusive; `status_min` must not exceed `status_max` |
| `bot_class` | `human`, `suspect`, `crawler`, `tool`, `bot` |
| `min_bot_score` | 0 to 100 |
| `host`, `path_prefix`, `client_ip`, `method` | Exact host (255 bytes at most), path prefix (1024 bytes at most), IP address, HTTP method token |
| `limit` | 1 to 1,000,000; default 1,000,000 |

The response is 200 with `Content-Type: text/csv; charset=utf-8` or `application/x-ndjson`, `Content-Disposition: attachment; filename="cite-<kind>-<site|all>-<UTC date>.<csv|ndjson>"`, `X-Content-Type-Options: nosniff` and `Cache-Control: no-store`. A bad parameter is a 400 `{error}` naming it. A third simultaneous export on one node is a 429. A failure after the download has started cannot change the status, so the connection is aborted instead of ending the body normally. Each export is recorded in the audit log as `analytics.export` with the kind, format and filters.

```sh
curl -H "Authorization: Bearer $TOKEN" -OJ \
  "https://node:7443/api/v1/analytics/export?kind=requests&bot_class=crawler&from=2026-11-01T00:00:00Z"
```

### Archives, backups and cuts

The archive directory is `CITE_ANALYTICS_ARCHIVE_DIR` (default `<data>/analytics/archive`). Names are those returned by the list; anything with a path separator, `..`, other characters or an unknown prefix or extension is a 400, and a well-formed name that is not there is a 404. How the files are written and verified is in [Analytics](analytics.md#archives-and-backups).

`POST /analytics/cut` takes exactly one of `before_ms` (epoch milliseconds, not negative and not in the future) or `before_days` (1 to 36500, counted back from now). `archive` defaults to `true`: each UTC day older than the cutoff is written to a verified archive file and then deleted, oldest first, and a failure stops the run with 503 `{error}` after leaving the rows of the failing day in place. Only `"archive": false` deletes without a copy. `"dry_run": true` changes nothing and reports `rows` (rows older than the cutoff), `oldest_ms`, and an empty `files`. `files` lists the archive names written, `archived_rows` how many rows they hold. The cutoff is rounded down to a whole hour and the one used is returned as `cutoff_ms`. Bodies are limited to 1 MiB and unknown fields are a 400.

```sh
curl -H "Authorization: Bearer $TOKEN" -X POST https://node:7443/api/v1/analytics/cut \
  -d '{"before_days": 90, "dry_run": true}'
```

Backups, cuts (dry runs included), restores, downloads and deletes are recorded in the audit log as `analytics.backup`, `analytics.cut`, `analytics.restore`, `analytics.archive.download` and `analytics.archive.delete`. Turning off `store_client_ips` or `store_user_agents` in the settings also blanks the field in existing archives and backups, recorded as `analytics.archive.scrub` with the file counts. Downloads share the 2-at-once limit of exports and answer 429 beyond it.

`PUT /settings` takes `retention.hour_buckets_days` of 0 (keep forever, the default) or 1 to 3650, and `retention.archive_before_delete` (boolean, default `true`, which an older client may omit).

Analytics read failures return 500 `{error:"internal error"}`; the cause is in the connector log.

The `sizes` buckets are cumulative: `count` is the number of responses up to and including `le` bytes, and the final bucket (`le` null) equals the total, so clients subtract the previous bucket to draw a histogram.

## Dashboard server

The dashboard container exposes its own API under `/api/v1` for the browser. `/nodes` lists configured nodes, and `/nodes/{node}/...` proxies to the matching connector route above using the stored token. `POST /session` logs in to the dashboard (`{username,password,totp}`), `GET /nodes/summary` fans out `/node` across all nodes, and `POST /deployments` takes `{nodes:[name],site:Site,mode:"each"\|"replicate",per_node?,github_token?}` and applies the site to every selected node. In `each` mode, `per_node` maps a node name to `{blue?,green?}` target lists that replace the site's own for that node; `replicate` ignores it. `github_token` needs a site with a `source`.
