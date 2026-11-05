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
| `GET /node` | `{name,version,uptime_secs,haproxy:{running,config_hash,last_reload_at,last_reload_ok,last_error},sites,firewall_rules}` |
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

Deploys, switches, rollbacks, site changes and every other change that touches the HAProxy config run to completion on the node even if the client disconnects or the 180 s request limit passes. Read the result afterwards from `GET /sites/{id}`. A change is refused, and the stored config restored, when a reachable HAProxy rejects the rendered config (400) or does not load it (400 for a refused reload, 503 for an unconfirmed one). When HAProxy cannot be reached at all the change is stored and applied on the next reload.

`POST /haproxy/reload` always asks HAProxy to reload, even when the config is unchanged, so renewed certificates are picked up and a failed reload can be retried. It returns 503 when HAProxy is unreachable or does not confirm a new worker.

`switch` and `rollback` start a stopped slot again on the git ref it last ran, not on the site's current branch.

`deploy` writes the targets into the idle slot, waits for every target to pass health checks (up to 60 s), flips the active slot through the HAProxy runtime API, and records a `Deployment`. A failed health check leaves the active slot untouched and records `failed`.

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

All accept `window` (`15m`, `1h`, `24h`, `7d`, `30d`; the default is `1h`) and optional `site`.

| Route | Response |
|---|---|
| `GET /analytics/summary` | `{requests,bytes_in,bytes_out,blocked,errors_4xx,errors_5xx,avg_ms,p50_ms,p95_ms,p99_ms,status:{"2xx":n,...},methods:{GET:n},content_types:{...},sizes:[{le,count}],top_paths:[{key,count,bytes}],top_ips:[...],top_user_agents:[...],top_hosts:[...],top_blocked:[...]}` |
| `GET /analytics/timeseries` | `{step_secs,points:[{ts,requests,bytes_out,errors,blocked,avg_ms}]}` |
| `GET /analytics/requests?limit=&status=&method=&path=&ip=&blocked=&site=` | `[LogEvent]` newest first |

The `sizes` buckets are cumulative: `count` is the number of responses up to and including `le` bytes, and the final bucket (`le` null) equals the total, so clients subtract the previous bucket to draw a histogram.

## Dashboard server

The dashboard container exposes its own API under `/api/v1` for the browser. `/nodes` lists configured nodes, and `/nodes/{node}/...` proxies to the matching connector route above using the stored token. `POST /session` logs in to the dashboard (`{username,password,totp}`), `GET /nodes/summary` fans out `/node` across all nodes, and `POST /deployments` takes `{nodes:[name],site:Site,mode:"each"\|"replicate",per_node?,github_token?}` and applies the site to every selected node. In `each` mode, `per_node` maps a node name to `{blue?,green?}` target lists that replace the site's own for that node; `replicate` ignores it. `github_token` needs a site with a `source`.
