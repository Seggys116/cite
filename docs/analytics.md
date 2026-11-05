# Analytics and retention

This page covers what a node records about traffic, the privacy settings, every retention setting with its default, and the memory bounds.

## Where the data comes from

HAProxy writes one log line per request and sends it as a UDP datagram in RFC 5424 format to the connector (`connector:5140` by default, on the internal `cite_edge` network). The connector parses the line and updates in-memory counters. There is no database.

Datagrams over 8192 bytes, lines that do not parse, and lines with an invalid client address are discarded. If the connector falls 4096 events behind, further events are dropped and a warning is logged.

## Fields collected

| Field | Notes |
|---|---|
| Timestamp | HAProxy's request time. A missing, zero or more than five minutes in the future value is replaced with the arrival time. |
| Client IP | Source address of the TCP connection. Cleared when `store_client_ips` is off. |
| Host | `Host` header, up to 255 characters. |
| Method | Up to 16 characters. |
| Path | Without the query string, up to 2048 characters. |
| Query length | The length of the query string in bytes. The query string itself is never logged. |
| Status | HTTP status. |
| Bytes in, bytes out | Request and response sizes. |
| Total time | Milliseconds from accept to the end of the response. |
| User agent | Up to 512 characters. Cleared when `store_user_agents` is off. |
| Referer | Up to 1024 characters, kept only on the recent-request list. |
| Content type | Response `Content-Type`, up to 128 characters. |
| Backend, server | The HAProxy backend and server that answered. The site is taken from the backend name. |
| Blocked | The id of the firewall rule that fired, when one did. |

Request and response headers other than those listed, cookies and bodies are never logged.

## What is aggregated

Counters are kept for the node as a whole and per site, in one-minute and one-hour buckets. Each bucket holds:

- Request, byte, error and blocked counts, plus counts per status class.
- A latency histogram on a log scale, used for the average and for p50, p95 and p99. Percentiles are reported as a bucket midpoint, with roughly 12% error above 4 ms.
- Response size buckets from 1 KiB to 64 MiB.
- Counts per method and content type.
- Top paths, client IPs, user agents, hosts and blocking rules.

Queries use a time window: `15m`, `1h`, `24h`, `7d` or `30d`. Windows up to 48 hours read the minute buckets. Longer windows read the hour buckets. A window is always clipped to what retention keeps.

## Privacy settings

| Setting | Default | Effect |
|---|---|---|
| `store_client_ips` | `true` | When false, client addresses are not recorded. |
| `store_user_agents` | `true` | When false, user agents are not recorded. |

Turning a flag off also removes what was already collected: the matching top list is cleared for the node and every site, and the value is cleared from every recent request. Turning it back on records new traffic only.

A firewall rule can still match on addresses and user agents when these flags are off, because matching happens in HAProxy before logging.

## Retention settings

These are the `retention` object in the node's settings (`GET` and `PUT /api/v1/settings`). The collector picks up a change at the latest when it next writes a snapshot, and shrinking a value then prunes data immediately.

| Setting | Default | Allowed | Meaning |
|---|---|---|---|
| `recent_events` | 5000 | 0 to 200000 | Most recent requests kept in full for the live request list. 0 keeps none. |
| `minute_buckets_hours` | 48 | 1 to 8760 | How long one-minute buckets are kept. |
| `hour_buckets_days` | 90 | 1 to 3650 | How long one-hour buckets are kept. |
| `audit_days` | 365 | 1 to 3650 | How long audit log entries are kept. |
| `persist_interval_secs` | 60 | 5 to 3600 | How often the analytics snapshot is written. |
| `store_user_agents` | `true` | boolean | See above. |
| `store_client_ips` | `true` | boolean | See above. |

Queries only read minute buckets for windows up to 48 hours and hour buckets beyond that. Raising `minute_buckets_hours` above 48 therefore keeps data that no query window reads, and the longest window offered is 30 days, so `hour_buckets_days` above 30 is headroom for the 30 day view.

Other limits are fixed:

| Limit | Value |
|---|---|
| Sites tracked separately | 256. Traffic from further sites is counted under `other`. |
| Audit log files | `audit.jsonl` rotates to `audit.jsonl.1` at 4 MiB, so at most about 8 MiB is kept. |

The audit log is pruned of entries older than `audit_days` once an hour. Because of the size cap, a very busy node can lose audit entries sooner than `audit_days`.

## Memory bounds

Memory use does not grow with traffic volume. It is bounded by the settings above and by fixed caps.

| What | Bound |
|---|---|
| Recent requests | `recent_events` entries, 5000 by default. |
| Buckets | One per minute for `minute_buckets_hours`, one per hour for `hour_buckets_days`, for the node and each tracked site. |
| Top lists per minute bucket | 32 paths, 24 IPs, 16 user agents, 8 hosts, 8 rules. |
| Top lists per hour bucket | 256 paths, 128 IPs, 64 user agents, 32 hosts, 32 rules. |
| Methods and content types per bucket | 16 and 32. |
| Key length | Paths 128, IPs 45, user agents 96, hosts 64, rules 64, methods 16, content types 64 characters. |
| Latency histogram | 128 slots per bucket. |
| Tracked sites | 256, plus `other`. |
| Events waiting to be counted | 4096. |

Old buckets are pruned automatically every 8192 requests and before each snapshot is written.

## Persistence

The connector writes a snapshot of the counters and the recent-request list to `analytics.json` in its data directory (`/conf`), mode 0600, every `persist_interval_secs`. It loads the file on start, so a restart keeps the history. A missing or corrupt file starts empty. The retention settings in force are applied when the snapshot loads, including the privacy flags.

Traffic that arrives while the connector is stopped is not counted, because the logs go to the connector over UDP and are not buffered. After a hard stop you lose up to one persist interval of counts.

## Reading it

| Route | Returns |
|---|---|
| `GET /api/v1/analytics/summary` | Totals, latency, status classes, methods, content types, size buckets and the top lists. |
| `GET /api/v1/analytics/timeseries` | Points per minute (windows up to 48 hours) or per hour: requests, bytes out, errors, blocked and average latency. |
| `GET /api/v1/analytics/requests` | Recent requests, newest first, filtered by `status`, `method`, `path`, `ip` or `blocked`. |

All three take `window` and an optional `site`. See [Connector API](node-api.md) for the response shapes. The dashboard's Traffic view shows the same data and refreshes the live request list every 3 seconds.
