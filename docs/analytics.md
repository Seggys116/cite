# Analytics and retention

This page covers what a node records about traffic, how it is stored, the privacy settings, retention, how requests are scored as bots, and how to read or export the data.

## Where the data comes from

HAProxy writes one log line per request and sends it as a datagram in RFC 5424 format to the connector. In the compose file this is a unix datagram socket (`/run/cite/log.sock` on the shared `cite_run` volume); a UDP address such as `connector:5140` also works. The connector parses the line, scores it for bot likelihood, and writes it as one row to an embedded SQLite database.

Datagrams over 8192 bytes, lines that do not parse, and lines with an invalid client address are discarded. Parsed events are never discarded inside the connector. If the database writer cannot keep up, the connector stops reading the socket until it catches up and counts each wait (`ingest_stalls` in `GET /api/v1/analytics/stats`). While it is not reading, the kernel buffers the socket (up to 4 MiB), and only a burst larger than that can lose datagrams, which HAProxy then cannot resend.

### Log format and truncation

HAProxy cuts a log message at its `len` limit, 1024 bytes unless raised, and an attacker can send a long path to push the end of the line past it. Two measures keep the verdict of such a request from being lost:

- The log target is rendered with `len 8192`, which is also the largest datagram the connector accepts.
- The fields are ordered so the fixed-size ones come first: time, client address, backend, server, method, status, bytes out, bytes in, total time, query length, blocked rule and site. The variable-size ones come last: host, path, user agent, referer, content type and the captured request headers. Each is cut before encoding, but percent-encoding can triple a field, so a hostile request can push a line past 8192 bytes. HAProxy then cuts the line. The connector drops the partial last field and leaves the event unclassified (empty bot class) instead of scoring missing headers as bot signals.

If a line still arrives short, the connector keeps the event. Fields that are missing are left empty, and the last field present is also emptied because it may be partial. A line that lacks any of the fixed fields is discarded.

Requests that never reach a site backend, such as blocked requests and maintenance pages, are logged against `fe_main`. The site is then read from a separate field that HAProxy fills from the host and path match, so those events still count towards the right site.

## Fields collected

Every request is stored as one row with these fields.

| Field | Notes |
|---|---|
| Timestamp | HAProxy's request time. A missing, zero or more than five minutes in the future value is replaced with the arrival time. |
| Client IP | Source address of the TCP connection. Not recorded when `store_client_ips` is off. |
| Host | `Host` header, up to 255 characters. |
| Method | Up to 16 characters. |
| Path | Without the query string, as normalised by the edge (see the firewall page), up to 2048 characters after decoding. |
| Query length | The length of the query string in bytes. The query string itself is never logged. |
| Status | HTTP status. |
| Bytes in, bytes out | Request and response sizes. |
| Total time | Milliseconds from accept to the end of the response. |
| Response time | Milliseconds HAProxy waited for the backend's response (`%Tr`). |
| User agent | Up to 512 characters. Not recorded when `store_user_agents` is off. |
| Referer | Up to 1024 characters. |
| Content type | Response `Content-Type`, up to 128 characters. |
| Backend, server | The HAProxy backend and server that answered. The site is taken from the backend name, or from the site field when the request was answered by the frontend. |
| Blocked | The id of the firewall rule that fired, when one did. |
| HTTP version, TLS version | Protocol version of the request and the TLS protocol of the connection, empty for plain HTTP. |
| Accept, Accept-Language, Accept-Encoding | Request headers, cut to 128, 64 and 64 characters. |
| Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest | Fetch metadata headers, cut to 24 characters each. |
| Sec-CH-UA | Client hints brand list, cut to 128 characters. |
| Bot score, bot class, bot signals | The result of the bot scoring below: a score from 0 to 100, one class, and the names of the signals that fired. |

Request and response headers other than those listed, cookies and bodies are never logged.

## Storage

The database is a single SQLite file, `analytics.db`, in WAL mode. Its default location is `/conf/analytics/analytics.db` (the `analytics` directory is created with mode 0700 inside the `cite_conf` volume, so it survives container recreation). `CITE_ANALYTICS_DB` moves it; the value must be an absolute path to a file. The connector creates the directory if it is missing, and the connector user must be able to write there.

Repeated text such as hosts, user agents, client addresses and header values is stored once in a dictionary table and referenced by id, which keeps the file small. Alongside the raw rows the connector keeps rollups per site: hourly ones for long windows and minute ones for short windows, so a query does not have to scan every row.

Windows of up to 6 hours (15 minutes and 1 hour are the usual ones) read the minute rollups, and longer windows read the hourly rollups. Answers from the minute rollups are exact, the same as a scan of the raw rows would give. Three cases read raw rows instead: a window that reaches back before the minute rollups began (a database upgraded from an earlier version, for the first 6 hours), a window that contains a minute loaded by a backfill or import (events spanning more than 10 minutes in one batch skip the minute rollups), and a window that contains a minute with more than 30,000 distinct values of one kind (paths, addresses, agents or referers), which is dropped from the minute rollups so a flood of unique values cannot grow them. Those queries are exact but as slow as a raw scan. Latency percentiles are reported as a histogram bucket midpoint, with roughly 12% error above 4 ms. Windows are `15m`, `1h`, `24h`, `7d` or `30d`. The request list and the exports always read raw rows.

Reads use their own connections and do not wait for ingest. Events reach the database in batches of up to 1000 rows or 250 ms, whichever comes first, so a new request shows up in queries within about a quarter of a second. On a clean shutdown the receiver reads the datagrams already waiting on the socket (until it has been quiet for 100 ms, at most 2 s), hands over its last partial batch, and the connector commits everything queued before folding the write-ahead log into the main file; if the writer still cannot commit, it logs an error with the number of events lost. After a hard stop, events that were still in memory (up to about 250 ms of traffic, plus anything waiting behind a saturated writer) are lost, and the database itself is intact.

Traffic that arrives while the connector is stopped is not counted, because the logs go to the connector as datagrams and are not buffered.

### Moving from the old snapshot

Earlier versions kept counters in memory and wrote them to `analytics.json` in the data directory. On the first start with the database, the connector imports the recent-request list from that file once and deletes it. The current privacy settings apply to the import, so a node with `store_client_ips` or `store_user_agents` off does not bring those fields back from the old file. A `analytics.json.migrated` copy left by an earlier version is deleted on start. The counters in the old file cannot be turned back into per-request rows, so the history before the upgrade is limited to those recent requests (5000 by default). A file that cannot be read or parsed is logged and left where it is.

## Retention

Rows are kept until they are older than the retention period. Nothing else removes them: there is no memory budget, and no limit on rows or on database size unless you set one. Retention removes everything that came with the expired rows: their hourly rollups (including the per-path rollups), and every dictionary entry that no remaining row or rollup refers to. Client addresses, user agents and referers are overwritten in the file when their dictionary entry is deleted, and the write-ahead log is folded away afterwards, so the text does not linger in either file. Path text of deleted raw rows is zeroed too, because the writer runs with `secure_delete=FAST`.

The minute rollups are not subject to the period: every retention pass removes the ones older than 7 hours, which is longer than the windows they serve. The period is the `hour_buckets_days` value of the `retention` object in the node's settings (`GET` and `PUT /api/v1/settings`), 90 days by default. Retention is applied every 10 minutes and straight after a settings change, so shortening it removes the older rows within moments. The connector's start uses the stored value.

| Setting | Default | Allowed | Meaning |
|---|---|---|---|
| `hour_buckets_days` | 90 | 1 to 3650 | Days a request row and its rollups are kept. |
| `audit_days` | 365 | 1 to 3650 | How long audit log entries are kept. |
| `store_user_agents` | `true` | boolean | See privacy settings. |
| `store_client_ips` | `true` | boolean | See privacy settings. |
| `recent_events`, `minute_buckets_hours`, `persist_interval_secs` | 5000, 48, 60 | as before | Accepted and returned unchanged so existing clients keep working, but they no longer size anything. Every request is stored, and there is no snapshot to write. |

The audit log is pruned of entries older than `audit_days` once an hour. `audit.jsonl` rotates to `audit.jsonl.1` at 4 MiB, so at most about 8 MiB is kept and a very busy node can lose audit entries sooner than `audit_days`.

### Optional size cap

`CITE_ANALYTICS_MAX_BYTES` sets a hard cap on the database size. It is unset by default, which means no cap. When it is set (8 MiB to 1 TiB), each retention pass (every 10 minutes) also trims the oldest rows until the data fits under the cap, and logs how many it removed. Between passes the file can briefly exceed the cap. A cap trades history for disk space, so set it only when the volume is small.

A pass removes at most 25% of the raw rows. A burst of traffic that pushes the file over the cap therefore costs history over several passes (10 minutes apart) instead of at once, and the file stays over the cap in between. When the file is at least twice the cap, the limit is lifted so the cap is still honoured. Trimming only removes raw rows; the hourly rollups and the dictionary stay. If those alone already exceed the cap, no raw row is deleted for it: the pass logs a warning, reports `trim_blocked`, and the cap needs raising. The current size and cap are in `GET /api/v1/analytics/stats`.

Plan the disk for the default of no cap: the file grows with the number of requests inside the retention period. Watch `db_bytes` against `rows` in `GET /api/v1/analytics/stats` for a few days to get the per-request cost of your own traffic, then size the volume or lower `hour_buckets_days` to match.

## Privacy settings

| Setting | Default | Effect |
|---|---|---|
| `store_client_ips` | `true` | When false, client addresses are not recorded. |
| `store_user_agents` | `true` | When false, user agents are not recorded. |

The flags apply to requests that arrive after the change, including requests that were already queued for the database when you changed them. Switching a flag from on to off also erases what was stored earlier: the field is cleared from every stored request, the matching dictionary entries and rollups are deleted, and the freed pages and the write-ahead log are overwritten and folded away. If readers keep the log busy, the fold is retried by the next retention pass. Bot scoring is computed before the flags apply, so a request keeps its score and signals even when its user agent is not stored. Turning a flag back on records new traffic only.

A firewall rule can still match on addresses and user agents when these flags are off, because matching happens in HAProxy before logging.

## Query limits and memory

Interactive queries (summary, timeseries, requests, bots and top lists) are cancelled after 20 seconds and the API answers 503. Exports and maintenance queries get 10 minutes per query; the request export reads in pages of 2000 rows and the hourly export likewise, so a slow download never keeps a read snapshot open between pages.

Readers keep their sort and group-by spill on disk (SQLite's temporary files) rather than in memory, so a query over many distinct long paths is bounded by disk and time, not by RAM. Put `SQLITE_TMPDIR` on a disk-backed directory if `/tmp` is a RAM disk. SQLite also gets a process-wide soft heap limit of 512 MiB and a hard limit of 1 GiB, which together leave room for the page caches (64 MiB for the writer, 16 MiB for each of up to 16 readers); a query that reaches the hard limit fails instead of taking the host down. A top list keeps at most 64 MiB of key text in memory, so an export of a top list over a flood of unique values ends at the highest-ranked entries that fit.

Windows of 6 hours or less read the minute rollups, which keep every path, client address, user agent and referer per minute and site. Writes to them are batched: the connector folds the rows that arrived since the last pass into the minute tables every 5 seconds, and a query reads the few seconds not folded yet straight from the raw rows, so a result is never behind and never approximate. A top-paths query over a long tail of unique paths does not read the tail: it sums the paths seen at least twice in a minute and completes the few contenders with their single sightings, and falls back to reading every row when that cannot prove the list. Longer windows read the hourly per-path rollups, which keep the 32 busiest paths per hour and site, for the usual top 20. A deeper path list (more than 20 entries) over a long window and the top-list exports still group raw rows, so they are the queries the time limit and the disk spill exist for.

## Files

The database directory is set to mode 0700 and the database, `-wal` and `-shm` files to 0600 when the store opens, including when they already exist with looser modes.

## Bot scoring

Each request gets a score from 0 (human) to 100 (bot), a class, and a list of named signals. Scoring runs once, when the event is parsed, and uses only what is in the log line. The result is stored on the row.

The checks run in two stages. Header signals come first and carry most of the weight: whether the expected browser headers are present and consistent with each other. The user agent comes second. It adds a named signal for known crawlers, automation frameworks and HTTP libraries, and it can pin the class. Weights add up and the total is capped at 100. A user agent that claims to be a browser (it starts with `Mozilla/`) is held to more than one that does not, so a missing `Accept-Language` counts 40 for the first and 10 for the second.

| Signal | Fires when | Weight |
|---|---|---|
| `empty_ua` | No user agent. | 40 |
| `missing_accept_language` | No `Accept-Language`. | 40 browser, 10 other |
| `missing_accept` | No `Accept`. | 35 browser, 15 other |
| `accept_wildcard_only` | `Accept: */*` on a request for a page. | 30 browser, 8 other |
| `missing_accept_encoding` | No `Accept-Encoding`. | 30 browser, 10 other |
| `no_sec_fetch` | A current browser over TLS sent none of the `Sec-Fetch-*` headers. | 30 |
| `sec_fetch_partial` | Some but not all of the three `Sec-Fetch-*` headers. | 20 |
| `sec_fetch_inconsistent` | Fetch metadata values that no browser sends together. | 30 |
| `no_sec_ch_ua` | A current Chromium over TLS sent no `Sec-CH-UA`. | 30 |
| `sec_ch_ua_mismatch` | `Sec-CH-UA` contradicts the user agent. | 40 |
| `http_1_0` | HTTP/1.0 request. | 20 |
| `http1_modern_browser` | A current browser over TLS using HTTP/1.x. | 25 |
| `old_tls` | SSLv3, TLS 1.0 or TLS 1.1. | 10 |
| `post_no_referer` | POST without a `Referer`. | 20 browser, 10 other |
| `ua_*` | The user agent names a known crawler, automation tool or HTTP library, for example `ua_googlebot`, `ua_curl`, `ua_headlesschrome`. | 60 to 85 |

"Current browser" means Chromium or Firefox 90 and later, or Safari 17 and later. The signal names are stored in the `bot_signals` field, comma separated.

| Class | Meaning |
|---|---|
| `human` | Score below 40 and no user agent match. |
| `suspect` | Score 40 to 69. |
| `bot` | Score 70 or more, or an automation or scraper user agent. |
| `crawler` | The user agent names a search, social, SEO or AI crawler. |
| `tool` | The user agent names an HTTP client or command line tool. |

The thresholds are 40 for `suspect` and 70 for `bot`. A user agent match pins the class (`crawler`, `tool` or `bot`) regardless of the score. The bot share in the summary counts every request whose class is not `human`.

This is a heuristic, not a verdict. It reads headers that a determined client can copy from a real browser, and it will miss that client. It also scores real people when their setup strips headers: privacy extensions, corporate proxies that rewrite requests, older browsers, and in-app browsers can all raise the score. A user agent is trivially forged, so a `crawler` class does not prove the request came from that crawler. Use the score to rank and filter, not to block. If you want to block something, write a firewall rule on a pattern you have confirmed.

## Reading it

All routes are `GET` under `/api/v1/analytics` and need the same bearer token as the rest of the API. See [Connector API](node-api.md) for the response shapes.

| Route | Returns |
|---|---|
| `/summary` | Totals, latency, status classes, methods, content types, size buckets and the top lists. |
| `/timeseries` | Points per minute (windows up to 48 hours) or per hour: requests, bytes out, errors, blocked and average latency. |
| `/requests` | Requests, newest first, filtered by `status`, `method`, `path`, `ip`, `blocked` or `site`. At most 1000 per call. |
| `/bots` | Bot share, counts per class, signal and user agent, and a score histogram. |
| `/top` | The highest-count values of one field: paths, hosts, referers, agents, content types, statuses, IPs or languages. |
| `/stats` | Row count, file size, oldest and newest timestamp, writer counters, retention days, size cap. |
| `/export` | A download of the underlying data. |

```sh
TOKEN=...   # an API token
NODE=https://node.example.com:7443

curl -sH "Authorization: Bearer $TOKEN" "$NODE/api/v1/analytics/bots?window=24h&site=blog"
curl -sH "Authorization: Bearer $TOKEN" "$NODE/api/v1/analytics/top?kind=agents&window=7d&limit=20"
curl -sH "Authorization: Bearer $TOKEN" "$NODE/api/v1/analytics/stats"
```

The dashboard's Traffic view shows the same data and refreshes the live request list every 3 seconds.

### Export

`GET /api/v1/analytics/export` streams a file. It reads raw rows, so it covers everything the node still holds, not only the recent requests.

```sh
# every 5xx from the last day for one site, as CSV
curl -sH "Authorization: Bearer $TOKEN" -OJ \
  "$NODE/api/v1/analytics/export?kind=requests&site=blog&status_min=500&from=2026-11-04T00:00:00Z"

# the same data as newline-delimited JSON
curl -sH "Authorization: Bearer $TOKEN" -OJ \
  "$NODE/api/v1/analytics/export?kind=requests&format=ndjson&bot_class=crawler"

# top user agents among likely bots
curl -sH "Authorization: Bearer $TOKEN" -OJ \
  "$NODE/api/v1/analytics/export?kind=top&top=agents&min_bot_score=40"
```

| Parameter | Meaning |
|---|---|
| `kind` | `requests` (default), `hourly`, `bots` or `top`. |
| `top` | Required with `kind=top`: `paths`, `hosts`, `referers`, `agents`, `content_types`, `statuses`, `ips` or `languages`. |
| `format` | `csv` (default) or `ndjson`. |
| `from`, `to` | Time range, `from` inclusive and `to` exclusive. Milliseconds since the epoch or RFC 3339. `from` must be earlier than `to`. |
| `site` | A site id. |
| `status_min`, `status_max` | Status range, 100 to 599, inclusive. |
| `bot_class` | `human`, `suspect`, `crawler`, `tool` or `bot`. |
| `min_bot_score` | 0 to 100. |
| `host`, `path_prefix`, `client_ip`, `method` | Exact host, path prefix, exact address, method. |
| `limit` | Most rows to write, 1 to 1,000,000. The default is 1,000,000. |

Every value is checked and a bad one is a 400 naming the parameter. `kind=hourly`, `bots` and `top` use `from`, `to`, `site` and `limit` only.

The response is `text/csv; charset=utf-8` or `application/x-ndjson`, with `Content-Disposition: attachment` and a generated name such as `cite-requests-blog-2026-11-05.csv` (site id or `all`, then the UTC date). It also carries `X-Content-Type-Options: nosniff` and `Cache-Control: no-store`. The body streams as it is read, so a large export does not build up in memory, and a client that disconnects stops the query. A node runs at most 2 exports at once; a third gets 429. Each export is written to the audit log with who ran it and the filters used.

If the connector fails part-way, it aborts the connection instead of ending the file cleanly, so a truncated download shows up as a transfer error in the client.

#### Columns

Request exports are oldest first, with a header row. `timestamp` is ISO 8601 in UTC and `ts_ms` is the same instant in epoch milliseconds.

| Kind | Columns |
|---|---|
| `requests` | `timestamp`, `ts_ms`, `client_ip`, `host`, `method`, `path`, `query_len`, `status`, `bytes_in`, `bytes_out`, `total_ms`, `user_agent`, `referer`, `content_type`, `backend`, `server`, `site`, `blocked`, `http_version`, `accept`, `accept_language`, `accept_encoding`, `sec_fetch_site`, `sec_fetch_mode`, `sec_fetch_dest`, `sec_ch_ua`, `tls_version`, `resp_ms`, `bot_score`, `bot_class`, `bot_signals` |
| `hourly` | `hour`, `hour_ts_ms`, `site`, `requests`, `bytes_in`, `bytes_out`, `status_other`, `status_1xx`, `status_2xx`, `status_3xx`, `status_4xx`, `status_5xx`, `blocked`, `bot_requests`, `ms_sum`, `avg_ms` |
| `bots` | `section`, `key`, `count`, `bytes`. The sections are `summary` (`total_requests`, `bot_requests`), `class`, `signal`, `agent` and `score_bucket`. |
| `top` | `key`, `count`, `bytes` |

CSV follows RFC 4180: rows end in CRLF, and fields containing a comma, a quote or a line break are quoted with embedded quotes doubled. Request fields come from the network, so a spreadsheet could run them as formulas. A text field that starts with `=`, `+`, `-`, `@`, a tab or a carriage return gets a leading apostrophe, which spreadsheets show as plain text. Numbers are written as they are. The apostrophe is in the file, so strip it if you load the CSV into something other than a spreadsheet; NDJSON is never altered.

## Reading the database directly

The file is plain SQLite, so you can query it with `sqlite3`. Open it read-only; WAL mode lets this run while the connector writes.

```sh
# on the host, through the volume's mount point
sqlite3 -readonly /var/lib/docker/volumes/<project>_cite_conf/_data/analytics/analytics.db
```

The `requests` table holds one row per request. `ts` is epoch milliseconds. Repetitive text columns such as `host_id`, `ua_id`, `client_ip_id` and `bot_class_id` hold ids into the `dict` table (`id`, `kind`, `val`). `path`, `status`, `bytes_in`, `bytes_out`, `total_ms`, `resp_ms` and `bot_score` are stored directly.

```sql
-- requests per status over the last hour
SELECT status, count(*) FROM requests
WHERE ts > (strftime('%s','now') - 3600) * 1000
GROUP BY status ORDER BY 2 DESC;

-- busiest hosts
SELECT d.val, count(*) FROM requests r JOIN dict d ON d.id = r.host_id
GROUP BY d.val ORDER BY 2 DESC LIMIT 10;
```

Do not write to the file, and do not copy it while the connector runs without also copying the `-wal` file next to it. The table layout is versioned (`PRAGMA user_version`) and may change between releases; the export and API formats are the stable interface.

## Limits

| Limit | Value |
|---|---|
| Requests listed per call | 1000. |
| Top items per call | 1000 (the summary lists 20). |
| Rows per export | 1,000,000. |
| Exports at once | 2 per node. |
| Longest window | 30 days in the API. |
| Events queued before the database | About 16,000 in the connector plus 16,000 in the writer, then the socket reader waits. |
