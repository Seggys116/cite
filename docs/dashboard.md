# Dashboard

This page covers the web console that manages Cite nodes: what each view does, how it signs in, and how it talks to connectors.

The console source is in `crates/cite-dashboard/web`. The dashboard server that serves these files and relays requests to connectors is in `crates/cite-dashboard`. Its proxy behaviour is described in the last section of [Connector API](node-api.md).

## Running it

```bash
docker compose -f docker-compose.dashboard.yml up -d
```

The console listens on port 8088 (`CITE_DASHBOARD_PORT`) and is published on `127.0.0.1` unless `CITE_DASHBOARD_BIND` says otherwise. Open `http://127.0.0.1:8088` to finish setup in the browser, or run `docker compose -f docker-compose.dashboard.yml run --rm dashboard init` to create the account from the command line. `scripts/setup.sh --mode dashboard` (or `both`, with a node) installs the same compose file.

| Variable | Default | Meaning |
|---|---|---|
| `CITE_DASHBOARD_PORT`, `CITE_DASHBOARD_BIND` | `8088`, `127.0.0.1` | Host port and address the compose file publishes. |
| `CITE_DASHBOARD_ALLOW` | empty | Source addresses or CIDRs allowed to connect. Empty applies no allowlist. |
| `CITE_DASHBOARD_TLS_CERT`, `CITE_DASHBOARD_TLS_KEY` | empty | PEM certificate and key paths inside the container. Both or neither. The compose file does not mount any, so add a volume of your own. |
| `CITE_DASHBOARD_COOKIE_SECURE` | on when TLS is configured | Set `true` when a TLS proxy sits in front, so the session cookie is marked Secure. |
| `CITE_DASHBOARD_SESSION_TTL` | `28800` (8 hours) | Session lifetime in seconds, from 60 to 2592000. Sessions also expire after 60 minutes idle, or sooner when the lifetime is shorter. |
| `CITE_DASHBOARD_MEM`, `CITE_DASHBOARD_CPUS`, `CITE_DASHBOARD_PIDS` | `256m`, `1.0`, `128` | Container limits. |

Boolean values accept `1`, `true`, `yes`, `on`, `0`, `false`, `no` and `off`. A malformed value stops the dashboard at start.

## Signing in

The first visit shows a setup form. Until an account exists, the dashboard prints a one-time setup token to its log on every start (`docker compose -f docker-compose.dashboard.yml logs dashboard`). The form asks for that token first, so only someone with access to the log can claim an unconfigured console. It then asks for a username, a password with confirmation, and then a confirmation code from an authenticator app. After that, signing in takes the username, the password and the current six-digit code. The form requires at least 8 characters and shows a strength hint.

The Sign out action in the top bar and the command palette ends the session.

The session cookie is named `cite_session` over plain HTTP. When the cookie is Secure (TLS, or `CITE_DASHBOARD_COOKIE_SECURE=true`) it is named `__Host-cite_session` with `Path=/` and no `Domain`, so a sibling subdomain cannot plant a copy. A request that carries more than one cookie with the session name is treated as signed out. Failed sign-ins are rate limited per client address (IPv6 clients are grouped by /64), and only attempts that name the real account count toward the dashboard-wide lockout. Each attempt is charged against the limit before its password hash runs and cleared on success, so a burst of parallel guesses cannot exceed the limit, and at most two hashes run at once.

Running `init --force` against a live dashboard replaces the account for the running process too: the dashboard notices the newer configuration, signs everyone out and never writes the old account back. Node proxy calls that deploy, switch, roll back, create a site or change maintenance wait up to 700 seconds; other calls wait 30 seconds.

## Nodes

A node is a connector. Add one with a name, its connector URL (for example `https://edge.example.com:8443`), a connector API token and, for a node that uses the CA from `init`, the contents of its `ca.pem`. Create the token with `POST /api/v1/tokens` on the connector, using a session from `POST /api/v1/auth/login`. The token is shown once.

The Nodes view lists the connectors this console manages. A node switcher in the header scopes every other view to one node or to All nodes. Removing a node removes it from the console only; the node keeps serving.

The connector's certificate comes from a self-signed authority created by `init`. The `init` output prints the CA certificate path and its SHA-256 fingerprint; compare the fingerprint before you trust the CA.

## Views

| View | What it shows or does |
|---|---|
| Overview | Health and traffic across every connected node, and recent deployments from all of them. |
| Nodes | Add and remove connectors. |
| Sites | A table of sites with node, kind (site or API), hosts, active slot, health and state. Create site opens the form described below. |
| Site page | Routing, access (Cloudflare only and SSL mode), health check settings, a live view of targets in each slot, deploy history, Deploy new version, Switch active slot, Roll back, a maintenance toggle with page choice, and Delete site. |
| Traffic | Requests over time, status classes, methods, latency (average, p50, p95, p99), response sizes, content types, top paths, client IPs, user agents, hosts and blocking rules, and a live request list that refreshes every 3 seconds. A time window selector offers 15 minutes, 1 hour, 24 hours, 7 days and 30 days, and a site selector narrows every panel to one site. The request list filters by status, method, path, client IP and blocked only, and a request can be turned into a rule that blocks its path or its address. |
| Firewall | An ordered list of rules. A rule blocks (deny, drop silently or tarpit), redirects, or changes headers and handles CORS, and has a scope of one site or all. Each row shows its effect, label, matchers and hits over 24 hours and can be switched on or off. Presets sit below the list. See Firewall rules below. |
| Maintenance | Custom maintenance pages: a name, a status code and the HTML (up to 15000 bytes). A page that a site uses cannot be deleted. |
| Settings | Data retention, connection limits, certificates, Cloudflare ranges, API tokens, the audit log (most recent 200 entries), the rendered `haproxy.cfg` with process and backend status, and dashboard appearance and session. |

Connection limit changes apply on the next HAProxy reload. The retention form edits the settings described in [Analytics and retention](analytics.md): recent events, minute history, how long hourly history is kept (forever by default) and whether old data is archived before it is deleted, audit days, the persist interval and the two privacy flags. See Retention, backup, cut and restore below.

A command palette offers shortcuts to views, Create site, Add firewall rule, Add node, switching nodes, toggling the light or dark theme, reloading the view and signing out.

## Bot analytics and export

Below the traffic charts, the Traffic view adds the panels below. All of them follow the time window and site selectors.

| Panel | What it shows |
|---|---|
| Bot traffic | The share of requests not classed human, a breakdown by class (human, suspect, crawler, tool, bot), a histogram of bot scores in five bands, the signals raised most often and the user agents behind flagged requests. The info button explains how detection works. |
| Top explorer | A ranked list of one field: paths, hosts, referers, user agents, content types, status codes, client IPs or languages. Choose the field and the number of rows (10 to 100). |
| Analytics storage | Rows stored, database size, oldest and newest request, the retention in force and the write counters. A non-zero write error count is flagged. A node that predates these statistics shows a note instead. |
| Live requests | Each row gains a bot class badge and a score. Opening a request shows the bot analysis (class, score, signals as chips) and every captured header: HTTP and TLS version, Accept, Accept-Language, Accept-Encoding, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Sec-CH-UA and the backend response time. |

Bot detection reads the request headers first and the user agent second, and the score from 0 to 100 is a heuristic. A bot that copies a browser's headers can score low, and an unusual browser can score high, so treat the classes as a guide and not as proof. Each class keeps one colour across the badge, the bars and the chart, in both the light and dark themes, and the class name is always written out.

Export opens a dialog with the following choices.

| Option | Notes |
|---|---|
| What to export | Requests (one row per request), hourly rollups, the bot summary, or a top list of one field. |
| Format | CSV or NDJSON. |
| Time range | The current window, or a custom start and end in your local time. |
| Site | All sites or one site. |
| Filters | Request and bot exports only: status range, bot class, minimum bot score, host, path prefix, client IP and method. |
| Row limit | Defaults to 100000. Leave it empty for no limit. |

The dialog checks every field first and then sends a one-row probe to the node, so an invalid request or an expired session is reported in the dialog instead of as a failed download. The file itself is then fetched by a same-origin download that carries your session cookie, so the browser streams it straight to disk and the console never holds the export in memory. The dashboard server relays the node's response without buffering it, keeps only the CSV or NDJSON content type, rebuilds the file name from safe characters and adds `nosniff` and `no-store`. An export comes from the one node selected in the header; it is not merged across nodes.

## Retention, backup, cut and restore

Analytics history is kept forever by default. In Settings, Retention, the Keep data choice offers Forever (stored as `hour_buckets_days` of 0) or Delete data older than a number of days from 1 to 3650. The checkbox Archive old data before deleting it is on by default, so a limit moves old rows into archive files on the node instead of discarding them. Choosing a limit with archiving off shows a warning and asks you to confirm before it saves, because that data is then deleted for good.

The Analytics storage card on the Traffic view adds three things.

| Action | What it does |
|---|---|
| Back up now | Asks the node for a consistent snapshot of the live analytics database. The backup is listed beside the archives. |
| Cut old data | Opens a dialog. Pick Older than N days or Before a date, leave Archive the rows before deleting them ticked, and choose Preview to see how many rows would be cut and the oldest date. Cut stays disabled until a preview of the same settings has succeeded. With archiving on, the rows are written to archive files and verified before anything is deleted. With archiving off the cut is permanent, and you must tick I understand this deletes data permanently and confirm a second time. |
| Archives and backups | A list of the files on the node with name, kind, size, creation time, a short SHA-256, and the row count and date range when known. Each row has Download, Restore and Delete. Restore imports the file back into the live database and Delete removes it from the node; both ask for confirmation. |

Download is a same-origin download like an export, so large files stream to disk. The dashboard server relays the file without buffering it, keeps only the gzip, SQLite or octet-stream content type, rebuilds the file name from the stored name with one of the extensions `.ndjson.gz`, `.csv.gz` or `.db`, and adds `nosniff` and `no-store`. Back up, cut, restore and delete are write requests, so they need the session's CSRF token like any other change, and the connector records each in its audit log. A node that returns 404 for these routes predates them and shows a note that it needs a connector update.

## Creating a site

| Field | Notes |
|---|---|
| Kind | Site or API. APIs usually route by path prefix, sites by host name. |
| Hosts | Host names that route to the site. |
| Path regex | Optional. A built-in tester shows whether the regex is valid and whether a sample path matches. Empty means every path on those hosts. |
| Source | Existing upstreams (the default) or Build from GitHub. See below. |
| Access | Whether to accept traffic only from Cloudflare, and the SSL mode (Full or Flexible). Both default to off and Full. See Access below. |
| Blue and green targets | Existing upstreams only. `host:port` addresses for each slot. At least one blue target is required. |
| Health check path | Must start with `/`. The form sends an interval of 2000 ms, a timeout of 1500 ms, 2 passes to be healthy and 3 failures to be down. |
| Placement | Selected nodes, or Replicate to all nodes. |

With Existing upstreams the form creates a site with no `source`, so it routes to upstreams you run. The new site starts with the blue slot active. The form sends one request to the dashboard server with the chosen nodes and the site definition. With Replicate to all nodes the same site is created on every connected node, so use addresses that mean the same thing on each. The connector rejects targets that are loopback, link-local, unspecified or multicast addresses, or that name the node's own services (see [Firewall and maintenance](firewall.md#targets-and-health-checks)).

Build from GitHub hides the targets, because the connector provisions the stack for the live slot. The form then asks for:

| Field | Notes |
|---|---|
| Repository | `owner/name`: two parts of letters, digits, dot, underscore or dash, none starting with a dot. |
| Branch | Defaults to `main`. |
| Runtime | `node`, `bun`, `static` or `rust`. Every runtime except `rust` also takes a Node version, 22 or 24. |
| Poll interval | Defaults to `5m`. A number followed by `s`, `m` or `h`. |
| GitHub token | Required for private repositories. Sent once as the top-level `github_token` of `POST /api/v1/deployments`, never inside `source`. The dashboard forwards it to the connector and neither stores nor returns it, and the field is emptied as soon as you submit. |

The connector accepts `github_token` only for a site with a `source`. In `each` mode `POST /deployments` also takes `per_node`, a map of node name to `{blue, green}` target lists, so each node can get its own upstreams.

On a site with a `source`, the overview tab lists the repository, branch, runtime and poll interval, and the Deploy new version panel asks for a Git ref (a branch, tag or commit sha, up to 100 characters of letters, digits, dot, underscore, dash and slash, not starting with a dash or containing `..`) instead of targets. It posts `{git_ref, note}` to the node's `/sites/{id}/deploy`.

## Access

The Access card appears in the create form and on the Routing tab of a site. It stores `access` on the site as `{"cloudflare_only": bool, "tls": "full" | "flexible"}`. The console leaves `access` out of the request while it holds the default (off, Full) and the site has none, so a node that predates the field never receives it.

| Setting | Meaning |
|---|---|
| Only accept traffic from Cloudflare | The edge refuses requests that do not come from a Cloudflare address, so nobody can bypass Cloudflare and reach the node directly. The addresses come from the node's Cloudflare ranges, shown below the toggle with their source (built-in or custom) and date. |
| SSL mode: Full | Cloudflare connects to the node over HTTPS. The node needs a certificate that covers the host. |
| SSL mode: Flexible | Cloudflare terminates HTTPS and talks plain HTTP to the node, so no certificate is needed on the node. Pair it with Only accept traffic from Cloudflare. |

Choosing Flexible without Cloudflare only shows a warning on the card: anyone who reaches the node directly is then served over plain HTTP. The warning does not block saving.

Settings, Cloudflare shows the active list for the selected node, with its source, date and count. The override box takes one CIDR range per line, IPv4 or IPv6. A bare address counts as a single host (`/32` or `/128`). The console applies the node's width rules before saving: IPv4 ranges must be `/12` or narrower, IPv6 ranges `/28` or narrower, `/0` is refused as trusting every address, and an IPv6 range that overlaps `::ffff:0:0/96`, `::/96`, `2002::/16` or `64:ff9b::/96` is refused because it would also match IPv4 clients (an IPv4-mapped address such as `::ffff:198.51.100.0/120` is read as the IPv4 range). Octets and prefix lengths with leading zeros (`010.0.0.1`, `/08`) are refused, as the node refuses them. Lines that are not addresses or ranges are refused, and up to 256 ranges are allowed. Save ranges writes `cloudflare_ranges` through `PUT /settings`; an empty box, or Use built-in list, saves an empty list so the node falls back to its built-in one. A wrong custom list locks real visitors out of sites that only accept Cloudflare traffic, so use it only when Cloudflare publishes ranges the node does not know yet.

### Bot policy and zone lock

The Access card also holds two settings that are stored in the same `access` object. Neither is sent while it has its default value and the site has no `access` yet.

| Setting | Meaning |
|---|---|
| Bot policy | `bots`: Allow all bots (default), Block scraper and tool bots (`block_bad`) or Block all bots including search engines (`block_all`). The last choice shows a warning that search engines, link previews and uptime monitors are blocked too. A note on the card says user-agent matching can be faked and that blocked requests still appear in analytics. |
| Only my Cloudflare zone | `zone_lock`. The checkbox is enabled only while Only accept traffic from Cloudflare is on, and turning that off clears it. The edge then refuses requests that lack the site's secret header `X-Cite-Origin-Secret`. |

The node generates the zone secret and returns it only from `POST /sites/{id}/zone-secret`. After you save a site whose zone lock was off and is now on (in the create form, once per node the site was created on, even when other nodes failed: the error then lists the failed nodes and says the secret for the others is shown in the dialog), the console calls that route and shows the secret in a dialog: the header name, the secret with a copy button, the secret's fingerprint and date, and numbered Cloudflare steps (Rules, Transform Rules, Modify Request Header, Set static header). The dialog warns that the secret is not shown again. It has no close icon and ignores Escape and clicks outside; it closes only with the I have saved it button, which asks for confirmation first if Copy was never pressed. Closing it empties the text and drops the copies held by the page. The secret is not written to storage, the address or any log.

On the Routing tab of a site with the lock on, the card shows when the secret was created and its fingerprint (`GET /sites/{id}/zone-secret`, which never returns the secret) and a Rotate secret button. When the node reports `readable: false` (it could not read its secret store at start), the line says the lock state is unknown and to fix the file or rotate after restoring it, instead of claiming no secret exists. Rotating asks for confirmation, because the old secret stops working at once. The dashboard proxy passes only `GET` and `POST` on `sites/{id}/zone-secret`, checks the site id, and marks both answers `Cache-Control: no-store`.

## Firewall rules

Add rule and Edit rule open a drawer with a Kind control.

| Kind | Fields |
|---|---|
| Block | The action: Deny, Drop silently or Tarpit. At least one matcher is required, as before. |
| Redirect | A target template and a status of 301, 302, 307 or 308. The placeholders `{scheme}`, `{host}`, `{www_host}`, `{apex_host}`, `{path}` and `{query}` are buttons that insert themselves at the cursor. The template and the loop checks (a redirect that keeps the host needs a path matcher, an https redirect to the same host needs the scheme matcher set to http) are checked with the same rules as the node before saving. |
| Headers and CORS | A list of header changes (request or response, set, add or remove, name, value) and an optional CORS block: allowed origins one per line, methods, allowed and exposed headers, credentials and a max age. Inline checks mirror the node: at most 16 changes, reserved and identity headers refused, `*` cannot be combined with credentials or other origins, at most 32 entries per list, max age up to 86400. |

Every kind also takes an optional label, which replaces the rule id in logs and the blocked-by-rule table. The new matchers are the connection scheme (any, http or https), a referer regex and a request header test: a header name, Equals or Matches regex, a value, an option to match when the test fails, and Secret value. A secret value is typed into a password box, is not shown again after saving, and the editor opens with the box empty and a note that the stored value is kept; leave it empty to keep it or type a new value to replace it. Switching a rule on or off from the list keeps a stored secret as well. A secret value is never shown in the list, where the matcher appears as `header X-Key = (secret)`.

The rule list shows an Effect column: Deny, Drop silently or Tarpit for blocks, the status and target for redirects, and the number of header changes or the CORS origin for the rest. The three redirect presets (`redirect-to-www`, `redirect-to-apex`, `force-https`) appear with the other presets. They have no site, so Apply asks for confirmation first and says they act on every site on the node. See [Firewall and maintenance](firewall.md) for the rules the node enforces.

## Certificates

Settings, Certificates lists the TLS certificates stored on the selected node and manages them through the connector's `/certificates` routes. Each row shows the name and subject, the names the certificate is valid for as chips, the issuer, the expiry date with the days left, the key type, a short SHA-256 fingerprint and the site hosts the certificate covers. The expiry gets a warning chip under 30 days and a danger chip under 7 days or once expired. The private key is never returned by the node, so it is never shown.

| Action | What it does |
|---|---|
| Upload certificate | Opens a dialog with a name, the certificate chain and the private key. Paste the PEM text or choose a file, which the browser reads into the box. The dialog checks for the PEM markers, refuses an encrypted key, a key pasted into the certificate box, a name that does not start with a letter or digit, starts or ends with a space or contains `-----`, and a certificate and key that together exceed 100 KiB before sending (the connector caps the whole JSON body at 128 KiB). A server error is shown in the dialog exactly as the node wrote it, and the private key box is cleared when an upload fails. A warning from the node is shown as a message and left in the status line. |
| Replace | The same dialog for an existing certificate, with the name pre-filled. Both blocks are required. |
| Delete | Asks for confirmation, then removes the certificate. Hosts only that certificate covered stop being served over HTTPS. |

Certificate files placed in the node's certificate directory by hand are listed too, with source `manual` and an id such as `file:legacy.pem`. They are read-only through the API (the item routes answer 404), so the row shows the badge "Placed on the node by hand: read-only" instead of Replace and Delete, plus the node's per-certificate warning when the file could not be read. The proxy still refuses `file:` ids, because only 26-character ULIDs are allowed in the path.

The key and chain are held only in the dialog's text boxes and the one request. The boxes are cleared when the upload succeeds or the dialog closes, the key box is also cleared when an upload fails, they have autocomplete and spellcheck off, and nothing is logged or kept in local storage, session storage or the URL. The dashboard proxy passes `GET` and `POST /certificates`, `GET`, `PUT` and `DELETE /certificates/{id}` and `GET /cloudflare/ranges` and nothing else under those prefixes, requires an id of exactly 26 uppercase letters or digits (a ULID), needs the session's CSRF token for writes and refuses certificate bodies over 144 KiB.

A note above the table lists site hosts that no certificate covers. Visitors to those hosts over HTTPS get a certificate warning, unless the site uses Flexible SSL behind Cloudflare. When the node's `https_port` is empty, HTTPS is off and certificates are stored but not served. The tab then shows a port field (443 by default) that saves `https_port` with `PUT /settings`. A node that answers 404 for the certificate routes predates them, and the tab shows a note that it needs a connector update.

## How the console talks to connectors

The browser only ever talks to the dashboard server's `/api/v1`. The server holds each node's token and forwards `/nodes/{node}/...` to the matching connector route. Other routes handle login (`POST /session`), first-run setup (`POST /setup`, `POST /setup/confirm`), a summary across nodes (`GET /nodes/summary`) and placing a site on several nodes (`POST /deployments` with `mode` of `each` or `replicate`). Details and request shapes are in [Connector API](node-api.md).

Connectors still enforce their own rules: the source allowlist, TLS and token check apply to the dashboard server as they would to any client. See [Security model](security-model.md).
