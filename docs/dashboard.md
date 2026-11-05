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
| Site page | Routing, health check settings, a live view of targets in each slot, deploy history, Deploy new version, Switch active slot, Roll back, a maintenance toggle with page choice, and Delete site. |
| Traffic | Requests over time, status classes, methods, latency (average, p50, p95, p99), response sizes, content types, top paths, client IPs, user agents, hosts and blocking rules, and a live request list that refreshes every 3 seconds. A time window selector offers 15 minutes, 1 hour, 24 hours, 7 days and 30 days, and a site selector narrows every panel to one site. The request list filters by status, method, path, client IP and blocked only, and a request can be turned into a rule that blocks its path or its address. |
| Firewall | An ordered list of rules ("evaluated in order; the first match wins" in the UI) with path prefix, path regex, user agent regex, host, methods and client address matchers, an action (deny, drop silently or tarpit) and a scope of one site or all. Each row shows its hits over 24 hours and can be switched on or off. Presets sit below the list. |
| Maintenance | Custom maintenance pages: a name, a status code and the HTML (up to 15000 bytes). A page that a site uses cannot be deleted. |
| Settings | Data retention, connection limits, API tokens, the audit log (most recent 200 entries), the rendered `haproxy.cfg` with process and backend status, and dashboard appearance and session. |

Connection limit changes apply on the next HAProxy reload. The retention form edits the settings described in [Analytics and retention](analytics.md): recent events, minute and hour history, audit days, the persist interval and the two privacy flags.

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

## Creating a site

| Field | Notes |
|---|---|
| Kind | Site or API. APIs usually route by path prefix, sites by host name. |
| Hosts | Host names that route to the site. |
| Path regex | Optional. A built-in tester shows whether the regex is valid and whether a sample path matches. Empty means every path on those hosts. |
| Source | Existing upstreams (the default) or Build from GitHub. See below. |
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

## How the console talks to connectors

The browser only ever talks to the dashboard server's `/api/v1`. The server holds each node's token and forwards `/nodes/{node}/...` to the matching connector route. Other routes handle login (`POST /session`), first-run setup (`POST /setup`, `POST /setup/confirm`), a summary across nodes (`GET /nodes/summary`) and placing a site on several nodes (`POST /deployments` with `mode` of `each` or `replicate`). Details and request shapes are in [Connector API](node-api.md).

Connectors still enforce their own rules: the source allowlist, TLS and token check apply to the dashboard server as they would to any client. See [Security model](security-model.md).
