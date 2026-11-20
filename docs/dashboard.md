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

The Nodes view lists the connectors this console manages. Removing a node removes it from the console only; the node keeps serving.

The connector's certificate comes from a self-signed authority created by `init`. The `init` output prints the CA certificate path and its SHA-256 fingerprint; compare the fingerprint before you trust the CA.

### Choosing nodes

The switcher in the header picks one node or All nodes. It sets which nodes a page reads. It never chooses where a write goes.

| Screen | Reads | Writes |
|---|---|---|
| Sites | Every node in the switcher scope | None. Create site has its own placement step. |
| Firewall, Redirects | Every node in the switcher scope | The node picker. |
| Maintenance | Every node, whatever the switcher says | Per-node switches, confirmed bulk actions, and the node picker for Delete page. |
| Topology | Every node, whatever the switcher says | None. |
| Site page | The node in its address, `#/sites/{node}/{site}` | That node. Saving settings asks which nodes when several hold the site. |
| Traffic, Settings (all tabs except Dashboard) | The node chosen on the page's node bar | That node. |

The node picker opens before a write that can reach several nodes.

- Under All nodes nothing is ticked. With one node selected in the switcher, that node is ticked.
- Offline nodes are listed but cannot be ticked.
- The confirm button names the target, for example "Apply for edge-nyc" or "Apply for 2 nodes", and stays disabled until a node is ticked.
- One toast reports each node, for example "Added on edge-fra. Failed on edge-nyc: reason".

A node bar has one button per node, and an offline node is disabled. Under All nodes the page shows "Choose a node to continue" and requests nothing until a node is picked. The pick is kept per page while the switcher stays put, and moving the switcher resets it.

## Views

| View | What it shows or does |
|---|---|
| Overview | Health and traffic across every connected node, and recent deployments from all of them. |
| Nodes | Add and remove connectors. |
| Sites | One row per site across nodes. See Sites below. Create site opens the wizard described below. |
| Topology | Hosts, nodes and sites with live load. See Topology below. |
| Databases | For the node on the node bar: the shared Postgres instance, its tenants and backups, S3 backup targets, data left behind by deleted sites and transfers between nodes. See Data and databases below. |
| Site page | Settings (hosts, paths, access, health check), a live view of targets in each slot, deploy history, Deploy new version, Switch active slot, Roll back, maintenance with one switch per node, and Delete site. The nodes that hold the site are shown beside its title. |
| Traffic | For the node on the node bar: requests over time, status classes, methods, latency (average, p50, p95, p99), response sizes, content types, top paths, client IPs, user agents, hosts and blocking rules, and a live request list that refreshes every 3 seconds. A time window selector offers 15 minutes, 1 hour, 24 hours, 7 days and 30 days, and a site selector narrows every panel to one site. The request list filters by status, method, path, client IP and blocked only, and a request can be turned into a rule that blocks its path or its address. |
| Firewall | An ordered list of rules from every node in scope, merged by id. A rule blocks (deny, drop silently or tarpit), redirects, or changes headers and handles CORS, and has a scope of one site or all. Each row shows its effect, matchers and hits over 24 hours and can be switched on or off. Presets sit below the list. See Firewall rules below. |
| Redirects | A table of redirect rules with one Save changes button. Reached from Firewall. See Redirects below. |
| Maintenance | One page library across nodes and a site by node matrix. See Maintenance below. |
| Settings | For the node on the node bar: data retention, connection limits, certificates, Cloudflare ranges, API tokens, alerts, the audit log (most recent 200 entries) and the rendered `haproxy.cfg` with process and backend status. The Dashboard tab holds appearance and session and has no node bar. |

Connection limit changes apply on the next HAProxy reload. The retention form edits the settings described in [Analytics and retention](analytics.md): recent events, minute history, how long hourly history is kept (forever by default) and whether old data is archived before it is deleted, audit days, the persist interval and the two privacy flags. See Retention, backup, cut and restore below.

A command palette offers shortcuts to views, Create site, Add firewall rule, Add node, switching nodes, toggling the light or dark theme, reloading the view and signing out.

The console uses a neutral paper and ink palette with one accent colour, pill-shaped buttons and sentence-case text. It follows the OS light or dark setting unless Settings, Dashboard, Appearance sets Light or Dark.

## Sites

The Sites view has one row per site id across the nodes in the switcher scope.

| Column | Shows |
|---|---|
| Site | Name, id, and an API pill for an API site. |
| Hosts | Hosts, with path prefixes and `~` regexes under them. |
| Nodes | A chip per node that holds the site, with a health dot. A chip opens the site on that node. |
| Load | A one-hour sparkline summed over the nodes, and requests per second over 15 minutes. |
| State | One pill for the worst state on any node: Needs attention, Deploy failed, Maintenance or Serving. |

- The rate comes from one `/analytics/facets` call per node. The sparkline is fetched per site when its row scrolls into view.
- Needs attention means a target in the active slot fails its health check. Deploy failed means the latest deployment failed and no later one succeeded.
- The scope control offers All nodes, one button per node (with more than one node) and Needs attention with a count.
- The filter box matches name, id or host.
- A row opens the site on the scoped node, or on the first node that holds it.
- A node that does not answer is named in a notice, and its sites are not listed.

## Topology

Topology (`#/topology`) shows how requests reach each site in three columns: entries, nodes and sites.

- An entry is a host plus its path prefixes or regexes. A single-endpoint Rust API appears as a site with its path regex.
- Each link carries requests per second over 15 minutes, drawn as line width. The busiest link is highlighted. A link with no traffic now (a failover or idle route, or a route through an offline node) is dashed.
- An offline node stays on the chart.
- Click a node to dim every route that does not pass through it. Click it again or press Escape to clear.
- Click a site or an entry to open the site.
- It always covers every node and refreshes every 10 seconds while the tab is visible.

## Maintenance

The Maintenance view keeps one page library across nodes and a site by node matrix. Each node stores its own copy of every page, so a node keeps serving when the console is offline.

- **Pages.** One card per page id with a chip per node that holds it, and a `differs` pill when copies differ. A node that could not be read is never reported as missing a page.
- **Bring nodes in line.** Lists what it will do per node, then on confirmation creates missing pages and replaces differing copies with the version most nodes hold (a tie goes to the first node listed). Nothing is written when the page loads.
- **Saving a page.** Creating a page asks first. Editing one lists the change per node first when it reaches several nodes or replaces a differing copy. Only nodes that answered are written, and the rest are named in the result.
- **Delete page.** Opens the node picker, limited to nodes that hold the page. A page a site uses cannot be deleted.
- **Sites by node.** One row per site, a page choice, and one switch per node that holds the site. A dash means the node does not hold the site, is offline or could not be read.
- **Drain and Restore.** Per node, after confirmation. Drain puts the node's sites that are live into maintenance, and Restore takes the ones in maintenance out.
- **Page on the node.** A node cannot serve a page it does not hold, so turning maintenance on first creates the page on that node.

## Bot analytics and export

Below the traffic charts, the Traffic view adds the panels below. All of them follow the time window and site selectors.

| Panel | What it shows |
|---|---|
| Bot traffic | The share of requests not classed human, a breakdown by class (human, suspect, crawler, tool, bot), a histogram of bot scores in five bands, the signals raised most often and the user agents behind flagged requests. The info button explains how detection works. |
| Top explorer | A ranked list of one field: paths, hosts, referers, user agents, content types, status codes, client IPs or languages. Choose the field and the number of rows (10 to 100). |
| Analytics storage | Rows stored, database size, oldest and newest request, the retention in force and the write counters. A non-zero write error count is flagged. A node that predates these statistics shows a note instead. |
| Live requests | Each row gains a bot class badge and a score. Opening a request shows the bot analysis (class, score, signals as chips) and every captured header: HTTP and TLS version, Accept, Accept-Language, Accept-Encoding, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Sec-CH-UA and the backend response time. |

The dashboard server relays only these analytics reads to a node: `summary`, `timeseries`, `requests`, `bots`, `top`, `facets`, `compare`, `stats` and `export`, all as `GET`. The query string, including long filter lists, is passed to the node unchanged, so every filter in [Analytics](analytics.md#filtering) works through the console.

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

The dialog checks every field first and then sends a one-row probe to the node, so an invalid request or an expired session is reported in the dialog instead of as a failed download. The file itself is then fetched by a same-origin download that carries your session cookie, so the browser streams it straight to disk and the console never holds the export in memory. The dashboard server relays the node's response without buffering it, keeps only the CSV or NDJSON content type, rebuilds the file name from safe characters and adds `nosniff` and `no-store`. An export comes from the node chosen on the Traffic node bar; it is never merged across nodes.

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

Create site is a five-step wizard under the subtitle "Choose where the site comes from and which domains reach it". A progress list shows the current step, Back and Next move between steps, and Next stays disabled until the step is valid, with the reason shown beside it. Each step title receives focus when the step opens, the progress list marks the current step with `aria-current`, and Enter in a field moves to the next step. Nothing is sent until Create site on the last step.

| Step | What it asks |
|---|---|
| 1. Where does the site come from? | Two cards. Build from a GitHub repository is the first choice and the core flow. Serve servers I already run is the second. |
| 2. Details | For GitHub: Repository, Branch, Runtime and poll interval, and a token if one is needed (below). For your own servers: the upstream editor and the health check path. |
| 3. Name and domains | Kind (site or API), name, id, the domains, and optional paths. |
| 4. Protection | The Access card (see Access below). Nothing here is required. |
| 5. Where should it run? | Selected nodes, or Replicate to all nodes, and a review of every choice before Create site. |

The optional paths are a list of rows, each either Path starts with (a prefix) or Path matches regex, with a check on every row. A request that matches any row is routed to the site; no rows means every path on those domains. They are sent as `path_prefixes` and `path_regexes` on the site. A site saved with the older single `path_regex` still opens, and its regex appears as one row.

GitHub fields:

| Field | Notes |
|---|---|
| Repository | `owner/name`, or a pasted address: `https://github.com/owner/name`, with `.git` or a trailing slash, `https://www.github.com/...`, `.../tree/<branch>`, `git@github.com:owner/name.git`, `ssh://git@github.com/owner/name.git` or `github.com/owner/name`. It is reduced to `owner/name` when the field loses focus and a line below shows what will be stored. A `/tree/<branch>` address offers a button to use that branch and never changes the branch silently. An address with a user name and password or token is refused, without repeating it. For a host other than GitHub the note depends on the node: with the `forges` capability it says the node fetches from its configured forge API (the host `GET /node` reports as `github.api_host`), otherwise that the node only fetches from GitHub. |
| Branch | Defaults to `main`. Checked like a git branch name: no `..`, `//`, `@{`, `~^:?*[` or backslash, no leading `-` or `/`, no trailing `/`, `.` or `.lock`. |
| Runtime | `node`, `bun`, `static` or `rust`. Every runtime except `rust` also takes a Node version, 22 or 24. |
| Poll interval | Defaults to `5m`. `off` (or `0`) checks only when you deploy; otherwise a number and a unit (`ms`, `s`, `m`, `h`, `d`) from 60 seconds to 366 days. |
| Build settings | Folded behind "Show build settings", the same fields as the Build tab of the site page (below), all optional and on Auto. |

The GitHub path never mentions upstreams, blue or green. The console sends empty slots, because the connector provisions the stack for the live slot, and sets `source` from the fields above.

Each node reports in `GET /node` whether it already holds a GitHub token (`github.token_configured`, from `CITE_GITHUB_TOKEN`). The console reads that for every online node and decides about the token field from the nodes you pick:

| Nodes picked | Token field |
|---|---|
| All have a token | Folded away behind a quiet "Use a different token for this site" button, with the note "This node already has a GitHub token (CITE_GITHUB_TOKEN). Leave this empty to use it." |
| At least one has none | Shown and required, with the help "Fine-grained token with Contents: read for this repository. Better: set CITE_GITHUB_TOKEN on the node once (see docs). Stored only on the node." |
| A node has not answered, or predates the field | Shown, not required. |

With several nodes, the token is therefore required only if some selected node has none, and a token you type is sent for the whole request. The token is sent once as the top-level `github_token` of `POST /api/v1/deployments`, never inside `source`, and only for a GitHub site. The dashboard forwards it to the connector and neither stores nor returns it, and the field is emptied as soon as you submit.

Serve servers I already run creates a site with no `source`, so it routes to upstreams you run. Its blue and green slots take `host:port` addresses; at least one live (blue) server is required. The health check path must start with `/`, and the wizard sends an interval of 2000 ms, a timeout of 1500 ms, 2 passes to be healthy and 3 failures to be down. The new site starts with the blue slot active. With Replicate to all nodes the same site is created on every connected node, so use addresses that mean the same thing on each. The connector rejects targets that are loopback, link-local, unspecified or multicast addresses, or that name the node's own services (see [Firewall and maintenance](firewall.md#targets-and-health-checks)).

The connector accepts `github_token` only for a site with a `source`. In `each` mode `POST /deployments` also takes `per_node`, a map of node name to `{blue, green}` target lists, so each node can get its own upstreams.

On a site with a `source`, the overview tab lists the repository, branch, runtime and poll interval, and the Deploy new version panel asks for a Git ref (a branch, tag or commit sha, up to 100 characters of letters, digits, dot, underscore, dash and slash, not starting with a dash or containing `..`) instead of targets. It posts `{git_ref, note}` to the node's `/sites/{id}/deploy`.

## The site page

A site page has these tabs: Overview, Deployments, Build, Logs, Data, Settings, Maintenance and Danger zone. Build and Logs are for sites the node builds from a repository, and each appears only when the node lists the matching capability in `GET /node` (`source-build`, `site-logs`). Data appears for a site that runs a server when the node lists `data-postgres`, `data-external` or `data-s3` (see [Data and databases](#data-and-databases)). Other controls are gated the same way (`site-status`, `site-github-token`, `site-build-env`, `site-runtime-env`, `deploy-async`, `cert-generate`, `cert-origin-ca`, `cert-acme`, `alerts`, `forges`). A node that lists nothing, such as an older connector, simply shows fewer controls. The full guide is [Site status, logs and build settings](site-status.md).

**Status panel.** On Overview and Build. A chip shows the phase: fetching, building, packing, promoting, idle, failed, or unhealthy (idle, but the live slot is not passing its health check). While the manager works the chip pulses and the panel refreshes every 2 seconds; otherwise every 10 seconds. A failed or unhealthy site shows a red banner with the node's reason and a Copy reason button, and a Redeploy button. A "Changes not built yet" badge shows when the node reports `settings_current: false`. A table lists each slot with its container, health, phase, commit, last build time and restarts, with out-of-memory and exit codes when present. Polling runs only while the panel is on the page and the browser tab is visible, and an overlapping request is never started.

**Logs.** Manager (build) and Executor (running site) tabs, a slot picker, and a Follow switch. The first request asks for the last 300 lines; later requests send the `since` cursor from the previous answer, so only new lines are fetched, every 2 seconds, and only while the tab is visible and Follow is on. The viewer keeps the newest 5000 lines, removes terminal colour codes, colours error, warning and debug lines, searches as you type (matches are marked with elements, never markup built from log text), filters by level, and copies what is shown. The node masks secrets before they reach the log.

**Build settings (Build tab).** Every field the node accepts in `source`: repository (pasted addresses are normalised), branch, runtime, Node version, poll interval, root directory, package manager, install command, build command, output directory, rendering, start command, SPA fallback file, framework and prune. There is no per-site forge field: the forge is set for the whole node by the operator (`CITE_STACK_FORGE`), and the node refuses a site that names one. A field left empty is Auto and shows what the manager detected, for example "Auto (detected: pnpm)". Each field is checked with the node's rules as you type (relative paths without `..`, one-line commands up to 1024 bytes, a start command without shell characters that does not begin with a package manager, shell or env, and not with static rendering). Unsaved changes are flagged and Save stays off until the form is valid. After a save that changes how the site is built (anything but the poll interval) the console asks every time: "This change needs a rebuild", with Redeploy now and Later.

**Environment variables.** Values are write-only: no route returns one, so build and runtime variables list names only and the value box is labelled "Value (write-only)". A value can be typed for a new variable or to replace one, is kept in the page until you save, and is dropped when the node has it, when you discard, and when you leave the page. Names are capital letters, digits and underscores; the names the node reserves (`PATH`, `HOME`, `NODE_OPTIONS`, `LD_*`, `GIT_*`, `NPM_CONFIG_*`, `XDG_*`, `CITE_*`, proxy settings and a few more) are refused, a value is one line up to 4096 bytes, a site holds at most 128 and a change is at most 24 KiB. Saved variables apply on the next build.

**GitHub token.** The card says whether the site uses its own token, the node token or none, and whether the git host accepted it. A token is typed into a write-only box, sent once and the box is emptied at once; the node tests it before storing it. "Use the node token" removes the site token.

**Deployments.** Each history row shows its note (a failure's reason in red, in full), commit and actions: Redeploy for the live release and for failed attempts, Deploy this commit for an earlier release whose commit is known, and Roll back (disabled when there is no earlier release on the other slot). With the `deploy-async` capability a deploy returns at once with a `deployment_id` and is followed in the Status panel; a failed deploy shows the node's whole message in a toast and under the form.

**Settings.** Everything the node accepts in `PUT /sites/{id}` besides the source: name, kind, hosts, path prefixes and regexes, the health check (path, interval 100 to 60000 ms, timeout 100 to 10000 ms and not above the interval, rise and fall 1 to 10), and the Access card. Each field shows its own error, an "Unsaved changes" badge appears, and Save stays off until the form is valid and changed. The create wizard uses the same field components as the Build tab.

**Nodes that hold the site.** The same site id can exist on several nodes, and each node stores its own copy. The nodes that hold it appear as chips beside the title. The current node is marked and the others link to their own page for the site.

- Save on Settings (the Site card, Access and Health check) asks which nodes when more than one holds the site. The current node is ticked and no other.
- A node whose site has the same id but different hosts and a different repository is named in the dialog as a different site. Check it before ticking it.
- Each node keeps its own upstream targets, active slot and source. Only name, kind, hosts, paths, health check and access are written.
- Deploy, Switch active slot, Roll back, Redeploy and Delete site act on the node of the page only.
- Maintenance has one switch per node that holds the site, and a page choice. Turning it on creates the page on a node that lacks it first. Turn on everywhere and Turn off everywhere confirm first and skip a node that holds a different site with the same id.

Alerts are under Settings, Alerts, shown only for a node with the `alerts` capability.

## Access

The Access card appears in the create form and on the Settings tab of a site. It stores `access` on the site as `{"cloudflare_only": bool, "tls": "full" | "flexible"}`. The console leaves `access` out of the request while it holds the default (off, Full) and the site has none, so a node that predates the field never receives it.

| Setting | Meaning |
|---|---|
| Only allow traffic through the Cloudflare proxy | `cloudflare_only`. "When on, requests that do not arrive from Cloudflare's network are refused. Turn it on only for sites that are proxied by Cloudflare (orange cloud)." The text does not suggest that every site is routed through Cloudflare, and turning the option on alone never asks for a rule, a secret or a header. The addresses come from the node's Cloudflare ranges, shown below the toggle with their source (built-in or custom) and date. |
| Full (the node serves its own certificate) | `tls` of `full`. Visitors, or Cloudflare, connect over HTTPS and the node answers with its own certificate. Create or upload one under Settings, Certificates. |
| Flexible SSL (Cloudflare serves HTTPS to visitors and talks to your server over plain http) | `tls` of `flexible`. No certificate is needed on the node. It can be chosen without the option above. |

Choosing Flexible SSL without the proxy option shows a note on the card and does not block saving: without that option anyone can reach the server directly over plain http, with no encryption.

Settings, Cloudflare shows the active list for the node on the node bar, with its source, date and count. The override box takes one CIDR range per line, IPv4 or IPv6. A bare address counts as a single host (`/32` or `/128`). The console applies the node's width rules before saving: IPv4 ranges must be `/12` or narrower, IPv6 ranges `/28` or narrower, `/0` is refused as trusting every address, and an IPv6 range that overlaps `::ffff:0:0/96`, `::/96`, `2002::/16` or `64:ff9b::/96` is refused because it would also match IPv4 clients (an IPv4-mapped address such as `::ffff:198.51.100.0/120` is read as the IPv4 range). Octets and prefix lengths with leading zeros (`010.0.0.1`, `/08`) are refused, as the node refuses them. Lines that are not addresses or ranges are refused, and up to 256 ranges are allowed. Save ranges writes `cloudflare_ranges` through `PUT /settings`; an empty box, or Use built-in list, saves an empty list so the node falls back to its built-in one. A wrong custom list locks real visitors out of sites that only accept Cloudflare traffic, so use it only when Cloudflare publishes ranges the node does not know yet.

### Bot policy and zone lock

The Access card also holds two settings that are stored in the same `access` object. Neither is sent while it has its default value and the site has no `access` yet.

| Setting | Meaning |
|---|---|
| Bot policy | `bots`: Allow all bots (default), Block scraper and tool bots (`block_bad`) or Block all bots including search engines (`block_all`). The last choice shows a warning that search engines, link previews and uptime monitors are blocked too. A note on the card says user-agent matching can be faked and that blocked requests still appear in analytics. |

With Allow, the card says "No bot blocking is active for this site" instead of presenting the choice as protection. It then lists every firewall rule of the node that looks at user agents and applies to the site, whether it is for all sites or scoped to this one, with its action and patterns, and marks a rule that is switched off. That is where a bot could still be blocked, for example the Scanners preset.
| Also require that requests come from MY Cloudflare account (advanced) | `zone_lock`. It sits in a folded "advanced" section that opens by itself only when the site already uses it, so the plain option above never mentions rules or secrets. The checkbox is enabled only while Only allow traffic through the Cloudflare proxy is on, and turning that off clears it. The edge then refuses requests that lack the site's secret header `X-Cite-Origin-Secret`. |

The node generates the zone secret and returns it only from `POST /sites/{id}/zone-secret`. After you save a site whose zone lock was off and is now on (in the create form, once per node the site was created on, even when other nodes failed: the error then lists the failed nodes and says the secret for the others is shown in the dialog), the console calls that route and shows the secret in a dialog: the header name, the secret with a copy button, the secret's fingerprint and date, and numbered Cloudflare steps (Rules, Transform Rules, Modify Request Header, Set static header). The dialog warns that the secret is not shown again. It has no close icon and ignores Escape and clicks outside; it closes only with the I have saved it button, which asks for confirmation first if Copy was never pressed. Closing it empties the text and drops the copies held by the page. The secret is not written to storage, the address or any log.

On the Settings tab of a site with the lock on, the card shows when the secret was created and its fingerprint (`GET /sites/{id}/zone-secret`, which never returns the secret) and a Rotate secret button. When the node reports `readable: false` (it could not read its secret store at start), the line says the lock state is unknown and to fix the file or rotate after restoring it, instead of claiming no secret exists. Rotating asks for confirmation, because the old secret stops working at once. The dashboard proxy passes only `GET` and `POST` on `sites/{id}/zone-secret`, checks the site id, and marks both answers `Cache-Control: no-store`.

## Firewall rules

Add rule and Edit rule open a drawer with a four-step builder. Next stays disabled until the step is valid, and an existing rule opens in the same steps with its values filled in.

| Step | What it asks |
|---|---|
| 1. What should happen? | Block, Redirect, Change headers or CORS, as cards. |
| 2. When? | Condition rows, and a live sentence in plain English below them (see below). |
| 3. Details | Block: Deny, Drop silently or Tarpit. Redirect: a target template and a status of 301, 302, 307 or 308, with the placeholders `{scheme}`, `{host}`, `{www_host}`, `{apex_host}`, `{path}` and `{query}` as buttons that insert themselves at the cursor. Change headers: a list of changes (request or response, set, add or remove, name, value). CORS: allowed origins one per line, methods, allowed and exposed headers, credentials and a max age. |
| 4. Name and scope | A name, an optional label (replaces the rule id in logs and the blocked-by-rule table), one site or all sites, and a review. |

Each condition row has a type and a value: Path starts with, Path matches regex, User agent matches, Referer matches, Method is, Host is, IP is in range, Scheme is, or a request header test (a header name, Equals or Matches regex, a value, an option to match when the test fails, and Secret value). Rows of the same type are alternatives, so `/a` and `/b` match a request for either; rows of different types must all match. The sentence under the rows says so, for example "When the path starts with /a or /b, and the method is POST." A rule is sent with the list fields (`path_prefixes`, `path_regexes`, `user_agent_regexes`, `referer_regexes`, `hosts`, `methods`, `cidrs`, `scheme`, `headers`), and a rule saved with the older single-value matchers opens as one-item lists. A blocking rule needs at least one condition. Inline checks mirror the node: at most 32 values per kind of condition and 256 ranges, at most 16 header changes, reserved and identity headers refused, `*` cannot be combined with credentials or other origins, at most 32 entries per CORS list, max age up to 86400, and the redirect loop checks (a redirect that keeps the host needs a path condition, an https redirect to the same host needs the scheme condition set to http).

A secret header value is typed into a password box, is not shown again after saving, and the builder opens with the box empty and a note that the stored value is kept; leave it empty to keep it or type a new value to replace it. Switching a rule on or off from the list keeps a stored secret as well. A secret value is never shown in the list or in the sentence, where it appears as `header X-Key = (secret)` and "a secret value".

The rule list shows an Effect column: Deny, Drop silently or Tarpit for blocks, the status and target for redirects, and the number of header changes or the CORS origin for the rest. The three redirect presets (`redirect-to-www`, `redirect-to-apex`, `force-https`) appear with the other presets. They have no site, so the node picker for Apply says they act on every site on the node. See [Firewall and maintenance](firewall.md) for the rules the node enforces.

### Rules across nodes

- The page reads rules from every node in scope. The header names the scope, and a node that cannot be read is listed in a notice and left out.
- Identical rules (same id and same content, ignoring on or off) become one row. Under All nodes a Nodes column shows a chip per holder with an on or off dot.
- A rule with the same id but different content on another node is a separate row with a `differs` pill. It is never merged.
- Hits over 24 hours are summed over the nodes that hold the row.
- The switch is on only when every holder has the rule on. A rule held by one node changes that node. A rule held by several opens the node picker, limited to its holders.
- Add rule, Save rule, Delete rule and Apply on a preset open the node picker. Add rule offers online nodes, and for a rule scoped to a site only nodes that hold that site. Save rule offers only nodes that hold the rule. Apply offers online nodes.
- Saving a rule keeps each node's own on or off state.
- Match text wraps in full instead of ending in an ellipsis.

Each preset shows an "N rules" pill. Hover or focus it to list every rule the preset adds with its action and patterns, so Sensitive files lists its six rules. Each preset card also has a collapsible "What it blocks" list with the same content, which is the only form on touch screens.

## Redirects

Firewall, Manage redirects (or `#/redirects`) opens a table of the redirect rules, read from every node in scope and merged by id. When copies of a redirect differ between nodes, a notice says so and the first copy is shown. Each row has an on switch, From (Path starts with a prefix, or Path matches regex), To (a template with the same placeholder chips as the builder), a status of 301, 302, 307 or 308, and delete. Rules with other conditions, or the quick rows below, show what they match in place of the From box.

| Button | Adds |
|---|---|
| Add redirect | An empty row. |
| Add www redirect | A row sending to `{scheme}://{www_host}{path}{query}`. |
| Add https redirect | A row for plain http requests sending to `https://{host}{path}{query}`. |

Every row is checked as you type: the path must start with `/` for a prefix, the regex must compile, the target must be a valid template, no two rows may start from the same path, and the same loop checks as the builder apply. Save changes stays disabled until every row is valid and something changed, and the summary beside it counts rows to save and delete. Save changes opens the node picker (confirm button "Save redirects for ..."), then sends one `POST /firewall/bulk` request per picked node with `{"replace": [rules], "delete": [ids]}` containing only the rows that changed. Each node applies its request as one configuration change and answers `{created, replaced, deleted}`.

- The body for a node is built from that node's own stored rules. A node keeps its own on or off state unless you used that row's switch. A row that is on at some nodes and off at others carries a "differs by node" pill until then.
- A delete is sent only to nodes that hold the rule.
- New rows get the next free id `redirect-<n>` and the same text as their label, and an edited row keeps its id, label, name and site.
- If a node refuses a rule, its message appears under the row that sent it, prefixed with the node name. A message that names no row is shown below the table. Other nodes are not rolled back.
- Discard changes reloads the list.

The dashboard proxy passes only `POST` on exactly `firewall/bulk` (any other method or extra path segment is refused), needs the session's CSRF token, and refuses bodies over 512 KiB; every other firewall route keeps the usual limit.

## Certificates

Settings, Certificates lists the TLS certificates stored on the node on the node bar and manages them through the connector's `/certificates` routes. Each row shows the name and subject, the names the certificate is valid for as chips, the issuer, the expiry date with the days left, the key type, a short SHA-256 fingerprint and the site hosts the certificate covers. The expiry gets a warning chip under 30 days and a danger chip under 7 days or once expired. The private key is never returned by the node, so it is never shown.

| Action | What it does |
|---|---|
| Upload certificate | Opens a dialog with a name, the certificate chain and the private key. Paste the PEM text or choose a file, which the browser reads into the box. The dialog checks for the PEM markers, refuses an encrypted key, a key pasted into the certificate box, a name that does not start with a letter or digit, starts or ends with a space or contains `-----`, and a certificate and key that together exceed 100 KiB before sending (the connector caps the whole JSON body at 128 KiB). A server error is shown in the dialog exactly as the node wrote it, and the private key box is cleared when an upload fails. A warning from the node is shown as a message and left in the status line. |
| Replace | The same dialog for an existing certificate, with the name pre-filled. Both blocks are required. |
| Delete | Asks for confirmation, then removes the certificate. Hosts only that certificate covered stop being served over HTTPS. |

Certificate files placed in the node's certificate directory by hand are listed too, with source `manual` and an id such as `file:legacy.pem`. They are read-only through the API (the item routes answer 404), so the row shows the badge "Placed on the node by hand: read-only" instead of Replace and Delete, plus the node's per-certificate warning when the file could not be read. The proxy still refuses `file:` ids, because only 26-character ULIDs are allowed in the path.

The key and chain are held only in the dialog's text boxes and the one request. The boxes are cleared when the upload succeeds or the dialog closes, the key box is also cleared when an upload fails, they have autocomplete and spellcheck off, and nothing is logged or kept in local storage, session storage or the URL. The dashboard proxy passes `GET` and `POST /certificates`, `GET`, `PUT` and `DELETE /certificates/{id}` and `GET /cloudflare/ranges` and nothing else under those prefixes, requires an id of exactly 26 uppercase letters or digits (a ULID), needs the session's CSRF token for writes and refuses certificate bodies over 144 KiB.

A note above the table lists site hosts that no certificate covers. Visitors to those hosts over HTTPS get a certificate warning, unless the site uses Flexible SSL behind Cloudflare. When the node's `https_port` is empty, HTTPS is off and certificates are stored but not served. The tab then shows a port field (443 by default) that saves `https_port` with `PUT /settings`. A node that answers 404 for the certificate routes predates them, and the tab shows a note that it needs a connector update.

## Data and databases

What these controls do is described in [Site data services](data.md). The console shows them only for a node that lists the matching `data-*` capabilities; an older connector shows no Data tab and no Databases view. Passwords, external database URLs and S3 keys are write-only everywhere: no view shows one, and the inputs that take them are emptied after use.

### The Data tab

The Data tab of a site page reads `GET /sites/{id}/data` through the node bar's node and shows these cards. A node without data services shows "Data services are not enabled on this node".

| Card | What it does |
|---|---|
| Postgres | Turns Postgres on with a mode (dedicated or shared, shown with the trade-off table) and a Postgres major, and shows its health, resources and backup policy. An option creates the default `app` database with its users and links. Edit resources applies to dedicated. Turn off removes the database but keeps its data unless you also delete it. After a conversion, a notice offers Delete the old database. Shared mode needs the shared instance enabled on the Databases view first. |
| Databases and users | Databases with their users: level (owner, read and write, read only), connection limit, timeouts, whether the user is disabled, when the password was last rotated and which links use it. Add a database or user, edit, disable, rotate a password, delete. |
| Environment links | Each variable with its target (runtime or build) and source. Add a link, apply a preset (Generic, Prisma, Drizzle, Auth.js, Better Auth), or delete one. A conflict with a manual variable offers a replace, and a variable that Doppler also sets is marked as shadowed. Values are never shown. |
| Generated secrets | Create, rotate (with a warning that an auth secret signs everyone out) and delete random values. |
| External Postgres | Attach a database by URL (write-only). Shows the host, database, SSL mode, the forward port and warnings such as `verify-full` through the egress forward, and the note that external databases are backed up by hand only. |
| S3 storage | Attach a bucket with write-only keys. |
| Backups | Versions of each database with trigger, label, pin, size, checksum, status and where the copies are held. Back up now (optionally also to S3), label, pin, download, restore (it asks for the site id and says a backup is taken first), push to S3 and delete from the node, S3 or both. The schedule (every 1, 2, 3, 4, 6, 8, 12 or 24 hours at a minute, UTC), the retention numbers of each tier, the S3 target and Prune backups now with its preview are on this card. A note says an S3 copy needs the node key. |
| Convert | Starts a conversion between dedicated and shared with a freeze choice, follows it, compares the tables, and offers Cut over and Abort. |
| Move database to another node | See below. |

Changes that start work return at once and the card follows the job. A banner says when a redeploy is needed for running containers to see a change.

### Moving a database to another node

The card picks a target node (online and managed by this console), a database, how the site behaves during the final copy (maintenance page, or read only) and two options: replace a database of the same name on the target, and replace manual variables of the same name when the links are created. The dashboard server runs the transfer, so the dump never passes through the browser; the console starts, watches, resumes, cancels, cuts over and rolls back through `/api/v1/transfers`. A row shows the phase (waiting, freezing the source, dumping, copying, restoring, verifying, cutting over, done, failed, rolled back), progress in bytes, and the tables whose row counts differ between the two sides. Cut over is available once the counts match and is refused when they differ; Roll back and Cancel are available while the transfer has not finished, and Resume continues a failed or interrupted one. The target site must exist with Postgres enabled. Transfers that were started elsewhere, for example from the desktop app, appear as open sessions to finish where they were started.

The server keeps the transfers in `transfers.json` next to its configuration (mode 0600, no secrets), runs at most two at once, and marks one that was running when it stopped as failed so it can be resumed. See [Site data services](data.md#moving-a-database-to-another-node) for what each step does.

### The Databases view

`#/databases`, for the node on the node bar. It needs a node that lists `data-shared` or `data-postgres`.

| Card | What it does |
|---|---|
| Encryption key and backup volume | The node key id and where it comes from, and whether the backup volume is usable. |
| Shared instance | Enable, edit (memory, CPUs, connections and, at creation, the Postgres major), restart and delete the node's shared Postgres. Changing the limits recreates the container. |
| Tenants | The sites on the shared instance with the size of each database. |
| Instance backups | Back up every tenant database in one archive, download it and delete it. |
| Transfers between nodes | Open and recent transfers of all sites, with the same actions as the Data tab. |
| Backup targets | S3 buckets that hold backup copies: add, edit, test and delete. They are separate from the buckets sites use. |
| Left behind by deleted sites | Data kept when a site was deleted without `purge_data`, with a Purge action. A new site with the same id picks it up again. |

## How the console talks to connectors

The browser only ever talks to the dashboard server's `/api/v1`. The server holds each node's token and forwards `/nodes/{node}/...` to the matching connector route. Other routes handle login (`POST /session`), first-run setup (`POST /setup`, `POST /setup/confirm`), a summary across nodes (`GET /nodes/summary`) and placing a site on several nodes (`POST /deployments` with `mode` of `each` or `replicate`). Details and request shapes are in [Connector API](node-api.md).

Beyond the generic prefixes, these routes are exact (method, route) pairs, need the session's CSRF token for writes, and have their own body caps:

| Route | Methods | Cap |
|---|---|---|
| `sites/{id}/status`, `sites/{id}/logs` | GET | |
| `sites/{id}/github-token` | GET, PUT, DELETE | PUT 1 KiB |
| `sites/{id}/build-env`, `sites/{id}/runtime-env` | GET, PATCH | PATCH 64 KiB |
| `sites/{id}/deploy` | POST (`wait: false` answers at once) | usual |
| `certificates/generate`, `certificates/origin-ca`, `certificates/acme` | POST | 16 KiB |
| `certificates/acme`, `certificates/acme/{job}` | GET | |
| `alerts` | GET, PUT | PUT 64 KiB |
| `alerts/test` | POST | 1 KiB |
| `sites/{id}/data/...` | the site data routes of [Connector API](node-api.md#site-data-services), each an exact method and shape with validated ids and names | 64 KiB |
| `data/...` | node level: `data`, `data/jobs/{job}`, `data/targets...`, `data/shared...` (with backups and their download), `data/orphans...` | 64 KiB |
| `/api/v1/transfers` (the server's own route) | GET list, POST create | usual |
| `/api/v1/transfers/{id}` and its `resume`, `cancel`, `cutover` and `rollback` | GET, and POST for the four actions | usual |

The site id and the ACME job id are checked, the answers for status, logs, token, certificate issuing and alerts are sent with `Cache-Control: no-store`, and the long timeout used for deploys also applies to the token and ACME writes. `PATCH` is refused everywhere except the two environment routes and the data routes that take it (a database user and a backup's label and pin). Backup downloads are relayed as streams. The transfer routes of a connector (`exports`, `imports` and their chunks and manifest) are not proxied at all: the dashboard server drives them itself, so a browser never carries a chunk or sees a manifest.

Connectors still enforce their own rules: the source allowlist, TLS and token check apply to the dashboard server as they would to any client. See [Security model](security-model.md).
