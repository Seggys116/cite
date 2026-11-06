# Desktop app

This page covers `apps/desktop`, the native console for Cite nodes: how to get it, how it stores nodes and tokens, and how it differs from the web dashboard.

## What it is

The desktop app is a client for the connector API with the same views as the web console: Overview, Nodes, Sites (with a site page and a create form), Traffic, Firewall, Maintenance and Settings. It talks to each connector directly over HTTPS. It does not need the dashboard container, and the dashboard does not need it.

It is built with GPUI and lives in its own Cargo workspace, outside the root `Cargo.toml`, so `cargo build` at the repository root does not build it.

## Getting it

Every run of the `apps` workflow uploads desktop builds as artifacts, and each `v*` tag attaches them to the GitHub release together with a `.sha256` file:

| Platform | Archive |
|---|---|
| macOS, Apple silicon and Intel | `Cite-<version>-macos-<arch>.zip` containing `Cite.app` (macOS 13 or newer) |
| Linux x64 | `cite-desktop-<version>-linux-<arch>.tar.gz` with the binary, `cite.desktop` and a short README |
| Windows x64 | `cite-desktop-<version>-windows-x86_64.zip` with `cite-desktop.exe` |

The builds are unsigned and not notarised. On macOS, Gatekeeper blocks the first launch: right-click `Cite.app` and choose Open. On Windows, SmartScreen warns about an unknown publisher: choose More info, then Run anyway. The Windows build is marked experimental in CI. On Linux, put `cite-desktop` on your `PATH` and copy `cite.desktop` to `~/.local/share/applications/`.

To build from source you need Rust 1.88 or newer:

```bash
cd apps/desktop
cargo build --release --locked
./target/release/cite-desktop
```

On Linux the build needs the development packages CI installs: `libxkbcommon-x11-dev`, `libxkbcommon-dev`, `libwayland-dev`, `libxcb1-dev`, `libfontconfig-dev`, `libasound2-dev`, `libssl-dev`, `libvulkan-dev`, `libdbus-1-dev`, `mesa-vulkan-drivers`, `pkg-config`, `cmake` and `clang`.

## Command line

```
cite-desktop [--demo] [--view <name>] [--node <name>]
```

| Flag | Effect |
|---|---|
| `--demo` | Runs against built-in sample data instead of real nodes, for trying the app. |
| `--view <name>` | Opens on a view: `overview`, `nodes`, `sites`, `site-detail`, `site-new`, `traffic`, `request-detail`, `bots`, `explore`, `export`, `firewall`, `maintenance` or `settings`. The default is `overview`. |
| `--node <name>` | Selects a node on start. |
| `-h`, `--help` | Prints the usage and exits. |

## Analytics page

Analytics in the sidebar is a filtered view of traffic, separate from the Traffic page. The filter bar picks the node (or all nodes, queried at the same time and merged), a time range (15m, 1h, 24h, 7d, 30d or a custom UTC range such as `2026-11-01 08:30`), sites, methods, status classes, bot classes, blocked or not, and text fields for host, path prefix, exact path, client IP or network (`10.0.0.0/8`), user agent, referer, content type, exact status and minimum duration. Every active filter is shown as a chip with a remove button. Nodes without the `analytics-filters` capability understand only a window and one site; the page then hides the other controls and says which nodes were limited.

The page shows headline tiles with the change against the previous equal-length period (a rise in errors or latency is red), requests, errors and blocked over time, bandwidth, status classes, methods, latency percentiles, top paths, hosts, referers, user agents, client IPs and statuses (click a row to filter by it), bot share and classes (click a class to filter), and a request log that loads fifty at a time per node with "Load more" and a detail panel. A "Partial result" banner appears when the node read only the newest part of a large range. Auto refresh runs every ten seconds while the page and the window are active and never overlaps a running load.

Saved filters are stored in the app's config file as a name and a plain `key=value&key=value` text; nothing secret is in them. Copy puts the text on the clipboard so a colleague can paste it under "Use pasted filter". Export saves CSV or NDJSON of requests or hourly totals to the Downloads folder through the existing export route. That route takes one site, one method, one bot class, a status range and a plain client address, so the page lists any filter it cannot apply before you export. The node offers no country breakdown, so there is none.

## Bot analytics and export

Traffic has four tabs that share the window picker. Requests lists recent requests with a bot class badge and score, and Details opens the captured headers and the signals behind the verdict. Bots shows the bot share, the split by class (human, suspect, crawler, tool, bot), the score distribution, the top signals and the top bot agents. Detection reads the headers first and then the user agent, and the score is a heuristic, not proof. Explore has a top-value explorer for any field and a Storage card with the analytics database size and the oldest and newest record on each node. A node that predates these endpoints shows as "needs an update" instead of failing the page.

Export streams a file from the node (requests, hourly rollups, the bot summary or a top list) as CSV or NDJSON, for the current window or a custom UTC range, with optional site, status, bot class, score, host, path, client IP, method and row limit filters. The app has no native save dialog, so the file goes to the `Downloads` folder under your home directory, named by the node, and an existing file is never replaced: a number is added to the name instead. With "All nodes" selected the export comes from the first node, as on the other single-node screens.

## Retention, backups and archives

Analytics history is kept forever by default. Settings has a "Keep data" choice: Forever, or "Delete data older than N days" with a limit from 1 to 3650. "Archive old data before deleting it" is on by default, and choosing a limit with archiving off shows a warning that the deleted data cannot be recovered.

The Explore tab has a Backups and archives card for the selected node (the first node when "All nodes" is selected). Back up now writes a copy of the analytics database on the node. Cut old data removes everything older than a number of days or a UTC date: Preview shows how many rows would go and the oldest date, and Cut stays disabled until a preview of exactly those settings has succeeded. With archiving on, the rows are written to an archive file before they are deleted. With it off, Cut also needs the "I understand this deletes data permanently" box and a confirmation dialog.

The list shows each file's name, kind, size, creation time, short SHA-256 and row count. Download saves the file into the `Downloads` folder, never replacing an existing file, with an extension chosen by the app from the file kind (`.db` for backups, `.ndjson.gz` or `.csv.gz` for archives) rather than taken from the node. Restore and Delete ask for confirmation first. A node that predates these endpoints shows as "needs an update".

## Creating a site

Create site is a step-by-step wizard with a step indicator, Back and Next. Next stays disabled, with the reason beside it, until the visible step is valid. The first step asks where the site comes from, with two cards: "Build from a GitHub repository" (the default) and "Serve servers I already run". Only the fields of the chosen card appear afterwards.

- Repository (GitHub): the repository, branch, runtime, Node version and poll interval, which are every field the node's source accepts.
  - The repository takes owner/name or a pasted address: `https://github.com/owner/name`, with or without `.git`, a trailing slash, `www.`, a port, a query or fragment, `git@github.com:owner/name.git`, `ssh://git@github.com/owner/name.git`, or a `/tree/<branch>` link (a button then offers that branch). It is shortened to owner/name for the node. Other schemes, credentials in the address, percent-encoded or non-ASCII characters, `..` segments and pages inside a repository (issues, blob, pull) are refused with a specific message. An address on a host other than github.com is accepted with the note "The node fetches from its configured GitHub API (github.com unless CITE_GITHUB_API_URL is set). Other git hosts are not supported yet."
  - The branch follows the node's git ref rules (up to 100 characters, no leading `-`, no `..`).
  - Runtime lists every value the node accepts with one line each: `node` (install, build and run a Node.js site, server-rendered or static), `bun` (built like a Node.js site, then run by Bun), `static` (serve the built files only) and `rust` (build and run a Rust crate).
  - The Node version (22 or 24) is shown for every runtime except `rust`, because the node builds with it even when Bun or the static server runs the site.
  - The poll interval is `off` or at least `1m` (for example `5m`, `1h`, `1d`); anything shorter is refused here as the node refuses it.
  - The node has no package manager, install command, build command, output directory or start command in a site's source. A note under the fields says that the node detects the package manager from your lockfile (npm, pnpm, yarn or bun) and the build from `package.json` scripts; to override them the node itself needs its `CITE_PACKAGE_MANAGER`, `CITE_INSTALL_COMMAND`, `CITE_BUILD_COMMAND`, `CITE_OUTPUT_DIR`, `CITE_RENDERING`, `CITE_FRAMEWORK` or `CITE_START_COMMAND` settings, which the app cannot set.
  - The site is sent with both slots empty and a source; the node builds the live slot itself. The GitHub token control depends on the chosen nodes: if every chosen node already has a token (`CITE_GITHUB_TOKEN`), the field is hidden behind "Use a different token for this site"; if none or only some has one, the field is shown and required, and the final step refuses to continue without it. A hidden field never sends a token. In demo mode the first node has a token and the second does not.
- Servers: blue and green targets with weights and the health check (path, interval, timeout, rise and fall). These fields, and the wording "at least one blue target", exist only on this path; a GitHub site never asks for upstreams.
- Domains: name, kind, id, hosts and the optional routing paths: as many path prefixes and path regexes as needed (a request is routed when it starts with any prefix or matches any regex), each checked with the node's rules, with a sample path to test. The site page edits the same lists in its General card.
- Protection: the Access card described below.
- Place and review: the nodes, and a summary of every choice made.

## Certificates and Access

Settings has a Certificates card for the selected node (the first node when "All nodes" is selected). It lists each certificate with its subject, issuer, validity dates, key type, short SHA-256 fingerprint, the number of names it carries and the site hosts it covers. The days left show as a chip: muted above 30 days, yellow under 30, red under 7 and once expired. A note lists site hosts that no certificate covers, other than sites set to Flexible, which need none. When the node has no HTTPS port, the card says so and offers an inline port field with Enable HTTPS; until a port is set the node stores certificates but serves nothing over TLS. If the node reports its certificate directory as not ready, Upload is turned off.

Upload and Replace share one panel with a name and either pasted PEM text or the paths of two files, one for the certificate chain and one for the private key. The certificate and key together are capped at 100 KiB, files must be regular files, names use letters, digits, spaces, dots, dashes and underscores and start with a letter or a digit, and the app checks the PEM markers before sending: a swapped pair, an encrypted key or a cut-off block is refused with a message. Files are read on a background task. The private key is hidden while you paste it, sent once in the request, never written to the config file or logged, and cleared from its input as soon as the request is sent, and from every input when the upload succeeds, the panel closes, you switch between pasting and files, you change the selected node or you leave Settings. A panel opened for one node refuses to send anything if another node is selected when you submit. The app zeroes the copies it makes of the key itself: the form copy, the file read buffer (also when the read fails or the file is not text), the text before and after line-ending normalisation, the upload plan and the request when it is dropped. It does not zero what it cannot reach: the text typed or pasted into the input box (emptying the box frees that text without overwriting it), the clipboard, the HTTP client's internal buffers and the allocator's freed memory. Errors from the node are shown as received. Replace asks for the key again. Delete asks for confirmation and names the hosts that would lose coverage. Certificates a person placed directly in the node's certificate directory are listed with the note "Placed by hand on the node: read-only"; the node refuses to change them through the API, so Replace and Delete are not offered for them. Any warning the node reports for a certificate appears under it. A node that predates certificate management shows as "needs an update".

The Cloudflare ranges card shows whether the node uses its built-in list or a custom one, the date of that list and the ranges themselves in an editor with one CIDR range per line. Save ranges checks every line before sending (bare addresses are accepted; a prefix of `/0` is refused because it would trust every address). Use built-in list clears the custom list.

On the Protection step of the create wizard and on the site page, an Access card has an "Only allow traffic through the Cloudflare proxy" checkbox and an HTTPS choice. The checkbox means requests that do not arrive from Cloudflare's network are refused; turn it on only for sites proxied by Cloudflare (orange cloud). It is not assumed for every site. The HTTPS choice is "Full (the node serves its own certificate)", which needs a certificate that covers the host, or "Flexible SSL (Cloudflare serves HTTPS to visitors and talks to your server over plain http)", which needs none on the node but leaves traffic between Cloudflare and your server unencrypted. Flexible SSL does not require the proxy option, but without it anyone can reach your server directly over plain http, and the form warns about that. The site page saves the whole site through the normal update, so a node that does not know these fields shows its own error instead of the change being hidden.

The Access card also has a Bots choice and the zone lock. Bots is Allow all, Block scrapers and tools, or Block all bots. Block all bots also refuses search engines, so the card warns about the SEO cost. Bots are recognised by their User-Agent header, which a scraper can fake, so this is not a security boundary, and blocked requests still show up in analytics. "Also require that requests come from MY Cloudflare account (advanced)" is available only while the proxy option is on and is optional: without it, anyone using Cloudflare could send traffic to your server address. With it, the node refuses requests that lack a secret header set once in a Cloudflare Transform Rule in your own account. The proxy option alone never mentions a Transform Rule, a secret or a header.

When the zone lock is switched on and saved (on the create form, for every node that took the site, or on the site page), the app asks the node for a fresh secret and shows it once in a panel with its header name (`X-Cite-Origin-Secret`), the Cloudflare steps (Rules, Transform Rules, Modify Request Header, Set static), a Copy button and a warning that it is not shown again. The panel disappears when you press "I have saved it" or leave the site page, and the app zeroes the copy it stored. That is all that is wiped: the text drawn on screen, the system clipboard after Copy, the node's response buffer and any copies made by the text renderer or the allocator are outside the app's control and are not overwritten. If the node reports that its secret store could not be read, the card says the lock state is unknown instead of claiming that no secret exists. Otherwise the card shows only whether a secret exists, when it was created and a short fingerprint. Rotate zone secret on the site page asks for confirmation first, because the old secret stops working at once and Cloudflare requests get a 403 until the Transform Rule has the new value. The copy button puts the secret on the system clipboard, which the app cannot clear for you.

## Editing a site

The site page shows the same form sections as the wizard, filled from the node: General (kind, name, hosts, routing paths; the id is shown but cannot change), Source (for sites built from GitHub: repository, branch, runtime, Node version, poll interval), Health check (path, interval, timeout, rise, fall) and Access. Each field is checked with the node's own rules as you type, and one Save sends the whole site through the normal update. The stored GitHub token is never sent and never shown; the node keeps it. A "Unsaved changes" chip and Discard changes appear while the form differs from the node, and a reload (for example after a failed save) keeps your edits.

The node stores source settings on Save but only builds them on a deploy. When the repository, branch, runtime, Node version or poll interval changed, a second button, Save and redeploy, saves and then starts a deploy so the change takes effect; the line under the buttons says so. Routing, hosts, paths, health check and access apply as soon as they are saved. A source-built site is redeployed with its own "Redeploy from GitHub" card, which takes only a note; the client library always sends a target list, so the app sends a placeholder that the node ignores for source-built sites.

The node ignores the blue and green target lists in a site update (they only change through a deploy), so for a server site the targets are edited in the "Deploy new version" card, not in the form.

## Status, logs and build settings (nodes 0.4.0 and newer)

A node lists what it can do in `GET /node` (`capabilities`), and the site page shows a card only when the node has the matching capability, so older nodes keep the pages they had. For a source-built site:

- Status (`site-status`): the phase (fetching, building, packing, promoting, idle, failed, unhealthy), a red box with the reason and a Copy button, a "Pending changes" chip when saved settings are not in the running build, a Redeploy button, and a table with one row per slot (container, health, restarts, exit code or out of memory, manager phase, live and head commit, HAProxy state). While a build runs the card refreshes every three seconds.
- Build settings (`source-build`): root directory, package manager, install and build commands, output directory, rendering (static or ssr), framework, start command, single-page fallback, prune, and the resource limits (serving and build memory in MiB and CPUs; the node defaults are 2 GiB and 2 CPUs for serving and 4 GiB and 2 CPUs for builds). A blank field means "let the node decide", and the hint reads "Auto (detected: X)" when a manager has detected a value. With `forges` the node's forge host is shown read-only. Saving a change the running build does not have asks "This change needs a rebuild" with Redeploy now or Later; resource changes apply on the next redeploy.
- GitHub token (`site-github-token`): where the token comes from (site, node or none), whether the node has one, verification and expiry, Set or Change token (write-only, wiped after sending) and Use the node token.
- Build and runtime environment (`site-build-env`, `site-runtime-env`): the variable names, Remove, and a Name and Value form. Values are never shown again and are wiped from the form after sending.
- Builds (`site-status`, `deploy-async`): the last build each manager reports (commit, result, reason) and a "Deploy this commit" box that starts a build of a branch, tag or commit without waiting.
- Logs (`site-logs`): manager or executor, blue or green, Follow (polls every two seconds with the node's cursor, only while the site page is on screen and the window is active), search, Copy, colour by level, ANSI codes removed, newest first, the last 5000 lines kept.
- Bot policy: under the Access card, "No bot blocking is active for this site" appears when the policy is Allow and no enabled firewall rule matches user agents; otherwise the rules that could block bots are listed.

The Sites list reads health with one HAProxy stats call per node and shows rows first, and the loaders of the overview, traffic and site pages run their independent requests together.

## Failed deploys and unhealthy sites

When the newest deployment entry is a failure, or the active slot has a target that is down, a red banner at the top of the site page shows: the newest failure's time, slot and the node's note in full with a Copy button; the state of each slot and each target as HAProxy reports it; a "What to check" list; and, for sites built from GitHub, the commands to read the logs on the node, each with a Copy button. The node has no log endpoint and reports only a status per target, not why a probe failed, so the banner says so and gives `docker logs --tail 200 cite-<site>-<slot>-manager` (clone, install and build output) and `docker logs --tail 200 cite-<site>-<slot>-executor` (the running site), with the names the node's orchestrator gives its containers. A later successful deploy clears the banner. Error toasts stay on screen until you click them away or start the next action, and failed saves and deploys show the node's message in full on the page.

Actions that finish after you have moved to another node, site or page never change the page you are on: the result appears as a toast that names where it happened, for example "Deploy on shop (edge-fra): ...". A zone secret or a new API token that arrives that way is kept under its own node (and site) and shown only on that page, so the site page of another node never displays it; a notice points to it, and a site page lists the other nodes that still hold a new secret for the same site.

## Firewall rules

Add rule has three kinds. Block keeps the Deny, Drop silently and Tarpit actions. Redirect sends matching requests to a target, either an absolute http or https URL or a path starting with `/`, with the placeholders `{scheme}`, `{host}`, `{www_host}`, `{apex_host}`, `{path}` and `{query}` and a status of 301, 302, 307 or 308; example buttons fill in common targets. Headers and CORS lets matching requests through while setting, adding or removing request or response headers (up to 16 changes, proxy-managed and identity headers are refused by the node) and optionally answering CORS with up to 32 origins, methods and headers, a max age up to 86400 seconds and credentials. The form refuses the origin `*` together with credentials before anything is sent, and the connector's own validation runs on the finished rule, so what the form accepts is what the node accepts.

Each matcher takes several values: values of one matcher are alternatives (any one may match) and different matchers must all match, as the node evaluates them. Path prefixes, methods, hosts and CIDR ranges are separated by commas or spaces; regexes (path, user agent, referer) are separated by spaces only, because a comma is valid inside a regex. Every value is checked with the node's own rules (at most 16 values per matcher, 256 characters each, the regex subset in the firewall guide). Besides the path, method, user agent, CIDR and host matchers there are a header matcher (a name compared by equality or by regex, optionally negated), a scheme matcher (HTTP or HTTPS) and a referer regex. A header value can be marked secret: it is hidden while you type, sent to the node, and never shown in the rule list, which prints `(hidden)` instead, or kept in the form after saving. A rule can be limited to one site by its id and given a label that appears in logs. The list shows each rule's effect (the action, `Redirect 301`, `Headers`, `CORS`), the redirect target or header and CORS summary, and the label. The presets come from the node and now include Redirect to www, Redirect to the bare domain and Force HTTPS; a preset is added node-wide, so for a redirect that should affect one site use Add rule with a site id instead.

## Adding a node

Open Nodes and fill in a name, the connector URL and, when the node uses the CA from `init`, the CA certificate. The CA field takes either the PEM text or the path of a PEM file, for example the `cite-ca.pem` that `scripts/setup.sh` copies into its install directory. Compare the fingerprint printed by `init` before trusting it.

For credentials you can paste an API token, or switch to username login and enter the username, password and a TOTP code. With a login, the app signs in, creates an API token named `desktop-<hostname>`, signs the session out again and keeps only the token.

The URL must be a bare origin such as `https://edge.example.com:7443`, with no path, query or credentials. Plain `http://` is accepted only for loopback hosts. The node name is lowercase letters, digits and `-`, up to 40 characters.

## Where things are stored

| What | Where |
|---|---|
| Node list (name, URL, CA) | `~/Library/Application Support/Cite/desktop.json` on macOS. Elsewhere `$XDG_CONFIG_HOME/cite/desktop.json`, or `~/.config/cite/desktop.json` when that variable is unset or not absolute. Mode 0600. |
| API tokens | The operating system keychain, under the service `dev.seggys116.cite`, with the node name as the account. |

The config file never contains a token, and the app refuses a config file with unknown fields. When a node is added the token goes to the keychain first, and the keychain entry is removed again if the config cannot be saved.

Removing a node in the app removes it from the config and the keychain. It does not revoke the API token on the node. The connector only lets a login session revoke tokens (`DELETE /api/v1/tokens/{id}`), not an API token, so revoke it from a signed-in session such as the web dashboard's Settings page.

## Behaviour worth knowing

The Traffic view refreshes every 3 seconds. The window opens at 1320 by 840 points. Cmd-Q quits.

The app enforces nothing the connector does not. Allowlists, TLS, token checks and validation all happen on the node, as described in the [security model](security-model.md). A desktop machine that holds tokens for several nodes is as sensitive as the dashboard server: anyone who can read its keychain can act on those nodes.

See [Connector API](node-api.md) for the routes the app calls.
