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

## Bot analytics and export

Traffic has four tabs that share the window picker. Requests lists recent requests with a bot class badge and score, and Details opens the captured headers and the signals behind the verdict. Bots shows the bot share, the split by class (human, suspect, crawler, tool, bot), the score distribution, the top signals and the top bot agents. Detection reads the headers first and then the user agent, and the score is a heuristic, not proof. Explore has a top-value explorer for any field and a Storage card with the analytics database size and the oldest and newest record on each node. A node that predates these endpoints shows as "needs an update" instead of failing the page.

Export streams a file from the node (requests, hourly rollups, the bot summary or a top list) as CSV or NDJSON, for the current window or a custom UTC range, with optional site, status, bot class, score, host, path, client IP, method and row limit filters. The app has no native save dialog, so the file goes to the `Downloads` folder under your home directory, named by the node, and an existing file is never replaced: a number is added to the name instead. With "All nodes" selected the export comes from the first node, as on the other single-node screens.

## Retention, backups and archives

Analytics history is kept forever by default. Settings has a "Keep data" choice: Forever, or "Delete data older than N days" with a limit from 1 to 3650. "Archive old data before deleting it" is on by default, and choosing a limit with archiving off shows a warning that the deleted data cannot be recovered.

The Explore tab has a Backups and archives card for the selected node (the first node when "All nodes" is selected). Back up now writes a copy of the analytics database on the node. Cut old data removes everything older than a number of days or a UTC date: Preview shows how many rows would go and the oldest date, and Cut stays disabled until a preview of exactly those settings has succeeded. With archiving on, the rows are written to an archive file before they are deleted. With it off, Cut also needs the "I understand this deletes data permanently" box and a confirmation dialog.

The list shows each file's name, kind, size, creation time, short SHA-256 and row count. Download saves the file into the `Downloads` folder, never replacing an existing file, with an extension chosen by the app from the file kind (`.db` for backups, `.ndjson.gz` or `.csv.gz` for archives) rather than taken from the node. Restore and Delete ask for confirmation first. A node that predates these endpoints shows as "needs an update".

## Certificates and Access

Settings has a Certificates card for the selected node (the first node when "All nodes" is selected). It lists each certificate with its subject, issuer, validity dates, key type, short SHA-256 fingerprint, the number of names it carries and the site hosts it covers. The days left show as a chip: muted above 30 days, yellow under 30, red under 7 and once expired. A note lists site hosts that no certificate covers, other than sites set to Flexible, which need none. When the node has no HTTPS port, the card says so and offers an inline port field with Enable HTTPS; until a port is set the node stores certificates but serves nothing over TLS. If the node reports its certificate directory as not ready, Upload is turned off.

Upload and Replace share one panel with a name and either pasted PEM text or the paths of two files, one for the certificate chain and one for the private key. The certificate and key together are capped at 100 KiB, files must be regular files, names use letters, digits, spaces, dots, dashes and underscores and start with a letter or a digit, and the app checks the PEM markers before sending: a swapped pair, an encrypted key or a cut-off block is refused with a message. Files are read on a background task. The private key is hidden while you paste it, sent once in the request, never written to the config file or logged, and cleared from its input as soon as the request is sent, and from every input when the upload succeeds, the panel closes, you switch between pasting and files, you change the selected node or you leave Settings. A panel opened for one node refuses to send anything if another node is selected when you submit. The app zeroes the copies it makes of the key itself: the form copy, the file read buffer (also when the read fails or the file is not text), the text before and after line-ending normalisation, the upload plan and the request when it is dropped. It does not zero what it cannot reach: the text typed or pasted into the input box (emptying the box frees that text without overwriting it), the clipboard, the HTTP client's internal buffers and the allocator's freed memory. Errors from the node are shown as received. Replace asks for the key again. Delete asks for confirmation and names the hosts that would lose coverage. Certificates a person placed directly in the node's certificate directory are listed with the note "Placed by hand on the node: read-only"; the node refuses to change them through the API, so Replace and Delete are not offered for them. Any warning the node reports for a certificate appears under it. A node that predates certificate management shows as "needs an update".

The Cloudflare ranges card shows whether the node uses its built-in list or a custom one, the date of that list and the ranges themselves in an editor with one CIDR range per line. Save ranges checks every line before sending (bare addresses are accepted; a prefix of `/0` is refused because it would trust every address). Use built-in list clears the custom list.

On the Sites create form and on the site page, an Access card has an "Only accept traffic from Cloudflare" checkbox and an SSL mode, Full or Flexible. With Full, Cloudflare and visitors reach the node over HTTPS and a certificate must cover the host. With Flexible, Cloudflare terminates HTTPS and talks plain HTTP to the node, so no certificate is needed; use it only together with "Only accept traffic from Cloudflare", and the form shows a warning when Flexible is chosen without it. The site page saves the whole site through the normal update, so a node that does not know these fields shows its own error instead of the change being hidden.

The Access card also has a Bots choice and the zone lock. Bots is Allow all, Block scrapers and tools, or Block all bots. Block all bots also refuses search engines, so the card warns about the SEO cost. Bots are recognised by their User-Agent header, which a scraper can fake, so this is not a security boundary, and blocked requests still show up in analytics. "Only my Cloudflare zone" is available only while "Only accept traffic from Cloudflare" is on: the node then refuses requests that lack a secret header set by a Transform Rule in your own Cloudflare zone, because all Cloudflare customers share the same edge addresses.

When the zone lock is switched on and saved (on the create form, for every node that took the site, or on the site page), the app asks the node for a fresh secret and shows it once in a panel with its header name (`X-Cite-Origin-Secret`), the Cloudflare steps (Rules, Transform Rules, Modify Request Header, Set static), a Copy button and a warning that it is not shown again. The panel disappears when you press "I have saved it" or leave the site page, and the app zeroes the copy it stored. That is all that is wiped: the text drawn on screen, the system clipboard after Copy, the node's response buffer and any copies made by the text renderer or the allocator are outside the app's control and are not overwritten. If the node reports that its secret store could not be read, the card says the lock state is unknown instead of claiming that no secret exists. Otherwise the card shows only whether a secret exists, when it was created and a short fingerprint. Rotate zone secret on the site page asks for confirmation first, because the old secret stops working at once and Cloudflare requests get a 403 until the Transform Rule has the new value. The copy button puts the secret on the system clipboard, which the app cannot clear for you.

Actions that finish after you have moved to another node, site or page never change the page you are on: the result appears as a toast that names where it happened, for example "Deploy on shop (edge-fra): ...". A zone secret or a new API token that arrives that way is kept under its own node (and site) and shown only on that page, so the site page of another node never displays it; a notice points to it, and a site page lists the other nodes that still hold a new secret for the same site.

## Firewall rules

Add rule has three kinds. Block keeps the Deny, Drop silently and Tarpit actions. Redirect sends matching requests to a target, either an absolute http or https URL or a path starting with `/`, with the placeholders `{scheme}`, `{host}`, `{www_host}`, `{apex_host}`, `{path}` and `{query}` and a status of 301, 302, 307 or 308; example buttons fill in common targets. Headers and CORS lets matching requests through while setting, adding or removing request or response headers (up to 16 changes, proxy-managed and identity headers are refused by the node) and optionally answering CORS with up to 32 origins, methods and headers, a max age up to 86400 seconds and credentials. The form refuses the origin `*` together with credentials before anything is sent, and the connector's own validation runs on the finished rule, so what the form accepts is what the node accepts.

Besides the existing path, method, user agent, CIDR and host matchers there are a header matcher (a name compared by equality or by regex, optionally negated), a scheme matcher (HTTP or HTTPS) and a referer regex. A header value can be marked secret: it is hidden while you type, sent to the node, and never shown in the rule list, which prints `(hidden)` instead, or kept in the form after saving. A rule can be limited to one site by its id and given a label that appears in logs. The list shows each rule's effect (the action, `Redirect 301`, `Headers`, `CORS`), the redirect target or header and CORS summary, and the label. The presets come from the node and now include Redirect to www, Redirect to the bare domain and Force HTTPS; a preset is added node-wide, so for a redirect that should affect one site use Add rule with a site id instead.

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
