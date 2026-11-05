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
