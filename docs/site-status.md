# Site status, logs and build settings

This is the guide to everything that shows what a built site is doing and lets you change how it is built: the Status panel, the log viewer, build settings, environment variables, the per-site GitHub token, certificates and alerts. It applies to sites the node builds from a git repository, so the [orchestrator](orchestrator.md) must be enabled. The same functions are available in the [desktop app](desktop.md) and through the [Connector API](node-api.md).

## The Status panel

Every orchestrated site has a Status panel that reports what the site's manager is doing right now.

| Phase | Meaning |
|---|---|
| `fetching` | The manager is asking the git host for the newest commit and downloading it. |
| `building` | Dependencies are being installed and the build command is running. |
| `packing` | The build output is being checked and packed into a release. |
| `promoting` | The new release is being switched in. For a deploy to the idle slot, the slot is only promoted after the release it just built is ready. |
| `idle` | The site is built and waiting for the next commit or deploy. |
| `failed` | The last attempt did not finish. The panel shows the reason. |

The panel also shows the commit being built or served, when the phase last changed and which slot (blue or green) is live.

### How failures show up

A failed build never replaces the live site. The old release keeps serving, the phase becomes `failed`, and the reason is shown in three places:

- the Status panel (and `GET /sites/{id}/status`);
- the log viewer, which holds the full output of the failing step;
- the deployment history, where the failed attempt is recorded with the reason in its note.

A later successful build clears the failure. Fixing the cause (a build command, an environment variable, a token) and redeploying is the normal way out; see [Troubleshooting](#troubleshooting-by-status-message) below.

## The log viewer

The log viewer reads the logs of the site's containers.

- **Manager** logs show fetching, installing, building and promoting, including your build command's output. Start here for any build failure.
- **Executor** logs show what the running site prints, including start-up errors of a server-rendered site.
- **Tail** sets how many of the most recent lines to load (1 to 1000).
- **Follow** keeps the view updating while you watch a deploy.

### Redaction

Before logs are shown, the node masks the site's secrets: its GitHub token, build and runtime environment variable values and the zone secret. Masking only catches the exact value, and only values of 4 or more characters. A secret that a script prints in another form (base64, URL-encoded, split over lines, a substring) is not masked, and a value shorter than 4 characters is never masked. Do not print secrets in build scripts, and do not run `env` or `set -x` in a build that has secret variables.

## Build settings

Build settings control how the manager turns the repository into a site. The app detects defaults from the repository and shows them next to every field. Every default can be overridden, and clearing an override returns to the detected value.

| Setting | What it does |
|---|---|
| Package manager | `npm`, `pnpm`, `yarn` or `bun`. Detected from the lock file. |
| Install command | Replaces the default install step. |
| Build command | Replaces the default build step (`build` script of `package.json`). |
| Output directory | The folder the build writes, for example `dist`, `build` or `out`. |
| Rendering | `static` serves the output directory as files. `ssr` runs a server. |
| Start command | For `ssr` only: the command that starts the server. It is split into words, runs without a shell and cannot contain pipes, `;`, `&`, redirects or substitution. |
| Root directory | A subfolder of the repository to build, for a monorepo. |
| Node version | `22` or `24`. |
| SPA fallback | The file served for unknown paths, usually `index.html`, so client-side routing works on reload. |
| Framework | A preset name that selects sensible defaults. |
| Prune | Remove development dependencies after the build for an `ssr` site, to keep the release small. |

Install and build commands run through `sh -c` inside the sandboxed build helper, so shell syntax such as `&&` is allowed there.

## Environment variables

There are two sets, and neither is ever written to the routing config or to container labels.

- **Build environment variables** are visible to the install and build commands, for values like a public API URL baked into a static bundle.
- **Runtime environment variables** are given to the running `ssr` site.

After you save, the app and API show variable names only. To change a value, enter it again; leave a name alone to keep its stored value. Changes apply on the next deploy, so use Save and redeploy (below) to apply them now. Remember that anything a static build bakes into the output is public.

## The per-site GitHub token

A site uses its own token if you set one, otherwise the node's `CITE_GITHUB_TOKEN`. The panel shows which one is in use (`site` or `node`) and never the token itself.

- **Set or change**: the node tests the new token against the git host before storing it. If the host rejects it, the previous token stays and you see an invalid-token error.
- **Remove**: the site falls back to the node token. If the node has none, removal is refused.

Use a fine-grained, read-only token for the single repository.

## Save and Save-and-redeploy

Editing a site in the app asks every time you save: **Save** stores the change and applies it on the next build, **Save and redeploy** stores it and immediately deploys. Routing changes (hosts, firewall) apply at once either way; build settings, environment variables and the token only take effect when a build runs.

## Redeploy, history and rollback

- **Redeploy** builds the latest commit (or a branch or tag you give) into the idle slot and promotes it only when the build succeeded. A failed deploy leaves the live slot untouched.
- **History** lists every promote, rollback and failed attempt, with the note and, for failures, the reason.
- **Rollback** switches back to the previous slot. The slot is restarted on the ref it was built from.

## Certificates

The node serves HTTPS on port 443 for the hosts of its sites.

- **Automatic self-signed**: the node creates a self-signed certificate on its own. This is enough for Cloudflare in Full mode, which does not verify the origin certificate.
- **Create a certificate for me**: generates a new self-signed certificate for the selected hosts on demand.
- **Cloudflare Origin CA**: the node asks Cloudflare to issue an origin certificate for the hosts, using an Origin CA key. Browsers do not trust it directly, so it is for Cloudflare in Full (strict) mode only.
- **Let's Encrypt via Cloudflare DNS**: the node proves ownership with a DNS record at Cloudflare and gets a publicly trusted certificate. It works for hosts that are not reachable from the internet on port 80 and for wildcard names. The Cloudflare token is stored on the node (`secrets.json`, mode 0600) so renewals run unattended; scope it to DNS edit for the one zone.

### Cloudflare modes

| Cloudflare mode | Cloudflare to node | Certificate needed on the node |
|---|---|---|
| Flexible | `http` on port 80 | None. |
| Full | `https` on port 443 | The automatic self-signed certificate works. |
| Full (strict) | `https` on port 443, certificate verified | An Origin CA or Let's Encrypt certificate. |

See [HTTPS in front](https.md) for more on putting Cloudflare in front.

## Alerts

The node can tell you when something needs attention.

- **Channels**: a Discord webhook, a Slack webhook, a generic JSON webhook, or email.
- **Events**: choose which to send, for example a failed build, a site going down or recovering, and a certificate nearing expiry.
- **Cooldown**: the minimum time between repeated alerts for the same event and site, so a flapping site does not flood you.
- **Test**: sends a sample message to the configured channels so you can check them before you need them.

Webhook URLs are secrets: they are masked when read back, and the node refuses destinations that resolve to private or internal addresses.

## Other git hosts

GitHub is the default. A node operator can point the node at GitLab or Gitea by setting `CITE_FORGE` and `CITE_FORGE_API_URL` on the node; sites then build from that host with the same token and status behaviour. The setup and limits are in [forges](forges.md).

## Troubleshooting by status message

| Message in the Status panel or history | Likely cause | What to do |
|---|---|---|
| `failed` with the build command's own output | The install or build command exited non-zero. | Open the manager logs, fix the command or the code, then redeploy. A `build_command` override on the site is applied on the next deploy. |
| Invalid token, bad credentials or 401 from the host | The site or node token is wrong, revoked or expired. | Set a new per-site token, or remove it to use the node token. |
| Repository not found or 404 | The repo name or branch is wrong, or the token has no access to it. | Check `owner/name`, the branch and the token's repository access. |
| Rate limited | The host throttled the node. | Wait; lengthen the poll interval. |
| Output directory not found or empty | The build did not write the folder named in Output directory. | Set the correct output directory, or fix the build. |
| Release too large or too many files | The output exceeds the size or file limits. | Build less into the output folder; turn on Prune for `ssr`. |
| Start command refused | It contains shell syntax or begins with a package manager. | Use a plain command such as `node server.js`. |
| Site shows `idle` but serves the old version | No deploy ran since the change. | Use Save and redeploy, or redeploy. |
| Log text shows `***` in place of a value | The redactor masked a stored secret. | Expected. Do not rely on printing secrets in logs. |

## API summary

All routes are under `/api/v1` and need the bearer token. Bodies and replies are JSON unless noted. Full request and reply shapes are in [Connector API](node-api.md).

| Route | Purpose |
|---|---|
| `GET /sites/{id}/status` | Current phase, reason, commit and slot. |
| `GET /sites/{id}/logs` | Recent logs of the site's manager or executor; `tail` limits the lines. |
| `GET`, `PUT`, `DELETE /sites/{id}/github-token` | Read which token is in use, set or change the per-site token, remove it. |
| `GET`, `PATCH /sites/{id}/build-env` | List build variable names, set or remove variables. |
| `GET`, `PATCH /sites/{id}/runtime-env` | The same for runtime variables. |
| `POST /sites/{id}/deploy` | Deploy a ref to the idle slot. `wait` makes the call return when the deploy finishes. |
| `POST /certificates/generate` | Create a self-signed certificate. |
| `POST /certificates/origin-ca` | Issue a Cloudflare Origin CA certificate. |
| `POST /certificates/acme` | Issue a Let's Encrypt certificate through Cloudflare DNS. |
| `GET /certificates/acme` | State of the Let's Encrypt setup and renewals. |
| `GET`, `PUT /alerts` | Read or replace the alert settings. |
| `POST /alerts/test` | Send a test alert. |
| `GET /node` | Node status, including its `capabilities`, so a client can tell which of these features the node supports. |
