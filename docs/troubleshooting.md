# Troubleshooting

## `docker compose config` fails

- Ensure `.env` exists (`cp .env.example .env`) with `CITE_REPO=owner/name` and `CITE_GITHUB_TOKEN` set; Compose refuses to render without both.
- Upgrade to Engine **26+** and Compose **v2.26+** if `volume.subpath` or an optional `env_file` is rejected.

## Site returns 503

Executor starts without a release and serves 503 until the first successful deploy. Check:

```bash
docker compose logs manager --tail=200
docker compose exec manager cite status
```

## Deploy never starts

- PAT scopes / repo visibility, and that `CITE_GITHUB_TOKEN` is set in `.env` (`docker compose up -d` again after editing it)
- `CITE_GITHUB_API_URL` if using a mock
- Rate limits / 401s in manager logs (token redacted)

## Build fails, old site stays up

Expected: failed builds do not evict the live slot. Inspect `last_failed_sha`, `last_failed_phase` and `last_failed_reason` via `cite status`.

A failure reason starts with one line naming the step and the exact command, for example `install failed: exit status 1 (pnpm install --frozen-lockfile)` or `build failed: exit status 1 (pnpm run build)`, followed by the last 40 lines the command printed (stdout and stderr together, ANSI colours removed, each line cut at 300 characters, the token and build variable values masked). The same text is the deploy's failure note on the node and in the apps. The step is one of `fetch`, `install`, `build` (including the production prune and missing build output), `pack` and `start`. Common causes:

- `install failed` with a frozen-lockfile error: the lockfile does not match `package.json`, or Corepack ran a different pnpm or Yarn than the one that wrote it. Pin it with `"packageManager": "pnpm@<version>"` in `package.json`.
- `build failed` with `Cannot find module`: a package the build needs is missing from `package.json`.
- `static output_dir missing`: the build wrote somewhere else; set `CITE_OUTPUT_DIR`.
- `SSR start target missing`: the build did not write the server file, or the production prune removed a dev dependency it needs; move the package to `dependencies` or set `CITE_PRUNE=false`.

## Reading a site's status

The manager container prints one line of compact JSON from its Docker healthcheck, so `docker inspect --format '{{json .State.Health.Log}}' <manager>` shows the latest report in each entry's `Output`. The line is at most 3500 bytes (Docker keeps 4096). When it would be longer, `last_error` is cut first (its first line and its last lines are kept with a `...` line between), then `detected`, then optional fields are dropped. The exit code is unchanged: healthy whenever the manager answers its control socket.

| Field | Meaning |
|---|---|
| `v` | Report version, currently `1` |
| `phase` | `fetching`, `building`, `packing`, `promoting`, `idle` or `failed` (see below) |
| `since` | When the manager entered `phase` |
| `sha` | Commit being handled; absent when `idle` |
| `deploy` | `id`, `result` (`live` or `failed`) and, for a failure, `phase` of the last attempt started by `CITE_DEPLOY_ID` |
| `head_sha` | Newest branch head the manager has seen |
| `live_sha` | Commit currently deployed |
| `last_build_secs` | Duration of the last attempt since the manager started |
| `last_failed_sha` | Commit that failed and is not retried |
| `last_error` | Why the last attempt failed: the step and command, then the command's last output lines, with the token and build variable values masked |
| `failed_phase` | The step `last_error` comes from: `fetch`, `install`, `build`, `pack` or `start` |
| `token` | `ok`, `invalid`, or `unknown` before GitHub has answered |
| `token_expires_at` | Token expiry when GitHub reports one |
| `detected` | What the build uses: `framework`, `package_manager`, `rendering`, `node`, `install_command`, `build_command`, `output_dir` (static) or `start` (SSR), `confidence` (`high`, `medium`, `low`) and `notes` on anything detection assumed |
| `executor` | `active` slot and the `blue` and `green` slot states from `status/executor.json` |

Phases: `fetching` downloads the source for the commit; `building` extracts it and runs install and build; `packing` seals the output into a release; `promoting` starts it in the free slot and runs the health gate; `idle` means nothing is running and the last attempt succeeded or none ran; `failed` means the last attempt failed and `last_error` says why. `detected` stays after the attempt ends so a failure shows which commands ran.

## Health gate fails

Candidate never goes live; previous remains. The failure reason starts with `start failed:` and says what happened, followed by the server's last output lines:

- `the server process exited with code 1 before it listened on port N`: the server crashed at startup; its own error is in the lines below (a missing module, a missing environment variable, a database it cannot reach).
- `the server process did not answer / on port N with a status below 500 within 60s`: the server must listen on the `PORT` it is given (and `127.0.0.1` or all interfaces); a port hard-coded in the code or a `-p` flag in a custom start command breaks this. A slow start needs a longer `CITE_HEALTH_TIMEOUT`, and a server whose `/` fails needs `CITE_HEALTH_PATH`.
- `the server process could not be started`: the start file or interpreter is missing; for `bun` start commands set `CITE_RUNTIME=bun`.

`status/executor.json` `last_result` holds the same reason and the log tail.

## Cannot `docker exec` a shell into executor

Expected: the image is shell-less. Use `cite status` / Compose logs instead.

## Executor needs outbound HTTP

Default egress is denied. Attach the override:

```bash
docker compose -f docker-compose.yml -f docker-compose.egress.yml up -d
```

## Manager has no published ports

Expected. Operate with `docker compose exec manager cite …`.

## Subpath mount / empty releases

Engine must support volume subpaths. Confirm with `docker compose config`, Engine 26+ and Compose v2.26+.

## Site env vars missing in the build or SSR process

Put build-time variables in `build.env` and runtime variables in `runtime.env` next to `docker-compose.yml`, then `docker compose up -d`. Variables prefixed `CITE_` and host variables (`PATH`, `HOME`, ...) are not forwarded. See [config.md](config.md).

## Reset local data

```bash
docker compose down -v
docker compose up -d
```
