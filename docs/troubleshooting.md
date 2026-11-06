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

Expected: failed builds do not evict the live slot. Inspect `last_failed_sha` via `cite status`.

## Reading a site's status

The manager container prints one line of compact JSON from its Docker healthcheck, so `docker inspect --format '{{json .State.Health.Log}}' <manager>` shows the latest report in each entry's `Output`. The line is at most 3500 bytes (Docker keeps 4096). When it would be longer, `last_error` is cut first (the start and the end are kept with `...` between), then `detected`, then optional fields are dropped. The exit code is unchanged: healthy whenever the manager answers its control socket.

| Field | Meaning |
|---|---|
| `v` | Report version, currently `1` |
| `phase` | `fetching`, `building`, `packing`, `promoting`, `idle` or `failed` (see below) |
| `since` | When the manager entered `phase` |
| `sha` | Commit being handled; absent when `idle` |
| `deploy` | `id` and `result` (`live` or `failed`) of the last attempt started by `CITE_DEPLOY_ID` |
| `head_sha` | Newest branch head the manager has seen |
| `live_sha` | Commit currently deployed |
| `last_build_secs` | Duration of the last attempt since the manager started |
| `last_failed_sha` | Commit that failed and is not retried |
| `last_error` | Why the last attempt failed, with the token and build variable values masked |
| `token` | `ok`, `invalid`, or `unknown` before GitHub has answered |
| `token_expires_at` | Token expiry when GitHub reports one |
| `detected` | What the build uses: `framework`, `package_manager`, `rendering`, `node`, `install_command`, `build_command` |
| `executor` | `active` slot and the `blue` and `green` slot states from `status/executor.json` |

Phases: `fetching` downloads the source for the commit; `building` extracts it and runs install and build; `packing` seals the output into a release; `promoting` starts it in the free slot and runs the health gate; `idle` means nothing is running and the last attempt succeeded or none ran; `failed` means the last attempt failed and `last_error` says why. `detected` stays after the attempt ends so a failure shows which commands ran.

## Health gate fails

Candidate never goes live; previous remains. Check `status/executor.json` `last_result` and site logs in the status ring buffer.

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
