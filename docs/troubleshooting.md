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
