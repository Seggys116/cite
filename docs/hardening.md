# Hardening

Cite's Compose defaults aim for a small attack surface. Verify a live stack with:

```bash
./scripts/assert-hardening.sh          # live container settings
./scripts/assert-shellless.sh --compose
./scripts/assert-compose.sh            # rendered config snapshot
```

## Container defaults (production)

| Control | Manager | Executor |
|---|---|---|
| `init: true` | yes | yes |
| `read_only: true` | yes | yes |
| `cap_drop: ALL` | yes | yes |
| `cap_add` | `CHOWN`, `SETUID`, `SETGID`, `DAC_READ_SEARCH` | none |
| `no-new-privileges` | yes | yes |
| User | root → drops to **10002** for builds | **65532** |
| Published ports | **none** | host `CITE_PORT` → 8080 |
| Docker socket | **never** | **never** |
| Egress | yes (GitHub + registries) | **denied by default** |

Enable executor egress only when an SSR site must call external APIs:

```bash
docker compose -f docker-compose.yml -f docker-compose.egress.yml up -d
```

## Host firewall

Publish only the executor port (`CITE_PORT`, default 8080). The manager has no published ports. On the host, allow inbound traffic to that port and drop the rest of the Docker-published range. Keep the Docker bridge from reaching cloud metadata (below) and from reaching the host's own admin ports.

## Resource limits

Production Compose caps each service so one site cannot exhaust the host:

| Service | Memory | CPUs | PIDs |
|---|---|---|---|
| manager | 2 GB | 2 | 2048 |
| executor | 1 GB | 1 | 256 |

Build wall-clock time is capped by `CITE_BUILD_TIMEOUT` (default 15 m). The executor also caps connections, header bytes, and body bytes.

## Rootless Docker / userns-remap

Prefer **rootless Docker** or userns-remap on the host so the manager's in-container root maps to an unprivileged host uid. Documented Compose caps still apply inside the user namespace.

## Cloud metadata IP (`169.254.169.254`)

Builds run arbitrary repo code. On cloud VMs, block the instance metadata endpoint from the Docker bridge so a hostile build cannot steal cloud credentials.

Example iptables (adjust bridge name; often `docker0` or `br-*`):

```bash
# Drop traffic from containers to the link-local metadata address.
sudo iptables -I DOCKER-USER -d 169.254.169.254 -j DROP
sudo iptables -I DOCKER-USER -d 169.254.0.0/16 -j DROP
```

nftables sketch:

```bash
sudo nft add rule ip filter forward ip daddr 169.254.169.254 drop
```

Also restrict cloud IAM / instance profiles to least privilege. Cite does not proxy metadata.

## Logging & the GitHub PAT

- Log driver: `json-file`, `max-size=10m`, `max-file=3`.
- The PAT is set as `CITE_GITHUB_TOKEN` in `.env` and passed to the **manager container's environment only**. It is visible to `docker inspect` on the host and to root inside the manager, so restrict who can run Docker on the host and keep `.env` mode `600`.
- It is not visible to the uid-10002 build process (builds run with a cleared environment and `/proc/1/environ` is unreadable to that uid), and the executor never receives it: `docker inspect` of the executor shows no PAT.
- For rotation without a restart, mount a file and set `CITE_GITHUB_TOKEN_FILE` to its path; it is re-read on every poll. The file must be a regular file readable only by its owner (mode `0400` or `0600`); Cite refuses a group- or world-readable token file, because the build uid could otherwise read a bind mount. Mount it under `/run/cite/` (a root-only tmpfs), for example `./github_token:/run/cite/github_token:ro`, so uid 10002 cannot reach it whatever its mode.
- Use a fine-grained PAT limited to the one repository with `contents:read`.

## Executor shell-less

Executor images are distroless with no shell. `docker exec … sh` must fail.
