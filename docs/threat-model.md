# Threat model (abridged)

| Actor / asset | Threat | Mitigations |
|---|---|---|
| **Repo code at build time** (same container as the PAT) | Steal PAT, tamper with manager, persist | uid **10002** with all caps dropped; cleared build env (PAT is not in it) and `/proc/1/environ` unreadable to that uid; root-only control socket (`SO_PEERCRED`); read-only rootfs; limits + timeout; no `git`, no Docker socket |
| **Malicious build output** | Symlink/hardlink escape, specials, bombs | Pack via no-follow handles as 10002, then re-extract by the hardened manager into fresh inodes; size/count caps |
| **Malicious tarball** | Zip-slip, symlink escape, bombs | Hardened extractor + fuzzing |
| **RCE in the deployed site** | Shell, persist, pivot | Shell-less distroless executor; read-only rootfs; releases **ro**; non-root; caps dropped; no-new-privileges; pids/mem limits; egress denied by default; can write only `status/`; never receives the PAT |
| **Forged `status/` files** | Mislead manager | Strict schema + size caps; worst case false status, never code execution |
| **Visitor traffic** | Smuggling, Host/XFF spoofing, slowloris, traversal | Strict HTTP parsing, header policy, timeouts/limits, path containment |
| **Supply chain** | Bad deps/images/actions | `cargo deny` + audit, digest-pinned images, SHA-pinned Actions, Dependabot |
| **Host** | Container breakout | No socket, no privileged, minimal caps, default seccomp; prefer rootless / userns-remap |

## Where the GitHub PAT is exposed

The PAT is an environment variable (`CITE_GITHUB_TOKEN`) of the **manager container**, set from `.env` by Compose. Anyone who can do any of the following can read it:

- run `docker inspect` on the manager (any user with Docker access on the host, which is effectively root);
- read `.env` on the host;
- run code as root inside the manager container.

It is not visible to the uid-10002 build process or to the executor and the site it hosts. A compromised executor or site cannot obtain it; a compromise of the manager's root user or the Docker host can. Limit the blast radius with a fine-grained, read-only, single-repository PAT.

## Trust boundaries

```text
Internet ──HTTP──► executor (shell-less) ──files──► cite_data
                      ▲
GitHub ──HTTPS──► manager (has shell) ──files──► cite_data
                      │
                      └── cite_work / cite_cache (manager only)
```

Manager and executor share **no network path**, only the volume.
