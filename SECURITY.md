# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Reporting a vulnerability

Please use **GitHub Security Advisories** on this repository (Private vulnerability reporting).

Do **not** open a public issue for security bugs that could expose:

- GitHub PATs or build/runtime secrets
- Container escape / privilege-separation bypasses
- Path traversal or tar-extract escapes in the manager

We aim to acknowledge reports within a few business days.

## Hardening notes

Operators should also read:

- [docs/threat-model.md](docs/threat-model.md), including where the GitHub PAT is and is not visible
- [docs/hardening.md](docs/hardening.md) (rootless Docker, cloud metadata `169.254.169.254` blocking)
