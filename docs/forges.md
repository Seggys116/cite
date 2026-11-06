# Source forges: GitHub, GitLab, Gitea and Forgejo

The manager pulls a site's source from a forge over its REST API: it reads the branch head, downloads an archive of that exact commit, and builds it. GitHub is the default. GitLab (API v4) and Gitea or Forgejo (API v1) work the same way. No git binary is involved, and nothing is cloned.

## Configuration

The forge is chosen by the node operator, never by a site. Users pick a repository and branch; they cannot name a host.

| Variable | Values | Default |
|---|---|---|
| `CITE_FORGE` | `github`, `gitlab`, `gitea` (use `gitea` for Forgejo too) | `github` |
| `CITE_FORGE_API_URL` | Base URL of the forge API | GitHub: the existing `CITE_GITHUB_API_URL`; GitLab: `https://gitlab.com/api/v4`; Gitea: none, it must be set |
| `CITE_REPO` | `owner/name` | required |
| `CITE_BRANCH` | branch name | `main` |
| `CITE_GITHUB_TOKEN` / `CITE_GITHUB_TOKEN_FILE` | the forge token, whatever the forge | required |

The token keeps its existing variable names so that one storage and redaction path covers every forge.

Examples:

```sh
# GitLab.com
CITE_FORGE=gitlab
CITE_REPO=acme/website

# Self-hosted GitLab
CITE_FORGE=gitlab
CITE_FORGE_API_URL=https://git.example.com/api/v4

# Codeberg (Forgejo)
CITE_FORGE=gitea
CITE_FORGE_API_URL=https://codeberg.org/api/v1

# Self-hosted Gitea
CITE_FORGE=gitea
CITE_FORGE_API_URL=https://gitea.example.com/api/v1
```

`CITE_FORGE_API_URL` must be a plain `https://` URL: host, optional port and path only, with no user info, query, fragment, percent escapes, empty or `.`/`..` segments, and at most 200 characters. Plain `http://` is never accepted, not even for loopback addresses. These are the same shape rules the connector applies to the GitHub API URL. The connector passes `CITE_FORGE` and `CITE_FORGE_API_URL` to a manager only from its own operator allowlist.

## Tokens

Use a token that can only read the one repository the site builds from.

| Forge | Token | Scope or permission |
|---|---|---|
| GitHub | Fine-grained personal access token | Contents: read (Metadata: read is implied) |
| GitLab | Project access token (preferred) or personal access token | `read_api`, role Reporter or higher |
| Gitea / Forgejo | Access token | `read:repository` |

GitLab's `read_repository` scope covers git over HTTP and the repository files API, but not the branch, compare and archive endpoints the manager calls, so it is not enough on its own. A project access token with `read_api` is limited to one project, which keeps the blast radius equal to a GitHub fine-grained token.

Token expiry is reported where the forge exposes it:

- GitHub: from the `github-authentication-token-expiration` response header.
- GitLab: from `GET /personal_access_tokens/self` (personal, project and group access tokens). OAuth tokens do not expose it; the expiry is then simply unknown.
- Gitea / Forgejo: access tokens do not expire, so no expiry is reported.

The manager warns in its log when a token expires within 7 days.

## What the manager calls

| Operation | GitHub | GitLab | Gitea / Forgejo |
|---|---|---|---|
| Access check | `GET /repos/:owner/:name` | `GET /projects/:id` | `GET /repos/:owner/:name` |
| Branch head | `GET /repos/:owner/:name/commits/:branch` | `GET /projects/:id/repository/branches/:branch` | `GET /repos/:owner/:name/branches/:branch` |
| Path filter (`CITE_PATHS`) | `GET /repos/:owner/:name/compare/:base...:head` | `GET /projects/:id/repository/compare?from=&to=` | `GET /repos/:owner/:name/compare/:base...:head` |
| Archive | `GET /repos/:owner/:name/tarball/:sha` | `GET /projects/:id/repository/archive.tar.gz?sha=` | `GET /repos/:owner/:name/archive/:sha.tar.gz` |
| Auth header | `Authorization: Bearer` | `Authorization: Bearer` | `Authorization: token` |

The GitLab `:id` is the URL-encoded `owner/name` path (`owner%2Fname`). GitLab accepts personal, project, group and OAuth tokens in the `Authorization: Bearer` header, so one header covers them all.

Errors read the same on every forge. A rejected token during the access check reports "token is invalid or lacks access (bad token / no access)", a missing repository reports which token scope to check, a missing branch reports "branch `x` does not exist on owner/name", and a 401 while polling or downloading marks the token invalid exactly as on GitHub. A 429, or a 403 carrying rate limit headers, pauses polling until the reset time (`RateLimit-*`, `X-RateLimit-*` or `Retry-After`); a 429 without hints waits 60 seconds. When a compare call fails or the forge leaves out the changed files, the manager deploys rather than skipping a change it cannot see.

## Limits

- No submodules and no Git LFS. Forge archives contain submodules as empty directories and LFS files as pointer files, as on GitHub.
- GitLab projects in subgroups (`group/sub/name`) are not supported yet, because `CITE_REPO` is `owner/name`.
- The compressed archive is capped by `CITE_MAX_SOURCE_COMPRESSED_BYTES` (1 GiB by default), checked against `Content-Length` and again while streaming. A download that stalls for 60 seconds or takes longer than 30 minutes in total is abandoned.
- API responses are capped at 16 MiB, and error bodies are read up to 64 KiB and quoted in the error truncated to 200 bytes.
- GitLab.com rate limits archive downloads per user; a refused download is retried on a later poll.

## Security model

- **The token goes only to the configured API origin.** Redirects are followed by the manager itself, at most 5 hops. The token, and the `If-None-Match` header, are attached only when a hop's scheme, host and port equal those of `CITE_FORGE_API_URL`. An archive that redirects to object storage on another host is fetched there without the token, as GitHub's own client does.
- **No downgrade.** A redirect from `https` to `http`, to any other scheme, or to a URL carrying user info is refused.
- **A 401 is blamed on the token only when the API origin sent it.** A 401 from object storage fails the download without marking the token invalid.
- **No host from users.** The API URL is operator configuration validated at startup; owner, name and branch are URL-encoded into path segments, and commit ids must be 7 to 64 hex characters before they are placed in a URL. A branch head that is not a full 40 or 64 character commit id is rejected.
- **Same TLS stack.** Every request uses rustls with the bundled web PKI roots; self-signed certificates are refused.
- **Same extraction.** Archives from every forge are unpacked by the same hardened extractor (`cite_core::extract_archive`), with the top-level directory stripped, and the same size, entry and link limits.
- **The token is never logged.** Header values carrying it are marked sensitive, and errors never echo request headers.
