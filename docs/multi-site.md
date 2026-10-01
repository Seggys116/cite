# Multiple sites

Cite is **one site per Compose project**. Many sites mean many projects, each with its own PAT, volumes, and published port.

```bash
# site A
docker compose -p site-a --env-file site-a.env up -d

# site B
docker compose -p site-b --env-file site-b.env up -d
```

Example `site-a.env`:

```env
CITE_REPO=acme/marketing
CITE_GITHUB_TOKEN=ghp_replace_me
CITE_BRANCH=main
CITE_VERSION=0.2.0
CITE_NODE=22
CITE_PORT=8081
CITE_BIND=127.0.0.1
```

Use a separate env file per project, readable only by the operator (`chmod 600`), so PATs never cross.

## Front proxy sketch (Caddy)

```caddyfile
marketing.example.com {
  reverse_proxy 127.0.0.1:8081
}
app.example.com {
  reverse_proxy 127.0.0.1:8082
}
```

Or route hostnames with Cloudflare Tunnel / nginx to each executor's `CITE_PORT`. The executor remains plain HTTP; see [https.md](https.md).
