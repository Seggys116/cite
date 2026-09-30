# HTTPS in front of Cite

The executor speaks **HTTP only** (no TLS termination, no ACME). Put a tunnel or reverse proxy in front.

## Cloudflare Tunnel

1. Install `cloudflared` on the host.
2. Create a tunnel that points at `http://127.0.0.1:${CITE_PORT:-8080}`.
3. Bind Cite to localhost if the tunnel is local-only:

```env
CITE_BIND=127.0.0.1
CITE_PORT=8080
```

4. Set `CITE_TRUSTED_PROXIES` on the executor to the tunnel/proxy CIDRs if you rely on `X-Forwarded-*`.

## Caddy

```caddyfile
example.com {
  reverse_proxy 127.0.0.1:8080
}
```

Caddy handles certificates; Cite stays on HTTP loopback.

## Notes

- Do not publish the executor on `0.0.0.0:80` on a public NIC without a proxy unless you accept cleartext HTTP.
- Manager never needs inbound HTTPS — it only egresses to GitHub (certificate-validated).
