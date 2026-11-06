# Dashboard: certificate tools and alerts

This page covers two additions to the web console: guided certificate issuing on the Certificates tab, and the Alerts panel. Both talk to the node through the console proxy as `/api/v1/nodes/{node}/...`.

## Certificate tools

The Certificates tab shows a "Get a certificate" card under the certificate list. Each option opens a short form. Hosts are pre-filled from the node's sites; hosts with no certificate yet are ticked by default, and any other name can be typed in (wildcards such as `*.example.com` are allowed).

| Option | Use it when | Node route |
| --- | --- | --- |
| Create a certificate for me | Cloudflare sits in front with SSL mode Full. The certificate is self-signed, so a browser that reaches the node directly shows a warning. | `POST /certificates/generate` |
| Cloudflare Origin CA | All traffic goes through Cloudflare and you want Full (strict) with a long-lived certificate. | `POST /certificates/origin-ca` |
| Let's Encrypt | You want a certificate every browser trusts, renewed automatically. | `POST /certificates/acme`, then poll `GET /certificates/acme/{job_id}` |

### Cloudflare API tokens

Origin CA needs a custom token with `Zone - SSL and Certificates - Edit` and `Zone - Zone - Read`. Let's Encrypt (DNS challenge) needs `Zone - DNS - Edit` and `Zone - Zone - Read`. Limit either token to the zones involved.

### What happens to the token

- The token goes in a password-type box with autocomplete off. It is sent once in the request body and the box is emptied as soon as the request is sent, on failure, and when the form is cancelled. It is never written to browser storage, a URL or a log.
- Origin CA: the token is used for the request only, unless "Remember this token on the node" is ticked. That option is off by default; when on, the node keeps the token in its own configuration so a later request does not ask for it again.
- Let's Encrypt: the node must keep the token to renew the certificate, so it is stored on the node until the certificate is deleted. The form states this and requires ticking "I agree to the Let's Encrypt terms" (which includes that storage) before it can be submitted.

### Let's Encrypt progress

After the node accepts the request it returns a job id. The form checks the job every 3 seconds and shows the status in a live region. A failure shows the reason in a red banner. The page stops waiting after 15 minutes or after five failed status checks in a row; the node keeps working and the result appears in the certificate list. "Use test certificates (not trusted)" requests from the Let's Encrypt staging service, which has far higher rate limits but produces certificates browsers do not trust.

## Alerts panel

The Alerts panel reads and writes `GET /alerts` and `PUT /alerts`.

- Enable switch and cooldown (0 to 86400 seconds; the same alert is not repeated more often than this).
- Up to 10 webhooks. Each has a name, a kind (generic JSON, Discord or Slack), an `https://` URL and the events it receives. URLs are masked by the node; the box starts empty and an empty box keeps the stored URL for that webhook.
- Email through your own mail server: host, port, encryption (STARTTLS, TLS or none), user name, write-only password (shown as a "saved" badge, empty keeps it), From address and up to 5 recipients.
- Events: `site_unhealthy`, `site_recovered`, `build_failed`, `deploy_succeeded`, `cert_expiring`, `node_error`.
- "Send test" posts `POST /alerts/test` with `webhook:{id}` or `email` and shows the result beside the button. Tests use the saved settings, so a new item must be saved first.
- Saving with the email block switched off removes the stored email settings, including the password.
- An "Unsaved changes" badge shows while the form differs from what the node last returned. Typing into a secret box counts as a change.

Validation mirrors the node: HTTPS URLs without embedded credentials, at least one event per destination, valid addresses and port, and the webhook and recipient limits.

## Development

`?mock=1` serves the in-memory API. `web/mock-certs.js` adds all of the routes above with realistic delays. Handy cases: a host starting with `fail.` or a token starting with `fail` makes a Let's Encrypt job fail after about 6 seconds (others finish after about 9); a token starting with `invalid` is rejected by the Origin CA route; a webhook URL containing `fail` makes its test fail.

Pure logic lives in `web/js/certissue.js` and `web/js/alertslib.js` and is tested with `node --test crates/cite-dashboard/tests/js/*.test.mjs`.
