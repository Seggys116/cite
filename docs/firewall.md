# Firewall and maintenance

This page covers the edge firewall rules, the built-in presets, the per-IP rate limit, maintenance pages, and how blue/green switching changes routing without reloading HAProxy.

## Request order

For each request HAProxy applies these steps in order, and the first that answers ends the request:

1. Set `X-Forwarded-Proto` to `http` or `https`.
2. Per-IP rate limit. Over the limit answers 429.
3. Maximum body size, when set. A larger `Content-Length` answers 413.
4. Firewall rules, in list order.
5. Maintenance pages, one check per site.
6. Routing: the first site whose host (and path, if set) matches, through `active.map`.
7. No site matched: the `be_notfound` backend answers 404 with the body `not found`.

Firewall rules therefore run before maintenance and routing. A blocked request never reaches a backend, and it is counted in analytics with the rule id that fired.

## Rules

A rule has an id, a name, an enabled flag, an action, matchers and an optional site. Disabled rules are not rendered.

| Matcher | Matches |
|---|---|
| `path_regex` | The request path, as a regular expression. |
| `path_prefix` | The request path starting with this string. Must begin with `/` and contain no backslash. |
| `methods` | Any of up to 16 uppercase method names, for example `TRACE`. |
| `user_agent_regex` | The `User-Agent` header, as a regular expression. |
| `cidrs` | The client's TCP source address against up to 256 CIDRs or single IPs, IPv4 or IPv6. |
| `host` | The `Host` header without port, lower-cased. An exact name, or `*.example.com` for any subdomain. |

When a rule sets several matchers, all of them must match. A rule with no matcher is refused, because it would block everything.

| Action | Effect |
|---|---|
| `deny` | Answers 403. |
| `drop` | Closes the connection without sending a response. |
| `tarpit` | Holds the request for 5 seconds (`timeout tarpit 5s`), then HAProxy fails it with an error status. Slows scanners without spending a backend. |

The source address is the one HAProxy sees on the TCP connection. Behind another proxy or load balancer that is the proxy's address, not the visitor's, and `cidrs` and the rate limit act on it.

### Limits on what you can write

Values become words in the HAProxy config, so they are checked before rendering:

- Rule, site and page ids match `^[a-z0-9][a-z0-9-]{0,39}$`.
- Patterns are 1 to 256 printable ASCII characters. `#`, `"` and `'` are not allowed. Write a space as `\x20`.
- A pattern cannot start with `-`, equal a HAProxy keyword such as `if` or `or`, contain a doubled or trailing backslash, or contain `$` followed by a name.
- Regexes must compile. Path prefixes must start with `/`.
- A config holds at most 1000 sites, 1000 pages and 5000 rules.

The connector also asks `haproxy -c` to check the final file, so a regex that HAProxy's engine rejects is refused with its error message.

### Scope

A rule with a `site` id applies only to requests that match that site's host, and its path regex if it has one. A rule without a site applies to every request on the node. The site must exist.

## Presets

A preset is a fixed set of rules you add with one call: `POST /api/v1/firewall/presets/{name}/apply` returns the rules it added, and `GET /api/v1/firewall/presets` lists them. Rule ids are `preset-<name>-<n>` and stay the same between releases.

| Preset | Rule id | Action | Matches |
|---|---|---|---|
| `sensitive-files` | `preset-sensitive-files-1` | drop | Dotfiles: `.env`, `.git`, `.svn`, `.hg`, `.htaccess`, `.htpasswd`, `.ds_store` |
| | `preset-sensitive-files-2` | drop | Private keys: `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`, with or without `.pub` |
| | `preset-sensitive-files-3` | drop | `wp-config`, `wp-config.php` and variants |
| | `preset-sensitive-files-4` | drop | Paths ending in `.sql`, `.bak`, `.swp`, `.orig` |
| | `preset-sensitive-files-5` | drop | Archives named `backup`, `dump`, `db`, `database`, `www`, `site` or `public_html` as `.zip`, `.tar`, `.tgz`, `.gz`, `.7z`, `.rar` |
| `cms-probes` | `preset-cms-probes-1` | drop | `wp-login.php`, `wp-admin`, `xmlrpc.php` |
| | `preset-cms-probes-2` | drop | `phpmyadmin`, `pma`, `myadmin`, `mysqladmin` |
| | `preset-cms-probes-3` | drop | `vendor/phpunit`, `cgi-bin`, `boaform`, `HNAP1` |
| | `preset-cms-probes-4` | drop | `actuator`, `solr`, `manager/html` |
| `scanners` | `preset-scanners-1` | tarpit | User agents containing sqlmap, nikto, nmap, masscan, zgrab, gobuster, dirbuster, wpscan, nuclei, acunetix or havij |
| | `preset-scanners-2` | tarpit | An empty user agent |
| `odd-methods` | `preset-odd-methods-1` | deny | `TRACE`, `TRACK`, `CONNECT`, `DEBUG` |

The path presets use the `(?i)` flag so they match in any case. That needs a HAProxy built with PCRE. The HAProxy container and the connector image's `haproxy -c` check both use `haproxy:3.0-bookworm` by default. If the binary rejects the flag, applying the preset fails at the `haproxy -c` step and the stored configuration is restored.

Presets are ordinary rules once added. Edit, disable or delete them like any other.

## Rate limit

`settings.per_ip_rate_limit` is the number of requests one source address may make in a 10 second window. The default is 600. Over the limit, HAProxy answers 429. Set it to `null` to turn it off; the valid range is 1 to 1000000.

HAProxy tracks sources in a stick table of 200000 entries that expire after 10 minutes without traffic. `settings.max_body_bytes` (off by default) rejects requests whose `Content-Length` exceeds it with 413.

## Maintenance pages

Maintenance mode is per site. While it is on, every request that matches the site's host and path gets the page instead of reaching a backend. Other sites on the node are not affected. Firewall rules still run first.

| Item | Detail |
|---|---|
| Default page | A built-in dark HTML page ("We will be right back"), self-contained with no external requests, served with status 503. |
| Custom pages | Created with `POST /api/v1/pages`: an id, a name, the HTML (up to 256 KiB) and a status from 400 to 599, default 503. |
| Choosing a page | `POST /api/v1/sites/{id}/maintenance` with `{"enabled": true, "page_id": "..."}`. Without a page the default is used. |
| Headers | `Content-Type: text/html; charset=utf-8` and `Cache-Control: no-store`. |
| Deleting | A page used by a site cannot be deleted. |

Turning maintenance off without naming a page keeps the earlier page choice, so turning it on again restores it.

## Maps and reloads

Two small map files sit in `/conf/haproxy/maps/`, one line per site id.

```
# active.map
shop be_shop_blue
api  be_api_green

# maint.map
shop off
api  on
```

The rendered config never changes when you switch slots or toggle maintenance. It reads the maps on each request:

- Routing is `use_backend %[str(<site>),map(active.map)]`, so the map decides between `be_<site>_blue` and `be_<site>_green`.
- The maintenance rule is always present for every site and fires when `maint.map` says `on` for that site. A missing entry counts as `off`.

To change a map the connector first rewrites the file atomically, then sends HAProxy a runtime command on the admin socket (`set map`). Writing the file first means a later reload keeps the choice even if the socket is down. No reload happens.

What does cause a reload is any change to the rendered config or the page files: adding or removing sites, editing hosts, health checks, targets or firewall rules, or changing which page a site uses. The connector computes a hash over the config, both maps and all pages, skips the work when it matches what is installed, and otherwise validates, writes the files and signals the HAProxy master with `SIGUSR2`.

### Blue/green deploy sequence

1. Write the new targets into the idle slot. This changes the rendered config, so HAProxy reloads once.
2. Wait up to 60 seconds for every server in the idle backend to pass its health check. On failure, record a `failed` deployment and leave the active slot alone.
3. Update `active.map` through the runtime socket. If that fails, the old value is written back to the file.
4. Record the deployment, then update the stored active slot.

With the orchestrator on, the old slot's stack is stopped 30 seconds after the switch unless the site moved back. Rollback and switch use the same steps 2 to 4, and refuse a slot that has no targets or is not healthy.

Backends with more than one target use `leastconn`, and a single target uses `roundrobin`. Health checks send `GET <path>` at the configured interval. The defaults are path `/`, every 2000 ms, 1500 ms timeout, healthy after 2 passes and down after 3 failures.

## What the firewall does not do

- It does not inspect request bodies or response contents.
- It matches only the six matchers above. There is no rule on arbitrary headers, query strings or cookies.
- Rate limiting is per source address and per node. Nodes do not share counters.
- It is not a web application firewall. It removes known probe traffic and gives you a fast way to block an address or path.
