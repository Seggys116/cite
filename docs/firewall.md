# Firewall and maintenance

This page covers the edge firewall rules, the built-in presets, the per-IP rate limit, maintenance pages, and how blue/green switching changes routing without reloading HAProxy.

## Request order

For each request HAProxy applies these steps in order, and the first that answers ends the request:

1. Normalise the request path (see below). Requests with more than one `Host` header, or a `Host` containing a comma, answer 400.
2. The site is resolved from the host (and path, if set).
3. Cloudflare-only check, for sites with `access.cloudflare_only`. A connection whose TCP peer is not in the Cloudflare range list answers 403 and is recorded with the built-in rule label `cloudflare-only`. See [Access: Cloudflare only and Flexible SSL](sites.md#access-cloudflare-only-and-flexible-ssl).
4. Set `X-Forwarded-Proto` to `http` or `https` (for Flexible SSL sites reached through Cloudflare, from Cloudflare's header).
5. Real client address: for Cloudflare-only sites reached through Cloudflare, the source address becomes the single valid IP in `CF-Connecting-IP`.
6. Per-IP rate limit. Over the limit answers 429 and is recorded with the built-in rule label `rate-limit`.
7. Maximum body size, when set. A larger `Content-Length` answers 413.
8. Blocking firewall rules (those with an `action`), in list order. This includes a [zone lock](sites.md#zone-lock-prove-the-request-came-through-your-cloudflare-zone) rule.
9. Bot policy, for sites with `access.bots` other than `allow`. See [Bot policy](#bot-policy).
10. Zone header removal: when any site has `zone_lock`, or any enabled rule matches `X-Cite-Origin-Secret`, that header is deleted from every request once the zone lock has passed (Cloudflare sends it for the whole hostname, so unlocked sites on the same host must not receive it either). Configs without a zone lock render no such line.
11. Redirect rules (`redirect`), in list order. A redirect answers 301, 302, 307 or 308 and ends the request.
12. Request header changes (`headers` with `target` `request`).
13. CORS preflight: an `OPTIONS` request with `Access-Control-Request-Method` from a listed origin is answered 204 by the edge.
14. Maintenance pages, one check per site.
15. Routing: the first site whose host (and path, if set) matches, through `active.map`.
16. No site matched: the `be_notfound` backend answers 404 with the body `not found`.

Response phase, after the upstream answered: response header changes (`target` `response`) and the CORS response headers. HAProxy cannot read request headers in the response phase, so a rule with any response effect has its full condition (site, matchers, header, referer, scheme and the rest) evaluated once while the request is processed and kept in the variable `txn.m_<rule id>` (with every `-` in the id written as `_`, so rule `cors-app` uses `txn.m_cors_app`); the response lines test only that variable, which keeps negated header matchers correct. HAProxy does not run response rules on answers it generates itself, so a 403 from a block, a redirect, a preflight 204 and a maintenance page carry only the headers written into them.

Steps 3 and 5 run before the rate limit, the stick table and the firewall rules on purpose, so those see the visitor's address rather than a Cloudflare edge. The rate limit (steps 6 and 7) runs before the blocking rules, so blocked requests still count towards a source's request rate and a scanner that keeps hammering ends up at 429. The `cloudflare-only` label is a built-in rule id: a request it refuses shows up in the Traffic blocked-by-rule table next to the rules you wrote, and it cannot be edited or disabled except by turning `cloudflare_only` off for the site. Avoid giving your own rule the id `cloudflare-only`, because the two would be counted together. The same holds for the labels `bots-bad`, `bots-all` and `cloudflare-zone`.

Effect rules (redirects, header changes, CORS) only touch requests that matched a site. A request for an unknown host is answered 404 untouched, even by a rule that has no `site`.

### Path normalisation

Before any rule runs, the edge rewrites the request path so that rules see what a plain origin would see. Without this, `/%2eenv`, `/%2Egit/config` or `/wp%2dlogin.php` would slip past a rule written for `/.env`. The steps, in order, are:

- `percent-to-uppercase`: `%2f` becomes `%2F`.
- `percent-decode-unreserved`: escapes of letters, digits, `-`, `.`, `_` and `~` are decoded, so `%6c` becomes `l` and `%2e` becomes `.`.
- `path-merge-slashes`: `//` becomes `/`.
- `path-strip-dot` and `path-strip-dotdot full`: `/./` and `/a/../` segments are resolved, and leading `/../` is dropped instead of being kept.
- `fragment-strip`: a `#fragment` is removed.

This changes what your upstreams receive: they get the normalised path. Duplicate slashes are merged, dot segments are resolved, and unreserved characters are no longer percent-encoded. Reserved escapes such as `%2F`, `%20` and `%3B` are left alone, so `/a%20b` and `/a/b%2Fc` reach the upstream as sent. The query string is not changed.

Escapes of reserved characters stay encoded, and some origins decode them or treat them specially. Rules therefore also see a canonical path, kept in the `txn.cpath` variable. It is built from the normalised path by these steps:

- Path parameters are removed from every segment: `;` (or `%3B`) up to the next `/`. Tomcat and Spring treat `/;x/admin` and `/x/..;/admin` as `/admin`.
- Backslashes (`\` or `%5C`) become `/`, because IIS and some other servers treat them as separators.
- The path is normalised again (merged slashes, dot segments, `..` resolved), so `/x/..;/admin` becomes `/admin`.
- The result is fully URL-decoded.

`path_prefixes`, `path_regexes` and the preset path rules fire if either the normalised path as sent or the canonical path matches. `/;x/admin`, `/x/..;/admin`, `/.;/admin`, `/%3Bx/admin`, `/\admin`, `/%5cadmin`, `/../admin` and `/x%2f..%2f.env` are all caught by a `/admin` or `/.env` rule. The canonical path is only used for matching. The upstream still receives the normalised path, and the query string is unchanged. Requests containing `%2F`, `%5C` or a raw backslash are not rejected, because some applications use them legitimately; rules just see the backslash as `/`. `/x/%5Cadmin` is therefore not an `/admin` request (it is `/x/admin`).

Firewall rules therefore run before maintenance and routing. A blocked request never reaches a backend, and it is counted in analytics with the rule id that fired.

## Rules

A rule has an id, a name, an enabled flag, matchers, an optional site, an optional label, and exactly one kind of outcome: it either blocks or it has effects. Disabled rules are not rendered.

```json
{"id": "no-admin", "name": "No admin", "enabled": true, "action": "deny",
 "matchers": {"path_prefixes": ["/admin", "/wp-admin"]}, "site": "shop"}
```

| Outcome | Fields | Meaning |
|---|---|---|
| Block | `action` | `deny`, `drop` or `tarpit`. The request ends here and is logged. |
| Redirect | `redirect` | `{"to": "...", "status": 301}`. The request is answered with a redirect. |
| Header and CORS effects | `headers` and/or `cors` | The request continues to the site with headers changed or CORS handled. |

`action` is optional in the JSON and absent for effect rules. A rule that sets `action` together with `redirect`, `headers` or `cors`, a rule that sets `redirect` together with `headers` or `cors`, and a rule that sets nothing of these are all refused, and the error names the rule. Rules saved before effects existed always have an `action`, and load and serialise exactly as before. `label` (same shape as an id) replaces the rule id in logs and in the blocked-by-rule table; the zone lock uses it so every site shows up as `cloudflare-zone`.

| Matcher | Matches |
|---|---|
| `path_regexes` | The request path matches any of these regular expressions. |
| `path_prefixes` | The request path starts with any of these strings. Each must begin with `/`, be at most 256 characters and contain no backslash. |
| `methods` | Any of up to 16 uppercase method names, for example `TRACE`. |
| `user_agent_regexes` | The `User-Agent` header matches any of these regular expressions. |
| `cidrs` | The client's TCP source address against up to 256 CIDRs or single IPs, IPv4 or IPv6. Lists of more than 4 CIDRs, and more than 4 `methods`, are rendered as named ACLs split over several lines, because HAProxy aborts on a line of more than 64 words. Whatever a rule combines, no rendered line exceeds 60 words; a long condition is evaluated once into a variable, and rendering fails rather than emit a longer line. |
| `hosts` | The `Host` header without port, lower-cased, equals any of these. Each is an exact name, or `*.example.com` for any subdomain. |
| `scheme` | `"http"` or `"https"`: how the visitor connected. For Flexible SSL sites reached through Cloudflare it is Cloudflare's view. |
| `referer_regexes` | The `Referer` header matches any of these regular expressions. A list that is just `["^$"]` also matches a request without the header. |
| `headers` | Request header matchers, see below. All of them must hold. |

Within one list the values are alternatives (OR); across the different matcher fields all must match (AND); the exception is `headers`, whose entries are all required. So a rule with `"user_agent_regexes": ["evilone", "eviltwo"]` and `"path_prefixes": ["/a", "/b"]` fires for a user agent matching either regex on a path starting with either prefix. For a rule, `path_prefixes` and `path_regexes` are both path matchers and are AND'd with each other, like any two fields; a site treats them as alternatives (see [Sites](sites.md)). The singular names of earlier releases (`path_regex`, `path_prefix`, `user_agent_regex`, `host`, `referer_regex`, `header`) are still accepted when a rule is saved or loaded and become a one-entry list; the node writes only the list names.

Limits: each list holds at most 16 distinct entries (a repeated entry is refused), a rule holds at most 32 regexes in total (including header regexes), and each regex must pass the [regex subset](#regex-subset). The patterns of one field run one after another, so their work is added up: the summed bounds of the subset (20,000,000 steps over a capped subject, and 250,000 steps from one start position) apply to the whole list of a field, not to each pattern. `"^$"` must be the only entry of its list. Rendering uses one `acl` line per value under one name, so there is a single oversize guard per field, and a blocking rule gets one extra condition for each of the path and user agent fields.

When a rule sets several matchers, all of them must match. A blocking rule with no matcher is refused, because it would block everything. An effect rule may have none (a CORS or security-header rule for a whole site), except a redirect, which needs a matcher or a `{www_host}` / `{apex_host}` target so that it cannot loop.

| Action | Effect |
|---|---|
| `deny` | Answers 403. |
| `drop` | Closes the connection without sending a response. |
| `tarpit` | Holds the request for 5 seconds (`timeout tarpit 5s`), then HAProxy fails it with an error status. Slows scanners without spending a backend. |

### Header matcher

```json
{"headers": [{"name": "X-Env", "equals": "staging", "negate": true}]}
```

`name` is a header name (letters, digits, `-` and `_`, up to 64, starting with a letter) and is case-insensitive. Set exactly one of `regex` (same rules as every other regex) and `equals` (exact, case-sensitive; 1 to 256 characters from letters, digits and `- _ . ~ : / @ = + , ; * & ?`). `negate` inverts the test, so `"negate": true` with `equals` reads as "unless the header equals this value". A request without the header does not match the plain test, so it does match the negated one.

`secret: true` marks `equals` as a credential. The value is still written to the rendered `haproxy.cfg` (HAProxy has to compare it) and kept wherever the rule is stored, so treat both as secret. (The zone lock avoids the second: a site sets `access.zone_lock`, the node keeps the secret in its own 0600 file and adds the rule only when rendering, so the rules the API returns never hold it; rendering refuses a `zone_lock` site that has no enabled lock rule.) It is replaced by `<redacted>` in the rule's `Debug` output and in validation errors, and it is never part of a log or analytics label: those carry the rule id or label only.

### Redirects

```json
{"id": "to-www", "name": "To www", "enabled": true, "site": "shop",
 "matchers": {}, "redirect": {"to": "{scheme}://{www_host}{path}{query}", "status": 301}}
```

`status` is 301, 302, 307 or 308 (default 301). `to` is a template and is validated strictly, because it ends up in the HAProxy config:

- It is an absolute `http://` or `https://` URL, `{scheme}://` followed by a host, or a path starting with `/` (not `//`, and not `/{path}`). `javascript:`, `data:`, relative paths without a leading slash and protocol-relative URLs are refused.
- Only these placeholders exist, and any other `{name}` is an error: `{scheme}` (`http` or `https`, only at the start), `{host}` (the `Host` header, lower-cased, with its port), `{www_host}` (the host with `www.` added), `{apex_host}` (the host with a leading `www.` removed), `{path}` (the normalised path, always starting with `/`) and `{query}` (`?` and the query string, or nothing).
- No spaces, control characters (so no CR or LF), `"`, `'`, backslash, `#`, `$`, backtick, `<` or `>`; at most 512 characters. A literal `%` is allowed and sent as `%`. The host part of an absolute URL may hold only letters, digits, `.`, `-`, `:` and host placeholders (no `@`, so no `user@host` tricks).
- `{www_host}` and `{apex_host}` cannot be combined.

A `{www_host}` rule and an `{apex_host}` rule that are both enabled for the same site, or one unscoped and one scoped to it, would send a request back and forth forever, so the config is refused with an error naming both rules. Scope them to different sites or disable one.

Redirects cannot loop on their own. A `{www_host}` redirect only fires when the host does not already start with `www.`, and an `{apex_host}` redirect only when it does. Other shapes are checked when the rule is saved: a redirect that keeps the host needs a `path_prefix` or `path_regex` matcher (and a static path target must not start with the matched prefix); an `https://{host}...` redirect needs `"scheme": "http"`; a redirect to another host needs some matcher; and `{scheme}://{host}{path}` with nothing changed is refused outright. A redirect to a host that this node also serves is still your responsibility to keep acyclic.

A redirect to the node's own HTTPS (`https://` with a host placeholder) is not rendered when the node has no HTTPS listener on port 443, and it is never applied to Flexible SSL sites, which must not redirect because Cloudflare owns the scheme there. Redirects only apply to requests that matched a site.

### Header changes

```json
{"id": "sec-headers", "name": "Security headers", "enabled": true, "site": "shop",
 "headers": [
   {"target": "response", "op": "set", "name": "X-Frame-Options", "value": "DENY"},
   {"target": "request", "op": "remove", "name": "X-Debug"}
 ]}
```

`target` is `request` or `response`, `op` is `set` (replace), `add` (append) or `remove` (no `value`). At most 16 changes per rule. Values are 1 to 512 printable ASCII characters without `"`, backslash or `$`; they are literal text, never templates (a `%` is sent as `%`). Names follow the header matcher's name rules, with these refusals:

- Never allowed, for any target and operation: `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Keep-Alive`, `Upgrade`, `TE`, `Trailer`, `Expect`, and anything starting with `Proxy-`, `Sec-` or `X-Cite-`.
- Request `set` and `add` are also refused for client-identity headers: `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Forwarded-Port`, `X-Real-IP`, `Forwarded`, `True-Client-IP` and anything starting with `CF-`. Removing them is allowed.

### CORS

```json
{"id": "cors-app", "name": "CORS for the app", "enabled": true, "site": "api",
 "cors": {"origins": ["https://app.example.com"], "methods": ["GET", "POST"],
          "allow_headers": ["Content-Type", "Authorization"], "expose_headers": ["X-Request-Id"],
          "credentials": true, "max_age_secs": 600}}
```

`origins` holds 1 to 32 exact origins (`https://app.example.com`, optional port, no path, no wildcard host), or the single entry `"*"`. `methods`, `allow_headers` and `expose_headers` hold up to 32 entries each; `max_age_secs` is 0 to 86400. `"*"` together with `credentials`, or mixed with other origins, is refused.

- A request whose `Origin` equals a listed origin character for character gets CORS headers. An unlisted origin gets none, and the `Origin` value is only ever echoed behind that exact match, never reflected for arbitrary origins.
- A preflight (`OPTIONS` with `Access-Control-Request-Method`) from a listed origin is answered 204 by the edge, without reaching the upstream, with `Access-Control-Allow-Origin`, `-Allow-Credentials` (when set), `-Allow-Methods`, `-Allow-Headers` and `-Max-Age` (each only when configured) and `Vary: Origin`. A preflight from an unlisted origin goes to the upstream like any other request.
- Normal responses to a listed origin get `Access-Control-Allow-Origin`, `-Allow-Credentials` (when set) and `-Expose-Headers` (when set). A request with two `Origin` headers is treated as having none, because HAProxy could otherwise echo the unlisted copy.
- Without `"*"`, every response the rule applies to carries `Vary: Origin`, including requests with no or an unlisted `Origin`, so shared caches keep the variants apart. With `"*"` the value is a literal `*` and no `Vary` is added.

The source address is the one HAProxy sees on the TCP connection. Behind another proxy or load balancer that is the proxy's address, not the visitor's, and `cidrs` and the rate limit act on it. The one exception is Cloudflare: for every site, a connection whose TCP peer is in the Cloudflare range list and that carries exactly one valid `CF-Connecting-IP` has its source address replaced by that header, so `cidrs` and the rate limit see the visitor and not the shared Cloudflare edge address. The header is never trusted from any other peer.

### Limits on what you can write

Values become words in the HAProxy config, so they are checked before rendering:

- Rule, site and page ids match `^[a-z0-9][a-z0-9-]{0,39}$`.
- Patterns are 1 to 256 printable ASCII characters. `#`, `"` and `'` are not allowed. Spaces cannot be written; use `\s` in a regex (POSIX classes such as `[[:space:]]` are not part of the regex subset).
- A pattern cannot start with `-`, equal a HAProxy keyword such as `if` or `or`, contain a doubled or trailing backslash, or contain `$` followed by a name.
- Regexes must compile. Path prefixes must start with `/`.
- Regexes cannot contain `\x` escapes. HAProxy turns `\xNN` into a raw byte before the regex is parsed, so `\x7d` becomes `}` and breaks the config. Write the character itself or a class.
- Regexes run on PCRE2 in HAProxy, which backtracks, and a PCRE2 match-limit error counts as no match, which would make a deny rule fail open (a stalled match can also take the HAProxy process down). So a regex is parsed against a small whitelist grammar and refused with an error naming the construct if it uses anything else. See [Regex subset](#regex-subset).
- A config holds at most 1000 sites, 1000 pages and 5000 rules.

The connector also asks `haproxy -c` to check the final file, so a regex that HAProxy's engine rejects is refused with its error message.

### Regex subset

Every regex field (`path_regexes`, `user_agent_regexes`, `referer_regexes`, a header matcher's `regex`, and a site's `path_regexes`) accepts only this subset, on which PCRE2 and Rust's regex crate agree:

- Literal characters and escaped punctuation (`\. \/ \- \_ \+ \* \? \( \) \| \[ \] \{ \} \^ \$ \, \: \; \= \! \@ \% \& \~`); the dot; the anchors `^` and `$`; `\b` and `\B`; the shorthands `\d \D \w \W \s \S`.
- Character classes made of single characters, ranges (`a-z`), the shorthands above and escaped punctuation, optionally negated with a leading `^`. A `-` must start or end the class. No nested classes and no POSIX classes (`[[:alpha:]]`, `[[.x.]]`, `[[=x=]]`): any `[` inside a class is refused, as is `^` anywhere but first.
- Capturing groups and `(?:...)` groups, alternation `|`, and the flag `(?i)` at the very start only.
- The repeats `?`, `*`, `+`, `{n}`, `{n,}` and `{n,m}` with counts up to 1000. Lazy (`*?`) and possessive (`*+`) forms, repeating an anchor, and stacked repeats are refused.
- Refused: every other inline flag, `\Q..\E`, lookarounds, backreferences, atomic groups, conditionals, recursion, named groups, comments, `\p` properties, `\A \z \Z \n \t` and any other alphanumeric escape, `{,n}`, an unescaped `{`, `}` or `]`, and groups nested deeper than 8.
- A group may be repeated more than once (`+`, `*`, `{n,m}` with m above 1) only when it holds plain text: no alternation, no repeat, no other group. `(ab)+` is fine, `(a|b)+` and `(a+)+` are not. `?` on any group is fine.

The pattern must also compile with the regex crate, and its worst-case cost must be bounded for the subject length it will see. Three bounds apply. The product of all repeat counts (each limited to the cap, and a `?` counting 2) times the start positions (the cap, or 1 when every branch begins with `^`) must stay at or below 20,000,000. The work from a single start position, that product times an ambiguity factor for alternatives that start alike, must stay at or below 250,000, well under PCRE2's default match limit of 10 million (whose error HAProxy treats as no match). And at most 3 repeats may apply at once, where each `?` counts as one. In practice a pattern holds one unbounded repeat (`[a-z]+!`, `[^/]*`) or several bounded ones with small counts (`^[a-z]{1,60}[a-z]{1,60}[a-z]{1,60}!`); two unbounded repeats (`^[a-z]*[a-z]*!`), `.*.*.*.*`, `[a-z]{1,1000}` three times, `^[a-z]{1,1000}[a-z]{1,1000}[a-z]{1,76}!`, `(a|a){32}b`, `[[:a](x+)+y[:]]` and four or more `a?` in a row are all refused.

Matching sees only the first bytes of its subject, so the work is bounded whatever a client sends:

| Subject | Bytes matched |
|---|---|
| `User-Agent` (`user_agent_regexes`) | first 512 |
| `Referer` (`referer_regexes`) | first 1024 |
| a header (`headers[].regex`) | first 1024 |
| the path (`path_regexes`, rule or site), as sent and canonical | first 2048 |

What happens to a longer value depends on the field:

- **User agent and path, blocking rules (`deny`, `drop`, `tarpit`):** a longer subject counts as a match, so padding a value past the cap can never evade the rule. An over-long user agent is denied by any `user_agent_regexes` deny rule, and a path over 2048 bytes by any `path_regexes` rule, even if the regex would not have matched. The one exception is the empty-agent test `^$`, which padding cannot defeat.
- **User agent and path, effect rules (redirects, header changes, CORS):** a longer subject matches nothing and no effect applies. A site's `path_regexes` treat a path over 2048 bytes as not matching (its `path_prefixes` do not look at the length), so it falls through to the 404 exactly like any other unmatched request.
- **Referer and header regexes (any rule):** the regex is evaluated on the first 1024 bytes only, and a longer value is neither a match nor a non-match by itself. Referers and cookies longer than that are routine (click ids, SSO return URLs), so failing closed would deny real visitors. A negated header regex is evaluated on the same prefix, and a request without the header matches the negated test as before.

Because of that last point, referer and header regexes are advisory signals: padding a value past 1024 bytes can hide text from a deny rule. Anything that must not be evaded should use an `equals` header matcher (compared in full), a path or user-agent rule, or the zone lock. The bot-policy token regexes are literal alternations, run on the whole header and are exempt from the cap.

### Targets and health checks

A site target is `host:port` or `[ipv6]:port`. The edge refuses targets that would point it at its own control plane or at local services:

- Loopback (`127.0.0.0/8`, `::1`), unspecified (`0.0.0.0`, `::`), `0.0.0.0/8`, link-local (`169.254.0.0/16`, `fe80::/10`, which includes the cloud metadata address), multicast and the IPv4 broadcast address.
- `172.30.250.0/29`. HAProxy's admin and master listeners no longer use a network, because they are unix sockets, but the range stays refused.
- The IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible and NAT64 (`64:ff9b::/96`) IPv6 forms of all of the above.
- The names `localhost`, anything ending in `.localhost`, and the names of the stack's own services: `haproxy`, `connector` and `dockerproxy` (plus one older proxy name).
- Decimal, octal, hex and short IPv4 spellings such as `2130706433`, `0177.0.0.1`, `0x7f.1` and `127.1`. A name whose last label is numeric must be a canonical dotted IPv4 address.

Names ending in `.internal` are allowed because they are common for real services. A name is checked as written and not by where it resolves, so keep DNS you do not control out of target names.

Health settings are bounded so a bad target cannot be kept up indefinitely: `interval_ms` 100 to 60000, `timeout_ms` 100 to 10000 and not above `interval_ms`, `rise` and `fall` 1 to 10.

### Scope

A rule with a `site` id applies only to requests that match that site's host, and its path regex if it has one. A rule without a site applies to every request on the node. The site must exist.

## Bot policy

A site decides what happens to requests from known bots with `access.bots`:

```json
"access": {"bots": "block_bad"}
```

| Value | Effect |
|---|---|
| `allow` (default) | Nothing is blocked. Omitted from the JSON while it is the default. |
| `block_bad` | Answers 403 to requests whose `User-Agent` contains a known HTTP-library or scanner token: the tool list of the bot classifier (`curl/`, `wget`, `python-requests`, `python`, `go-http-client`, `okhttp`, `java/`, `axios`, `scrapy` and so on) and the scanner list of the `scanners` preset (`sqlmap`, `nikto`, `nmap`, `masscan`, `zgrab`, `gobuster`, `dirbuster`, `wpscan`, `nuclei`, `acunetix`, `havij`). |
| `block_all` | Every token class the classifier treats as a bot: everything in `block_bad`, plus the crawler list (search engines such as Googlebot, Bingbot, Baiduspider, Yandex and DuckDuckBot; link previews for Slack, Twitter, LinkedIn, Facebook, Discord and Telegram; SEO and AI crawlers; uptime monitors), the generic markers `bot/`, `+http`, `spider` and `crawl`, the automation tools (`headlesschrome`, `phantomjs`, `selenium`, `puppeteer`, `playwright`) and the generic `scrape` marker. |

The patterns are built at render time from the same token lists the Traffic bot classifier uses (`cite-edge/src/bot.rs`), as one case-insensitive regex per class, so what is blocked and what is reported as a tool or crawler cannot drift apart. A request with no `User-Agent` at all is not matched by either policy; use the `scanners` preset's empty-agent rule for that.

Blocked requests are still logged. The decision is a block labelled `bots-bad` or `bots-all`, recorded with the user agent, so Traffic shows them in the blocked-by-rule table and the bot class (tool, crawler) and score are still computed from the logged user agent. The rule runs after the Cloudflare check and the firewall rules and, like them, after the rate limiter has counted the request.

Read this before turning it on:

- User-agent matching is advisory. The header is chosen by the client, and any scraper can send a browser's. It stops honest tools and lazy scripts, not an attacker.
- `block_all` also blocks search engines and link-preview bots, so the site disappears from search results and shares lose their preview cards. It also blocks uptime monitors. Do not use it on a site that depends on search traffic.
- The `python` and `java/` tokens match any user agent containing them, including some legitimate API clients and mobile apps. Test an API's own clients before using `block_bad` on a `kind: "api"` site.

## Presets

A preset is a fixed set of rules you add with one call: `POST /api/v1/firewall/presets/{name}/apply` returns the rules it added, and `GET /api/v1/firewall/presets` lists them. Rule ids are `preset-<name>-<n>` and stay the same between releases.

| Preset | Rule id | Action | Matches |
|---|---|---|---|
| `sensitive-files` | `preset-sensitive-files-1` | drop | Dotfiles and anything after the name: `.env` (so `.env~`, `.env-prod`, `.env.local`), `.git`, `.svn`, `.hg`, `.htaccess`, `.htpasswd`, `.ds_store`, `.npmrc`, `.netrc`, `.pypirc`, `.dockerenv`, `.dockerignore`, `.bash_history`, `.aws`, `.ssh` |
| | `preset-sensitive-files-2` | drop | Private keys and keystores: `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519` with any suffix, `*private*.pem` and `*privkey*.pem`, and files ending in `.key`, `.p12`, `.pfx`, `.jks`, `.keystore`. Other `.pem` files, such as public certificates, are not matched |
| | `preset-sensitive-files-3` | drop | `wp-config`, `wp-config.php` and variants |
| | `preset-sensitive-files-4` | drop | Paths ending in `.sql`, `.bak`, `.swp`, `.swo`, `.orig`, `.old`, `.save` or `~` |
| | `preset-sensitive-files-5` | drop | Archives named `backup`, `dump`, `db`, `database`, `www`, `site` or `public_html` as `.zip`, `.tar`, `.tgz`, `.gz`, `.7z`, `.rar` |
| | `preset-sensitive-files-6` | drop | `docker-compose*.yml`/`.yaml`, `Dockerfile*`, `composer.json`, `composer.lock`. `package.json` is not matched because some sites serve it |
| `cms-probes` | `preset-cms-probes-1` | drop | `wp-login.php`, `wp-admin`, `xmlrpc.php` |
| | `preset-cms-probes-2` | drop | `phpmyadmin`, `pma`, `myadmin`, `mysqladmin` |
| | `preset-cms-probes-3` | drop | `vendor/phpunit`, `cgi-bin`, `boaform`, `HNAP1` |
| | `preset-cms-probes-4` | drop | `actuator`, `solr`, `manager/html` |
| `scanners` | `preset-scanners-1` | tarpit | User agents containing sqlmap, nikto, nmap, masscan, zgrab, gobuster, dirbuster, wpscan, nuclei, acunetix or havij |
| | `preset-scanners-2` | tarpit | An empty user agent |
| `odd-methods` | `preset-odd-methods-1` | deny | `TRACE`, `TRACK`, `CONNECT`, `DEBUG` |
| `redirect-to-www` | `preset-redirect-to-www-1` | redirect 301 | `{scheme}://{www_host}{path}{query}`, only when the host does not already start with `www.` |
| `redirect-to-apex` | `preset-redirect-to-apex-1` | redirect 301 | `{scheme}://{apex_host}{path}{query}`, only when the host starts with `www.` |
| `force-https` | `preset-force-https-1` | redirect 301 | `https://{host}{path}{query}` for requests with `scheme` `http` |

The three redirect presets have no `site`, so applied as they are they would act on every site on the node. Set `site` on the rule to apply one to a single site, and never enable `redirect-to-www` and `redirect-to-apex` for the same site: they undo each other. `redirect-to-www` rewrites every host of the site, so scope it to a site whose hosts are the bare domain and its `www` alias, not one that also serves other subdomains. `force-https` is skipped (not rendered) on a node with no HTTPS listener on port 443, and for Flexible SSL sites; the redirect keeps the `Host` header's port, so it assumes HTTPS is on 443. Let certificates exist before turning it on, or visitors are sent to a port that cannot complete a handshake.

The path presets use the `(?i)` flag so they match in any case. That needs a HAProxy built with PCRE. The HAProxy container and the connector image's `haproxy -c` check both use `haproxy:3.2-bookworm` by default. If the binary rejects the flag, applying the preset fails at the `haproxy -c` step and the stored configuration is restored.

Presets are ordinary rules once added. Edit, disable or delete them like any other.

### Upgrading from an earlier release

Rules saved by an earlier release are checked against the [regex subset](#regex-subset) when the node starts, and nothing is silently deleted:

- Only known old regexes are rewritten: a rule with the id `preset-sensitive-files-2`, `-4`, `-5` or `-6`, or `preset-cms-probes-2` or `-4`, that has an entry in `path_regexes` exactly equal to the text the previous release stored (its single `path_regex`) gets that entry replaced by the current preset's pattern. Every other entry and matcher, the action, the enabled flag, the site, the label and the name stay as they are.
- Owner edits are kept. A preset rule you changed (a different pattern, an added host, CIDR or user agent token, a narrower scope) or reused for another purpose is never touched, as long as it still passes the current limits.
- Any other enabled rule that the current limits refuse, such as `.*bot.*`, `[[:space:]]`, a repeat count above 1000 or a nested quantifier, is switched off and stays in the file. Rewrite its pattern and enable it again. A disabled rule's patterns are not checked when the configuration loads, because it is never rendered, but saving a disabled rule through the API validates it fully.
- A site whose `path_regexes` has a refused entry is not changed, and the node refuses to start with an error naming the site. Fix the pattern in the stored configuration first.

Each rewritten or disabled rule is reported by id, running the migration again changes nothing, and a configuration that already validates and holds no known old pattern is left exactly as it is.

## Rate limit

`settings.per_ip_rate_limit` is the number of requests one source address may make in a 10 second window. The default is 600. Over the limit, HAProxy answers 429 and logs the block as `rate-limit`. Requests that arrive through Cloudflare are counted per visitor (from `CF-Connecting-IP`), not per Cloudflare edge address; direct connections are counted per TCP source address. Set it to `null` to turn it off; the valid range is 1 to 1000000.

HAProxy tracks sources in an IPv6-keyed stick table (IPv4 addresses are stored in their mapped form, so both families are counted) of 200000 entries that expire after 10 minutes without traffic. `settings.max_body_bytes` (off by default) rejects requests whose `Content-Length` exceeds it with 413.

## Maintenance pages

Maintenance mode is per site. While it is on, every request that matches the site's host and path gets the page instead of reaching a backend. Other sites on the node are not affected. Firewall rules still run first.

| Item | Detail |
|---|---|
| Default page | A built-in dark HTML page ("We will be right back"), self-contained with no external requests, served with status 503. |
| Custom pages | Created with `POST /api/v1/pages`: an id, a name, the HTML (up to 15000 bytes) and a status from 400 to 599, default 503. |
| Choosing a page | `POST /api/v1/sites/{id}/maintenance` with `{"enabled": true, "page_id": "..."}`. Without a page the default is used. |
| Headers | `Content-Type: text/html; charset=utf-8` and `Cache-Control: no-store`. |
| Deleting | A page used by a site cannot be deleted. |

The 15000 byte limit comes from HAProxy, which loads a page into one buffer (`tune.bufsize`, 16384 bytes by default) and refuses a larger file at the config check. The limit leaves room for headers. Raising `tune.bufsize` would lift it but costs memory on every connection, so it is not changed. Keep CSS inline, use small data URIs, and link large assets from elsewhere.

Turning maintenance off without naming a page keeps the earlier page choice, so turning it on again restores it.

## Maps and reloads

Two small map files sit in `/conf/haproxy/maps/`, one line per site id. A third file, `cloudflare.lst`, holds the Cloudflare ranges (one CIDR per line) and is only filled while a site uses Cloudflare-only or Flexible SSL; it is part of the config hash, so changing the ranges reloads HAProxy.

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

What does cause a reload is any change to the rendered config or the page files: adding or removing sites, editing hosts, health checks, targets or firewall rules, or changing which page a site uses. The connector computes a hash over the config, both maps and all pages, skips the work when it matches what is installed, and otherwise validates, writes the files and sends `reload` to HAProxy's master CLI socket. The change counts as applied only after `show info` on the admin socket reports a new process. `POST /api/v1/haproxy/reload` forces a reload even when the hash matches, and a refused or unconfirmed reload makes the change fail instead of leaving a stored config HAProxy never loaded.

### Blue/green deploy sequence

1. Write the new targets into the idle slot. This changes the rendered config, so HAProxy reloads once.
2. Wait up to 60 seconds for every server in the idle backend to pass its health check. On failure, record a `failed` deployment and leave the active slot alone.
3. Update `active.map` through the runtime socket. If that fails, the old value is written back to the file.
4. Record the deployment, then update the stored active slot.

With the orchestrator on, the old slot's stack is stopped 30 seconds after the switch unless the site moved back. Rollback and switch use the same steps 2 to 4, and refuse a slot that has no targets or is not healthy.

Backends with more than one target use `leastconn`, and a single target uses `roundrobin`. Health checks send `GET <path>` at the configured interval. The defaults are path `/`, every 2000 ms, 1500 ms timeout, healthy after 2 passes and down after 3 failures.

## What the firewall does not do

- It does not inspect request bodies or response contents.
- It matches only the nine matchers above. There is no rule on query strings or cookies, and the header matcher reads one named header.
- User-agent, referer and header checks trust what the client sends. They are filters, not authentication; the one header check meant as a credential is the [zone lock](sites.md#zone-lock-prove-the-request-came-through-your-cloudflare-zone) secret, and in Flexible SSL mode that secret crosses the Cloudflare to origin hop in cleartext.
- Rate limiting is per source address and per node. Nodes do not share counters.
- It is not a web application firewall. It removes known probe traffic and gives you a fast way to block an address or path.
