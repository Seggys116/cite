use sha2::{Digest, Sha256};

use crate::logparse::LOG_FORMAT;
use crate::model::{EdgeConfig, FirewallAction, FirewallRule, Site, Slot};
use crate::validate::{ValidationError, invalid, parse_cidr, validate_config};

const HOST_FETCH: &str = "var(txn.host)";
// Runs of at least this many plain sites are routed by one map lookup instead of one ACL each.
const MAP_RUN_MIN: usize = 4;
// HAProxy cuts configuration lines at 2048 bytes and 64 words, so long pattern lists are split over repeated ACLs.
const MAX_ACL_LINE: usize = 1500;
const MAX_ACL_VALUES: usize = 48;
const DEFAULT_PAGE_FILE: &str = "_default.html";
const DEFAULT_PAGE_STATUS: u16 = 503;

pub const DEFAULT_PAGE_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Back soon</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #0e1116;
    color: #e6e9ee;
    font: 16px/1.6 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  }
  main {
    max-width: 30rem;
    margin: 2rem;
    padding: 2.5rem;
    border: 1px solid #262c36;
    border-radius: 12px;
    background: #151a22;
  }
  h1 { margin: 0 0 0.75rem; font-size: 1.6rem; font-weight: 600; }
  p { margin: 0; color: #9aa4b2; }
  .bar { width: 3rem; height: 4px; margin-bottom: 1.5rem; border-radius: 2px; background: #4f8cff; }
</style>
</head>
<body>
<main>
  <div class="bar"></div>
  <h1>We will be right back</h1>
  <p>This site is undergoing scheduled maintenance. Please try again in a few minutes.</p>
</main>
</body>
</html>
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderOptions {
    pub maps_dir: String,
    pub pages_dir: String,
    pub runtime_addr: String,
    pub log_addr: String,
    pub tls_dir: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    pub config: String,
    pub active_map: String,
    pub maint_map: String,
    pub pages: Vec<(String, String)>,
}

// Option values land in global directives and map paths, so they get the same word-safety rules.
fn check_option(what: &str, s: &str, extra: &[u8]) -> Result<(), ValidationError> {
    let ok = !s.is_empty()
        && s.len() <= 512
        && s.bytes().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, b'/' | b'.' | b'_' | b'-')
                || extra.contains(&c)
        });
    if !ok {
        return invalid(format!(
            "render option {what}: {s:?} is empty or has unsafe characters"
        ));
    }
    Ok(())
}

// Socket paths are absolute, short enough for sun_path and free of dot segments.
fn check_socket_path(what: &str, path: &str) -> Result<(), ValidationError> {
    let ok = path.starts_with('/')
        && path.len() <= 107
        && path
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'/' | b'.' | b'_' | b'-'))
        && path.split('/').all(|seg| seg != "." && seg != "..");
    if !ok {
        return invalid(format!(
            "render option {what}: {path:?} must be an absolute socket path of at most 107 characters without dot segments"
        ));
    }
    Ok(())
}

fn check_host_port(what: &str, s: &str) -> Result<(), ValidationError> {
    let ok = s
        .rsplit_once(':')
        .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok_and(|p| p > 0));
    if !ok {
        return invalid(format!("render option {what}: {s:?} must be host:port"));
    }
    Ok(())
}

// The admin socket is either a unix socket path or a TCP listener, with or without an ipv4@ or ipv6@ prefix.
fn check_runtime_addr(s: &str) -> Result<(), ValidationError> {
    check_option("runtime_addr", s, b"@:[]")?;
    match s.strip_prefix("unix@") {
        Some(path) => check_socket_path("runtime_addr", path),
        None => {
            let rest = s
                .strip_prefix("ipv4@")
                .or_else(|| s.strip_prefix("ipv6@"))
                .unwrap_or(s);
            check_host_port("runtime_addr", rest)
        }
    }
}

// The log target is a unix datagram socket path or a UDP host:port.
fn check_log_addr(s: &str) -> Result<(), ValidationError> {
    check_option("log_addr", s, b"@:[]")?;
    if s.starts_with('/') {
        return check_socket_path("log_addr", s);
    }
    let rest = s.rsplit_once('@').map_or(s, |(_, r)| r);
    check_host_port("log_addr", rest)
}

fn validate_options(opts: &RenderOptions) -> Result<(), ValidationError> {
    check_option("maps_dir", &opts.maps_dir, b"")?;
    check_option("pages_dir", &opts.pages_dir, b"")?;
    check_runtime_addr(&opts.runtime_addr)?;
    check_log_addr(&opts.log_addr)?;
    if let Some(dir) = &opts.tls_dir {
        check_option("tls_dir", dir, b"")?;
    }
    Ok(())
}

// Used for the log format only, which contains spaces and must stay one config word.
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' | '\r' => out.push(' '),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn push(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}

fn push_in(out: &mut String, line: &str) {
    out.push_str("    ");
    push(out, line);
}

fn dir_join(dir: &str, file: &str) -> String {
    format!("{}/{}", dir.trim_end_matches('/'), file)
}

// Exact hosts and wildcard suffixes need different match methods, so they become two ACL lines.
fn host_patterns(hosts: &[String]) -> (Vec<String>, Vec<String>) {
    let mut exact: Vec<String> = Vec::new();
    let mut suffix: Vec<String> = Vec::new();
    for host in hosts {
        let host = host.to_ascii_lowercase();
        let (list, value) = match host.strip_prefix('*') {
            Some(rest) => (&mut suffix, rest.to_string()),
            None => (&mut exact, host),
        };
        if !list.contains(&value) {
            list.push(value);
        }
    }
    (exact, suffix)
}

fn chunked_acl(name: &str, matcher: &str, values: &[String]) -> Vec<String> {
    let head = format!("acl {name} {matcher}");
    let mut lines = Vec::new();
    let mut line = head.clone();
    let mut count = 0;
    for value in values {
        if count >= MAX_ACL_VALUES || (count > 0 && line.len() + 1 + value.len() > MAX_ACL_LINE) {
            lines.push(std::mem::replace(&mut line, head.clone()));
            count = 0;
        }
        line.push(' ');
        line.push_str(value);
        count += 1;
    }
    if count > 0 {
        lines.push(line);
    }
    lines
}

fn host_acl_lines(name: &str, hosts: &[String]) -> Vec<String> {
    let (exact, suffix) = host_patterns(hosts);
    let mut lines = chunked_acl(name, &format!("{HOST_FETCH} -m str"), &exact);
    lines.extend(chunked_acl(name, &format!("{HOST_FETCH} -m end"), &suffix));
    lines
}

fn host_inline(host: &str) -> String {
    let host = host.to_ascii_lowercase();
    match host.strip_prefix('*') {
        Some(rest) => format!("{{ {HOST_FETCH} -m end {rest} }}"),
        None => format!("{{ {HOST_FETCH} -m str {host} }}"),
    }
}

// A site matched by its own ACLs; plain sites in a long run are matched through the host map instead.
fn site_cond(site: &Site) -> String {
    match site.path_regex {
        Some(_) => format!("host_{0} path_{0}", site.id),
        None => format!("host_{}", site.id),
    }
}

// A repeated acl name is an OR, so each path matcher tests the path as sent and as a plain origin would decode it.
fn rule_acl_lines(rule: &FirewallRule) -> Vec<String> {
    let m = &rule.matchers;
    let mut lines = Vec::new();
    if let Some(re) = &m.path_regex {
        lines.push(format!("acl rp_{} path_reg -- {re}", rule.id));
        lines.push(format!("acl rp_{} path,url_dec -m reg -- {re}", rule.id));
    }
    if let Some(p) = &m.path_prefix {
        lines.push(format!("acl rb_{} path_beg {p}", rule.id));
        lines.push(format!("acl rb_{} path,url_dec -m beg {p}", rule.id));
    }
    lines
}

// Cheap matchers come first because HAProxy stops at the first condition that fails.
fn rule_cond(rule: &FirewallRule, cfg: &EdgeConfig) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(site) = rule
        .site
        .as_ref()
        .filter(|sid| cfg.sites.iter().any(|s| &s.id == *sid))
    {
        parts.push(format!("{{ var(txn.site) -m str {site} }}"));
    }
    let m = &rule.matchers;
    if !m.methods.is_empty() {
        parts.push(format!("{{ method {} }}", m.methods.join(" ")));
    }
    let cidrs: Vec<String> = m.cidrs.iter().filter_map(|c| parse_cidr(c)).collect();
    if !cidrs.is_empty() {
        parts.push(format!("{{ src {} }}", cidrs.join(" ")));
    }
    if let Some(h) = &m.host {
        parts.push(host_inline(h));
    }
    if m.path_prefix.is_some() {
        parts.push(format!("rb_{}", rule.id));
    }
    if m.path_regex.is_some() {
        parts.push(format!("rp_{}", rule.id));
    }
    if let Some(re) = &m.user_agent_regex {
        parts.push(format!("{{ req.hdr(user-agent) -m reg -- {re} }}"));
    }
    parts.join(" ")
}

fn render_global(cfg: &EdgeConfig, opts: &RenderOptions, tls: bool, out: &mut String) {
    push(
        out,
        "# generated by cite-edge; changes are overwritten on the next render",
    );
    push(out, "global");
    // normalize-uri is still marked experimental in haproxy 3.0
    push_in(out, "expose-experimental-directives");
    // len 8192 keeps long request lines from cutting the trailing log fields
    push_in(
        out,
        &format!("log {} len 8192 format rfc5424 local0", opts.log_addr),
    );
    push_in(out, &format!("maxconn {}", cfg.settings.max_conn));
    // a unix socket is reachable only through the shared volume, so it is owner-only
    let socket_mode = if opts.runtime_addr.starts_with("unix@") {
        " mode 600"
    } else {
        ""
    };
    push_in(
        out,
        &format!(
            "stats socket {}{socket_mode} level admin expose-fd listeners",
            opts.runtime_addr
        ),
    );
    if tls {
        push_in(out, "tune.ssl.default-dh-param 2048");
        push_in(
            out,
            "ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets",
        );
        push_in(
            out,
            "ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305",
        );
        push_in(
            out,
            "ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
        );
    }
    push(out, "");
}

// Names resolve lazily so a stopped standby slot cannot stop HAProxy from loading.
fn render_resolvers(out: &mut String) {
    push(out, "resolvers cite");
    push_in(out, "parse-resolv-conf");
    push_in(out, "resolve_retries 3");
    push_in(out, "timeout resolve 1s");
    push_in(out, "timeout retry 1s");
    push_in(out, "hold valid 10s");
    push_in(out, "hold nx 5s");
    push(out, "");
}

fn render_defaults(cfg: &EdgeConfig, out: &mut String) {
    let s = &cfg.settings;
    push(out, "defaults");
    push_in(out, "mode http");
    push_in(out, "log global");
    push_in(out, "option forwardfor");
    push_in(out, "option http-keep-alive");
    push_in(out, "option abortonclose");
    push_in(out, "http-reuse safe");
    push_in(out, &format!("timeout connect {}ms", s.connect_timeout_ms));
    push_in(out, &format!("timeout client {}ms", s.client_timeout_ms));
    push_in(out, &format!("timeout server {}ms", s.server_timeout_ms));
    push_in(out, "timeout http-request 10s");
    push_in(out, "timeout http-keep-alive 10s");
    push_in(out, "timeout tarpit 5s");
    push(out, "");
}

// The condition is evaluated once; the action then tests the variable, which also names the rule in the log.
fn action_lines(rule: &FirewallRule, cond: &str, out: &mut String) {
    push_in(
        out,
        &format!(
            "http-request set-var(txn.blocked) str({}) if {cond}",
            rule.id
        ),
    );
    let action = match rule.action {
        FirewallAction::Deny => "deny deny_status 403",
        FirewallAction::Drop => "silent-drop",
        FirewallAction::Tarpit => "tarpit",
    };
    push_in(
        out,
        &format!(
            "http-request {action} if {{ var(txn.blocked) -m str {} }}",
            rule.id
        ),
    );
}

enum Segment<'a> {
    Map(&'a [Site]),
    One(&'a Site),
}

fn is_plain(site: &Site) -> bool {
    site.path_regex.is_none() && site.hosts.iter().all(|h| !h.starts_with('*'))
}

// Config order decides which site claims a request, so only neighbouring plain sites share a map.
fn segments(sites: &[Site]) -> Vec<Segment<'_>> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(site) = sites.get(i) {
        if !is_plain(site) {
            out.push(Segment::One(site));
            i += 1;
            continue;
        }
        let end = sites[i..]
            .iter()
            .position(|s| !is_plain(s))
            .map_or(sites.len(), |p| i + p);
        if end - i >= MAP_RUN_MIN {
            out.push(Segment::Map(&sites[i..end]));
        } else {
            out.extend(sites[i..end].iter().map(Segment::One));
        }
        i = end;
    }
    out
}

// Keys are the lowercase host plus the run number; site ids never contain '@', so they cannot collide with the id keys.
fn host_entries(segs: &[Segment<'_>]) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    let mut run = 0;
    for seg in segs {
        let Segment::Map(sites) = seg else { continue };
        let mut seen = std::collections::HashSet::new();
        for site in *sites {
            for host in &site.hosts {
                let host = host.to_ascii_lowercase();
                if seen.insert(host.clone()) {
                    entries.push((format!("{host}@{run}"), site.id.clone()));
                }
            }
        }
        run += 1;
    }
    entries
}

struct PageRef {
    file: String,
    status: u16,
}

fn page_for(site: &Site, cfg: &EdgeConfig) -> PageRef {
    let found = site
        .maintenance
        .page_id
        .as_ref()
        .and_then(|pid| cfg.pages.iter().find(|p| &p.id == pid));
    match found {
        Some(p) => PageRef {
            file: format!("{}.html", p.id),
            status: p.status,
        },
        None => PageRef {
            file: DEFAULT_PAGE_FILE.to_string(),
            status: DEFAULT_PAGE_STATUS,
        },
    }
}

fn render_frontend(
    cfg: &EdgeConfig,
    segs: &[Segment<'_>],
    opts: &RenderOptions,
    tls: bool,
    out: &mut String,
) {
    let s = &cfg.settings;
    let active_path = dir_join(&opts.maps_dir, "active.map");
    let maint_path = dir_join(&opts.maps_dir, "maint.map");
    push(out, "frontend fe_main");
    push_in(out, &format!("log-format {}", quote(LOG_FORMAT)));
    push_in(out, &format!("bind :{}", s.http_port));
    if let (true, Some(port), Some(dir)) = (tls, s.https_port, &opts.tls_dir) {
        push_in(out, &format!("bind :{port} ssl crt {dir} alpn h2,http/1.1"));
    }
    // path rules must see what the origin will see, so the path is normalised before anything reads it
    for normalizer in [
        "percent-to-uppercase",
        "percent-decode-unreserved",
        "path-merge-slashes",
        "path-strip-dot",
        "path-strip-dotdot",
        "fragment-strip",
    ] {
        push_in(out, &format!("http-request normalize-uri {normalizer}"));
    }
    // request headers are gone by log time, so the fields are copied into variables first
    for line in [
        "http-request set-var(txn.host) req.hdr(host),field(1,:),lower",
        "http-request set-var(txn.path) path",
        "http-request set-var(txn.qlen) query,length",
        "http-request set-var(txn.ua) req.fhdr(user-agent)",
        "http-request set-var(txn.ref) req.fhdr(referer)",
        "http-response set-var(txn.ct) res.hdr(content-type)",
    ] {
        push_in(out, line);
    }
    // a second or comma-joined Host lets a proxy and its origin disagree about the site
    push_in(
        out,
        "http-request deny deny_status 400 if { req.hdr_cnt(host) gt 1 }",
    );
    push_in(
        out,
        "http-request deny deny_status 400 if { req.fhdr(host) -m sub , }",
    );
    for seg in segs {
        let Segment::One(site) = seg else { continue };
        for line in host_acl_lines(&format!("host_{}", site.id), &site.hosts) {
            push_in(out, &line);
        }
        if let Some(re) = &site.path_regex {
            push_in(out, &format!("acl path_{} path_reg -- {re}", site.id));
            push_in(
                out,
                &format!("acl path_{} path,url_dec -m reg -- {re}", site.id),
            );
        }
    }
    // the first matching site labels the transaction, so blocked and maintenance requests still name a site
    let mut run = 0;
    for seg in segs {
        match seg {
            Segment::One(site) => push_in(
                out,
                &format!(
                    "http-request set-var(txn.site) str({}) if !{{ var(txn.site) -m found }} {}",
                    site.id,
                    site_cond(site)
                ),
            ),
            Segment::Map(_) => {
                push_in(
                    out,
                    &format!(
                        "http-request set-var(txn.site) var(txn.host),concat(@{run}),map({active_path}) if !{{ var(txn.site) -m found }}"
                    ),
                );
                run += 1;
            }
        }
    }
    push_in(
        out,
        "http-request set-header X-Forwarded-Proto https if { ssl_fc }",
    );
    push_in(
        out,
        "http-request set-header X-Forwarded-Proto http unless { ssl_fc }",
    );
    if let Some(limit) = s.per_ip_rate_limit {
        push_in(
            out,
            "stick-table type ip size 200k expire 10m store http_req_rate(10s)",
        );
        push_in(out, "http-request track-sc0 src");
        push_in(
            out,
            &format!("http-request deny deny_status 429 if {{ sc_http_req_rate(0) gt {limit} }}"),
        );
    }
    if let Some(max) = s.max_body_bytes {
        push_in(
            out,
            &format!(
                "http-request deny deny_status 413 if {{ req.hdr_val(content-length) gt {max} }}"
            ),
        );
    }
    for rule in cfg.firewall.iter().filter(|r| r.enabled) {
        for line in rule_acl_lines(rule) {
            push_in(out, &line);
        }
        action_lines(rule, &rule_cond(rule, cfg), out);
    }
    // maintenance rules are always emitted; the maint map toggles them at runtime without a reload
    let mut pages: Vec<(PageRef, Vec<String>)> = Vec::new();
    for site in &cfg.sites {
        let page = page_for(site, cfg);
        match pages
            .iter_mut()
            .find(|(p, _)| p.file == page.file && p.status == page.status)
        {
            Some((_, ids)) => ids.push(site.id.clone()),
            None => pages.push((page, vec![site.id.clone()])),
        }
    }
    for (i, (page, ids)) in pages.iter().enumerate() {
        for line in chunked_acl(&format!("maint_pg{i}"), "var(txn.site) -m str", ids) {
            push_in(out, &line);
        }
        push_in(
            out,
            &format!(
                "http-request return status {} content-type \"text/html; charset=utf-8\" file {} hdr cache-control no-store if maint_pg{i} {{ var(txn.site),map({maint_path},off) -m str on }}",
                page.status,
                dir_join(&opts.pages_dir, &page.file),
            ),
        );
    }
    // the active map picks blue or green, so switching slots is a runtime-API map update
    if !cfg.sites.is_empty() {
        push_in(
            out,
            &format!(
                "use_backend %[var(txn.site),map({active_path})] if {{ var(txn.site) -m found }}"
            ),
        );
    }
    push_in(out, "default_backend be_notfound");
    push(out, "");
}

fn render_backend(site: &Site, slot: Slot, out: &mut String) {
    let upstream = match slot {
        Slot::Blue => &site.blue,
        Slot::Green => &site.green,
    };
    let h = &site.health;
    push(out, &format!("backend be_{}_{}", site.id, slot.as_str()));
    let balance = if upstream.targets.len() > 1 {
        "leastconn"
    } else {
        "roundrobin"
    };
    push_in(out, &format!("balance {balance}"));
    push_in(out, &format!("option httpchk GET {}", h.path));
    push_in(out, &format!("timeout check {}ms", h.timeout_ms));
    for (i, t) in upstream.targets.iter().enumerate() {
        push_in(
            out,
            &format!(
                "server t{} {} check inter {}ms rise {} fall {} weight {} resolvers cite init-addr none",
                i + 1,
                t.addr,
                h.interval_ms,
                h.rise,
                h.fall,
                t.weight
            ),
        );
    }
    push(out, "");
}

fn render_notfound(out: &mut String) {
    push(out, "backend be_notfound");
    push_in(
        out,
        "http-request return status 404 content-type \"text/plain; charset=utf-8\" string \"not found\\n\"",
    );
}

pub fn render(cfg: &EdgeConfig, opts: &RenderOptions) -> Result<Rendered, ValidationError> {
    validate_config(cfg)?;
    validate_options(opts)?;
    let tls = cfg.settings.https_port.is_some() && opts.tls_dir.is_some();
    let mut config = String::new();
    render_global(cfg, opts, tls, &mut config);
    render_defaults(cfg, &mut config);
    render_resolvers(&mut config);
    let segs = segments(&cfg.sites);
    render_frontend(cfg, &segs, opts, tls, &mut config);
    for site in &cfg.sites {
        render_backend(site, Slot::Blue, &mut config);
        render_backend(site, Slot::Green, &mut config);
    }
    render_notfound(&mut config);

    let mut active: Vec<(&str, String)> = cfg
        .sites
        .iter()
        .map(|s| (s.id.as_str(), format!("be_{}_{}", s.id, s.active.as_str())))
        .collect();
    active.sort();
    let mut active_map: String = active.iter().map(|(k, v)| format!("{k} {v}\n")).collect();
    for (host, site) in host_entries(&segs) {
        active_map.push_str(&format!("{host} {site}\n"));
    }

    let mut maint: Vec<(&str, &str)> = cfg
        .sites
        .iter()
        .map(|s| {
            (
                s.id.as_str(),
                if s.maintenance.enabled { "on" } else { "off" },
            )
        })
        .collect();
    maint.sort();
    let maint_map: String = maint.iter().map(|(k, v)| format!("{k} {v}\n")).collect();

    let mut pages: Vec<(String, String)> = cfg
        .pages
        .iter()
        .map(|p| (format!("{}.html", p.id), p.html.clone()))
        .collect();
    pages.push((DEFAULT_PAGE_FILE.to_string(), DEFAULT_PAGE_HTML.to_string()));
    pages.sort();

    Ok(Rendered {
        config,
        active_map,
        maint_map,
        pages,
    })
}

// Each part is length-prefixed so moving bytes between parts changes the hash.
pub fn config_hash(rendered: &Rendered) -> String {
    let mut hasher = Sha256::new();
    let mut part = |bytes: &[u8]| {
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    };
    part(rendered.config.as_bytes());
    part(rendered.active_map.as_bytes());
    part(rendered.maint_map.as_bytes());
    for (name, html) in &rendered.pages {
        part(name.as_bytes());
        part(html.as_bytes());
    }
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FirewallAction, MaintenancePage, Matchers, Target};
    use crate::validate::fixtures::{config, rule, site};
    use proptest::prelude::*;

    fn opts() -> RenderOptions {
        RenderOptions {
            maps_dir: "/run/cite/maps".into(),
            pages_dir: "/run/cite/pages".into(),
            runtime_addr: "ipv4@127.0.0.1:9999".into(),
            log_addr: "127.0.0.1:514".into(),
            tls_dir: None,
        }
    }

    fn lines_with<'a>(r: &'a Rendered, needle: &str) -> Vec<&'a str> {
        r.config.lines().filter(|l| l.contains(needle)).collect()
    }

    fn position(r: &Rendered, needle: &str) -> usize {
        r.config.find(needle).unwrap_or(usize::MAX)
    }

    #[test]
    fn render_is_deterministic() {
        let cfg = config(vec![site("b", "b.com"), site("a", "a.com")]);
        let one = render(&cfg, &opts()).unwrap();
        let two = render(&cfg, &opts()).unwrap();
        assert_eq!(one, two);
        assert_eq!(config_hash(&one), config_hash(&two));
        assert_eq!(config_hash(&one).len(), 64);
    }

    #[test]
    fn hash_changes_with_target_and_with_active_slot() {
        let mut cfg = config(vec![site("a", "a.com")]);
        let base = config_hash(&render(&cfg, &opts()).unwrap());
        cfg.sites[0].blue.targets[0].addr = "10.0.0.2:8080".into();
        let moved = config_hash(&render(&cfg, &opts()).unwrap());
        assert_ne!(base, moved);
        cfg.sites[0].active = Slot::Green;
        assert_ne!(moved, config_hash(&render(&cfg, &opts()).unwrap()));
    }

    #[test]
    fn hash_changes_with_page_html() {
        let mut cfg = config(vec![site("a", "a.com")]);
        cfg.pages.push(MaintenancePage {
            id: "p".into(),
            name: "p".into(),
            html: "one".into(),
            status: 503,
        });
        let one = config_hash(&render(&cfg, &opts()).unwrap());
        cfg.pages[0].html = "two".into();
        assert_ne!(one, config_hash(&render(&cfg, &opts()).unwrap()));
    }

    #[test]
    fn exact_and_wildcard_hosts_render_as_separate_acls() {
        let mut s = site("a", "Example.com");
        s.hosts.push("*.Example.com".into());
        let r = render(&config(vec![s]), &opts()).unwrap();
        let acls = lines_with(&r, "acl host_a");
        assert_eq!(acls.len(), 2);
        assert!(acls[0].ends_with("var(txn.host) -m str example.com"));
        assert!(acls[1].ends_with("var(txn.host) -m end .example.com"));
    }

    #[test]
    fn path_regex_adds_path_acl_to_routing() {
        let mut s = site("a", "a.com");
        s.path_regex = Some("^/api/".into());
        let r = render(&config(vec![s]), &opts()).unwrap();
        assert_eq!(lines_with(&r, "acl path_a path_reg -- ^/api/").len(), 1);
        assert_eq!(
            lines_with(&r, "acl path_a path,url_dec -m reg -- ^/api/").len(),
            1
        );
        let route = lines_with(&r, "use_backend");
        assert_eq!(
            route,
            ["    use_backend %[var(txn.site),map(/run/cite/maps/active.map)] if { var(txn.site) -m found }"]
        );
    }

    #[test]
    fn active_map_and_backends_follow_the_model() {
        let mut a = site("a", "a.com");
        a.active = Slot::Green;
        a.green.targets = vec![
            Target {
                addr: "10.0.0.5:80".into(),
                weight: 50,
            },
            Target {
                addr: "10.0.0.6:80".into(),
                weight: 10,
            },
        ];
        let r = render(&config(vec![site("b", "b.com"), a]), &opts()).unwrap();
        assert_eq!(r.active_map, "a be_a_green\nb be_b_blue\n");
        assert!(r.config.contains("backend be_a_blue\n"));
        assert!(
            r.config
                .contains("backend be_a_green\n    balance leastconn\n")
        );
        assert!(
            r.config
                .contains("server t2 10.0.0.6:80 check inter 2000ms rise 2 fall 3 weight 10 resolvers cite init-addr none")
        );
        assert!(r.config.contains("option httpchk GET /"));
    }

    #[test]
    fn firewall_rules_keep_order_and_come_before_routing() {
        let mut cfg = config(vec![site("a", "a.com")]);
        let m = |p: &str| Matchers {
            path_prefix: Some(p.into()),
            ..Default::default()
        };
        cfg.firewall.push(rule("first", m("/one")));
        let mut second = rule("second", m("/two"));
        second.action = FirewallAction::Drop;
        cfg.firewall.push(second);
        let mut third = rule("third", m("/three"));
        third.action = FirewallAction::Tarpit;
        cfg.firewall.push(third);
        let r = render(&cfg, &opts()).unwrap();
        let (p1, p2, p3) = (
            position(&r, "str(first)"),
            position(&r, "str(second)"),
            position(&r, "str(third)"),
        );
        assert!(p1 < p2 && p2 < p3);
        assert!(p3 < position(&r, "use_backend"));
        assert!(
            r.config
                .contains("http-request deny deny_status 403 if { var(txn.blocked) -m str first }")
        );
        assert!(
            r.config
                .contains("http-request silent-drop if { var(txn.blocked) -m str second }")
        );
        assert!(
            r.config
                .contains("http-request tarpit if { var(txn.blocked) -m str third }")
        );
        assert!(r.config.contains("timeout tarpit 5s"));
    }

    #[test]
    fn disabled_rules_are_not_rendered() {
        let mut cfg = config(vec![site("a", "a.com")]);
        let mut off = rule(
            "off",
            Matchers {
                path_prefix: Some("/x".into()),
                ..Default::default()
            },
        );
        off.enabled = false;
        cfg.firewall.push(off);
        assert!(!render(&cfg, &opts()).unwrap().config.contains("str(off)"));
    }

    #[test]
    fn rule_scoping_and_matchers() {
        let mut cfg = config(vec![site("a", "a.com"), site("b", "b.com")]);
        let mut scoped = rule(
            "scoped",
            Matchers {
                methods: vec!["TRACE".into(), "DEBUG".into()],
                user_agent_regex: Some("(?i)bot".into()),
                cidrs: vec!["10.0.0.0/8".into(), "2001:db8::1".into()],
                host: Some("*.a.com".into()),
                ..Default::default()
            },
        );
        scoped.site = Some("b".into());
        cfg.firewall.push(scoped);
        cfg.firewall.push(rule(
            "global",
            Matchers {
                path_regex: Some("^/admin".into()),
                ..Default::default()
            },
        ));
        let r = render(&cfg, &opts()).unwrap();
        let line = lines_with(&r, "str(scoped) if { var(txn.site) -m str b }")[0];
        assert!(line.ends_with(
            "if { var(txn.site) -m str b } { method TRACE DEBUG } { src 10.0.0.0/8 2001:db8::1 } { var(txn.host) -m end .a.com } { req.hdr(user-agent) -m reg -- (?i)bot }"
        ));
        let global = lines_with(&r, "str(global) if rp_global");
        assert_eq!(global.len(), 1);
        assert!(!global[0].contains("host_"));
        assert_eq!(lines_with(&r, "acl rp_global path_reg -- ^/admin").len(), 1);
        assert_eq!(
            lines_with(&r, "acl rp_global path,url_dec -m reg -- ^/admin").len(),
            1
        );
    }

    #[test]
    fn blocked_var_is_set_once_and_the_action_tests_it() {
        let mut cfg = config(vec![]);
        cfg.firewall.push(rule(
            "r1",
            Matchers {
                path_prefix: Some("/x".into()),
                ..Default::default()
            },
        ));
        let r = render(&cfg, &opts()).unwrap();
        let set = "http-request set-var(txn.blocked) str(r1) if rb_r1";
        let act = "http-request deny deny_status 403 if { var(txn.blocked) -m str r1 }";
        assert!(position(&r, set) < position(&r, act));
        assert_eq!(lines_with(&r, "rb_r1").len(), 3);
        assert_eq!(lines_with(&r, "path_beg /x").len(), 1);
        assert_eq!(lines_with(&r, "path,url_dec -m beg /x").len(), 1);
    }

    #[test]
    fn uri_is_normalised_before_vars_acls_and_rules() {
        let mut cfg = config(vec![site("a", "a.com")]);
        cfg.firewall.push(rule(
            "r1",
            Matchers {
                path_prefix: Some("/x".into()),
                ..Default::default()
            },
        ));
        let r = render(&cfg, &opts()).unwrap();
        assert!(r.config.contains("    expose-experimental-directives\n"));
        let order = [
            "normalize-uri percent-to-uppercase",
            "normalize-uri percent-decode-unreserved",
            "normalize-uri path-merge-slashes",
            "normalize-uri path-strip-dot\n",
            "normalize-uri path-strip-dotdot",
            "normalize-uri fragment-strip",
            "set-var(txn.path) path",
            "acl host_a",
            "set-var(txn.site)",
            "acl rb_r1",
            "set-var(txn.blocked)",
            "use_backend",
        ];
        let at: Vec<usize> = order.iter().map(|n| position(&r, n)).collect();
        assert!(at.windows(2).all(|w| w[0] < w[1]), "{at:?}");
    }

    #[test]
    fn ambiguous_host_headers_are_denied() {
        let r = render(&config(vec![]), &opts()).unwrap();
        assert!(
            r.config
                .contains("http-request deny deny_status 400 if { req.hdr_cnt(host) gt 1 }")
        );
        assert!(
            r.config
                .contains("http-request deny deny_status 400 if { req.fhdr(host) -m sub , }")
        );
        assert!(r.config.contains("set-var(txn.ua) req.fhdr(user-agent)"));
        assert!(r.config.contains("set-var(txn.ref) req.fhdr(referer)"));
    }

    #[test]
    fn site_label_is_set_for_the_first_matching_site() {
        let mut b = site("b", "b.com");
        b.path_regex = Some("^/api".into());
        let r = render(&config(vec![site("a", "a.com"), b]), &opts()).unwrap();
        assert_eq!(
            lines_with(&r, "set-var(txn.site)"),
            [
                "    http-request set-var(txn.site) str(a) if !{ var(txn.site) -m found } host_a",
                "    http-request set-var(txn.site) str(b) if !{ var(txn.site) -m found } host_b path_b",
            ]
        );
        assert!(r.config.contains("%[var(txn.site),url_enc]"));
    }

    #[test]
    fn log_target_allows_long_lines_and_unix_sockets() {
        let mut o = opts();
        o.log_addr = "/run/cite/log.sock".into();
        o.runtime_addr = "unix@/run/cite/admin.sock".into();
        let r = render(&config(vec![]), &o).unwrap();
        assert!(
            r.config
                .contains("    log /run/cite/log.sock len 8192 format rfc5424 local0\n")
        );
        assert!(r.config.contains(
            "    stats socket unix@/run/cite/admin.sock mode 600 level admin expose-fd listeners\n"
        ));
        assert!(!lines_with(&r, "stats socket")[0].contains("ipv4"));
    }

    #[test]
    fn page_limit_fits_the_haproxy_buffer() {
        let mut cfg = config(vec![site("a", "a.com")]);
        cfg.pages.push(MaintenancePage {
            id: "big".into(),
            name: "big".into(),
            html: "x".repeat(15_000),
            status: 503,
        });
        assert!(render(&cfg, &opts()).is_ok());
        cfg.pages[0].html.push('x');
        assert!(render(&cfg, &opts()).is_err());
    }

    #[test]
    fn long_runs_of_plain_sites_share_one_host_map_lookup() {
        let sites: Vec<Site> = (0..6)
            .map(|i| site(&format!("s{i}"), &format!("S{i}.example.com")))
            .collect();
        let r = render(&config(sites), &opts()).unwrap();
        let labels = lines_with(&r, "set-var(txn.site)");
        assert_eq!(
            labels,
            ["    http-request set-var(txn.site) var(txn.host),concat(@0),map(/run/cite/maps/active.map) if !{ var(txn.site) -m found }"]
        );
        assert!(r.config.lines().all(|l| !l.starts_with("    acl host_")));
        assert!(r.active_map.starts_with("s0 be_s0_blue\n"));
        assert!(r.active_map.contains("\ns3 be_s3_blue\ns4 be_s4_blue\ns5 be_s5_blue\n"));
        assert!(r.active_map.ends_with("s0.example.com@0 s0\ns1.example.com@0 s1\ns2.example.com@0 s2\ns3.example.com@0 s3\ns4.example.com@0 s4\ns5.example.com@0 s5\n"));
    }

    #[test]
    fn host_map_runs_keep_config_order_around_other_sites() {
        let plain = |range: std::ops::Range<usize>| -> Vec<Site> {
            range
                .map(|i| site(&format!("s{i}"), &format!("s{i}.example.com")))
                .collect()
        };
        let mut wild = site("wild", "wild.example.com");
        wild.hosts = vec!["*.example.com".into()];
        let mut sites = plain(0..4);
        sites.push(wild);
        sites.extend(plain(4..8));
        let r = render(&config(sites), &opts()).unwrap();
        let labels = lines_with(&r, "set-var(txn.site)");
        assert_eq!(labels.len(), 3);
        assert!(labels[0].contains("concat(@0)"));
        assert!(labels[1].contains("str(wild) if !{ var(txn.site) -m found } host_wild"));
        assert!(labels[2].contains("concat(@1)"));
        assert!(r.active_map.contains("s3.example.com@0 s3\n"));
        assert!(r.active_map.contains("s4.example.com@1 s4\n"));
    }

    #[test]
    fn duplicate_hosts_in_a_run_go_to_the_first_site() {
        let sites: Vec<Site> = (0..4)
            .map(|i| site(&format!("s{i}"), "shared.example.com"))
            .collect();
        let r = render(&config(sites), &opts()).unwrap();
        let entries: Vec<&str> = r
            .active_map
            .lines()
            .filter(|l| l.contains("@0"))
            .collect();
        assert_eq!(entries, ["shared.example.com@0 s0"]);
    }

    #[test]
    fn long_acl_value_lists_are_split_below_the_line_limit() {
        let ids: Vec<String> = (0..600).map(|i| format!("site-{i}")).collect();
        let lines = chunked_acl("maint_pg0", "var(txn.site) -m str", &ids);
        assert!(lines.len() > 1);
        assert!(lines.iter().all(|l| l.len() <= MAX_ACL_LINE));
        assert!(lines.iter().all(|l| l.split(' ').count() <= 60));
        let joined: Vec<&str> = lines
            .iter()
            .flat_map(|l| l.split(" ").skip(5))
            .collect();
        assert_eq!(joined.len(), ids.len());
    }

    #[test]
    fn maintenance_map_and_pages() {
        let mut a = site("a", "a.com");
        a.maintenance.enabled = true;
        a.maintenance.page_id = Some("down".into());
        let b = site("b", "b.com");
        let mut cfg = config(vec![a, b]);
        cfg.pages.push(MaintenancePage {
            id: "down".into(),
            name: "down".into(),
            html: "<p>down</p>".into(),
            status: 502,
        });
        let r = render(&cfg, &opts()).unwrap();
        assert_eq!(r.maint_map, "a on\nb off\n");
        assert_eq!(lines_with(&r, "acl maint_pg0 var(txn.site) -m str a").len(), 1);
        assert_eq!(lines_with(&r, "acl maint_pg1 var(txn.site) -m str b").len(), 1);
        let on = "if maint_pg{} { var(txn.site),map(/run/cite/maps/maint.map,off) -m str on }";
        let a_line = lines_with(&r, "file /run/cite/pages/down.html")[0];
        assert!(a_line.contains("return status 502"));
        assert!(a_line.ends_with(&on.replace("{}", "0")));
        let b_line = lines_with(&r, "file /run/cite/pages/_default.html")[0];
        assert!(b_line.contains("return status 503"));
        assert!(b_line.ends_with(&on.replace("{}", "1")));
        let names: Vec<&str> = r.pages.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["_default.html", "down.html"]);
        assert_eq!(r.pages[0].1, DEFAULT_PAGE_HTML);
        assert_eq!(r.pages[1].1, "<p>down</p>");
        assert!(position(&r, "return status 502") < position(&r, "use_backend"));
    }

    #[test]
    fn zero_sites_answers_404() {
        let r = render(&config(vec![]), &opts()).unwrap();
        assert!(r.active_map.is_empty() && r.maint_map.is_empty());
        assert!(!r.config.contains("use_backend"));
        assert!(r.config.contains("default_backend be_notfound"));
        assert!(
            r.config
                .contains("backend be_notfound\n    http-request return status 404")
        );
        assert_eq!(r.pages.len(), 1);
    }

    #[test]
    fn global_and_defaults_follow_settings() {
        let mut cfg = config(vec![]);
        cfg.settings.max_conn = 1234;
        cfg.settings.per_ip_rate_limit = Some(77);
        cfg.settings.max_body_bytes = Some(1_000_000);
        let r = render(&cfg, &opts()).unwrap();
        assert!(r.config.contains("    maxconn 1234\n"));
        assert!(
            r.config
                .contains("stats socket ipv4@127.0.0.1:9999 level admin expose-fd listeners")
        );
        assert!(
            r.config
                .contains("log 127.0.0.1:514 len 8192 format rfc5424 local0")
        );
        assert!(r.config.contains("timeout client 30000ms"));
        assert!(
            r.config
                .contains("http-request deny deny_status 429 if { sc_http_req_rate(0) gt 77 }")
        );
        assert!(r.config.contains(
            "http-request deny deny_status 413 if { req.hdr_val(content-length) gt 1000000 }"
        ));
        assert!(
            r.config
                .contains("stick-table type ip size 200k expire 10m store http_req_rate(10s)")
        );
        assert!(!r.config.contains("dontlognull"));
        assert!(!r.config.contains("tune.ssl") && !r.config.contains("ssl crt"));
        cfg.settings.per_ip_rate_limit = None;
        cfg.settings.max_body_bytes = None;
        let r = render(&cfg, &opts()).unwrap();
        assert!(
            !r.config.contains("stick-table")
                && !r.config.contains("429")
                && !r.config.contains("413")
        );
    }

    #[test]
    fn tls_bind_needs_port_and_directory() {
        let mut cfg = config(vec![]);
        cfg.settings.https_port = Some(443);
        assert!(!render(&cfg, &opts()).unwrap().config.contains("bind :443"));
        let mut o = opts();
        o.tls_dir = Some("/etc/cite/tls".into());
        let r = render(&cfg, &o).unwrap();
        assert!(
            r.config
                .contains("bind :443 ssl crt /etc/cite/tls alpn h2,http/1.1")
        );
        assert!(r.config.contains("ssl-min-ver TLSv1.2"));
        assert!(r.config.contains("tune.ssl.default-dh-param 2048"));
        cfg.settings.https_port = None;
        assert!(!render(&cfg, &o).unwrap().config.contains("bind :443"));
    }

    #[test]
    fn log_format_is_quoted() {
        let r = render(&config(vec![]), &opts()).unwrap();
        let line = lines_with(&r, "log-format ")[0];
        assert!(line.starts_with("    log-format \"") && line.ends_with('"'));
    }

    #[test]
    fn injection_attempts_are_rejected() {
        let attempts = [
            "a.com\n    http-request allow",
            "a.com #",
            "a\"b.com",
            "a.com'",
            "a.com }",
        ];
        for bad in attempts {
            assert!(
                render(&config(vec![site("a", bad)]), &opts()).is_err(),
                "host {bad:?}"
            );
        }
        let mut s = site("a", "a.com");
        s.path_regex = Some("^/x\nbackend evil".into());
        assert!(render(&config(vec![s]), &opts()).is_err());
        assert!(render(&config(vec![site("a\nbackend x", "a.com")]), &opts()).is_err());
        let mut cfg = config(vec![site("a", "a.com")]);
        cfg.pages.push(MaintenancePage {
            id: "p\nq".into(),
            name: "p".into(),
            html: String::new(),
            status: 503,
        });
        assert!(render(&cfg, &opts()).is_err());
        let mut cfg = config(vec![]);
        cfg.firewall.push(rule(
            "r",
            Matchers {
                user_agent_regex: Some("a#b".into()),
                ..Default::default()
            },
        ));
        assert!(render(&cfg, &opts()).is_err());
    }

    #[test]
    fn unsafe_render_options_are_rejected() {
        let cfg = config(vec![]);
        for field in 0..4 {
            let mut o = opts();
            let bad = "/x\nbackend y".to_string();
            match field {
                0 => o.maps_dir = bad,
                1 => o.pages_dir = bad,
                2 => o.runtime_addr = bad,
                _ => o.log_addr = bad,
            }
            assert!(render(&cfg, &o).is_err(), "field {field}");
        }
    }

    #[test]
    fn socket_and_listener_options_are_checked() {
        let cfg = config(vec![]);
        let runtime = [
            ("unix@/run/cite/admin.sock", true),
            ("ipv4@0.0.0.0:9999", true),
            ("ipv6@[::1]:9999", true),
            ("unix@run/admin.sock", false),
            ("unix@/run/../admin.sock", false),
            ("unix@/run/a b.sock", false),
            ("unix@/run/a\"b.sock", false),
            ("unix@/run/a#b.sock", false),
            ("unix@/run/a:b.sock", false),
            ("unix@/run/cite/admin.sock\nbackend x", false),
            ("unix@", false),
            ("ipv4@1.2.3.4", false),
            ("ipv4@1.2.3.4:0", false),
        ];
        for (addr, ok) in runtime {
            let mut o = opts();
            o.runtime_addr = addr.into();
            assert_eq!(render(&cfg, &o).is_ok(), ok, "runtime_addr {addr:?}");
        }
        let log = [
            ("/run/cite/log.sock", true),
            ("172.30.250.2:5140", true),
            ("[2001:db8::1]:514", true),
            ("run/log.sock", false),
            ("/run/../log.sock", false),
            ("/run/log sock", false),
            ("/run/log.sock\n", false),
            ("/run/lo'g.sock", false),
            ("host", false),
        ];
        for (addr, ok) in log {
            let mut o = opts();
            o.log_addr = addr.into();
            assert_eq!(render(&cfg, &o).is_ok(), ok, "log_addr {addr:?}");
        }
    }

    #[test]
    fn default_page_is_self_contained() {
        assert!(DEFAULT_PAGE_HTML.contains("<!doctype html>"));
        for needle in ["http://", "https://", "src=", "@import", "url("] {
            assert!(!DEFAULT_PAGE_HTML.contains(needle), "{needle}");
        }
        assert!(DEFAULT_PAGE_HTML.is_ascii());
    }

    #[test]
    fn preset_rules_render() {
        let mut cfg = config(vec![site("a", "a.com")]);
        for p in crate::presets::presets() {
            cfg.firewall.extend(p.rules);
        }
        let r = render(&cfg, &opts()).unwrap();
        assert!(r.config.contains("str(preset-odd-methods-1)"));
        assert_eq!(
            lines_with(&r, "set-var(txn.blocked)").len(),
            cfg.firewall.len()
        );
    }

    proptest! {
        #[test]
        fn random_hosts_never_add_directive_lines(host in "\\PC{0,40}", re in "\\PC{0,40}") {
            let baseline = render(&config(vec![site("a", "ok.example.com")]), &opts()).unwrap();
            let mut s = site("a", &host);
            s.path_regex = Some(re);
            let mut base = site("a", "ok.example.com");
            base.path_regex = Some("^/ok".into());
            let expected = render(&config(vec![base]), &opts()).unwrap().config.lines().count();
            prop_assert!(baseline.config.lines().count() < expected);
            if let Ok(r) = render(&config(vec![s]), &opts()) {
                prop_assert_eq!(r.config.lines().count(), expected);
                for line in r.config.lines() {
                    let ok = line.is_empty()
                        || line.starts_with("    ")
                        || line.starts_with('#')
                        || ["global", "defaults", "frontend ", "backend "]
                            .iter()
                            .any(|k| line.starts_with(k));
                    prop_assert!(ok, "stray line {:?}", line);
                }
                for acl in r.config.lines().filter(|l| l.contains("acl host_a")) {
                    prop_assert_eq!(acl.split_whitespace().count(), 6);
                }
            }
        }
    }
}
