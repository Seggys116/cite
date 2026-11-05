use sha2::{Digest, Sha256};

use crate::logparse::LOG_FORMAT;
use crate::model::{EdgeConfig, FirewallAction, FirewallRule, Site, Slot};
use crate::validate::{ValidationError, invalid, parse_cidr, validate_config};

const HOST_FETCH: &str = "req.hdr(host),field(1,:),lower";
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

fn validate_options(opts: &RenderOptions) -> Result<(), ValidationError> {
    check_option("maps_dir", &opts.maps_dir, b"")?;
    check_option("pages_dir", &opts.pages_dir, b"")?;
    check_option("runtime_addr", &opts.runtime_addr, b"@:[]")?;
    check_option("log_addr", &opts.log_addr, b"@:[]")?;
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

fn host_acl_lines(name: &str, hosts: &[String]) -> Vec<String> {
    let (exact, suffix) = host_patterns(hosts);
    let mut lines = Vec::new();
    if !exact.is_empty() {
        lines.push(format!(
            "acl {name} {HOST_FETCH} -m str {}",
            exact.join(" ")
        ));
    }
    if !suffix.is_empty() {
        lines.push(format!(
            "acl {name} {HOST_FETCH} -m end {}",
            suffix.join(" ")
        ));
    }
    lines
}

fn host_inline(host: &str) -> String {
    let host = host.to_ascii_lowercase();
    match host.strip_prefix('*') {
        Some(rest) => format!("{{ {HOST_FETCH} -m end {rest} }}"),
        None => format!("{{ {HOST_FETCH} -m str {host} }}"),
    }
}

fn site_cond(site: &Site) -> String {
    match site.path_regex {
        Some(_) => format!("host_{0} path_{0}", site.id),
        None => format!("host_{}", site.id),
    }
}

fn rule_cond(rule: &FirewallRule, cfg: &EdgeConfig) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(site) = rule
        .site
        .as_ref()
        .and_then(|sid| cfg.sites.iter().find(|s| &s.id == sid))
    {
        parts.push(site_cond(site));
    }
    let m = &rule.matchers;
    if let Some(re) = &m.path_regex {
        parts.push(format!("{{ path_reg -- {re} }}"));
    }
    if let Some(p) = &m.path_prefix {
        parts.push(format!("{{ path_beg {p} }}"));
    }
    if !m.methods.is_empty() {
        parts.push(format!("{{ method {} }}", m.methods.join(" ")));
    }
    if let Some(re) = &m.user_agent_regex {
        parts.push(format!("{{ req.hdr(user-agent) -m reg -- {re} }}"));
    }
    let cidrs: Vec<String> = m.cidrs.iter().filter_map(|c| parse_cidr(c)).collect();
    if !cidrs.is_empty() {
        parts.push(format!("{{ src {} }}", cidrs.join(" ")));
    }
    if let Some(h) = &m.host {
        parts.push(host_inline(h));
    }
    parts.join(" ")
}

fn render_global(cfg: &EdgeConfig, opts: &RenderOptions, tls: bool, out: &mut String) {
    push(
        out,
        "# generated by cite-edge; changes are overwritten on the next render",
    );
    push(out, "global");
    push_in(out, &format!("log {} format rfc5424 local0", opts.log_addr));
    push_in(out, &format!("maxconn {}", cfg.settings.max_conn));
    push_in(
        out,
        &format!(
            "stats socket {} level admin expose-fd listeners",
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

// The variable is set first so the log line of a blocked request names the rule that fired.
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
    push_in(out, &format!("http-request {action} if {cond}"));
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

fn render_frontend(cfg: &EdgeConfig, opts: &RenderOptions, tls: bool, out: &mut String) {
    let s = &cfg.settings;
    let active_path = dir_join(&opts.maps_dir, "active.map");
    let maint_path = dir_join(&opts.maps_dir, "maint.map");
    push(out, "frontend fe_main");
    push_in(out, &format!("log-format {}", quote(LOG_FORMAT)));
    push_in(out, &format!("bind :{}", s.http_port));
    if let (true, Some(port), Some(dir)) = (tls, s.https_port, &opts.tls_dir) {
        push_in(out, &format!("bind :{port} ssl crt {dir} alpn h2,http/1.1"));
    }
    // request headers are gone by log time, so the fields are copied into variables first
    for line in [
        "http-request set-var(txn.host) req.hdr(host),field(1,:),lower",
        "http-request set-var(txn.path) path",
        "http-request set-var(txn.qlen) query,length",
        "http-request set-var(txn.ua) req.hdr(user-agent)",
        "http-request set-var(txn.ref) req.hdr(referer)",
        "http-response set-var(txn.ct) res.hdr(content-type)",
    ] {
        push_in(out, line);
    }
    for site in &cfg.sites {
        for line in host_acl_lines(&format!("host_{}", site.id), &site.hosts) {
            push_in(out, &line);
        }
        if let Some(re) = &site.path_regex {
            push_in(out, &format!("acl path_{} path_reg -- {re}", site.id));
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
        action_lines(rule, &rule_cond(rule, cfg), out);
    }
    // maintenance rules are always emitted; the maint map toggles them at runtime without a reload
    for site in &cfg.sites {
        let page = page_for(site, cfg);
        push_in(
            out,
            &format!(
                "http-request return status {} content-type \"text/html; charset=utf-8\" file {} hdr cache-control no-store if {} {{ str({}),map({maint_path},off) -m str on }}",
                page.status,
                dir_join(&opts.pages_dir, &page.file),
                site_cond(site),
                site.id
            ),
        );
    }
    // the active map picks blue or green, so switching slots is a runtime-API map update
    for site in &cfg.sites {
        push_in(
            out,
            &format!(
                "use_backend %[str({}),map({active_path})] if {}",
                site.id,
                site_cond(site)
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
    render_frontend(cfg, opts, tls, &mut config);
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
    let active_map: String = active.iter().map(|(k, v)| format!("{k} {v}\n")).collect();

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
        assert!(acls[0].ends_with("req.hdr(host),field(1,:),lower -m str example.com"));
        assert!(acls[1].ends_with("req.hdr(host),field(1,:),lower -m end .example.com"));
    }

    #[test]
    fn path_regex_adds_path_acl_to_routing() {
        let mut s = site("a", "a.com");
        s.path_regex = Some("^/api/".into());
        let r = render(&config(vec![s]), &opts()).unwrap();
        assert_eq!(lines_with(&r, "acl path_a path_reg -- ^/api/").len(), 1);
        let route = lines_with(&r, "use_backend");
        assert_eq!(
            route,
            ["    use_backend %[str(a),map(/run/cite/maps/active.map)] if host_a path_a"]
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
                .contains("http-request deny deny_status 403 if { path_beg /one }")
        );
        assert!(
            r.config
                .contains("http-request silent-drop if { path_beg /two }")
        );
        assert!(
            r.config
                .contains("http-request tarpit if { path_beg /three }")
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
        let line = lines_with(&r, "deny_status 403 if host_b")[0];
        assert!(line.ends_with(
            "if host_b { method TRACE DEBUG } { req.hdr(user-agent) -m reg -- (?i)bot } { src 10.0.0.0/8 2001:db8::1 } { req.hdr(host),field(1,:),lower -m end .a.com }"
        ));
        let global = lines_with(&r, "deny_status 403 if { path_reg -- ^/admin }");
        assert_eq!(global.len(), 1);
        assert!(!global[0].contains("host_"));
    }

    #[test]
    fn blocked_var_is_set_before_the_action_with_same_condition() {
        let mut cfg = config(vec![]);
        cfg.firewall.push(rule(
            "r1",
            Matchers {
                path_prefix: Some("/x".into()),
                ..Default::default()
            },
        ));
        let r = render(&cfg, &opts()).unwrap();
        let set = "http-request set-var(txn.blocked) str(r1) if { path_beg /x }";
        let act = "http-request deny deny_status 403 if { path_beg /x }";
        assert!(position(&r, set) < position(&r, act));
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
        let a_line = lines_with(&r, "str(a),map(/run/cite/maps/maint.map,off)")[0];
        assert!(a_line.contains("return status 502"));
        assert!(a_line.contains("file /run/cite/pages/down.html"));
        assert!(
            a_line.contains("if host_a { str(a),map(/run/cite/maps/maint.map,off) -m str on }")
        );
        let b_line = lines_with(&r, "str(b),map(/run/cite/maps/maint.map,off)")[0];
        assert!(b_line.contains("return status 503"));
        assert!(b_line.contains("file /run/cite/pages/_default.html"));
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
        assert!(r.config.contains("log 127.0.0.1:514 format rfc5424 local0"));
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
