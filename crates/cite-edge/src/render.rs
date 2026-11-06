use sha2::{Digest, Sha256};

use crate::bot::{all_bot_regex, bad_bot_regex};
use crate::cloudflare::effective_ranges;
use crate::effects::{Template, parse_template, render_location};
use crate::logparse::LOG_FORMAT;
use crate::model::{
    BotPolicy, Cors, EdgeConfig, FirewallAction, FirewallRule, HeaderMatch, HeaderOp, HeaderOpKind,
    HeaderTarget, Site, Slot, TlsMode,
};
use crate::pattern::{HEADER_CAP, PATH_CAP, REFERER_CAP, UA_CAP};
use crate::presets::ZONE_HEADER;
use crate::validate::{ValidationError, invalid, parse_cidr, validate_config};

const HOST_FETCH: &str = "var(txn.host)";

// The path is rewritten to its canonical form, normalised again and copied out, then restored so the origin still gets the normalised path.
const CANONICAL_PATH: [&str; 7] = [
    "http-request set-path %[path,regsub(;[^/]*,,g),regsub(%3B[^/]*,,g),regsub(\\\\\\\\\\\\\\\\,/,g),regsub(%5C,/,g)]",
    "http-request normalize-uri path-merge-slashes",
    "http-request normalize-uri path-strip-dot",
    "http-request normalize-uri path-strip-dotdot full",
    "http-request set-var(txn.cpath) path",
    "http-request set-path %[var(txn.path)]",
    "http-request set-var(txn.cpath) var(txn.cpath),url_dec",
];
// Runs of at least this many plain sites are routed by one map lookup instead of one ACL each.
const MAP_RUN_MIN: usize = 4;
// HAProxy cuts configuration lines at 2048 bytes and 64 words, so long pattern lists are split over repeated ACLs.
const MAX_ACL_LINE: usize = 1500;
const MAX_ACL_VALUES: usize = 48;
const DEFAULT_PAGE_FILE: &str = "_default.html";
const DEFAULT_PAGE_STATUS: u16 = 503;
const CF_PEER: &str = "cf_peer";
// Shown as the rule label in logs and the Traffic blocked-by-rule table.
const CF_RULE: &str = "cloudflare-only";
const CF_CLIENT_HEADERS: [&str; 5] = [
    "CF-Connecting-IP",
    "True-Client-IP",
    "CF-Visitor",
    "CF-Connecting-IPv6",
    "CF-Pseudo-IPv4",
];

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
    /// Path HAProxy reads the Cloudflare ranges from; required when a site uses cloudflare_only or Flexible SSL.
    pub cloudflare_file: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    pub config: String,
    pub active_map: String,
    pub maint_map: String,
    pub pages: Vec<(String, String)>,
    /// One CIDR per line for `cloudflare_file`; empty when no site depends on Cloudflare.
    pub cloudflare_list: String,
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
    if let Some(file) = &opts.cloudflare_file {
        check_option("cloudflare_file", file, b"")?;
    }
    Ok(())
}

// Site ids grouped by how they depend on the Cloudflare range list, in config order.
#[derive(Default)]
struct CloudflareSites {
    only: Vec<String>,
    flexible: Vec<String>,
    aware: Vec<String>,
}

fn cloudflare_sites(cfg: &EdgeConfig) -> CloudflareSites {
    let mut out = CloudflareSites::default();
    for site in &cfg.sites {
        let only = site.access.cloudflare_only;
        let flexible = site.access.tls == TlsMode::Flexible;
        if only {
            out.only.push(site.id.clone());
        }
        if flexible {
            out.flexible.push(site.id.clone());
        }
        if only || flexible {
            out.aware.push(site.id.clone());
        }
    }
    out
}

// The peer test uses fc_src, the TCP peer, because a client cannot forge it the way it can a header.
fn cloudflare_acls(cf: &CloudflareSites, file: &str, out: &mut String) {
    push_in(out, &format!("acl {CF_PEER} fc_src -f {file}"));
    for (name, ids) in [
        ("cf_only", &cf.only),
        ("cf_flex", &cf.flexible),
        ("cf_aware", &cf.aware),
    ] {
        for line in chunked_acl(name, "var(txn.site) -m str", ids) {
            push_in(out, &line);
        }
    }
}

// Runs before anything reads the client address; the denial is recorded through txn.blocked like a firewall rule.
fn cloudflare_gate(cf: &CloudflareSites, out: &mut String) {
    if !cf.only.is_empty() {
        push_in(
            out,
            &format!("http-request set-var(txn.blocked) str({CF_RULE}) if cf_only !{CF_PEER}"),
        );
        push_in(
            out,
            &format!(
                "http-request deny deny_status 403 if {{ var(txn.blocked) -m str {CF_RULE} }}"
            ),
        );
    }
    for header in CF_CLIENT_HEADERS {
        push_in(
            out,
            &format!("http-request del-header {header} if cf_aware !{CF_PEER}"),
        );
    }
    if !cf.flexible.is_empty() {
        push_in(
            out,
            &format!(
                "http-request set-var(txn.cfproto) req.fhdr(x-forwarded-proto) if cf_flex {CF_PEER}"
            ),
        );
    }
}

// Flexible sites take the scheme from Cloudflare, which saw the visitor's real connection, but only when the peer is Cloudflare and only the exact value https.
fn cloudflare_forwarded_proto(cf: &CloudflareSites, out: &mut String) {
    if cf.flexible.is_empty() {
        return;
    }
    let https = "{ var(txn.cfproto) -m str https }";
    push_in(
        out,
        &format!("http-request set-header X-Forwarded-Proto https if cf_flex {CF_PEER} {https}"),
    );
    push_in(
        out,
        &format!("http-request set-header X-Forwarded-Proto http if cf_flex {CF_PEER} !{https}"),
    );
}

// Needs a header that is present once and is a single IP, otherwise src stays the Cloudflare edge address.
fn cloudflare_real_client(cf: &CloudflareSites, out: &mut String) {
    if cf.only.is_empty() {
        return;
    }
    push_in(
        out,
        &format!(
            "http-request set-src req.fhdr(cf-connecting-ip) if cf_only {CF_PEER} {{ req.hdr_cnt(cf-connecting-ip) eq 1 }} {{ req.fhdr(cf-connecting-ip) -m ip 0.0.0.0/0 ::/0 }}"
        ),
    );
}

// An unusable range file would leave cloudflare_only sites open or shut, so rendering refuses to guess.
fn check_cloudflare_file(
    cf: &CloudflareSites,
    opts: &RenderOptions,
) -> Result<(), ValidationError> {
    if !cf.aware.is_empty() && opts.cloudflare_file.is_none() {
        return invalid(
            "render option cloudflare_file: required because a site uses cloudflare_only or Flexible SSL"
                .into(),
        );
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
// A site with prefixes and regexes gets one condition for each, and each becomes its own set-var line, which makes them alternatives.
fn site_conds(site: &Site) -> Vec<String> {
    let id = &site.id;
    let mut conds = Vec::new();
    if !site.path_prefixes.is_empty() {
        conds.push(format!("host_{id} pathp_{id}"));
    }
    if !site.path_regexes.is_empty() {
        conds.push(format!("host_{id} path_{id} pathok_{id}"));
    }
    if conds.is_empty() {
        conds.push(format!("host_{id}"));
    }
    conds
}

// Regexes only ever see the first cap bytes. User agent and path fields also get one guard ACL (see guard_acl_line): blocking rules get a "big" ACL that is true for a longer subject, so padding cannot hide a match, and effect rules get an "ok" ACL, so a longer subject matches nothing. Referer and header regexes have no guard: they judge the prefix, because long values of both are routine.
fn regex_acl_lines(
    lines: &mut Vec<String>,
    stem: &str,
    rule: &FirewallRule,
    fetch: &str,
    cap: usize,
    re: &str,
) {
    let id = &rule.id;
    lines.push(format!(
        "acl {stem}_{id} {fetch},bytes(0,{cap}) -m reg -- {re}"
    ));
}

// One oversize or length guard per field, however many regexes the field holds.
fn guard_acl_line(stem: &str, rule: &FirewallRule, fetch: &str, cap: usize) -> String {
    let id = &rule.id;
    if rule.action.is_some() {
        format!("acl {stem}big_{id} {fetch},length gt {cap}")
    } else {
        format!("acl {stem}ok_{id} {fetch},length le {cap}")
    }
}

// The empty-agent test ^$ is the only entry of its list, so it never mixes with ACL-based regexes.
fn is_empty_test(list: &[String]) -> bool {
    list.len() == 1 && list[0] == "^$"
}

// The first header matcher keeps the plain stem, so a rule with one header renders as it always did.
fn header_stem(k: usize) -> String {
    if k == 0 {
        "rh".to_string()
    } else {
        format!("rh{k}")
    }
}

// A repeated acl name is an OR, so each path matcher tests the path as sent and its canonical form.
fn rule_acl_lines(rule: &FirewallRule) -> Vec<String> {
    let m = &rule.matchers;
    let mut lines = Vec::new();
    let id = &rule.id;
    if !m.path_regexes.is_empty() {
        for re in &m.path_regexes {
            regex_acl_lines(&mut lines, "rp", rule, "path", PATH_CAP, re);
        }
        lines.push(guard_acl_line("rp", rule, "path", PATH_CAP));
        for re in &m.path_regexes {
            lines.push(format!(
                "acl rp_{id} var(txn.cpath),bytes(0,{PATH_CAP}) -m reg -- {re}"
            ));
        }
        // effect rules judge the length of the path as sent only, while a blocking rule treats either form being long as a match
        if rule.action.is_some() {
            lines.push(format!(
                "acl rpbig_{id} var(txn.cpath),length gt {PATH_CAP}"
            ));
        }
    }
    if !m.user_agent_regexes.is_empty() && !is_empty_test(&m.user_agent_regexes) {
        for re in &m.user_agent_regexes {
            regex_acl_lines(&mut lines, "ru", rule, "req.fhdr(user-agent)", UA_CAP, re);
        }
        lines.push(guard_acl_line("ru", rule, "req.fhdr(user-agent)", UA_CAP));
    }
    if !m.referer_regexes.is_empty() && !is_empty_test(&m.referer_regexes) {
        for re in &m.referer_regexes {
            regex_acl_lines(&mut lines, "rr", rule, "req.fhdr(referer)", REFERER_CAP, re);
        }
    }
    for (k, h) in m.headers.iter().enumerate() {
        if let Some(re) = &h.regex {
            let fetch = format!("req.fhdr({})", h.name.to_ascii_lowercase());
            regex_acl_lines(&mut lines, &header_stem(k), rule, &fetch, HEADER_CAP, re);
        } else if m.headers.len() > INLINE_HEADERS {
            lines.push(format!("acl rhe{k}_{id} {}", header_test(h)));
        }
    }
    for p in &m.path_prefixes {
        lines.push(format!("acl rb_{id} path_beg {p}"));
        lines.push(format!("acl rb_{id} var(txn.cpath) -m beg {p}"));
    }
    if m.hosts.len() > 1 {
        lines.extend(host_acl_lines(&format!("rhost_{id}"), &m.hosts));
    }
    let cidrs = rule_cidrs(rule);
    if cidrs.len() > INLINE_CIDRS {
        lines.extend(chunked_acl(&format!("rc_{}", rule.id), "src", &cidrs));
    }
    if rule.matchers.methods.len() > INLINE_METHODS {
        lines.extend(chunked_acl(
            &format!("rm_{}", rule.id),
            "method",
            &rule.matchers.methods,
        ));
    }
    lines
}

// HAProxy truncates a config line after 64 words, which is fatal, so long lists become named ACLs and a whole rule fits in 60.
const INLINE_CIDRS: usize = 4;
const INLINE_METHODS: usize = 4;
const INLINE_HEADERS: usize = 2;
const MAX_LINE_WORDS: usize = 60;
// An effect condition above this many words is evaluated once into a variable instead of being repeated on every line that uses it.
const MAX_COND_WORDS: usize = 30;

fn rule_cidrs(rule: &FirewallRule) -> Vec<String> {
    rule.matchers
        .cidrs
        .iter()
        .filter_map(|c| parse_cidr(c))
        .collect()
}

// The regex field whose test is replaced by "the subject is oversized" in the extra condition of a blocking rule.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    Path,
    UserAgent,
}

fn rule_cond(rule: &FirewallRule, cfg: &EdgeConfig) -> String {
    rule_cond_over(rule, cfg, None)
}

// One condition per regex field: the normal one, and one for each field where an oversized subject counts as a match.
fn block_conds(rule: &FirewallRule, cfg: &EdgeConfig) -> Vec<String> {
    let m = &rule.matchers;
    let mut conds = vec![rule_cond(rule, cfg)];
    let mut over = Vec::new();
    if !m.path_regexes.is_empty() {
        over.push(Field::Path);
    }
    if !m.user_agent_regexes.is_empty() && !is_empty_test(&m.user_agent_regexes) {
        over.push(Field::UserAgent);
    }
    conds.extend(over.into_iter().map(|f| rule_cond_over(rule, cfg, Some(f))));
    conds
}

// Names one regex test: the oversize ACL when this is the field being widened, else the guard for effect rules plus the regex ACL. A field of None has no guard and is judged on its prefix, which is also what a negated test sees.
fn regex_test(
    rule: &FirewallRule,
    stem: &str,
    field: Option<Field>,
    over: Option<Field>,
    negate: bool,
    parts: &mut Vec<String>,
) {
    let id = &rule.id;
    if field.is_some() && over == field {
        parts.push(format!("{stem}big_{id}"));
        return;
    }
    if field.is_some() && rule.action.is_none() {
        parts.push(format!("{stem}ok_{id}"));
    }
    let bang = if negate { "!" } else { "" };
    parts.push(format!("{bang}{stem}_{id}"));
}

// Cheap matchers come first because HAProxy stops at the first condition that fails.
fn rule_cond_over(rule: &FirewallRule, cfg: &EdgeConfig, over: Option<Field>) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(site) = rule
        .site
        .as_ref()
        .filter(|sid| cfg.sites.iter().any(|s| &s.id == *sid))
    {
        parts.push(format!("{{ var(txn.site) -m str {site} }}"));
    }
    let m = &rule.matchers;
    if m.methods.len() > INLINE_METHODS {
        parts.push(format!("rm_{}", rule.id));
    } else if !m.methods.is_empty() {
        parts.push(format!("{{ method {} }}", m.methods.join(" ")));
    }
    let cidrs = rule_cidrs(rule);
    if cidrs.len() > INLINE_CIDRS {
        parts.push(format!("rc_{}", rule.id));
    } else if !cidrs.is_empty() {
        parts.push(format!("{{ src {} }}", cidrs.join(" ")));
    }
    match m.hosts.as_slice() {
        [] => {}
        [one] => parts.push(host_inline(one)),
        _ => parts.push(format!("rhost_{}", rule.id)),
    }
    if !m.path_prefixes.is_empty() {
        parts.push(format!("rb_{}", rule.id));
    }
    if !m.path_regexes.is_empty() {
        regex_test(rule, "rp", Some(Field::Path), over, false, &mut parts);
    }
    if !m.user_agent_regexes.is_empty() {
        if is_empty_test(&m.user_agent_regexes) {
            parts.push(empty_header_cond("user-agent"));
        } else {
            regex_test(rule, "ru", Some(Field::UserAgent), over, false, &mut parts);
        }
    }
    if !m.referer_regexes.is_empty() {
        if is_empty_test(&m.referer_regexes) {
            parts.push(empty_header_cond("referer"));
        } else {
            regex_test(rule, "rr", None, over, false, &mut parts);
        }
    }
    if let Some(scheme) = &m.scheme {
        // the frontend rewrites this header on every request, so it is the one place the visitor's scheme is trustworthy
        parts.push(format!("{{ req.fhdr(x-forwarded-proto) -m str {scheme} }}"));
    }
    for (k, h) in m.headers.iter().enumerate() {
        if h.regex.is_some() {
            regex_test(rule, &header_stem(k), None, over, h.negate, &mut parts);
        } else if m.headers.len() > INLINE_HEADERS {
            let bang = if h.negate { "!" } else { "" };
            parts.push(format!("{bang}rhe{k}_{}", rule.id));
        } else {
            parts.push(header_cond(h));
        }
    }
    parts.join(" ")
}

// fhdr keeps the commas inside "(KHTML, like Gecko)" in one value. A request with no header yields no sample, so an empty-value rule is written as the negation of "has any character", which also fires when the header is absent.
fn empty_header_cond(header: &str) -> String {
    format!("!{{ req.fhdr({header}) -m reg . }}")
}

// A missing header yields no sample, so the plain test is false and the negated one is true.
fn header_test(h: &HeaderMatch) -> String {
    let name = h.name.to_ascii_lowercase();
    match &h.equals {
        Some(v) => format!("req.fhdr({name}) -m str -- {v}"),
        None => format!("req.fhdr({name}) -m found"),
    }
}

fn header_cond(h: &HeaderMatch) -> String {
    let bang = if h.negate { "!" } else { "" };
    format!("{bang}{{ {} }}", header_test(h))
}

// A caller that forgets to inject the lock must not get an open site, so rendering refuses instead.
fn check_zone_locks(cfg: &EdgeConfig) -> Result<(), ValidationError> {
    for site in cfg.sites.iter().filter(|s| s.access.zone_lock) {
        let locked = cfg.firewall.iter().any(|r| {
            r.enabled
                && r.action.is_some()
                && r.site.as_deref() == Some(site.id.as_str())
                && r.matchers.headers.iter().any(|h| {
                    h.name.eq_ignore_ascii_case(ZONE_HEADER) && h.negate && h.equals.is_some()
                })
        });
        if !locked {
            return invalid(format!(
                "site {}: zone_lock is on but no enabled zone-lock rule is present",
                site.id
            ));
        }
    }
    Ok(())
}

fn is_zone_rule(rule: &FirewallRule) -> bool {
    rule.matchers
        .headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case(ZONE_HEADER))
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

// libc resolves names at load so a reload serves at once; a name that does not resolve loads with no address, so a stopped standby slot cannot stop HAProxy.
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
fn action_lines(rule: &FirewallRule, action: FirewallAction, conds: &[String], out: &mut String) {
    let label = rule.label.as_deref().unwrap_or(&rule.id);
    for cond in conds {
        push_in(
            out,
            &format!("http-request set-var(txn.blocked) str({label}) if {cond}"),
        );
    }
    let action = match action {
        FirewallAction::Deny => "deny deny_status 403",
        FirewallAction::Drop => "silent-drop",
        FirewallAction::Tarpit => "tarpit",
    };
    push_in(
        out,
        &format!("http-request {action} if {{ var(txn.blocked) -m str {label} }}"),
    );
}

// One ACL per class holds the pattern and one holds the sites, so the long regex is written once however many sites opt in.
fn bot_policy_lines(cfg: &EdgeConfig, out: &mut String) {
    let classes = [
        (BotPolicy::BlockBad, "bots-bad", "bots_bad", bad_bot_regex()),
        (BotPolicy::BlockAll, "bots-all", "bots_all", all_bot_regex()),
    ];
    for (policy, label, stem, regex) in classes {
        let sites: Vec<String> = cfg
            .sites
            .iter()
            .filter(|s| s.access.bots == policy)
            .map(|s| s.id.clone())
            .collect();
        if sites.is_empty() {
            continue;
        }
        push_in(
            out,
            &format!("acl {stem}_ua req.fhdr(user-agent) -m reg -- {regex}"),
        );
        for line in chunked_acl(&format!("{stem}_site"), "var(txn.site) -m str", &sites) {
            push_in(out, &line);
        }
        push_in(
            out,
            &format!("http-request set-var(txn.blocked) str({label}) if {stem}_site {stem}_ua"),
        );
        push_in(
            out,
            &format!("http-request deny deny_status 403 if {{ var(txn.blocked) -m str {label} }}"),
        );
    }
}

// Cloudflare sends the secret for the whole hostname, so it is removed from every request, not only those of the locked site.
fn zone_strip_lines(cfg: &EdgeConfig, out: &mut String) {
    let used = cfg.sites.iter().any(|s| s.access.zone_lock)
        || cfg.firewall.iter().any(|r| r.enabled && is_zone_rule(r));
    if used {
        push_in(out, &format!("http-request del-header {ZONE_HEADER}"));
    }
}

fn effect_cond(rule: &FirewallRule, cfg: &EdgeConfig) -> String {
    let base = rule_cond(rule, cfg);
    let found = "{ var(txn.site) -m found }";
    match (rule.site.is_some(), base.is_empty()) {
        (true, false) => base,
        (_, true) => found.to_string(),
        (false, false) => format!("{found} {base}"),
    }
}

fn quoted_value(v: &str) -> String {
    format!("\"{}\"", v.replace('%', "%%"))
}

fn header_op_line(op: &HeaderOp, cond: &str) -> String {
    let phase = match op.target {
        HeaderTarget::Request => "http-request",
        HeaderTarget::Response => "http-response",
    };
    let value = quoted_value(op.value.as_deref().unwrap_or(""));
    match op.op {
        HeaderOpKind::Set => format!("{phase} set-header {} {value} if {cond}", op.name),
        HeaderOpKind::Add => format!("{phase} add-header {} {value} if {cond}", op.name),
        HeaderOpKind::Remove => format!("{phase} del-header {} if {cond}", op.name),
    }
}

// Request headers are gone by the response phase, so the matched origin is carried in a per-rule variable.
fn cors_var(rule: &FirewallRule) -> String {
    format!("txn.cors_{}", rule.id.replace('-', "_"))
}

fn cors_wildcard(c: &Cors) -> bool {
    c.origins.iter().any(|o| o == "*")
}

fn cors_acl_lines(rule: &FirewallRule, c: &Cors) -> Vec<String> {
    if cors_wildcard(c) {
        return Vec::new();
    }
    let origins: Vec<String> = c.origins.iter().map(|o| o.to_ascii_lowercase()).collect();
    chunked_acl(
        &format!("cors_{}", rule.id),
        "req.fhdr(origin) -m str --",
        &origins,
    )
}

// Only a request with exactly one Origin equal to a listed origin gets CORS headers; a second copy could otherwise be the one that is echoed.
fn cors_origin_cond(rule: &FirewallRule, c: &Cors) -> String {
    if cors_wildcard(c) {
        "{ req.hdr_cnt(origin) gt 0 }".to_string()
    } else {
        format!("cors_{} {{ req.hdr_cnt(origin) eq 1 }}", rule.id)
    }
}

// Response rules cannot read request headers, so the full request-phase condition is evaluated once into this variable.
fn match_var(rule: &FirewallRule) -> String {
    format!("txn.m_{}", rule.id.replace('-', "_"))
}

fn has_response_effect(rule: &FirewallRule) -> bool {
    rule.cors.is_some()
        || rule
            .headers
            .iter()
            .any(|o| o.target == HeaderTarget::Response)
}

fn matched_cond(rule: &FirewallRule) -> String {
    format!("{{ var({}) -m found }}", match_var(rule))
}

// Words as HAProxy counts them: split on blanks, with a double-quoted string being one word.
fn word_count(line: &str) -> usize {
    let (mut words, mut in_word, mut quoted, mut escaped) = (0, false, false, false);
    for c in line.chars() {
        if quoted {
            match (escaped, c) {
                (true, _) => escaped = false,
                (false, '\\') => escaped = true,
                (false, '"') => quoted = false,
                _ => {}
            }
        } else if c.is_whitespace() {
            in_word = false;
        } else {
            if !in_word {
                words += 1;
                in_word = true;
            }
            quoted = c == '"';
        }
    }
    words
}

fn heavy_cond(rule: &FirewallRule, cfg: &EdgeConfig) -> bool {
    word_count(&effect_cond(rule, cfg)) > MAX_COND_WORDS
}

fn needs_match_var(rule: &FirewallRule, cfg: &EdgeConfig) -> bool {
    has_response_effect(rule) || heavy_cond(rule, cfg)
}

// Lines that only test the request keep the full condition unless it is long enough to risk the word limit.
fn request_cond(rule: &FirewallRule, cfg: &EdgeConfig) -> String {
    if heavy_cond(rule, cfg) {
        matched_cond(rule)
    } else {
        effect_cond(rule, cfg)
    }
}

// Header, value pairs; the response phase gets Expose-Headers, the preflight gets Methods, Headers and Max-Age.
fn cors_headers(rule: &FirewallRule, c: &Cors, preflight: bool) -> Vec<(&'static str, String)> {
    let wildcard = cors_wildcard(c);
    let origin = if wildcard {
        "\"*\"".to_string()
    } else if preflight {
        "\"%[req.fhdr(origin)]\"".to_string()
    } else {
        format!("\"%[var({})]\"", cors_var(rule))
    };
    let mut h = vec![("Access-Control-Allow-Origin", origin)];
    if c.credentials {
        h.push(("Access-Control-Allow-Credentials", quoted_value("true")));
    }
    if preflight {
        if !c.methods.is_empty() {
            h.push((
                "Access-Control-Allow-Methods",
                quoted_value(&c.methods.join(", ")),
            ));
        }
        if !c.allow_headers.is_empty() {
            h.push((
                "Access-Control-Allow-Headers",
                quoted_value(&c.allow_headers.join(", ")),
            ));
        }
        if c.max_age_secs > 0 {
            h.push((
                "Access-Control-Max-Age",
                quoted_value(&c.max_age_secs.to_string()),
            ));
        }
    } else if !c.expose_headers.is_empty() {
        h.push((
            "Access-Control-Expose-Headers",
            quoted_value(&c.expose_headers.join(", ")),
        ));
    }
    // the preflight answer carries its own Vary; normal responses get it for every request, see render_effects
    if !wildcard && preflight {
        h.push(("Vary", quoted_value("Origin")));
    }
    h
}

// A redirect to the node's own HTTPS listener is dropped where there is none, and for Flexible sites Cloudflare already owns the scheme.
fn redirect_wanted(rule: &FirewallRule, https_ok: bool) -> bool {
    let Some(r) = &rule.redirect else {
        return true;
    };
    https_ok || !parse_template(&r.to).is_ok_and(|t| t.is_own_https())
}

// The www and apex guards make those helper redirects fire only when they change the host, so they cannot loop.
fn redirect_line(
    rule: &FirewallRule,
    cfg: &EdgeConfig,
    cf: &CloudflareSites,
    t: &Template,
    status: u16,
) -> String {
    let mut cond = request_cond(rule, cfg);
    if t.uses_www() {
        cond.push_str(" !{ var(txn.host) -m beg www. }");
    }
    if t.uses_apex() {
        cond.push_str(" { var(txn.host) -m beg www. }");
    }
    if t.is_own_https() && !cf.flexible.is_empty() {
        cond.push_str(" !cf_flex");
    }
    format!(
        "http-request redirect location {} code {status} if {cond}",
        render_location(&t.pieces)
    )
}

// Request-phase effects run after every blocking rule, in this order: redirects, request header changes, CORS preflight. Response-phase effects follow.
fn render_effects(cfg: &EdgeConfig, cf: &CloudflareSites, https_ok: bool, out: &mut String) {
    let rules: Vec<&FirewallRule> = cfg
        .firewall
        .iter()
        .filter(|r| r.enabled && r.action.is_none() && redirect_wanted(r, https_ok))
        .collect();
    for rule in &rules {
        for line in rule_acl_lines(rule) {
            push_in(out, &line);
        }
        if let Some(c) = &rule.cors {
            for line in cors_acl_lines(rule, c) {
                push_in(out, &line);
            }
        }
    }
    for rule in rules.iter().filter(|r| needs_match_var(r, cfg)) {
        push_in(
            out,
            &format!(
                "http-request set-var({}) int(1) if {}",
                match_var(rule),
                effect_cond(rule, cfg)
            ),
        );
    }
    for rule in &rules {
        if let Some(r) = &rule.redirect
            && let Ok(t) = parse_template(&r.to)
        {
            push_in(out, &redirect_line(rule, cfg, cf, &t, r.status));
        }
    }
    for rule in &rules {
        let cond = request_cond(rule, cfg);
        for op in rule
            .headers
            .iter()
            .filter(|o| o.target == HeaderTarget::Request)
        {
            push_in(out, &header_op_line(op, &cond));
        }
    }
    for rule in &rules {
        let Some(c) = &rule.cors else { continue };
        let cond = format!("{} {}", matched_cond(rule), cors_origin_cond(rule, c));
        push_in(
            out,
            &format!(
                "http-request set-var({}) req.fhdr(origin) if {cond}",
                cors_var(rule)
            ),
        );
    }
    for rule in &rules {
        let Some(c) = &rule.cors else { continue };
        let cond = format!(
            "{} {} {{ method OPTIONS }} {{ req.hdr_cnt(access-control-request-method) gt 0 }}",
            matched_cond(rule),
            cors_origin_cond(rule, c)
        );
        let mut line = String::from("http-request return status 204");
        for (name, value) in cors_headers(rule, c, true) {
            line.push_str(&format!(" hdr {name} {value}"));
        }
        push_in(out, &format!("{line} if {cond}"));
    }
    for rule in rules.iter().filter(|r| has_response_effect(r)) {
        let matched = matched_cond(rule);
        for op in rule
            .headers
            .iter()
            .filter(|o| o.target == HeaderTarget::Response)
        {
            push_in(out, &header_op_line(op, &matched));
        }
        let Some(c) = &rule.cors else { continue };
        let cond = format!("{matched} {{ var({}) -m found }}", cors_var(rule));
        for (name, value) in cors_headers(rule, c, false) {
            push_in(
                out,
                &format!("http-response set-header {name} {value} if {cond}"),
            );
        }
        // the answer depends on Origin even when this request had none, so caches must be told
        if !cors_wildcard(c) {
            push_in(
                out,
                &format!("http-response add-header Vary \"Origin\" if {matched}"),
            );
        }
    }
}

enum Segment<'a> {
    Map(&'a [Site]),
    One(&'a Site),
}

fn is_plain(site: &Site) -> bool {
    site.path_regexes.is_empty()
        && site.path_prefixes.is_empty()
        && site.hosts.iter().all(|h| !h.starts_with('*'))
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
        "path-strip-dotdot full",
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
        "http-request set-var(txn.accept) req.fhdr(accept)",
        "http-request set-var(txn.alang) req.fhdr(accept-language)",
        "http-request set-var(txn.aenc) req.fhdr(accept-encoding)",
        "http-request set-var(txn.sfs) req.fhdr(sec-fetch-site)",
        "http-request set-var(txn.sfm) req.fhdr(sec-fetch-mode)",
        "http-request set-var(txn.sfd) req.fhdr(sec-fetch-dest)",
        "http-request set-var(txn.chua) req.fhdr(sec-ch-ua)",
        "http-response set-var(txn.ct) res.hdr(content-type)",
    ] {
        push_in(out, line);
    }
    // rules also see the path as a lenient origin would: no path parameters, backslashes as slashes, dot segments resolved
    for line in CANONICAL_PATH {
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
        for re in &site.path_regexes {
            push_in(
                out,
                &format!(
                    "acl path_{} path,bytes(0,{PATH_CAP}) -m reg -- {re}",
                    site.id
                ),
            );
            push_in(
                out,
                &format!(
                    "acl path_{} path,url_dec,bytes(0,{PATH_CAP}) -m reg -- {re}",
                    site.id
                ),
            );
        }
        if !site.path_regexes.is_empty() {
            // a path longer than the cap routes nowhere through a regex, exactly like a path that does not match
            push_in(
                out,
                &format!("acl pathok_{} path,length le {PATH_CAP}", site.id),
            );
        }
        for p in &site.path_prefixes {
            push_in(out, &format!("acl pathp_{} path_beg {p}", site.id));
            push_in(
                out,
                &format!("acl pathp_{} path,url_dec -m beg {p}", site.id),
            );
        }
    }
    // the first matching site labels the transaction, so blocked and maintenance requests still name a site
    let mut run = 0;
    for seg in segs {
        match seg {
            Segment::One(site) => {
                for cond in site_conds(site) {
                    push_in(
                        out,
                        &format!(
                            "http-request set-var(txn.site) str({}) if !{{ var(txn.site) -m found }} {cond}",
                            site.id
                        ),
                    );
                }
            }
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
    let cf = cloudflare_sites(cfg);
    // the peer is judged before set-src runs, so the later rules never see a rewritten address
    if let (false, Some(file)) = (cf.aware.is_empty(), &opts.cloudflare_file) {
        cloudflare_acls(&cf, file, out);
        cloudflare_gate(&cf, out);
    }
    push_in(
        out,
        "http-request set-header X-Forwarded-Proto https if { ssl_fc }",
    );
    push_in(
        out,
        "http-request set-header X-Forwarded-Proto http unless { ssl_fc }",
    );
    if !cf.aware.is_empty() && opts.cloudflare_file.is_some() {
        cloudflare_forwarded_proto(&cf, out);
        cloudflare_real_client(&cf, out);
    }
    if let Some(limit) = s.per_ip_rate_limit {
        push_in(
            out,
            "stick-table type ipv6 size 200k expire 10m store http_req_rate(10s)",
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
    // blocking rules: firewall rules in config order, then the bot policy; the rate limit above already counted these requests
    for rule in cfg.firewall.iter().filter(|r| r.enabled) {
        let Some(action) = rule.action else { continue };
        for line in rule_acl_lines(rule) {
            push_in(out, &line);
        }
        action_lines(rule, action, &block_conds(rule, cfg), out);
    }
    bot_policy_lines(cfg, out);
    zone_strip_lines(cfg, out);
    // an HTTPS redirect needs the node's own listener on the default port, or the Location would point nowhere
    let https_ok = tls && s.https_port == Some(443);
    render_effects(cfg, &cf, https_ok, out);
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
                "server t{} {} check inter {}ms rise {} fall {} weight {} resolvers cite init-addr libc,none",
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
    check_zone_locks(cfg)?;
    check_cloudflare_file(&cloudflare_sites(cfg), opts)?;
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
    // last guard: HAProxy aborts on a line of more than 64 words, and the line is not echoed because it may hold a secret
    if let Some((n, line)) = config
        .lines()
        .enumerate()
        .find(|(_, l)| word_count(l) > MAX_LINE_WORDS)
    {
        return invalid(format!(
            "rendered config line {} has {} words (limit {MAX_LINE_WORDS}); simplify the rule with the most matchers",
            n + 1,
            word_count(line)
        ));
    }

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

    let cloudflare_list: String = if cloudflare_sites(cfg).aware.is_empty() {
        String::new()
    } else {
        effective_ranges(&cfg.settings)
            .iter()
            .map(|r| format!("{r}\n"))
            .collect()
    };

    Ok(Rendered {
        config,
        active_map,
        maint_map,
        pages,
        cloudflare_list,
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
    part(rendered.cloudflare_list.as_bytes());
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
    use crate::model::{FirewallAction, MaintenancePage, Matchers, Redirect, Target, TlsMode};
    use crate::presets::{preset, zone_lock_rule};
    use crate::validate::fixtures::{config, rule, site};
    use proptest::prelude::*;

    fn opts() -> RenderOptions {
        RenderOptions {
            maps_dir: "/run/cite/maps".into(),
            pages_dir: "/run/cite/pages".into(),
            runtime_addr: "ipv4@127.0.0.1:9999".into(),
            log_addr: "127.0.0.1:514".into(),
            tls_dir: None,
            cloudflare_file: Some("/run/cite/maps/cloudflare.lst".into()),
        }
    }

    fn cf_site(id: &str, host: &str, only: bool, tls: TlsMode) -> Site {
        let mut s = site(id, host);
        s.access.cloudflare_only = only;
        s.access.tls = tls;
        s
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
        s.path_regexes = vec!["^/api/".into()];
        let r = render(&config(vec![s]), &opts()).unwrap();
        assert_eq!(
            lines_with(&r, "acl path_a path,bytes(0,2048) -m reg -- ^/api/").len(),
            1
        );
        assert_eq!(
            lines_with(&r, "acl path_a path,url_dec,bytes(0,2048) -m reg -- ^/api/").len(),
            1
        );
        assert_eq!(
            lines_with(&r, "acl pathok_a"),
            ["    acl pathok_a path,length le 2048"]
        );
        let route = lines_with(&r, "use_backend");
        assert_eq!(
            route,
            [
                "    use_backend %[var(txn.site),map(/run/cite/maps/active.map)] if { var(txn.site) -m found }"
            ]
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
                .contains("server t2 10.0.0.6:80 check inter 2000ms rise 2 fall 3 weight 10 resolvers cite init-addr libc,none")
        );
        assert!(r.config.contains("option httpchk GET /"));
    }

    #[test]
    fn firewall_rules_keep_order_and_come_before_routing() {
        let mut cfg = config(vec![site("a", "a.com")]);
        let m = |p: &str| Matchers {
            path_prefixes: vec![p.into()],
            ..Default::default()
        };
        cfg.firewall.push(rule("first", m("/one")));
        let mut second = rule("second", m("/two"));
        second.action = Some(FirewallAction::Drop);
        cfg.firewall.push(second);
        let mut third = rule("third", m("/three"));
        third.action = Some(FirewallAction::Tarpit);
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
                path_prefixes: vec!["/x".into()],
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
                user_agent_regexes: vec!["(?i)bot".into()],
                cidrs: vec!["10.0.0.0/8".into(), "2001:db8::1".into()],
                hosts: vec!["*.a.com".into()],
                ..Default::default()
            },
        );
        scoped.site = Some("b".into());
        cfg.firewall.push(scoped);
        cfg.firewall.push(rule(
            "global",
            Matchers {
                path_regexes: vec!["^/admin".into()],
                ..Default::default()
            },
        ));
        let r = render(&cfg, &opts()).unwrap();
        let line = lines_with(&r, "str(scoped) if { var(txn.site) -m str b }")[0];
        assert!(line.ends_with(
            "if { var(txn.site) -m str b } { method TRACE DEBUG } { src 10.0.0.0/8 2001:db8::1 } { var(txn.host) -m end .a.com } ru_scoped"
        ));
        assert_eq!(
            lines_with(&r, "acl ru_scoped"),
            ["    acl ru_scoped req.fhdr(user-agent),bytes(0,512) -m reg -- (?i)bot"]
        );
        assert_eq!(
            lines_with(&r, "acl rubig_scoped"),
            ["    acl rubig_scoped req.fhdr(user-agent),length gt 512"]
        );
        // an oversized user agent counts as a match, so padding cannot hide the pattern
        assert_eq!(
            lines_with(&r, "str(scoped) if")[1],
            "    http-request set-var(txn.blocked) str(scoped) if { var(txn.site) -m str b } { method TRACE DEBUG } { src 10.0.0.0/8 2001:db8::1 } { var(txn.host) -m end .a.com } rubig_scoped"
        );
        let global = lines_with(&r, "str(global) if rp_global");
        assert_eq!(global.len(), 1);
        assert!(!global[0].contains("host_"));
        assert_eq!(
            lines_with(&r, "acl rp_global"),
            [
                "    acl rp_global path,bytes(0,2048) -m reg -- ^/admin",
                "    acl rp_global var(txn.cpath),bytes(0,2048) -m reg -- ^/admin",
            ]
        );
        assert_eq!(
            lines_with(&r, "acl rpbig_global"),
            [
                "    acl rpbig_global path,length gt 2048",
                "    acl rpbig_global var(txn.cpath),length gt 2048",
            ]
        );
        assert_eq!(lines_with(&r, "str(global) if rpbig_global").len(), 1);
        let deny = "http-request deny deny_status 403 if { var(txn.blocked) -m str global }";
        assert_eq!(lines_with(&r, deny).len(), 1);
    }

    #[test]
    fn lists_render_as_repeated_acl_names_and_one_condition() {
        let mut cfg = config(vec![site("a", "a.com")]);
        cfg.firewall.push(rule(
            "multi",
            Matchers {
                path_prefixes: vec!["/one".into(), "/two".into()],
                path_regexes: vec!["^/x".into(), "^/y".into()],
                user_agent_regexes: vec!["bot".into(), "spider".into()],
                referer_regexes: vec!["evil".into(), "worse".into()],
                hosts: vec!["a.com".into(), "*.b.com".into()],
                ..Default::default()
            },
        ));
        let r = render(&cfg, &opts()).unwrap();
        assert_eq!(
            lines_with(&r, "acl rb_multi"),
            [
                "    acl rb_multi path_beg /one",
                "    acl rb_multi var(txn.cpath) -m beg /one",
                "    acl rb_multi path_beg /two",
                "    acl rb_multi var(txn.cpath) -m beg /two",
            ]
        );
        assert_eq!(
            lines_with(&r, "acl rp_multi"),
            [
                "    acl rp_multi path,bytes(0,2048) -m reg -- ^/x",
                "    acl rp_multi path,bytes(0,2048) -m reg -- ^/y",
                "    acl rp_multi var(txn.cpath),bytes(0,2048) -m reg -- ^/x",
                "    acl rp_multi var(txn.cpath),bytes(0,2048) -m reg -- ^/y",
            ]
        );
        // one oversize ACL per field, however many patterns it holds
        assert_eq!(
            lines_with(&r, "acl rpbig_multi"),
            [
                "    acl rpbig_multi path,length gt 2048",
                "    acl rpbig_multi var(txn.cpath),length gt 2048",
            ]
        );
        assert_eq!(
            lines_with(&r, "acl ru_multi"),
            [
                "    acl ru_multi req.fhdr(user-agent),bytes(0,512) -m reg -- bot",
                "    acl ru_multi req.fhdr(user-agent),bytes(0,512) -m reg -- spider",
            ]
        );
        assert_eq!(lines_with(&r, "acl rubig_multi").len(), 1);
        assert_eq!(lines_with(&r, "acl rr_multi").len(), 2);
        assert_eq!(lines_with(&r, "acl rrbig_multi").len(), 0);
        assert_eq!(
            lines_with(&r, "acl rhost_multi"),
            [
                "    acl rhost_multi var(txn.host) -m str a.com",
                "    acl rhost_multi var(txn.host) -m end .b.com",
            ]
        );
        // across fields every name appears once and all must hold; each regex field has one variant where an oversized value stands in
        assert_eq!(
            lines_with(&r, "str(multi) if"),
            [
                "    http-request set-var(txn.blocked) str(multi) if rhost_multi rb_multi rp_multi ru_multi rr_multi",
                "    http-request set-var(txn.blocked) str(multi) if rhost_multi rb_multi rpbig_multi ru_multi rr_multi",
                "    http-request set-var(txn.blocked) str(multi) if rhost_multi rb_multi rp_multi rubig_multi rr_multi",
            ]
        );
    }

    #[test]
    fn a_single_host_stays_inline_and_header_lists_use_named_acls_from_three_up() {
        let eq = |name: &str, negate: bool| HeaderMatch {
            name: name.into(),
            equals: Some("1".into()),
            negate,
            ..HeaderMatch::default()
        };
        let re = |name: &str, negate: bool| HeaderMatch {
            name: name.into(),
            regex: Some("^v".into()),
            negate,
            ..HeaderMatch::default()
        };
        let mut cfg = config(vec![site("a", "a.com")]);
        cfg.firewall.push(rule(
            "two",
            Matchers {
                headers: vec![re("X-A", false), eq("X-B", true)],
                hosts: vec!["*.a.com".into()],
                ..Default::default()
            },
        ));
        cfg.firewall.push(rule(
            "three",
            Matchers {
                headers: vec![eq("X-A", false), re("X-B", true), eq("X-C", true)],
                ..Default::default()
            },
        ));
        let r = render(&cfg, &opts()).unwrap();
        assert_eq!(
            lines_with(&r, "str(two) if"),
            [
                "    http-request set-var(txn.blocked) str(two) if { var(txn.host) -m end .a.com } rh_two !{ req.fhdr(x-b) -m str -- 1 }"
            ]
        );
        assert_eq!(lines_with(&r, "acl rhost_two").len(), 0);
        assert_eq!(
            lines_with(&r, "acl rh_two"),
            ["    acl rh_two req.fhdr(x-a),bytes(0,1024) -m reg -- ^v"]
        );
        assert_eq!(
            lines_with(&r, "acl rhe0_three"),
            ["    acl rhe0_three req.fhdr(x-a) -m str -- 1"]
        );
        assert_eq!(
            lines_with(&r, "acl rh1_three"),
            ["    acl rh1_three req.fhdr(x-b),bytes(0,1024) -m reg -- ^v"]
        );
        assert_eq!(
            lines_with(&r, "acl rhe2_three"),
            ["    acl rhe2_three req.fhdr(x-c) -m str -- 1"]
        );
        assert_eq!(
            lines_with(&r, "str(three) if"),
            [
                "    http-request set-var(txn.blocked) str(three) if rhe0_three !rh1_three !rhe2_three"
            ]
        );
    }

    #[test]
    fn a_site_with_prefixes_and_regexes_gets_one_routing_line_for_each() {
        let mut both = site("b", "b.com");
        both.path_prefixes = vec!["/a".into(), "/b".into()];
        both.path_regexes = vec!["^/c".into(), "^/d".into()];
        let mut only_prefix = site("c", "c.com");
        only_prefix.path_prefixes = vec!["/p".into()];
        let r = render(&config(vec![both, only_prefix]), &opts()).unwrap();
        assert_eq!(
            lines_with(&r, "set-var(txn.site)"),
            [
                "    http-request set-var(txn.site) str(b) if !{ var(txn.site) -m found } host_b pathp_b",
                "    http-request set-var(txn.site) str(b) if !{ var(txn.site) -m found } host_b path_b pathok_b",
                "    http-request set-var(txn.site) str(c) if !{ var(txn.site) -m found } host_c pathp_c",
            ]
        );
        assert_eq!(
            lines_with(&r, "acl pathp_b"),
            [
                "    acl pathp_b path_beg /a",
                "    acl pathp_b path,url_dec -m beg /a",
                "    acl pathp_b path_beg /b",
                "    acl pathp_b path,url_dec -m beg /b",
            ]
        );
        assert_eq!(lines_with(&r, "acl path_b ").len(), 4);
        assert_eq!(lines_with(&r, "acl pathok_b").len(), 1);
        assert_eq!(lines_with(&r, "acl pathok_c").len(), 0);
    }

    #[test]
    fn full_lists_stay_under_the_line_limit_in_every_role() {
        let mut big = maximal_matchers();
        big.path_prefixes = (0..16).map(|i| format!("/pre{i}")).collect();
        big.path_regexes = (0..8).map(|i| format!("^/re{i}/")).collect();
        big.user_agent_regexes = (0..8).map(|i| format!("agent{i}")).collect();
        big.referer_regexes = (0..8).map(|i| format!("^https://r{i}[.]com/")).collect();
        big.hosts = (0..16).map(|i| format!("*.h{i}.example.com")).collect();
        big.headers = (0..5)
            .map(|i| HeaderMatch {
                name: format!("X-H{i}"),
                equals: Some("v".into()),
                negate: i % 2 == 0,
                ..HeaderMatch::default()
            })
            .collect();
        let mut cfg = config(vec![site("a", "a.com")]);
        let mut block = scoped_to(rule("blk", big.clone()), "a");
        block.action = Some(FirewallAction::Drop);
        cfg.firewall.push(block);
        let mut cors = cors_rule(&["https://a.example.com"]);
        cors.matchers = big.clone();
        cfg.firewall.push(cors);
        let mut redirect = scoped_to(effect("rdr"), "a");
        redirect.matchers = big;
        redirect.redirect = Some(Redirect {
            to: "{scheme}://{www_host}{path}{query}".into(),
            status: 301,
        });
        cfg.firewall.push(redirect);
        let r = render(&cfg, &opts()).unwrap();
        assert!(longest_line(&r) <= 60, "{}", longest_line(&r));
        for line in lines_with(&r, "http-response") {
            assert!(!line.contains("req."), "{line}");
        }
    }

    #[test]
    fn user_agent_rules_read_the_whole_header_and_cover_a_missing_one() {
        let mut cfg = config(vec![site("a", "a.com")]);
        cfg.firewall.push(rule(
            "chrome",
            Matchers {
                user_agent_regexes: vec!["KHTML,\\slike\\sGecko".into()],
                ..Default::default()
            },
        ));
        cfg.firewall.push(rule(
            "empty",
            Matchers {
                user_agent_regexes: vec!["^$".into()],
                ..Default::default()
            },
        ));
        let r = render(&cfg, &opts()).unwrap();
        assert!(!r.config.contains("req.hdr(user-agent)"));
        assert_eq!(
            lines_with(
                &r,
                "acl ru_chrome req.fhdr(user-agent),bytes(0,512) -m reg -- KHTML,\\slike\\sGecko"
            )
            .len(),
            1
        );
        assert_eq!(lines_with(&r, "str(chrome) if ru_chrome").len(), 1);
        // the empty-agent rule has no oversize line: padding makes an agent non-empty, which is the point
        assert_eq!(lines_with(&r, "str(empty)").len(), 1);
        assert_eq!(
            lines_with(&r, "str(empty) if !{ req.fhdr(user-agent) -m reg . }").len(),
            1
        );
    }

    #[test]
    fn blocked_var_is_set_once_and_the_action_tests_it() {
        let mut cfg = config(vec![]);
        cfg.firewall.push(rule(
            "r1",
            Matchers {
                path_prefixes: vec!["/x".into()],
                ..Default::default()
            },
        ));
        let r = render(&cfg, &opts()).unwrap();
        let set = "http-request set-var(txn.blocked) str(r1) if rb_r1";
        let act = "http-request deny deny_status 403 if { var(txn.blocked) -m str r1 }";
        assert!(position(&r, set) < position(&r, act));
        assert_eq!(lines_with(&r, "rb_r1").len(), 3);
        assert_eq!(lines_with(&r, "path_beg /x").len(), 1);
        assert_eq!(lines_with(&r, "var(txn.cpath) -m beg /x").len(), 1);
    }

    #[test]
    fn uri_is_normalised_before_vars_acls_and_rules() {
        let mut cfg = config(vec![site("a", "a.com")]);
        cfg.firewall.push(rule(
            "r1",
            Matchers {
                path_prefixes: vec!["/x".into()],
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
            "normalize-uri path-strip-dotdot full",
            "normalize-uri fragment-strip",
            "set-var(txn.path) path",
            "set-path %[path,regsub(",
            "set-var(txn.cpath) path",
            "set-path %[var(txn.path)]",
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
    fn canonical_path_strips_parameters_and_backslashes_then_restores_the_path() {
        let r = render(&config(vec![site("a", "a.com")]), &opts()).unwrap();
        let set = lines_with(&r, "set-path %[path,regsub(");
        assert_eq!(set.len(), 1);
        for part in [
            "regsub(;[^/]*,,g)",
            "regsub(%3B[^/]*,,g)",
            "regsub(%5C,/,g)",
        ] {
            assert!(set[0].contains(part), "{part}");
        }
        assert!(set[0].contains(r"regsub(\\\\\\\\,/,g)"));
        assert_eq!(
            lines_with(&r, "normalize-uri path-strip-dotdot full").len(),
            2
        );
        assert_eq!(lines_with(&r, "normalize-uri path-strip-dotdot").len(), 2);
        let order = [
            "set-var(txn.path) path",
            "set-path %[path,regsub(",
            "set-var(txn.cpath) path",
            "set-path %[var(txn.path)]",
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
    fn bot_headers_are_copied_into_vars_and_logged() {
        let r = render(&config(vec![]), &opts()).unwrap();
        let pairs = [
            ("accept", "accept"),
            ("alang", "accept-language"),
            ("aenc", "accept-encoding"),
            ("sfs", "sec-fetch-site"),
            ("sfm", "sec-fetch-mode"),
            ("sfd", "sec-fetch-dest"),
            ("chua", "sec-ch-ua"),
        ];
        for (var, header) in pairs {
            let set = format!("http-request set-var(txn.{var}) req.fhdr({header})");
            assert_eq!(lines_with(&r, &set).len(), 1, "{set}");
            assert!(LOG_FORMAT.contains(&format!("%[var(txn.{var}),bytes(0,")));
            assert!(position(&r, &set) < position(&r, "default_backend"));
        }
        assert!(r.config.contains("%HV"));
        assert!(r.config.contains("ssl_fc_protocol"));
    }

    #[test]
    fn site_label_is_set_for_the_first_matching_site() {
        let mut b = site("b", "b.com");
        b.path_regexes = vec!["^/api".into()];
        let r = render(&config(vec![site("a", "a.com"), b]), &opts()).unwrap();
        assert_eq!(
            lines_with(&r, "set-var(txn.site)"),
            [
                "    http-request set-var(txn.site) str(a) if !{ var(txn.site) -m found } host_a",
                "    http-request set-var(txn.site) str(b) if !{ var(txn.site) -m found } host_b path_b pathok_b",
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
            [
                "    http-request set-var(txn.site) var(txn.host),concat(@0),map(/run/cite/maps/active.map) if !{ var(txn.site) -m found }"
            ]
        );
        assert!(r.config.lines().all(|l| !l.starts_with("    acl host_")));
        assert!(r.active_map.starts_with("s0 be_s0_blue\n"));
        assert!(
            r.active_map
                .contains("\ns3 be_s3_blue\ns4 be_s4_blue\ns5 be_s5_blue\n")
        );
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
        let entries: Vec<&str> = r.active_map.lines().filter(|l| l.contains("@0")).collect();
        assert_eq!(entries, ["shared.example.com@0 s0"]);
    }

    #[test]
    fn long_acl_value_lists_are_split_below_the_line_limit() {
        let ids: Vec<String> = (0..600).map(|i| format!("site-{i}")).collect();
        let lines = chunked_acl("maint_pg0", "var(txn.site) -m str", &ids);
        assert!(lines.len() > 1);
        assert!(lines.iter().all(|l| l.len() <= MAX_ACL_LINE));
        assert!(lines.iter().all(|l| l.split(' ').count() <= 60));
        let joined: Vec<&str> = lines.iter().flat_map(|l| l.split(" ").skip(5)).collect();
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
        assert_eq!(
            lines_with(&r, "acl maint_pg0 var(txn.site) -m str a").len(),
            1
        );
        assert_eq!(
            lines_with(&r, "acl maint_pg1 var(txn.site) -m str b").len(),
            1
        );
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
                .contains("stick-table type ipv6 size 200k expire 10m store http_req_rate(10s)")
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
        s.path_regexes = vec!["^/x\nbackend evil".into()];
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
                user_agent_regexes: vec!["a#b".into()],
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
        let mut cfg = config(vec![site("a", "a.com"), site("b", "b.com")]);
        for p in crate::presets::presets() {
            cfg.firewall.extend(p.rules);
        }
        // opposing www and apex redirects may not share a scope
        for r in &mut cfg.firewall {
            match r.id.as_str() {
                "preset-redirect-to-www-1" => r.site = Some("a".into()),
                "preset-redirect-to-apex-1" => r.site = Some("b".into()),
                _ => {}
            }
        }
        let r = render(&cfg, &opts()).unwrap();
        assert!(r.config.contains("str(preset-odd-methods-1)"));
        let blocking = cfg.firewall.iter().filter(|r| r.action.is_some()).count();
        // every regex field of a blocking rule adds one line for an oversized subject, except the empty-agent test
        let oversize = cfg
            .firewall
            .iter()
            .filter(|r| r.action.is_some())
            .map(|r| {
                usize::from(!r.matchers.path_regexes.is_empty())
                    + usize::from(
                        !r.matchers.user_agent_regexes.is_empty()
                            && !is_empty_test(&r.matchers.user_agent_regexes),
                    )
            })
            .sum::<usize>();
        assert_eq!(
            lines_with(&r, "set-var(txn.blocked)").len(),
            blocking + oversize
        );
        // no HTTPS listener, so force-https is skipped; the two www presets are rendered
        assert_eq!(lines_with(&r, "http-request redirect").len(), 2);
    }

    #[test]
    fn sites_without_access_settings_render_no_cloudflare_lines() {
        let cfg = config(vec![site("a", "a.com"), site("b", "b.com")]);
        let with_file = render(&cfg, &opts()).unwrap();
        let mut o = opts();
        o.cloudflare_file = None;
        let without_file = render(&cfg, &o).unwrap();
        assert_eq!(with_file, without_file);
        for needle in [
            "cf_",
            "fc_src",
            "CF-Connecting-IP",
            "True-Client-IP",
            "set-src",
            "cloudflare",
        ] {
            assert!(!with_file.config.contains(needle), "{needle}");
        }
        assert!(with_file.cloudflare_list.is_empty());
        assert_eq!(
            lines_with(&with_file, "X-Forwarded-Proto"),
            [
                "    http-request set-header X-Forwarded-Proto https if { ssl_fc }",
                "    http-request set-header X-Forwarded-Proto http unless { ssl_fc }",
            ]
        );
    }

    #[test]
    fn hash_covers_the_range_list() {
        let plain = render(&config(vec![site("a", "a.com")]), &opts()).unwrap();
        assert!(plain.cloudflare_list.is_empty());
        let mut changed = plain.clone();
        changed.cloudflare_list = "198.51.100.0/24\n".into();
        assert_ne!(config_hash(&plain), config_hash(&changed));
        let mut cfg = config(vec![cf_site("a", "a.com", true, TlsMode::Full)]);
        let one = config_hash(&render(&cfg, &opts()).unwrap());
        cfg.settings.cloudflare_ranges = vec!["198.51.100.0/24".into()];
        assert_ne!(one, config_hash(&render(&cfg, &opts()).unwrap()));
    }

    #[test]
    fn cloudflare_only_site_is_denied_for_peers_outside_the_list() {
        let cfg = config(vec![
            site("open", "open.com"),
            cf_site("cf", "cf.com", true, TlsMode::Full),
        ]);
        let r = render(&cfg, &opts()).unwrap();
        assert_eq!(
            lines_with(&r, "acl cf_peer"),
            ["    acl cf_peer fc_src -f /run/cite/maps/cloudflare.lst"]
        );
        assert_eq!(
            lines_with(&r, "acl cf_only"),
            ["    acl cf_only var(txn.site) -m str cf"]
        );
        let set = "http-request set-var(txn.blocked) str(cloudflare-only) if cf_only !cf_peer";
        let deny =
            "http-request deny deny_status 403 if { var(txn.blocked) -m str cloudflare-only }";
        assert_eq!(lines_with(&r, set).len(), 1);
        assert_eq!(lines_with(&r, deny).len(), 1);
        let order = [
            "set-var(txn.site)",
            "acl cf_peer",
            set,
            deny,
            "X-Forwarded-Proto https if { ssl_fc }",
            "http-request set-src",
            "use_backend",
        ];
        let at: Vec<usize> = order.iter().map(|n| position(&r, n)).collect();
        assert!(at.windows(2).all(|w| w[0] < w[1]), "{at:?}");
        assert!(!r.cloudflare_list.is_empty());
        for range in r.cloudflare_list.lines() {
            assert!(
                !r.config.contains(range),
                "{range} must live only in the list file"
            );
        }
        assert!(!r.config.contains("hdr(cf-connecting-ip) -f"));
    }

    #[test]
    fn cloudflare_checks_run_before_firewall_rate_limit_and_tracking() {
        let mut cfg = config(vec![cf_site("cf", "cf.com", true, TlsMode::Full)]);
        cfg.settings.per_ip_rate_limit = Some(50);
        cfg.firewall.push(rule(
            "ip",
            Matchers {
                cidrs: vec!["203.0.113.0/24".into()],
                ..Default::default()
            },
        ));
        let r = render(&cfg, &opts()).unwrap();
        let order = [
            "str(cloudflare-only)",
            "http-request set-src",
            "stick-table",
            "track-sc0 src",
            "str(ip)",
        ];
        let at: Vec<usize> = order.iter().map(|n| position(&r, n)).collect();
        assert!(at.windows(2).all(|w| w[0] < w[1]), "{at:?}");
    }

    #[test]
    fn real_client_address_comes_only_from_a_single_valid_header_of_a_cloudflare_peer() {
        let r = render(
            &config(vec![cf_site("cf", "cf.com", true, TlsMode::Full)]),
            &opts(),
        )
        .unwrap();
        assert_eq!(
            lines_with(&r, "set-src"),
            [
                "    http-request set-src req.fhdr(cf-connecting-ip) if cf_only cf_peer { req.hdr_cnt(cf-connecting-ip) eq 1 } { req.fhdr(cf-connecting-ip) -m ip 0.0.0.0/0 ::/0 }"
            ]
        );
        assert_eq!(
            lines_with(&r, "del-header"),
            [
                "    http-request del-header CF-Connecting-IP if cf_aware !cf_peer",
                "    http-request del-header True-Client-IP if cf_aware !cf_peer",
                "    http-request del-header CF-Visitor if cf_aware !cf_peer",
                "    http-request del-header CF-Connecting-IPv6 if cf_aware !cf_peer",
                "    http-request del-header CF-Pseudo-IPv4 if cf_aware !cf_peer",
            ]
        );
        assert!(!r.config.contains("set-src hdr"));
    }

    #[test]
    fn flexible_sites_take_the_scheme_from_cloudflare_only_for_cloudflare_peers() {
        let cfg = config(vec![
            site("open", "open.com"),
            cf_site("flex", "flex.com", false, TlsMode::Flexible),
        ]);
        let r = render(&cfg, &opts()).unwrap();
        assert_eq!(
            lines_with(&r, "acl cf_flex"),
            ["    acl cf_flex var(txn.site) -m str flex"]
        );
        assert!(lines_with(&r, "acl cf_only").is_empty());
        assert!(lines_with(&r, "str(cloudflare-only)").is_empty());
        assert!(lines_with(&r, "set-src").is_empty());
        assert_eq!(
            lines_with(&r, "X-Forwarded-Proto"),
            [
                "    http-request set-header X-Forwarded-Proto https if { ssl_fc }",
                "    http-request set-header X-Forwarded-Proto http unless { ssl_fc }",
                "    http-request set-header X-Forwarded-Proto https if cf_flex cf_peer { var(txn.cfproto) -m str https }",
                "    http-request set-header X-Forwarded-Proto http if cf_flex cf_peer !{ var(txn.cfproto) -m str https }",
            ]
        );
        let capture =
            "http-request set-var(txn.cfproto) req.fhdr(x-forwarded-proto) if cf_flex cf_peer";
        assert!(position(&r, capture) < position(&r, "X-Forwarded-Proto https if { ssl_fc }"));
        assert!(!r.config.contains("redirect"));
    }

    #[test]
    fn full_mode_sites_keep_the_ssl_fc_logic_even_next_to_cloudflare_only() {
        let r = render(
            &config(vec![cf_site("cf", "cf.com", true, TlsMode::Full)]),
            &opts(),
        )
        .unwrap();
        assert!(lines_with(&r, "cf_flex").is_empty());
        assert!(lines_with(&r, "cfproto").is_empty());
        assert_eq!(lines_with(&r, "X-Forwarded-Proto").len(), 2);
    }

    #[test]
    fn range_list_follows_settings_and_is_empty_without_cloudflare_sites() {
        let mut cfg = config(vec![cf_site("cf", "cf.com", true, TlsMode::Full)]);
        let r = render(&cfg, &opts()).unwrap();
        assert!(r.cloudflare_list.starts_with("173.245.48.0/20\n"));
        assert!(r.cloudflare_list.ends_with("2c0f:f248::/32\n"));
        assert_eq!(
            r.cloudflare_list.lines().count(),
            crate::cloudflare::BUILTIN_RANGES.len()
        );
        cfg.settings.cloudflare_ranges = vec!["198.51.100.0/24".into(), "198.51.100.0/24".into()];
        assert_eq!(
            render(&cfg, &opts()).unwrap().cloudflare_list,
            "198.51.100.0/24\n"
        );
        cfg.sites[0].access = Default::default();
        assert!(render(&cfg, &opts()).unwrap().cloudflare_list.is_empty());
    }

    #[test]
    fn cloudflare_sites_need_a_range_file_and_it_must_be_a_safe_path() {
        let cfg = config(vec![cf_site("cf", "cf.com", true, TlsMode::Full)]);
        let mut o = opts();
        o.cloudflare_file = None;
        let err = render(&cfg, &o).unwrap_err();
        assert!(err.to_string().contains("cloudflare_file"));
        let flex = config(vec![cf_site("f", "f.com", false, TlsMode::Flexible)]);
        assert!(render(&flex, &o).is_err());
        o.cloudflare_file = Some("/x\nbackend y".into());
        assert!(render(&cfg, &o).is_err());
        assert!(render(&config(vec![site("a", "a.com")]), &o).is_err());
    }

    #[test]
    fn many_cloudflare_sites_split_the_site_acl_below_the_line_limit() {
        let sites: Vec<Site> = (0..300)
            .map(|i| {
                cf_site(
                    &format!("site-number-{i}"),
                    &format!("h{i}.com"),
                    true,
                    TlsMode::Flexible,
                )
            })
            .collect();
        let r = render(&config(sites), &opts()).unwrap();
        assert!(
            r.config
                .lines()
                .filter(|l| l.trim_start().starts_with("acl cf_"))
                .all(|l| l.len() <= MAX_ACL_LINE + 4)
        );
        assert!(lines_with(&r, "acl cf_only").len() > 1);
        assert!(lines_with(&r, "acl cf_aware").len() > 1);
    }

    fn effect(id: &str) -> FirewallRule {
        FirewallRule {
            id: id.into(),
            name: id.into(),
            enabled: true,
            ..FirewallRule::default()
        }
    }

    fn scoped_to(mut rule: FirewallRule, site_id: &str) -> FirewallRule {
        rule.site = Some(site_id.into());
        rule
    }

    fn preset_rule(name: &str) -> FirewallRule {
        preset(name).expect("preset").rules.remove(0)
    }

    fn header_op(
        target: HeaderTarget,
        kind: HeaderOpKind,
        name: &str,
        value: Option<&str>,
    ) -> HeaderOp {
        HeaderOp {
            target,
            op: kind,
            name: name.into(),
            value: value.map(String::from),
        }
    }

    fn tls_opts(cfg: &mut EdgeConfig, port: u16) -> RenderOptions {
        cfg.settings.https_port = Some(port);
        RenderOptions {
            tls_dir: Some("/etc/cite/tls".into()),
            ..opts()
        }
    }

    const SECRET: &str = "k3Y9-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const WWW_LOCATION: &str = "%[req.fhdr(x-forwarded-proto)]://www.%[req.fhdr(host),lower]%[path]%[url,regsub(^[^?]*,,i)]";

    #[test]
    fn configs_without_the_new_features_render_exactly_as_before() {
        let mut cfg = config(vec![site("a", "a.com")]);
        cfg.firewall.push(rule(
            "r1",
            Matchers {
                path_prefixes: vec!["/x".into()],
                ..Default::default()
            },
        ));
        let r = render(&cfg, &opts()).unwrap();
        let tail: Vec<&str> = r
            .config
            .lines()
            .skip_while(|l| !l.contains("track-sc0"))
            .skip(1)
            .take_while(|l| !l.starts_with("backend"))
            .collect();
        assert_eq!(
            tail,
            [
                "    http-request deny deny_status 429 if { sc_http_req_rate(0) gt 600 }",
                "    acl rb_r1 path_beg /x",
                "    acl rb_r1 var(txn.cpath) -m beg /x",
                "    http-request set-var(txn.blocked) str(r1) if rb_r1",
                "    http-request deny deny_status 403 if { var(txn.blocked) -m str r1 }",
                "    acl maint_pg0 var(txn.site) -m str a",
                "    http-request return status 503 content-type \"text/html; charset=utf-8\" file /run/cite/pages/_default.html hdr cache-control no-store if maint_pg0 { var(txn.site),map(/run/cite/maps/maint.map,off) -m str on }",
                "    use_backend %[var(txn.site),map(/run/cite/maps/active.map)] if { var(txn.site) -m found }",
                "    default_backend be_notfound",
                "",
            ]
        );
        for needle in [
            "redirect",
            "status 204",
            "bots",
            "cloudflare-zone",
            "X-Cite",
            "cors_",
            "del-header",
            "http-response set-header",
            "http-response add-header",
        ] {
            assert!(!r.config.contains(needle), "{needle}");
        }
        assert_eq!(lines_with(&r, "http-response").len(), 1);
    }

    #[test]
    fn bot_policy_blocks_with_one_regex_per_class_after_the_cloudflare_gate_and_firewall_rules() {
        let mut bad = cf_site("bad", "bad.com", true, TlsMode::Full);
        bad.access.bots = BotPolicy::BlockBad;
        let mut all = site("all", "all.com");
        all.access.bots = BotPolicy::BlockAll;
        let mut cfg = config(vec![bad, all, site("open", "open.com")]);
        cfg.firewall.push(rule(
            "ip",
            Matchers {
                cidrs: vec!["203.0.113.0/24".into()],
                ..Default::default()
            },
        ));
        let r = render(&cfg, &opts()).unwrap();
        assert_eq!(
            lines_with(&r, "acl bots_"),
            [
                format!(
                    "    acl bots_bad_ua req.fhdr(user-agent) -m reg -- {}",
                    bad_bot_regex()
                ),
                "    acl bots_bad_site var(txn.site) -m str bad".to_string(),
                format!(
                    "    acl bots_all_ua req.fhdr(user-agent) -m reg -- {}",
                    all_bot_regex()
                ),
                "    acl bots_all_site var(txn.site) -m str all".to_string(),
            ]
        );
        assert_eq!(
            lines_with(&r, "str(bots-"),
            [
                "    http-request set-var(txn.blocked) str(bots-bad) if bots_bad_site bots_bad_ua",
                "    http-request set-var(txn.blocked) str(bots-all) if bots_all_site bots_all_ua",
            ]
        );
        for label in ["bots-bad", "bots-all"] {
            let deny = format!(
                "http-request deny deny_status 403 if {{ var(txn.blocked) -m str {label} }}"
            );
            assert_eq!(lines_with(&r, &deny).len(), 1, "{label}");
        }
        let order = [
            "str(cloudflare-only)",
            "http-request set-src",
            "str(ip)",
            "str(bots-bad)",
            "str(bots-all)",
            "use_backend",
        ];
        let at: Vec<usize> = order.iter().map(|n| position(&r, n)).collect();
        assert!(at.windows(2).all(|w| w[0] < w[1]), "{at:?}");
    }

    #[test]
    fn bot_policy_keeps_the_user_agent_in_the_log_and_never_blocks_a_missing_one() {
        let mut s = site("a", "a.com");
        s.access.bots = BotPolicy::BlockBad;
        let r = render(&config(vec![s]), &opts()).unwrap();
        let set_ua = position(&r, "http-request set-var(txn.ua) req.fhdr(user-agent)");
        assert!(set_ua < position(&r, "str(bots-bad)"));
        assert!(LOG_FORMAT.contains("%[var(txn.ua),bytes(0,512),url_enc]"));
        assert!(r.config.contains("%[var(txn.blocked),url_enc]"));
        // a positive match on a header that is absent is false, so an empty User-Agent is left to the scanners preset
        assert!(!lines_with(&r, "acl bots_bad_ua")[0].contains('!'));
        assert!(
            lines_with(&r, "set-var(txn.blocked) str(bots-bad)")[0]
                .ends_with("if bots_bad_site bots_bad_ua")
        );
    }

    #[test]
    fn zone_lock_denies_without_the_secret_labels_the_block_and_strips_the_header() {
        let mut flex = cf_site("shop", "shop.com", true, TlsMode::Flexible);
        flex.access.bots = BotPolicy::Allow;
        let mut cfg = config(vec![flex, site("other", "other.com")]);
        cfg.firewall.push(zone_lock_rule("shop", SECRET));
        let r = render(&cfg, &opts()).unwrap();
        let set = format!(
            "    http-request set-var(txn.blocked) str(cloudflare-zone) if {{ var(txn.site) -m str shop }} !{{ req.fhdr(x-cite-origin-secret) -m str -- {SECRET} }}"
        );
        assert_eq!(lines_with(&r, "str(cloudflare-zone)"), [set.as_str()]);
        assert_eq!(
            lines_with(&r, "-m str cloudflare-zone"),
            [
                "    http-request deny deny_status 403 if { var(txn.blocked) -m str cloudflare-zone }"
            ]
        );
        assert_eq!(
            lines_with(&r, "del-header X-Cite-Origin-Secret"),
            ["    http-request del-header X-Cite-Origin-Secret"]
        );
        let order = [
            "str(cloudflare-only)",
            "http-request set-src",
            "str(cloudflare-zone)",
            "del-header X-Cite-Origin-Secret",
            "use_backend",
        ];
        let at: Vec<usize> = order.iter().map(|n| position(&r, n)).collect();
        assert!(at.windows(2).all(|w| w[0] < w[1]), "{at:?}");
        // the rule id, not the secret, is what the log carries
        assert!(!r.config.contains(&format!("str({SECRET})")));
        let mut off = cfg.clone();
        off.firewall[0].enabled = false;
        let r = render(&off, &opts()).unwrap();
        assert!(!r.config.contains("X-Cite") && !r.config.contains(SECRET));
    }

    #[test]
    fn www_and_apex_redirects_carry_a_guard_so_they_cannot_loop() {
        let mut cfg = config(vec![site("a", "a.com"), site("b", "b.com")]);
        cfg.firewall
            .push(scoped_to(preset_rule("redirect-to-www"), "a"));
        cfg.firewall
            .push(scoped_to(preset_rule("redirect-to-apex"), "b"));
        let r = render(&cfg, &opts()).unwrap();
        assert_eq!(
            lines_with(&r, "http-request redirect"),
            [
                format!("    http-request redirect location {WWW_LOCATION} code 301 if {{ var(txn.site) -m str a }} !{{ var(txn.host) -m beg www. }}"),
                "    http-request redirect location %[req.fhdr(x-forwarded-proto)]://%[req.fhdr(host),lower,regsub(^www[.],,i)]%[path]%[url,regsub(^[^?]*,,i)] code 301 if { var(txn.site) -m str b } { var(txn.host) -m beg www. }".to_string(),
            ]
        );
        // a redirect never fires for a host that matched no site
        assert!(
            lines_with(&r, "redirect")
                .iter()
                .all(|l| l.contains("var(txn.site)"))
        );
    }

    #[test]
    fn redirects_come_after_blocking_rules_and_before_maintenance_and_routing() {
        let mut cfg = config(vec![site("a", "a.com")]);
        cfg.firewall.push(preset_rule("redirect-to-www"));
        cfg.firewall.push(rule(
            "blk",
            Matchers {
                path_prefixes: vec!["/x".into()],
                ..Default::default()
            },
        ));
        let r = render(&cfg, &opts()).unwrap();
        let order = [
            "track-sc0 src",
            "str(blk)",
            "http-request redirect",
            "return status 503",
            "use_backend",
        ];
        let at: Vec<usize> = order.iter().map(|n| position(&r, n)).collect();
        assert!(at.windows(2).all(|w| w[0] < w[1]), "{at:?}");
    }

    #[test]
    fn static_redirects_use_their_status_and_escape_percent_signs() {
        let mut cfg = config(vec![site("a", "a.com")]);
        let mut mv = effect("mv");
        mv.matchers.path_prefixes = vec!["/old".into()];
        mv.redirect = Some(Redirect {
            to: "/new/a%20b".into(),
            status: 308,
        });
        cfg.firewall.push(mv);
        let r = render(&cfg, &opts()).unwrap();
        assert_eq!(
            lines_with(&r, "redirect"),
            [
                "    http-request redirect location /new/a%%20b code 308 if { var(txn.site) -m found } rb_mv"
            ]
        );
        assert!(position(&r, "acl rb_mv path_beg /old") < position(&r, "http-request redirect"));
    }

    #[test]
    fn force_https_needs_the_nodes_own_listener_and_skips_flexible_sites() {
        let https = "    http-request redirect location https://%[req.fhdr(host),lower]%[path]%[url,regsub(^[^?]*,,i)] code 301 if { var(txn.site) -m found } { req.fhdr(x-forwarded-proto) -m str http }";
        let mut cfg = config(vec![site("a", "a.com")]);
        cfg.firewall.push(preset_rule("force-https"));
        let r = render(&cfg, &opts()).unwrap();
        assert!(lines_with(&r, "redirect").is_empty());
        assert!(!r.config.contains("x-forwarded-proto) -m str http"));
        let o = tls_opts(&mut cfg, 8443);
        assert!(lines_with(&render(&cfg, &o).unwrap(), "redirect").is_empty());
        let o = tls_opts(&mut cfg, 443);
        let r = render(&cfg, &o).unwrap();
        assert_eq!(lines_with(&r, "redirect"), [https]);
        cfg.sites
            .push(cf_site("flex", "flex.com", false, TlsMode::Flexible));
        let r = render(&cfg, &o).unwrap();
        assert_eq!(lines_with(&r, "redirect"), [format!("{https} !cf_flex")]);
        assert!(position(&r, "acl cf_flex") < position(&r, "http-request redirect"));
        let mut only_flex = scoped_to(preset_rule("force-https"), "flex");
        only_flex.id = "fh".into();
        cfg.firewall = vec![only_flex];
        let r = render(&cfg, &o).unwrap();
        assert!(lines_with(&r, "redirect")[0].ends_with("!cf_flex"));
        assert!(lines_with(&r, "redirect")[0].contains("-m str flex"));
    }

    #[test]
    fn header_changes_render_in_their_phase_with_safe_quoting() {
        use HeaderOpKind::{Add, Remove, Set};
        use HeaderTarget::{Request, Response};
        let mut cfg = config(vec![site("a", "a.com")]);
        let mut hdr = scoped_to(effect("hdr"), "a");
        hdr.headers = vec![
            header_op(Response, Set, "X-Frame-Options", Some("DENY")),
            header_op(Request, Set, "X-Env", Some("prod")),
            header_op(Request, Add, "X-Trace", Some("a b%c")),
            header_op(Request, Remove, "X-Debug", None),
            header_op(Response, Remove, "Server", None),
        ];
        cfg.firewall.push(hdr);
        let r = render(&cfg, &opts()).unwrap();
        let site_cond = "if { var(txn.site) -m str a }";
        let matched = "if { var(txn.m_hdr) -m found }";
        let lines = [
            format!("    http-request set-header X-Env \"prod\" {site_cond}"),
            format!("    http-request add-header X-Trace \"a b%%c\" {site_cond}"),
            format!("    http-request del-header X-Debug {site_cond}"),
            format!("    http-response set-header X-Frame-Options \"DENY\" {matched}"),
            format!("    http-response del-header Server {matched}"),
        ];
        assert_eq!(
            lines_with(&r, "set-var(txn.m_hdr)"),
            ["    http-request set-var(txn.m_hdr) int(1) if { var(txn.site) -m str a }"]
        );
        let at: Vec<usize> = lines.iter().map(|l| position(&r, l)).collect();
        assert!(at.iter().all(|p| *p != usize::MAX), "{at:?}");
        assert!(at.windows(2).all(|w| w[0] < w[1]), "{at:?}");
        assert!(at[4] < position(&r, "use_backend"));
        assert!(position(&r, "set-var(txn.cpath) var(txn.cpath),url_dec") < at[0]);
    }

    #[test]
    fn global_header_rules_only_touch_requests_that_matched_a_site() {
        let mut cfg = config(vec![site("a", "a.com")]);
        let mut hdr = effect("sec");
        hdr.headers = vec![header_op(
            HeaderTarget::Response,
            HeaderOpKind::Set,
            "X-Content-Type-Options",
            Some("nosniff"),
        )];
        cfg.firewall.push(hdr);
        let r = render(&cfg, &opts()).unwrap();
        assert_eq!(
            lines_with(&r, "X-Content-Type-Options"),
            [
                "    http-response set-header X-Content-Type-Options \"nosniff\" if { var(txn.m_sec) -m found }"
            ]
        );
        assert_eq!(
            lines_with(&r, "set-var(txn.m_sec)"),
            ["    http-request set-var(txn.m_sec) int(1) if { var(txn.site) -m found }"]
        );
    }

    fn cors_rule(origins: &[&str]) -> FirewallRule {
        let mut cr = scoped_to(effect("cr"), "a");
        cr.cors = Some(Cors {
            origins: origins.iter().map(|o| o.to_string()).collect(),
            methods: vec!["GET".into(), "POST".into()],
            allow_headers: vec!["Content-Type".into()],
            expose_headers: vec!["X-Id".into()],
            credentials: origins != ["*"],
            max_age_secs: 600,
        });
        cr
    }

    #[test]
    fn cors_answers_preflight_at_the_edge_and_decorates_responses_for_listed_origins_only() {
        let mut cfg = config(vec![site("a", "a.com")]);
        cfg.firewall.push(cors_rule(&[
            "https://App.example.com",
            "https://b.example.com",
        ]));
        let r = render(&cfg, &opts()).unwrap();
        assert_eq!(
            lines_with(&r, "acl cors_cr"),
            [
                "    acl cors_cr req.fhdr(origin) -m str -- https://app.example.com https://b.example.com"
            ]
        );
        let cond = "{ var(txn.m_cr) -m found } cors_cr { req.hdr_cnt(origin) eq 1 }";
        assert_eq!(
            lines_with(&r, "return status 204"),
            [format!(
                "    http-request return status 204 hdr Access-Control-Allow-Origin \"%[req.fhdr(origin)]\" hdr Access-Control-Allow-Credentials \"true\" hdr Access-Control-Allow-Methods \"GET, POST\" hdr Access-Control-Allow-Headers \"Content-Type\" hdr Access-Control-Max-Age \"600\" hdr Vary \"Origin\" if {cond} {{ method OPTIONS }} {{ req.hdr_cnt(access-control-request-method) gt 0 }}"
            )]
        );
        let resp = "{ var(txn.m_cr) -m found } { var(txn.cors_cr) -m found }";
        assert_eq!(
            lines_with(&r, "http-request set-var(txn.cors_cr)"),
            [format!(
                "    http-request set-var(txn.cors_cr) req.fhdr(origin) if {cond}"
            )]
        );
        assert_eq!(
            lines_with(&r, "http-response")[1..],
            [
                format!(
                    "    http-response set-header Access-Control-Allow-Origin \"%[var(txn.cors_cr)]\" if {resp}"
                ),
                format!(
                    "    http-response set-header Access-Control-Allow-Credentials \"true\" if {resp}"
                ),
                format!(
                    "    http-response set-header Access-Control-Expose-Headers \"X-Id\" if {resp}"
                ),
                "    http-response add-header Vary \"Origin\" if { var(txn.m_cr) -m found }"
                    .to_string(),
            ]
        );
        assert_eq!(
            lines_with(&r, "set-var(txn.m_cr)"),
            ["    http-request set-var(txn.m_cr) int(1) if { var(txn.site) -m str a }"]
        );
        // the Origin header is only ever echoed behind the exact-match ACL
        for line in lines_with(&r, "req.fhdr(origin)") {
            if !line.contains("acl cors_cr") {
                assert!(line.contains(" cors_cr"), "{line}");
            }
        }
        assert!(position(&r, "return status 204") < position(&r, "return status 503"));
        assert!(position(&r, "return status 204") < position(&r, "use_backend"));
    }

    #[test]
    fn cors_wildcard_sends_a_literal_star_and_no_vary() {
        let mut cfg = config(vec![site("a", "a.com")]);
        cfg.firewall.push(cors_rule(&["*"]));
        let r = render(&cfg, &opts()).unwrap();
        assert!(lines_with(&r, "acl cors_").is_empty());
        let pre = lines_with(&r, "return status 204");
        assert_eq!(pre.len(), 1);
        assert!(pre[0].contains("hdr Access-Control-Allow-Origin \"*\" "));
        assert!(!pre[0].contains("Vary") && !pre[0].contains("Credentials"));
        assert!(pre[0].ends_with("if { var(txn.m_cr) -m found } { req.hdr_cnt(origin) gt 0 } { method OPTIONS } { req.hdr_cnt(access-control-request-method) gt 0 }"));
        assert!(!r.config.contains("%[req.fhdr(origin)]"));
        assert!(!r.config.contains("%[var(txn.cors_"));
        assert!(lines_with(&r, "http-response add-header").is_empty());
    }

    #[test]
    fn minimal_cors_omits_the_optional_headers() {
        let mut cfg = config(vec![site("a", "a.com")]);
        let mut cr = scoped_to(effect("cr"), "a");
        cr.cors = Some(Cors {
            origins: vec!["https://a.example.com".into()],
            ..Cors::default()
        });
        cfg.firewall.push(cr);
        let r = render(&cfg, &opts()).unwrap();
        let pre = lines_with(&r, "return status 204")[0];
        for absent in ["Methods", "Headers", "Max-Age", "Credentials"] {
            assert!(!pre.contains(absent), "{absent}");
        }
        assert!(lines_with(&r, "Expose-Headers").is_empty());
    }

    #[test]
    fn disabled_effect_rules_render_nothing() {
        let mut cfg = config(vec![site("a", "a.com")]);
        let mut www = preset_rule("redirect-to-www");
        www.enabled = false;
        let mut cors = cors_rule(&["*"]);
        cors.enabled = false;
        cfg.firewall.extend([www, cors]);
        let r = render(&cfg, &opts()).unwrap();
        assert_eq!(
            r,
            render(&config(vec![site("a", "a.com")]), &opts()).unwrap()
        );
    }

    #[test]
    fn invalid_effect_rules_stop_the_render() {
        let mut cfg = config(vec![site("a", "a.com")]);
        let mut bad = effect("bad");
        bad.redirect = Some(Redirect {
            to: "javascript:alert(1)".into(),
            status: 301,
        });
        bad.matchers.path_prefixes = vec!["/x".into()];
        cfg.firewall.push(bad);
        assert!(
            render(&cfg, &opts())
                .unwrap_err()
                .to_string()
                .contains("rule bad")
        );
    }

    fn locked_site() -> Site {
        let mut s = cf_site("shop", "shop.com", true, TlsMode::Full);
        s.access.zone_lock = true;
        s
    }

    #[test]
    fn zone_lock_flag_refuses_to_render_without_an_enabled_lock_rule() {
        let cfg = config(vec![locked_site()]);
        let err = render(&cfg, &opts()).unwrap_err().to_string();
        assert!(
            err.contains("site shop") && err.contains("zone-lock"),
            "{err}"
        );
        let mut with = cfg.clone();
        with.firewall.push(zone_lock_rule("shop", SECRET));
        assert!(render(&with, &opts()).is_ok());
        with.firewall[0].enabled = false;
        assert!(render(&with, &opts()).is_err());
        let mut other = cfg.clone();
        other.sites.push(site("other", "other.com"));
        other.firewall.push(zone_lock_rule("other", SECRET));
        assert!(render(&other, &opts()).is_err());
        let mut weak = cfg;
        let mut r = zone_lock_rule("shop", SECRET);
        r.matchers.headers[0].negate = false;
        weak.firewall.push(r);
        assert!(render(&weak, &opts()).is_err());
    }

    #[test]
    fn zone_lock_requires_cloudflare_only() {
        let mut s = site("shop", "shop.com");
        s.access.zone_lock = true;
        let err = render(&config(vec![s]), &opts()).unwrap_err().to_string();
        assert!(err.contains("requires cloudflare_only"), "{err}");
    }

    #[test]
    fn with_zone_locks_injects_one_rule_per_locked_site_and_fails_closed() {
        use crate::presets::with_zone_locks;
        let cfg = config(vec![locked_site(), site("open", "open.com")]);
        let secret_for = |id: &str| (id == "shop").then(|| SECRET.to_string());
        let full = with_zone_locks(&cfg, secret_for).expect("injected");
        assert_eq!(full.firewall.len(), 1);
        assert!(cfg.firewall.is_empty(), "the input is not modified");
        assert!(render(&full, &opts()).is_ok());
        let err = with_zone_locks(&cfg, |_| None).unwrap_err().to_string();
        assert!(
            err.contains("site shop") && err.contains("no zone secret"),
            "{err}"
        );
        let short = with_zone_locks(&cfg, |_| Some("short".to_string())).unwrap_err();
        assert!(!short.to_string().contains("short\""), "{short}");
        let none = config(vec![site("open", "open.com")]);
        assert_eq!(with_zone_locks(&none, |_| None).expect("no locks"), none);
    }

    #[test]
    fn changing_the_zone_secret_changes_the_config_hash() {
        use crate::presets::with_zone_locks;
        let cfg = config(vec![locked_site()]);
        let hash = |secret: &str| {
            let full = with_zone_locks(&cfg, |_| Some(secret.to_string())).expect("injected");
            config_hash(&render(&full, &opts()).unwrap())
        };
        let a = hash(SECRET);
        assert_eq!(a, hash(SECRET));
        assert_ne!(a, hash(&SECRET.replace("k3Y9", "k3Y8")));
    }

    #[test]
    fn zone_lock_flag_is_omitted_from_json_when_off_and_loads_when_absent() {
        let s = site("a", "a.com");
        let v = serde_json::to_value(&s.access).unwrap();
        assert!(v.get("zone_lock").is_none());
        let on: crate::model::SiteAccess =
            serde_json::from_str(r#"{"cloudflare_only": true, "zone_lock": true}"#).unwrap();
        assert!(on.zone_lock);
        assert_eq!(serde_json::to_value(&on).unwrap()["zone_lock"], true);
    }

    fn maximal_matchers() -> Matchers {
        Matchers {
            path_regexes: vec!["^/api/v[0-9]+/".into()],
            path_prefixes: vec!["/api".into()],
            methods: (0..16)
                .map(|i| format!("METHOD{}", "A".repeat(i % 5 + 1)))
                .collect(),
            user_agent_regexes: vec!["(?i)mozilla".into()],
            cidrs: (0..8).map(|i| format!("203.0.113.{i}")).collect(),
            hosts: vec!["*.a.com".into()],
            headers: vec![HeaderMatch {
                name: "X-Gate".into(),
                equals: Some("v".into()),
                negate: true,
                ..HeaderMatch::default()
            }],
            scheme: Some("http".into()),
            referer_regexes: vec!["^https://x[.]com/".into()],
        }
    }

    fn longest_line(r: &Rendered) -> usize {
        r.config.lines().map(word_count).max().unwrap_or(0)
    }

    #[test]
    fn word_counting_treats_quoted_strings_as_one_word() {
        assert_eq!(word_count("a b  c"), 3);
        assert_eq!(word_count(r#"set-header X "a b c" if { x }"#), 7);
        assert_eq!(word_count(r#"hdr V "a \" b" next"#), 4);
        assert_eq!(word_count(""), 0);
    }

    #[test]
    fn a_rule_with_every_matcher_stays_under_the_line_limit_in_every_role() {
        let mut cfg = config(vec![site("a", "a.com")]);
        let mut block = scoped_to(rule("blk", maximal_matchers()), "a");
        block.action = Some(FirewallAction::Tarpit);
        cfg.firewall.push(block);
        let mut redirect = scoped_to(effect("rdr"), "a");
        redirect.matchers = maximal_matchers();
        redirect.redirect = Some(Redirect {
            to: "{scheme}://{www_host}{path}{query}".into(),
            status: 301,
        });
        cfg.firewall.push(redirect);
        let mut hdr = effect("hdr");
        hdr.matchers = maximal_matchers();
        hdr.headers = vec![
            header_op(HeaderTarget::Request, HeaderOpKind::Set, "X-A", Some("1")),
            header_op(HeaderTarget::Response, HeaderOpKind::Set, "X-B", Some("2")),
        ];
        cfg.firewall.push(hdr);
        let mut cors = cors_rule(&["https://a.example.com", "https://b.example.com"]);
        cors.matchers = maximal_matchers();
        cfg.firewall.push(cors);
        let r = render(&cfg, &opts()).unwrap();
        assert!(longest_line(&r) <= 60, "{}", longest_line(&r));
        assert_eq!(lines_with(&r, "acl rm_blk").len(), 1);
        assert_eq!(lines_with(&r, "acl rm_hdr").len(), 1);
        assert!(lines_with(&r, "str(blk)")[0].contains(" rm_blk"));
        // a long condition is evaluated once and the other lines test the variable
        let preflight = lines_with(&r, "return status 204");
        assert!(
            preflight[0].contains("{ var(txn.m_cr) -m found }"),
            "{}",
            preflight[0]
        );
        assert!(lines_with(&r, "http-request redirect")[0].contains("{ var(txn.m_rdr) -m found }"));
        assert!(
            lines_with(&r, "http-request set-header X-A")[0]
                .contains("{ var(txn.m_hdr) -m found }")
        );
        for line in lines_with(&r, "http-response") {
            assert!(!line.contains("req."), "{line}");
        }
    }

    #[test]
    fn the_largest_host_lists_stay_chunked_under_the_word_limit() {
        let mut s = site("many", "m.com");
        s.hosts = (0..64).map(|i| format!("h{i}.m.com")).collect();
        let mut wild = site("wild", "w.com");
        wild.hosts = (0..64).map(|i| format!("*.w{i}.com")).collect();
        let r = render(&config(vec![s, wild]), &opts()).unwrap();
        assert!(longest_line(&r) <= 60, "{}", longest_line(&r));
    }

    #[test]
    fn referer_and_header_regexes_judge_the_prefix_and_never_add_an_oversize_guard() {
        let hm = |negate: bool| HeaderMatch {
            name: "X-Gate".into(),
            regex: Some("^v".into()),
            negate,
            ..HeaderMatch::default()
        };
        let mut cfg = config(vec![site("a", "a.com")]);
        cfg.firewall.push(response_rule(
            "neg",
            Matchers {
                headers: vec![hm(true)],
                ..Default::default()
            },
        ));
        cfg.firewall.push(response_rule(
            "ref",
            Matchers {
                referer_regexes: vec!["^https://x[.]com/".into()],
                ..Default::default()
            },
        ));
        let mut deny = rule(
            "blk",
            Matchers {
                headers: vec![hm(false)],
                referer_regexes: vec!["evil".into()],
                ..Default::default()
            },
        );
        deny.site = Some("a".into());
        cfg.firewall.push(deny);
        let r = render(&cfg, &opts()).unwrap();
        for stem in ["rhok", "rhbig", "rrok", "rrbig"] {
            assert!(!r.config.contains(stem), "{stem}");
        }
        assert_eq!(
            lines_with(&r, "acl rh_neg"),
            ["    acl rh_neg req.fhdr(x-gate),bytes(0,1024) -m reg -- ^v"]
        );
        // a header that is absent has no sample, so the negated test alone is what lets the rule fire
        assert_eq!(
            lines_with(&r, "set-var(txn.m_neg)"),
            ["    http-request set-var(txn.m_neg) int(1) if { var(txn.site) -m found } !rh_neg"]
        );
        assert_eq!(
            lines_with(&r, "set-var(txn.m_ref)"),
            ["    http-request set-var(txn.m_ref) int(1) if { var(txn.site) -m found } rr_ref"]
        );
        assert_eq!(lines_with(&r, "str(blk)").len(), 1);
    }

    fn response_rule(id: &str, matchers: Matchers) -> FirewallRule {
        let mut r = effect(id);
        r.matchers = matchers;
        r.headers = vec![header_op(
            HeaderTarget::Response,
            HeaderOpKind::Set,
            "X-A",
            Some("1"),
        )];
        r
    }

    #[test]
    fn response_rules_never_read_request_headers_whatever_the_matcher() {
        let hm = |negate: bool| HeaderMatch {
            name: "X-Gate".into(),
            equals: Some("v".into()),
            negate,
            ..HeaderMatch::default()
        };
        let variants = [
            (
                "ua",
                "ruok_ua ru_ua",
                Matchers {
                    user_agent_regexes: vec!["(?i)bot".into()],
                    ..Default::default()
                },
            ),
            (
                "ref",
                "rr_ref",
                Matchers {
                    referer_regexes: vec!["^https://x[.]com/".into()],
                    ..Default::default()
                },
            ),
            (
                "hdr",
                "req.fhdr(x-gate) -m str -- v",
                Matchers {
                    headers: vec![hm(false)],
                    ..Default::default()
                },
            ),
            (
                "neg",
                "!{ req.fhdr(x-gate) -m str -- v }",
                Matchers {
                    headers: vec![hm(true)],
                    ..Default::default()
                },
            ),
            (
                "sch",
                "req.fhdr(x-forwarded-proto) -m str http",
                Matchers {
                    scheme: Some("http".into()),
                    ..Default::default()
                },
            ),
        ];
        for (id, in_request, matchers) in variants {
            let mut cfg = config(vec![site("a", "a.com")]);
            cfg.firewall.push(response_rule(id, matchers.clone()));
            let mut cors = scoped_to(effect(&format!("c{id}")), "a");
            cors.matchers = matchers;
            cors.cors = Some(Cors {
                origins: vec!["https://a.example.com".into()],
                ..Cors::default()
            });
            cfg.firewall.push(cors);
            let r = render(&cfg, &opts()).unwrap();
            for line in lines_with(&r, "http-response") {
                assert!(!line.contains("req."), "{id}: {line}");
            }
            let set = lines_with(&r, &format!("http-request set-var(txn.m_{id}) int(1)"));
            assert_eq!(set.len(), 1, "{id}");
            assert!(set[0].contains(in_request), "{id}: {}", set[0]);
            assert_eq!(
                lines_with(
                    &r,
                    &format!(
                        "http-response set-header X-A \"1\" if {{ var(txn.m_{id}) -m found }}"
                    )
                )
                .len(),
                1,
                "{id}"
            );
            assert!(position(&r, &format!("set-var(txn.m_{id})")) < position(&r, "use_backend"));
        }
    }

    #[test]
    fn the_zone_header_is_removed_from_every_request_when_any_site_is_locked() {
        let mut shop = cf_site("shop", "shared.com", true, TlsMode::Full);
        shop.path_regexes = vec!["^/shop".into()];
        shop.access.zone_lock = true;
        let mut blog = site("blog", "shared.com");
        blog.path_regexes = vec!["^/blog".into()];
        let mut cfg = config(vec![shop, blog]);
        cfg.firewall.push(zone_lock_rule("shop", SECRET));
        let r = render(&cfg, &opts()).unwrap();
        assert_eq!(
            lines_with(&r, "X-Cite-Origin-Secret"),
            ["    http-request del-header X-Cite-Origin-Secret"]
        );
        assert_eq!(
            lines_with(&r, "str(cloudflare-zone)"),
            [format!(
                "    http-request set-var(txn.blocked) str(cloudflare-zone) if {{ var(txn.site) -m str shop }} !{{ req.fhdr(x-cite-origin-secret) -m str -- {SECRET} }}"
            )]
        );
        assert!(position(&r, "-m str cloudflare-zone") < position(&r, "del-header X-Cite"));
        assert!(position(&r, "del-header X-Cite") < position(&r, "use_backend"));
        let plain = render(&config(vec![site("a", "a.com")]), &opts()).unwrap();
        assert!(!plain.config.contains("X-Cite"));
        // a rule that references the header without the site flag still strips it everywhere
        let mut rule_only = config(vec![site("a", "a.com"), site("b", "b.com")]);
        rule_only.firewall.push(zone_lock_rule("a", SECRET));
        let r = render(&rule_only, &opts()).unwrap();
        assert_eq!(
            lines_with(&r, "del-header X-Cite"),
            ["    http-request del-header X-Cite-Origin-Secret"]
        );
    }

    #[test]
    fn long_cidr_lists_become_named_acls_below_the_word_limit() {
        let many = |n: usize| Matchers {
            cidrs: (0..n)
                .map(|i| format!("10.{}.{}.0/24", i / 256, i % 256))
                .collect(),
            ..Default::default()
        };
        let mut cfg = config(vec![site("a", "a.com")]);
        cfg.firewall.push(rule("big", many(200)));
        cfg.firewall.push(rule("small", many(4)));
        let r = render(&cfg, &opts()).unwrap();
        let acls = lines_with(&r, "acl rc_big src");
        assert!(acls.len() >= 5, "{}", acls.len());
        assert!(acls.iter().all(|l| l.split_whitespace().count() <= 64));
        let values: usize = acls.iter().map(|l| l.split_whitespace().count() - 3).sum();
        assert_eq!(values, 200);
        assert_eq!(
            lines_with(&r, "str(big)"),
            ["    http-request set-var(txn.blocked) str(big) if rc_big"]
        );
        assert!(lines_with(&r, "acl rc_small").is_empty());
        assert!(lines_with(&r, "str(small)")[0].contains("{ src 10.0.0.0/24"));
    }

    #[test]
    fn cors_needs_exactly_one_origin_header_and_vary_covers_requests_without_one() {
        let mut cfg = config(vec![site("a", "a.com")]);
        cfg.firewall.push(cors_rule(&["https://a.example.com"]));
        let r = render(&cfg, &opts()).unwrap();
        for line in lines_with(&r, "cors_cr")
            .iter()
            .filter(|l| l.contains("http-request"))
        {
            assert!(line.contains("{ req.hdr_cnt(origin) eq 1 }"), "{line}");
        }
        assert!(
            lines_with(&r, "http-response add-header Vary")[0]
                .ends_with("if { var(txn.m_cr) -m found }")
        );
    }

    fn effect_for(
        kind: u8,
        i: usize,
        site_ix: Option<usize>,
        flag: bool,
        status_ix: usize,
    ) -> FirewallRule {
        let mut r = effect(&format!("e{i}"));
        r.site = site_ix.map(|s| format!("s{s}"));
        match kind {
            // fixed scopes keep the two opposing redirects from sharing one, which validation refuses
            0 => {
                r.redirect = preset_rule("redirect-to-www").redirect;
                r.site = Some("s0".into());
            }
            1 => {
                r.redirect = preset_rule("redirect-to-apex").redirect;
                r.site = Some("s1".into());
            }
            2 => {
                r = preset_rule("force-https");
                r.id = format!("e{i}");
                r.site = site_ix.map(|s| format!("s{s}"));
            }
            3 => {
                r.matchers.path_prefixes = vec![format!("/old{i}")];
                r.redirect = Some(Redirect {
                    to: format!("/new{i}/{{path}}x"),
                    status: [301, 302, 307, 308][status_ix % 4],
                });
            }
            4 => {
                r.headers = vec![
                    header_op(
                        HeaderTarget::Response,
                        HeaderOpKind::Set,
                        "X-A",
                        Some("1 2 %"),
                    ),
                    header_op(HeaderTarget::Request, HeaderOpKind::Add, "X-B", Some("v")),
                    header_op(HeaderTarget::Request, HeaderOpKind::Remove, "X-C", None),
                ];
                r.matchers.scheme = flag.then(|| "https".to_string());
            }
            5 => {
                r.cors = Some(Cors {
                    origins: if flag {
                        vec!["*".into()]
                    } else {
                        vec![
                            "https://a.example.com".into(),
                            "http://localhost:3000".into(),
                        ]
                    },
                    methods: vec!["GET".into()],
                    credentials: !flag,
                    max_age_secs: 60,
                    ..Cors::default()
                });
            }
            6 => {
                r.action = Some(FirewallAction::Deny);
                r.matchers.headers = vec![HeaderMatch {
                    name: "X-Gate".into(),
                    equals: Some("v-1.x".into()),
                    negate: flag,
                    ..HeaderMatch::default()
                }];
            }
            _ => {
                r = zone_lock_rule("s0", SECRET);
                r.id = format!("e{i}");
            }
        }
        r
    }

    proptest! {
        #[test]
        fn random_valid_effect_combinations_render_structurally_valid_configs(
            specs in proptest::collection::vec(
                (0u8..8, proptest::option::of(0usize..3), any::<bool>(), 0usize..4, any::<bool>()),
                0..12,
            ),
            policies in proptest::collection::vec(0u8..3, 3),
            cf in proptest::collection::vec(any::<bool>(), 3),
            https in 0u8..3,
        ) {
            let sites: Vec<Site> = (0..3)
                .map(|i| {
                    let mut s = cf_site(&format!("s{i}"), &format!("s{i}.example.com"), cf[i], if cf[i] { TlsMode::Flexible } else { TlsMode::Full });
                    s.access.bots = [BotPolicy::Allow, BotPolicy::BlockBad, BotPolicy::BlockAll][usize::from(policies[i])];
                    s
                })
                .collect();
            let mut cfg = config(sites);
            for (i, (kind, site_ix, flag, status_ix, enabled)) in specs.iter().enumerate() {
                let mut rule = effect_for(*kind, i, *site_ix, *flag, *status_ix);
                rule.enabled = *enabled;
                cfg.firewall.push(rule);
            }
            let o = match https {
                0 => opts(),
                1 => tls_opts(&mut cfg, 443),
                _ => tls_opts(&mut cfg, 8443),
            };
            let rendered = render(&cfg, &o);
            prop_assert!(rendered.is_ok(), "{:?}", rendered.err());
            if let Ok(r) = rendered {
                for line in r.config.lines() {
                    let ok = line.is_empty()
                        || line.starts_with("    ")
                        || line.starts_with('#')
                        || ["global", "defaults", "resolvers ", "frontend ", "backend "]
                            .iter()
                            .any(|k| line.starts_with(k));
                    prop_assert!(ok, "stray line {:?}", line);
                    prop_assert!(!line.contains('\r') && !line.contains('\t'));
                }
                let frontend: Vec<&str> = r.config
                    .lines()
                    .skip_while(|l| !l.starts_with("frontend fe_main"))
                    .take_while(|l| !l.starts_with("backend"))
                    .collect();
                for line in &frontend {
                    if line.contains("http-request redirect location ") {
                        prop_assert!(line.contains(" code 30"));
                        prop_assert!(line.contains(" if "));
                        prop_assert!(!line.contains('"'));
                    }
                    if line.contains("return status 204") {
                        prop_assert!(line.contains(" { method OPTIONS }"), "preflight line lacks the OPTIONS condition");
                    }
                    if line.contains("%[req.fhdr(origin)]") {
                        prop_assert!(line.contains(" cors_e"));
                    }
                }
                let uses = |needle: &str| frontend.iter().position(|l| l.contains(needle));
                if let (Some(redirect), Some(blocked)) = (
                    uses("http-request redirect"),
                    frontend.iter().rposition(|l| l.contains("deny deny_status 403")),
                ) {
                    prop_assert!(blocked < redirect);
                }
                if let (Some(preflight), Some(routing)) = (uses("return status 204"), uses("use_backend")) {
                    prop_assert!(preflight < routing);
                }
            }
        }
    }

    // IPv6 starts at 2400::/12 and up so no generated range can touch the blocks validation refuses.
    fn valid_range() -> impl Strategy<Value = String> {
        prop_oneof![
            (any::<u32>(), 12u8..=32)
                .prop_map(|(a, p)| format!("{}/{p}", std::net::Ipv4Addr::from(a))),
            (0x2400u16..=0x2fff, any::<u128>(), 28u8..=128).prop_map(|(h, r, p)| {
                let addr = (u128::from(h) << 112) | (r >> 16);
                format!("{}/{p}", std::net::Ipv6Addr::from(addr))
            }),
        ]
    }

    proptest! {
        #[test]
        fn access_settings_keep_the_config_structurally_valid(
            only in proptest::collection::vec(any::<bool>(), 1..6),
            flexible in proptest::collection::vec(any::<bool>(), 1..6),
            ranges in proptest::collection::vec(valid_range(), 0..5),
        ) {
            let sites: Vec<Site> = only
                .iter()
                .zip(flexible.iter().cycle())
                .enumerate()
                .map(|(i, (o, f))| {
                    let tls = if *f { TlsMode::Flexible } else { TlsMode::Full };
                    cf_site(&format!("s{i}"), &format!("s{i}.example.com"), *o, tls)
                })
                .collect();
            let mut cfg = config(sites);
            cfg.settings.cloudflare_ranges = ranges.clone();
            let rendered = render(&cfg, &opts());
            prop_assert!(rendered.is_ok(), "{:?}", rendered.err());
            if let Ok(r) = rendered {
                let any_aware = cfg.sites.iter().any(|s| {
                    s.access.cloudflare_only || s.access.tls == TlsMode::Flexible
                });
                if any_aware {
                    prop_assert!(!r.cloudflare_list.is_empty());
                    if !ranges.is_empty() {
                        prop_assert!(r.cloudflare_list.lines().count() <= ranges.len());
                    }
                }
                for line in r.config.lines() {
                    let ok = line.is_empty()
                        || line.starts_with("    ")
                        || line.starts_with('#')
                        || ["global", "defaults", "resolvers ", "frontend ", "backend "]
                            .iter()
                            .any(|k| line.starts_with(k));
                    prop_assert!(ok, "stray line {:?}", line);
                }
                for entry in r.cloudflare_list.lines() {
                    prop_assert!(parse_cidr(entry).is_some(), "bad entry {:?}", entry);
                }
                let any_only = cfg.sites.iter().any(|s| s.access.cloudflare_only);
                prop_assert_eq!(r.config.contains("set-src"), any_only);
                prop_assert_eq!(r.config.contains("str(cloudflare-only)"), any_only);
            }
        }

        #[test]
        fn random_hosts_never_add_directive_lines(host in "\\PC{0,40}", re in "\\PC{0,40}") {
            let baseline = render(&config(vec![site("a", "ok.example.com")]), &opts()).unwrap();
            let mut s = site("a", &host);
            s.path_regexes = vec![re];
            let mut base = site("a", "ok.example.com");
            base.path_regexes = vec!["^/ok".into()];
            let expected = render(&config(vec![base]), &opts()).unwrap().config.lines().count();
            prop_assert!(baseline.config.lines().count() < expected);
            if let Ok(r) = render(&config(vec![s]), &opts()) {
                prop_assert_eq!(r.config.lines().count(), expected);
                for line in r.config.lines() {
                    let ok = line.is_empty()
                        || line.starts_with("    ")
                        || line.starts_with('#')
                        || ["global", "defaults", "resolvers ", "frontend ", "backend "]
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
