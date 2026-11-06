use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use ipnet::IpNet;
use regex::Regex;
use thiserror::Error;

use crate::cloudflare::{check_width, parse_range};
use crate::effects::{Piece, Target, parse_template};
use crate::model::{
    Cors, EdgeConfig, EdgeSettings, FirewallRule, HeaderMatch, HeaderOp, HeaderOpKind,
    HeaderTarget, HealthCheck, MaintenancePage, Matchers, Redirect, Site,
};
use crate::pattern::{Subject, check_budget, check_regex, work as pattern_work};
use crate::presets::ZONE_HEADER;

// HAProxy loads a page file into one buffer (tune.bufsize 16384 by default), so larger pages fail the config check.
pub const MAX_PAGE_BYTES: usize = 15_000;
const MAX_TARGETS: usize = 32;
const MAX_PATTERN_LEN: usize = 256;
const MAX_TEXT_LEN: usize = 128;
const MAX_HEADER_OPS: usize = 16;
const MAX_LIST: usize = 16;
const MAX_REGEXES_PER_RULE: usize = 32;
const MAX_CORS_ENTRIES: usize = 32;
const MAX_HEADER_VALUE: usize = 512;
const MAX_MATCH_VALUE: usize = 256;
const MAX_CORS_MAX_AGE: u32 = 86_400;
const REDIRECT_STATUSES: [u16; 4] = [301, 302, 307, 308];

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{0}")]
pub struct ValidationError(pub String);

pub(crate) fn invalid<T>(msg: String) -> Result<T, ValidationError> {
    Err(ValidationError(msg))
}

pub fn is_valid_id(s: &str) -> bool {
    let b = s.as_bytes();
    let first_ok = b
        .first()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    first_ok
        && b.len() <= 40
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

pub(crate) fn is_hostname(s: &str, allow_underscore: bool) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.split('.').all(|label| {
        let b = label.as_bytes();
        let edge_ok = |c: Option<&u8>| c.is_some_and(|c| c.is_ascii_alphanumeric());
        b.len() <= 63
            && edge_ok(b.first())
            && edge_ok(b.last())
            && b.iter().all(|c| {
                c.is_ascii_alphanumeric() || *c == b'-' || (allow_underscore && *c == b'_')
            })
    })
}

// These words end or alter an ACL pattern list in haproxy, so they cannot be used as values.
fn is_reserved_token(s: &str) -> bool {
    ["or", "and", "if", "unless", "{", "}", "||", "&&", "!"]
        .iter()
        .any(|t| s.eq_ignore_ascii_case(t))
}

pub(crate) fn validate_host(what: &str, host: &str) -> Result<(), ValidationError> {
    let name = host.strip_prefix("*.").unwrap_or(host);
    if !is_hostname(name, false) || is_reserved_token(name) {
        return invalid(format!(
            "{what}: {host:?} is not a valid hostname or *.wildcard"
        ));
    }
    Ok(())
}

// Values become bare haproxy words: printable ASCII only, no # or quotes; use \s for spaces.
pub(crate) fn validate_pattern(what: &str, s: &str, regex: bool) -> Result<(), ValidationError> {
    validate_any_pattern(what, s, regex.then_some(Subject::UserAgent))
}

// The subject decides the length cap the cost bound is computed for.
pub(crate) fn validate_regex(what: &str, s: &str, subject: Subject) -> Result<(), ValidationError> {
    validate_any_pattern(what, s, Some(subject))
}

fn validate_any_pattern(
    what: &str,
    s: &str,
    regex: Option<Subject>,
) -> Result<(), ValidationError> {
    if s.is_empty() || s.len() > MAX_PATTERN_LEN {
        return invalid(format!("{what}: must be 1 to {MAX_PATTERN_LEN} characters"));
    }
    if let Some(c) = s
        .chars()
        .find(|c| !c.is_ascii_graphic() || matches!(*c, '#' | '"' | '\''))
    {
        return invalid(format!(
            "{what}: character {c:?} is not allowed (use \\s for spaces; POSIX classes like [[:space:]] are not supported)"
        ));
    }
    if s.starts_with('-') || is_reserved_token(s) {
        return invalid(format!("{what}: {s:?} is not allowed as a pattern"));
    }
    // haproxy collapses a doubled backslash and strips a trailing one, changing the pattern
    if s.contains("\\\\") || s.ends_with('\\') {
        return invalid(format!("{what}: dangling or doubled backslash in {s:?}"));
    }
    // haproxy turns \xNN into a raw byte before the regex engine sees it, which can produce { or }
    if s.contains("\\x") {
        return invalid(format!(
            "{what}: \\x escapes are not allowed in {s:?}; write the character or a class instead"
        ));
    }
    // haproxy expands $NAME and ${NAME} from the environment in unquoted words
    let bytes = s.as_bytes();
    let env_like = bytes
        .windows(2)
        .any(|w| w[0] == b'$' && (w[1].is_ascii_alphanumeric() || w[1] == b'_' || w[1] == b'{'));
    if env_like {
        return invalid(format!(
            "{what}: $ followed by a name is not allowed in {s:?}"
        ));
    }
    if let Some(subject) = regex {
        if let Err(e) = Regex::new(s) {
            return invalid(format!("{what}: regex {s:?} does not compile: {e}"));
        }
        if let Err(e) = check_regex(s, subject.cap()) {
            return invalid(format!("{what}: regex {s:?} is refused: {e}"));
        }
    } else if !s.starts_with('/') || s.contains('\\') {
        return invalid(format!(
            "{what}: {s:?} must start with / and contain no backslash"
        ));
    }
    Ok(())
}

// Returns the normalised form so the rendered text never echoes raw user input.
pub(crate) fn parse_cidr(s: &str) -> Option<String> {
    if let Ok(net) = IpNet::from_str(s) {
        return Some(net.to_string());
    }
    IpAddr::from_str(s).ok().map(|ip| ip.to_string())
}

// Names of the stack's own services; a target must never point the edge back at its control plane.
const RESERVED_HOSTS: [&str; 5] = [
    "localhost",
    "haproxy",
    "connector",
    "dockerproxy",
    "socketproxy",
];

// HAProxy admin and master sockets listen here; a target on this subnet would relay requests as CLI commands.
const CONTROL_NET: [u8; 3] = [172, 30, 250];

fn forbidden_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || o[0] == 0
        || (o[..3] == CONTROL_NET && o[3] < 8)
}

fn forbidden_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    let embedded = |hi: u16, lo: u16| {
        let [a, b] = hi.to_be_bytes();
        let [c, d] = lo.to_be_bytes();
        Ipv4Addr::new(a, b, c, d)
    };
    let mapped = s[..5] == [0; 5] && s[5] == 0xffff;
    let compat = s[..6] == [0; 6];
    let nat64 = s[..6] == [0x64, 0xff9b, 0, 0, 0, 0];
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || s[0] & 0xffc0 == 0xfe80
        || ((mapped || compat || nat64) && forbidden_v4(embedded(s[6], s[7])))
}

// A last label that is all digits or 0x-hex is how decimal, octal and hex IPv4 spellings look.
fn looks_numeric(label: &str) -> bool {
    let hex = label
        .strip_prefix("0x")
        .or_else(|| label.strip_prefix("0X"))
        .unwrap_or("");
    let digits = !label.is_empty() && label.bytes().all(|c| c.is_ascii_digit());
    digits || (!hex.is_empty() && hex.bytes().all(|c| c.is_ascii_hexdigit()))
}

pub(crate) fn valid_target_addr(addr: &str) -> bool {
    let Some((host, port)) = addr.rsplit_once(':') else {
        return false;
    };
    let port_ok = !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|c| c.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|p| p > 0);
    if !port_ok {
        return false;
    }
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return inner.parse::<Ipv6Addr>().is_ok_and(|ip| !forbidden_v6(ip));
    }
    if !is_hostname(host, true) {
        return false;
    }
    let lower = host.to_ascii_lowercase();
    if RESERVED_HOSTS.contains(&lower.as_str()) || lower.ends_with(".localhost") {
        return false;
    }
    let last = lower.rsplit('.').next().unwrap_or("");
    if looks_numeric(last) {
        return lower.parse::<Ipv4Addr>().is_ok_and(|ip| !forbidden_v4(ip));
    }
    true
}

fn validate_text(what: &str, s: &str) -> Result<(), ValidationError> {
    if s.chars().count() > MAX_TEXT_LEN || s.chars().any(char::is_control) {
        return invalid(format!(
            "{what}: must be at most {MAX_TEXT_LEN} characters without control characters"
        ));
    }
    Ok(())
}

fn validate_id(what: &str, id: &str) -> Result<(), ValidationError> {
    if !is_valid_id(id) {
        return invalid(format!(
            "{what}: id {id:?} must match ^[a-z0-9][a-z0-9-]{{0,39}}$"
        ));
    }
    Ok(())
}

fn check_range(what: &str, v: u64, lo: u64, hi: u64) -> Result<(), ValidationError> {
    if v < lo || v > hi {
        return invalid(format!("{what}: {v} is outside {lo}..={hi}"));
    }
    Ok(())
}

fn validate_health(site_id: &str, h: &HealthCheck) -> Result<(), ValidationError> {
    let what = format!("site {site_id}: health");
    let p = &h.path;
    let path_ok = p.starts_with('/')
        && p.len() <= 512
        && p.chars()
            .all(|c| c.is_ascii_graphic() && !matches!(c, '#' | '"' | '\'' | '\\' | '$'));
    if !path_ok {
        return invalid(format!(
            "{what} path {p:?} must start with / and be plain printable ASCII"
        ));
    }
    // a short interval and a long timeout would keep a dead target looking alive
    check_range(
        &format!("{what} interval_ms"),
        h.interval_ms.into(),
        100,
        60_000,
    )?;
    check_range(
        &format!("{what} timeout_ms"),
        h.timeout_ms.into(),
        100,
        10_000,
    )?;
    if h.timeout_ms > h.interval_ms {
        return invalid(format!(
            "{what}: timeout_ms {} must not exceed interval_ms {}",
            h.timeout_ms, h.interval_ms
        ));
    }
    check_range(&format!("{what} rise"), h.rise.into(), 1, 10)?;
    check_range(&format!("{what} fall"), h.fall.into(), 1, 10)
}

pub fn validate_site(site: &Site) -> Result<(), ValidationError> {
    let what = format!("site {}", site.id);
    validate_id("site", &site.id)?;
    validate_text(&format!("{what} name"), &site.name)?;
    if site.hosts.is_empty() || site.hosts.len() > 64 {
        return invalid(format!("{what}: needs 1 to 64 hosts"));
    }
    for host in &site.hosts {
        validate_host(&format!("{what} host"), host)?;
    }
    validate_regex_list(&what, "path_regexes", &site.path_regexes, Subject::Path)?;
    validate_prefix_list(&what, &site.path_prefixes)?;
    for (slot, up) in [("blue", &site.blue), ("green", &site.green)] {
        if up.targets.len() > MAX_TARGETS {
            return invalid(format!(
                "{what}: {slot} has more than {MAX_TARGETS} targets"
            ));
        }
        for t in &up.targets {
            if !valid_target_addr(&t.addr) {
                return invalid(format!(
                    "{what}: {slot} target {:?} must be host:port with port 1..=65535",
                    t.addr
                ));
            }
            check_range(&format!("{what} {slot} weight"), t.weight.into(), 0, 256)?;
        }
    }
    if let Some(pid) = &site.maintenance.page_id {
        validate_id(&format!("{what} maintenance page"), pid)?;
    }
    validate_health(&site.id, &site.health)
}

// Loading a stored config uses validate_site, which never judges a source an older node already accepted.
pub fn validate_site_strict(site: &Site) -> Result<(), ValidationError> {
    validate_site(site)?;
    if let Some(src) = &site.source {
        validate_source(src).map_err(|e| ValidationError(format!("site {} {}", site.id, e.0)))?;
    }
    Ok(())
}

const SOURCE_RUNTIMES: [&str; 4] = ["node", "bun", "static", "rust"];
const SOURCE_NODE_MAJORS: [u8; 2] = [22, 24];
const MAX_SOURCE_PATH: usize = 255;
const MAX_SOURCE_COMMAND: usize = 1024;
const MIN_MEMORY_MB: u32 = 256;
const MAX_MEMORY_MB: u32 = 1_048_576;
// The Docker proxy refuses less than a quarter CPU (MIN_STACK_NANO_CPUS).
const MIN_CPUS: f32 = 0.25;
const MAX_CPUS: f32 = 1024.0;
const MAX_POLL_SECS: u64 = 366 * 86_400;
const START_DENIED_ARGV0: [&str; 8] = ["npm", "npx", "pnpm", "yarn", "cargo", "sh", "bash", "env"];

fn source_error<T>(field: &str, msg: &str) -> Result<T, ValidationError> {
    invalid(format!("source {field}: {msg}"))
}

// Errors name the field only; the value may hold a token or other secret.
pub fn validate_source(src: &crate::model::Source) -> Result<(), ValidationError> {
    validate_repo(&src.repo)?;
    if let Some(b) = &src.branch {
        validate_branch(b)?;
    }
    let runtime = src.runtime.as_deref().unwrap_or("node");
    if !SOURCE_RUNTIMES.contains(&runtime) {
        return source_error("runtime", "must be node, bun, static or rust");
    }
    if let Some(major) = src.node_major
        && runtime != "rust"
        && !SOURCE_NODE_MAJORS.contains(&major)
    {
        return source_error("node_major", "must be 22 or 24");
    }
    if let Some(p) = &src.poll_interval {
        validate_poll(p)?;
    }
    for (field, value) in [
        ("root_dir", &src.root_dir),
        ("output_dir", &src.output_dir),
        ("spa_fallback", &src.spa_fallback),
    ] {
        if let Some(v) = value {
            validate_relative_path(field, v)?;
        }
    }
    for (field, value) in [
        ("install_command", &src.install_command),
        ("build_command", &src.build_command),
    ] {
        if let Some(v) = value {
            validate_command_text(field, v)?;
        }
    }
    if let Some(cmd) = &src.start_command {
        validate_start_command(cmd)?;
        if src.rendering == Some(crate::model::RenderMode::Static) {
            return source_error(
                "rendering",
                "must not be static when a start_command is set",
            );
        }
    }
    for (field, value) in [
        ("memory_mb", src.memory_mb),
        ("build_memory_mb", src.build_memory_mb),
    ] {
        if let Some(mb) = value
            && !(MIN_MEMORY_MB..=MAX_MEMORY_MB).contains(&mb)
        {
            return source_error(field, "must be 256 to 1048576 MiB");
        }
    }
    for (field, value) in [("cpus", src.cpus), ("build_cpus", src.build_cpus)] {
        if let Some(c) = value
            && !(c.0.is_finite() && (MIN_CPUS..=MAX_CPUS).contains(&c.0))
        {
            return source_error(field, "must be a number from 0.25 to 1024");
        }
    }
    if let Some(v) = &src.framework {
        let ok = (1..=32).contains(&v.len())
            && v.bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
        if !ok {
            return source_error(
                "framework",
                "must be 1 to 32 characters of a-z, 0-9 and '-'",
            );
        }
    }
    // Managers read the forge from the node env only, so a per-site value would be silently ignored.
    if src.forge.as_deref().is_some_and(|f| !f.is_empty()) {
        return source_error(
            "forge",
            "the forge is set for the whole node by the operator (CITE_STACK_FORGE); a per-site forge is not supported",
        );
    }
    if let Some(binding) = &src.doppler {
        validate_doppler_binding(binding)?;
    }
    Ok(())
}

const MAX_DOPPLER_SLUG: usize = 100;

/// A Doppler project or config name: 1 to 100 of letters, digits, '.', '_' and '-'.
pub fn is_valid_doppler_slug(s: &str) -> bool {
    (1..=MAX_DOPPLER_SLUG).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

pub fn validate_doppler_binding(b: &crate::model::DopplerBinding) -> Result<(), ValidationError> {
    for (field, value) in [("project", &b.project), ("config", &b.config)] {
        if !is_valid_doppler_slug(value) {
            return source_error(
                &format!("doppler {field}"),
                "must be 1 to 100 characters of letters, digits, '.', '_' and '-'",
            );
        }
    }
    if !b.build && !b.runtime {
        return source_error(
            "doppler",
            "must feed the build variables, the runtime variables or both",
        );
    }
    Ok(())
}

fn validate_repo(repo: &str) -> Result<(), ValidationError> {
    let part_ok = |p: &str| {
        (1..=100).contains(&p.len())
            && p != "."
            && p != ".."
            && p.bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
    };
    match repo.split_once('/') {
        Some((owner, name)) if part_ok(owner) && part_ok(name) => Ok(()),
        _ => source_error("repo", "must be owner/name"),
    }
}

fn validate_branch(b: &str) -> Result<(), ValidationError> {
    let ok = (1..=255).contains(&b.len())
        && b.bytes()
            .all(|c| c.is_ascii_graphic() && !b"~^:?*[\\".contains(&c))
        && !b.contains("..")
        && !b.contains("@{")
        && !b.contains("//")
        && !b.starts_with(['-', '/'])
        && !b.ends_with(['/', '.'])
        && !b.ends_with(".lock");
    if ok {
        Ok(())
    } else {
        source_error("branch", "is not a valid git branch name")
    }
}

// Same grammar as the manager: off or 0 disables polling, otherwise a duration from 60 seconds to 366 days.
fn validate_poll(text: &str) -> Result<(), ValidationError> {
    let t = text.trim();
    if t == "0" || t.eq_ignore_ascii_case("off") {
        return Ok(());
    }
    let bad = || {
        source_error(
            "poll_interval",
            "must be off or a number with a unit such as 5m, 1h or 1d",
        )
    };
    let Some(split) = t.find(|c: char| c.is_ascii_alphabetic()) else {
        return bad();
    };
    let (num, unit) = t.split_at(split);
    let Ok(n) = num.parse::<u64>() else {
        return bad();
    };
    let secs = match unit.to_ascii_lowercase().as_str() {
        "ms" => n / 1000,
        "s" | "sec" | "secs" => n,
        "m" | "min" | "mins" => n.saturating_mul(60),
        "h" | "hr" | "hrs" => n.saturating_mul(3_600),
        "d" | "day" | "days" => n.saturating_mul(86_400),
        _ => return bad(),
    };
    if secs < 60 {
        return source_error("poll_interval", "must be at least 60 seconds (or off)");
    }
    if secs > MAX_POLL_SECS {
        return source_error("poll_interval", "must be at most 366d");
    }
    Ok(())
}

fn validate_relative_path(field: &str, p: &str) -> Result<(), ValidationError> {
    let ok = (1..=MAX_SOURCE_PATH).contains(&p.len())
        && p.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'/' | b'-'))
        && !p.starts_with(['/', '-'])
        && !p.split('/').any(|seg| seg == "..");
    if ok {
        Ok(())
    } else {
        source_error(
            field,
            "must be a relative path of letters, digits, '.', '_', '-' and '/' without '..'",
        )
    }
}

fn validate_command_text(field: &str, cmd: &str) -> Result<(), ValidationError> {
    if cmd.trim().is_empty() || cmd.len() > MAX_SOURCE_COMMAND {
        return source_error(field, "must be 1 to 1024 bytes");
    }
    if cmd.chars().any(char::is_control) {
        return source_error(field, "must be one line without control characters");
    }
    Ok(())
}

// The start command is meant to be one program with arguments, so shell syntax is refused instead of escaped.
fn validate_start_command(cmd: &str) -> Result<(), ValidationError> {
    const FIELD: &str = "start_command";
    validate_command_text(FIELD, cmd)?;
    let mut quote: Option<char> = None;
    for c in cmd.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some('\''), _) => {}
            (Some(_), '$' | '`' | '\\') => {
                return source_error(FIELD, "must not use shell expansion");
            }
            (Some(_), _) => {}
            (None, '\'' | '"') => quote = Some(c),
            (
                None,
                ';' | '|' | '&' | '<' | '>' | '`' | '$' | '(' | ')' | '{' | '}' | '*' | '?' | '~'
                | '!' | '#' | '\\',
            ) => {
                return source_error(FIELD, "must not contain shell metacharacters");
            }
            (None, _) => {}
        }
    }
    if quote.is_some() {
        return source_error(FIELD, "has an unterminated quote");
    }
    let argv0 = cmd
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_matches(['\'', '"']);
    let program = argv0.rsplit('/').next().unwrap_or("");
    if program.is_empty() || argv0.contains('=') || START_DENIED_ARGV0.contains(&program) {
        return source_error(
            FIELD,
            "must start with the program to run, not a package manager, shell or env",
        );
    }
    Ok(())
}

pub fn validate_rule(rule: &FirewallRule) -> Result<(), ValidationError> {
    let what = format!("rule {}", rule.id);
    validate_id("rule", &rule.id)?;
    validate_text(&format!("{what} name"), &rule.name)?;
    if let Some(site) = &rule.site {
        validate_id(&format!("{what} site"), site)?;
    }
    if let Some(label) = &rule.label {
        validate_id(&format!("{what} label"), label)?;
    }
    validate_kind(&what, rule)?;
    let m = &rule.matchers;
    // a blocking rule without matchers would block every request
    if rule.action.is_some() && !has_matcher(m) {
        return invalid(format!("{what}: needs at least one matcher"));
    }
    validate_matchers(&what, m)?;
    if let Some(r) = &rule.redirect {
        validate_redirect(&what, r, m)?;
    }
    if rule.headers.len() > MAX_HEADER_OPS {
        return invalid(format!("{what}: at most {MAX_HEADER_OPS} header changes"));
    }
    for op in &rule.headers {
        validate_header_op(&what, op)?;
    }
    if let Some(c) = &rule.cors {
        validate_cors(&what, c)?;
    }
    Ok(())
}

fn has_matcher(m: &Matchers) -> bool {
    !m.path_regexes.is_empty()
        || !m.path_prefixes.is_empty()
        || !m.methods.is_empty()
        || !m.user_agent_regexes.is_empty()
        || !m.cidrs.is_empty()
        || !m.hosts.is_empty()
        || !m.headers.is_empty()
        || m.scheme.is_some()
        || !m.referer_regexes.is_empty()
}

// A list holds at most MAX_LIST distinct values.
fn check_list<T: PartialEq>(what: &str, field: &str, items: &[T]) -> Result<(), ValidationError> {
    if items.len() > MAX_LIST {
        return invalid(format!("{what}: at most {MAX_LIST} {field}"));
    }
    for (i, a) in items.iter().enumerate() {
        if items[..i].contains(a) {
            return invalid(format!("{what}: {field} lists entry {} twice", i + 1));
        }
    }
    Ok(())
}

// Each pattern is checked on its own, then the sum of their work must stay inside the same bounds as one pattern, because HAProxy runs them one after another.
pub(crate) fn validate_regex_list(
    what: &str,
    field: &str,
    items: &[String],
    subject: Subject,
) -> Result<(), ValidationError> {
    check_list(what, field, items)?;
    let mut work = Vec::new();
    for re in items {
        validate_regex(&format!("{what} {field}"), re, subject)?;
        if let Ok(w) = pattern_work(re, subject.cap()) {
            work.push(w);
        }
    }
    check_budget(&work)
        .map_err(|e| ValidationError(format!("{what}: {field} together are too costly: {e}")))
}

fn validate_prefix_list(what: &str, items: &[String]) -> Result<(), ValidationError> {
    check_list(what, "path_prefixes", items)?;
    for p in items {
        validate_pattern(&format!("{what} path_prefixes"), p, false)?;
    }
    Ok(())
}

// A rule blocks or it has effects; mixing them would leave it unclear whether the request still reaches the site.
fn validate_kind(what: &str, rule: &FirewallRule) -> Result<(), ValidationError> {
    let headers = !rule.headers.is_empty() || rule.cors.is_some();
    if rule.action.is_some() && (rule.redirect.is_some() || headers) {
        return invalid(format!(
            "{what}: a rule either blocks (action) or has effects (redirect, headers, cors), not both"
        ));
    }
    if rule.redirect.is_some() && headers {
        return invalid(format!(
            "{what}: a redirect cannot be combined with headers or cors"
        ));
    }
    if rule.action.is_none() && rule.redirect.is_none() && !headers {
        return invalid(format!(
            "{what}: needs an action or an effect (redirect, headers or cors)"
        ));
    }
    Ok(())
}

fn validate_matchers(what: &str, m: &Matchers) -> Result<(), ValidationError> {
    let header_regexes = m.headers.iter().filter(|h| h.regex.is_some()).count();
    let regexes = m.path_regexes.len()
        + m.user_agent_regexes.len()
        + m.referer_regexes.len()
        + header_regexes;
    if regexes > MAX_REGEXES_PER_RULE {
        return invalid(format!(
            "{what}: at most {MAX_REGEXES_PER_RULE} regexes in total"
        ));
    }
    validate_regex_list(what, "path_regexes", &m.path_regexes, Subject::Path)?;
    validate_prefix_list(what, &m.path_prefixes)?;
    validate_regex_list(
        what,
        "user_agent_regexes",
        &m.user_agent_regexes,
        Subject::UserAgent,
    )?;
    check_list(what, "hosts", &m.hosts)?;
    for h in &m.hosts {
        validate_host(&format!("{what} host"), h)?;
    }
    if m.methods.len() > 16 {
        return invalid(format!("{what}: at most 16 methods"));
    }
    for method in &m.methods {
        let ok = !method.is_empty()
            && method.len() <= 24
            && method.bytes().all(|c| c.is_ascii_uppercase() || c == b'-');
        if !ok {
            return invalid(format!(
                "{what}: method {method:?} must be an uppercase token"
            ));
        }
    }
    if m.cidrs.len() > 256 {
        return invalid(format!("{what}: at most 256 cidrs"));
    }
    for c in &m.cidrs {
        if parse_cidr(c).is_none() {
            return invalid(format!("{what}: {c:?} is not a CIDR or IP address"));
        }
    }
    if let Some(s) = &m.scheme
        && s != "http"
        && s != "https"
    {
        return invalid(format!("{what}: scheme must be \"http\" or \"https\""));
    }
    validate_regex_list(
        what,
        "referer_regexes",
        &m.referer_regexes,
        Subject::Referer,
    )?;
    // the empty-value test is rendered as its own condition, so it cannot be one alternative among several
    for (field, list) in [
        ("user_agent_regexes", &m.user_agent_regexes),
        ("referer_regexes", &m.referer_regexes),
    ] {
        if list.len() > 1 && list.iter().any(|s| s == "^$") {
            return invalid(format!(
                "{what}: \"^$\" (an empty value) must be the only entry of {field}; use a separate rule"
            ));
        }
    }
    // header matchers may hold secrets, so a repeated one is reported by position only
    check_list(what, "headers", &m.headers)?;
    let mut work = Vec::new();
    for h in &m.headers {
        validate_header_match(what, h)?;
        if let Some(w) = h
            .regex
            .as_deref()
            .and_then(|re| pattern_work(re, Subject::Header.cap()).ok())
        {
            work.push(w);
        }
    }
    check_budget(&work).map_err(|e| {
        ValidationError(format!(
            "{what}: header regexes together are too costly: {e}"
        ))
    })
}

// Header names are written into fetch arguments, so they are limited to letters, digits, - and _.
fn valid_header_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_alphabetic()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
}

fn validate_header_match(what: &str, h: &HeaderMatch) -> Result<(), ValidationError> {
    let what = format!("{what} header matcher");
    if !valid_header_name(&h.name) {
        return invalid(format!(
            "{what}: name {:?} must be 1 to 64 letters, digits, - or _, starting with a letter",
            h.name
        ));
    }
    match (&h.regex, &h.equals) {
        (Some(_), Some(_)) | (None, None) => {
            invalid(format!("{what}: set exactly one of regex or equals"))
        }
        (Some(_), None) if h.secret => invalid(format!("{what}: secret applies to equals only")),
        (Some(_), None) if h.name.eq_ignore_ascii_case(ZONE_HEADER) => {
            invalid(format!("{what}: {ZONE_HEADER} must be matched with equals"))
        }
        (Some(re), None) => validate_regex(&format!("{what} regex"), re, Subject::Header),
        (None, Some(v)) => validate_equals(&what, h, v),
    }
}

// The value is never echoed when the matcher is secret, so a rejected secret cannot leak through an error.
fn validate_equals(what: &str, h: &HeaderMatch, v: &str) -> Result<(), ValidationError> {
    if h.name.eq_ignore_ascii_case(ZONE_HEADER) {
        let ok = (32..=128).contains(&v.len())
            && v.bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'));
        if !ok {
            return invalid(format!(
                "{what}: the {ZONE_HEADER} secret must be 32 to 128 characters of letters, digits, - and _"
            ));
        }
        if !h.secret {
            return invalid(format!(
                "{what}: the {ZONE_HEADER} value must be marked secret"
            ));
        }
        return Ok(());
    }
    let ok = !v.is_empty()
        && v.len() <= MAX_MATCH_VALUE
        && v.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.~:/@=+,;*&?".contains(&c))
        && !is_reserved_token(v);
    if !ok {
        let shown = if h.secret {
            "<redacted>".to_string()
        } else {
            format!("{v:?}")
        };
        return invalid(format!(
            "{what}: equals value {shown} must be 1 to {MAX_MATCH_VALUE} characters from letters, digits and - _ . ~ : / @ = + , ; * & ?"
        ));
    }
    Ok(())
}

fn validate_redirect(what: &str, r: &Redirect, m: &Matchers) -> Result<(), ValidationError> {
    let what = format!("{what} redirect");
    if !REDIRECT_STATUSES.contains(&r.status) {
        return invalid(format!(
            "{what}: status {} must be 301, 302, 307 or 308",
            r.status
        ));
    }
    let t = parse_template(&r.to).map_err(|e| ValidationError(format!("{what} to: {e}")))?;
    let path_matcher = !m.path_prefixes.is_empty() || !m.path_regexes.is_empty();
    let keeps_host = matches!(
        t.target,
        Target::Relative
            | Target::Absolute {
                same_host: true,
                ..
            }
    );
    let upgrade = matches!(
        t.target,
        Target::Absolute {
            https: true,
            same_host: true,
            ..
        }
    );
    // Every branch exists because a redirect that the matchers still select after it was followed would loop.
    if upgrade {
        if m.scheme.as_deref() != Some("http") {
            return invalid(format!(
                "{what}: an https redirect to the same host needs the matcher scheme \"http\", or it loops"
            ));
        }
    } else if keeps_host {
        if !path_matcher {
            return invalid(format!(
                "{what}: a redirect that keeps the host needs a path_prefix or path_regex matcher, or it loops"
            ));
        }
        if let [Piece::Lit(lit)] = t.pieces.as_slice()
            && m.path_prefixes.iter().any(|p| lit.starts_with(p.as_str()))
        {
            return invalid(format!(
                "{what}: the target {lit:?} starts with the matched path_prefix and would loop"
            ));
        }
    } else if !t.uses_www() && !t.uses_apex() && !has_matcher(m) {
        return invalid(format!(
            "{what}: needs a matcher, or {{www_host}} or {{apex_host}}, so that it cannot loop"
        ));
    }
    Ok(())
}

// Hop-by-hop and framing headers would corrupt the message; identity and browser-controlled headers must stay trustworthy.
fn header_denied(target: HeaderTarget, op: HeaderOpKind, name: &str) -> Option<&'static str> {
    const FRAMING: [&str; 9] = [
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "upgrade",
        "te",
        "trailer",
        "expect",
    ];
    const IDENTITY: [&str; 7] = [
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-forwarded-host",
        "x-forwarded-port",
        "x-real-ip",
        "forwarded",
        "true-client-ip",
    ];
    let lower = name.to_ascii_lowercase();
    if FRAMING.contains(&lower.as_str()) {
        return Some("is managed by the proxy and cannot be changed");
    }
    if ["proxy-", "sec-", "x-cite-"]
        .iter()
        .any(|p| lower.starts_with(p))
    {
        return Some("is reserved and cannot be changed");
    }
    let identity = IDENTITY.contains(&lower.as_str()) || lower.starts_with("cf-");
    if target == HeaderTarget::Request && op != HeaderOpKind::Remove && identity {
        return Some("carries the client identity; a request rule can only remove it");
    }
    None
}

fn validate_header_op(what: &str, op: &HeaderOp) -> Result<(), ValidationError> {
    let what = format!("{what} header {:?}", op.name);
    if !valid_header_name(&op.name) {
        return invalid(format!(
            "{what}: name must be 1 to 64 letters, digits, - or _, starting with a letter"
        ));
    }
    if let Some(why) = header_denied(op.target, op.op, &op.name) {
        return invalid(format!("{what}: this header {why}"));
    }
    match (op.op, &op.value) {
        (HeaderOpKind::Remove, Some(_)) => invalid(format!("{what}: remove takes no value")),
        (HeaderOpKind::Remove, None) => Ok(()),
        (_, Some(v)) if valid_header_value(v) => Ok(()),
        _ => invalid(format!(
            "{what}: value must be 1 to {MAX_HEADER_VALUE} printable ASCII characters without \" \\ or $"
        )),
    }
}

fn valid_header_value(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= MAX_HEADER_VALUE
        && v.bytes()
            .all(|c| (0x20..=0x7e).contains(&c) && !matches!(c, b'"' | b'\\' | b'$'))
}

// An origin is scheme, host and optional port, nothing else; the Origin header is compared to it character for character.
fn valid_origin(o: &str) -> bool {
    let Some(rest) = o
        .strip_prefix("https://")
        .or_else(|| o.strip_prefix("http://"))
    else {
        return false;
    };
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (rest, None),
    };
    let port_ok = port.is_none_or(|p| {
        p.bytes().all(|c| c.is_ascii_digit()) && p.parse::<u16>().is_ok_and(|n| n > 0)
    });
    port_ok && is_hostname(host, false)
}

fn validate_cors(what: &str, c: &Cors) -> Result<(), ValidationError> {
    let what = format!("{what} cors");
    if c.origins.is_empty() || c.origins.len() > MAX_CORS_ENTRIES {
        return invalid(format!("{what}: needs 1 to {MAX_CORS_ENTRIES} origins"));
    }
    let wildcard = c.origins.iter().any(|o| o == "*");
    if wildcard && c.origins.len() != 1 {
        return invalid(format!("{what}: \"*\" must be the only origin"));
    }
    if wildcard && c.credentials {
        return invalid(format!(
            "{what}: credentials cannot be combined with the origin \"*\""
        ));
    }
    for o in c.origins.iter().filter(|o| *o != "*") {
        if !valid_origin(o) {
            return invalid(format!(
                "{what}: origin {o:?} must be like https://app.example.com with no path"
            ));
        }
    }
    for (label, list) in [
        ("methods", &c.methods),
        ("allow_headers", &c.allow_headers),
        ("expose_headers", &c.expose_headers),
    ] {
        if list.len() > MAX_CORS_ENTRIES {
            return invalid(format!("{what}: at most {MAX_CORS_ENTRIES} {label}"));
        }
    }
    for method in &c.methods {
        let ok = !method.is_empty()
            && method.len() <= 24
            && method.bytes().all(|b| b.is_ascii_uppercase() || b == b'-');
        if !ok {
            return invalid(format!(
                "{what}: method {method:?} must be an uppercase token"
            ));
        }
    }
    for name in c.allow_headers.iter().chain(&c.expose_headers) {
        if !valid_header_name(name) {
            return invalid(format!(
                "{what}: header name {name:?} must be 1 to 64 letters, digits, - or _"
            ));
        }
    }
    if c.max_age_secs > MAX_CORS_MAX_AGE {
        return invalid(format!(
            "{what}: max_age_secs must be at most {MAX_CORS_MAX_AGE}"
        ));
    }
    Ok(())
}

pub fn validate_page(page: &MaintenancePage) -> Result<(), ValidationError> {
    let what = format!("page {}", page.id);
    validate_id("page", &page.id)?;
    validate_text(&format!("{what} name"), &page.name)?;
    if page.html.len() > MAX_PAGE_BYTES {
        return invalid(format!("{what}: html exceeds {MAX_PAGE_BYTES} bytes"));
    }
    check_range(&format!("{what} status"), page.status.into(), 400, 599)
}

pub fn validate_settings(s: &EdgeSettings) -> Result<(), ValidationError> {
    check_range("settings http_port", s.http_port.into(), 1, 65535)?;
    // 0 tells the node never to bind the TLS port on its own
    if let Some(p) = s.https_port.filter(|p| *p != 0) {
        check_range("settings https_port", p.into(), 1, 65535)?;
        if p == s.http_port {
            return invalid("settings: https_port must differ from http_port".into());
        }
    }
    check_range("settings max_conn", s.max_conn.into(), 1, 1_000_000)?;
    check_range(
        "settings client_timeout_ms",
        s.client_timeout_ms.into(),
        100,
        3_600_000,
    )?;
    check_range(
        "settings server_timeout_ms",
        s.server_timeout_ms.into(),
        100,
        3_600_000,
    )?;
    check_range(
        "settings connect_timeout_ms",
        s.connect_timeout_ms.into(),
        100,
        600_000,
    )?;
    if let Some(r) = s.per_ip_rate_limit {
        check_range("settings per_ip_rate_limit", r.into(), 1, 1_000_000)?;
    }
    if let Some(b) = s.max_body_bytes {
        check_range("settings max_body_bytes", b, 1, 1 << 40)?;
    }
    let r = &s.retention;
    check_range(
        "retention recent_events",
        r.recent_events as u64,
        0,
        200_000,
    )?;
    check_range(
        "retention persist_interval_secs",
        r.persist_interval_secs.into(),
        5,
        3600,
    )?;
    check_range(
        "retention minute_buckets_hours",
        r.minute_buckets_hours.into(),
        1,
        8760,
    )?;
    check_range(
        "retention hour_buckets_days",
        r.hour_buckets_days.into(),
        0,
        3650,
    )?;
    check_range("retention audit_days", r.audit_days.into(), 1, 3650)?;
    validate_cloudflare_ranges(&s.cloudflare_ranges)
}

const MAX_CLOUDFLARE_RANGES: usize = 256;

// A typo such as 0.0.0.0/0 would trust every client as Cloudflare, so wide or IPv4-covering ranges are refused outright.
fn validate_cloudflare_ranges(ranges: &[String]) -> Result<(), ValidationError> {
    if ranges.len() > MAX_CLOUDFLARE_RANGES {
        return invalid(format!(
            "settings cloudflare_ranges: at most {MAX_CLOUDFLARE_RANGES} entries"
        ));
    }
    for raw in ranges {
        let Some(net) = parse_range(raw) else {
            return invalid(format!(
                "settings cloudflare_ranges: {raw:?} is not a CIDR or IP address"
            ));
        };
        check_width(raw, &net).map_err(ValidationError)?;
    }
    Ok(())
}

fn check_unique<'a>(
    kind: &str,
    ids: impl Iterator<Item = &'a String>,
) -> Result<HashSet<&'a str>, ValidationError> {
    let mut seen = HashSet::new();
    for id in ids {
        if !seen.insert(id.as_str()) {
            return invalid(format!("{kind} id {id:?} is used more than once"));
        }
    }
    Ok(seen)
}

// A www redirect and an apex redirect that can apply to the same request send it back and forth forever.
fn check_redirect_cycles(cfg: &EdgeConfig) -> Result<(), ValidationError> {
    let mut www: Vec<&FirewallRule> = Vec::new();
    let mut apex: Vec<&FirewallRule> = Vec::new();
    for rule in cfg.firewall.iter().filter(|r| r.enabled) {
        let Some(r) = &rule.redirect else { continue };
        let Ok(t) = parse_template(&r.to) else {
            continue;
        };
        if t.uses_www() {
            www.push(rule);
        } else if t.uses_apex() {
            apex.push(rule);
        }
    }
    for a in &www {
        let a_hosts = scope_hosts(a, cfg);
        for b in &apex {
            let b_hosts = scope_hosts(b, cfg);
            let shared = a_hosts
                .iter()
                .find_map(|x| b_hosts.iter().find(|y| hosts_overlap(x, y)).map(|y| (x, y)));
            if let Some((x, y)) = shared {
                return invalid(format!(
                    "rules {} and {} would loop: one adds www and the other removes it for the hosts {x} and {y}; enable only one or scope them to unrelated hosts",
                    a.id, b.id
                ));
            }
        }
    }
    Ok(())
}

// Hosts a rule can see, lowercased with a leading www. removed, since the two redirects turn one into the other.
fn scope_hosts(rule: &FirewallRule, cfg: &EdgeConfig) -> Vec<String> {
    cfg.sites
        .iter()
        .filter(|s| rule.site.as_ref().is_none_or(|id| *id == s.id))
        .flat_map(|s| s.hosts.iter())
        .map(|h| {
            let h = h.to_ascii_lowercase();
            h.strip_prefix("www.")
                .map_or_else(|| h.clone(), String::from)
        })
        .collect()
}

fn hosts_overlap(a: &str, b: &str) -> bool {
    let suffix = |w: &str| w.strip_prefix('*').map(String::from);
    a == b
        || suffix(a).is_some_and(|t| b.ends_with(&t))
        || suffix(b).is_some_and(|t| a.ends_with(&t))
}

// A disabled rule is never rendered, so a regex the current grammar refuses may stay in the file until the owner fixes it; everything else is still checked.
fn with_regexes_stubbed(rule: &FirewallRule) -> FirewallRule {
    let mut out = rule.clone();
    let m = &mut out.matchers;
    // stubs differ from each other so the duplicate check still passes
    for list in [
        &mut m.path_regexes,
        &mut m.user_agent_regexes,
        &mut m.referer_regexes,
    ] {
        for (i, re) in list.iter_mut().enumerate() {
            *re = "x".repeat(i + 1);
        }
    }
    for (i, h) in m.headers.iter_mut().enumerate() {
        if h.regex.is_some() {
            h.regex = Some("x".repeat(i + 1));
        }
    }
    out
}

pub fn validate_config(cfg: &EdgeConfig) -> Result<(), ValidationError> {
    // caps keep the rendered config and the reload time bounded
    if cfg.sites.len() > 1000 || cfg.pages.len() > 1000 || cfg.firewall.len() > 5000 {
        return invalid("config has too many sites, pages or firewall rules".into());
    }
    let site_ids = check_unique("site", cfg.sites.iter().map(|s| &s.id))?;
    let page_ids = check_unique("page", cfg.pages.iter().map(|p| &p.id))?;
    check_unique("rule", cfg.firewall.iter().map(|r| &r.id)).map_err(|e| {
        if e.0.contains("\"zone-") {
            ValidationError(format!(
                "{} (ids starting with zone- belong to the zone lock of a site; pick another id)",
                e.0
            ))
        } else {
            e
        }
    })?;
    check_redirect_cycles(cfg)?;
    validate_settings(&cfg.settings)?;
    for page in &cfg.pages {
        validate_page(page)?;
    }
    for site in &cfg.sites {
        validate_site(site)?;
        if site.access.zone_lock && !site.access.cloudflare_only {
            return invalid(format!(
                "site {}: zone_lock requires cloudflare_only",
                site.id
            ));
        }
        if let Some(pid) = &site.maintenance.page_id
            && !page_ids.contains(pid.as_str())
        {
            return invalid(format!(
                "site {}: maintenance page {pid:?} does not exist",
                site.id
            ));
        }
    }
    for rule in &cfg.firewall {
        if rule.enabled {
            validate_rule(rule)?;
        } else {
            validate_rule(&with_regexes_stubbed(rule))?;
        }
        if let Some(sid) = &rule.site
            && !site_ids.contains(sid.as_str())
        {
            return invalid(format!("rule {}: site {sid:?} does not exist", rule.id));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod fixtures {
    use crate::model::*;

    pub fn site(id: &str, host: &str) -> Site {
        Site {
            id: id.into(),
            name: id.into(),
            hosts: vec![host.into()],
            path_regexes: vec![],
            path_prefixes: vec![],
            kind: SiteKind::Site,
            blue: Upstream {
                targets: vec![Target {
                    addr: "10.0.0.1:8080".into(),
                    weight: 100,
                }],
                label: None,
            },
            green: Upstream::default(),
            active: Slot::Blue,
            maintenance: Maintenance::default(),
            health: HealthCheck::default(),
            source: None,
            history: vec![],
            access: SiteAccess::default(),
        }
    }

    pub fn rule(id: &str, matchers: Matchers) -> FirewallRule {
        FirewallRule {
            id: id.into(),
            name: id.into(),
            enabled: true,
            action: Some(FirewallAction::Deny),
            matchers,
            ..FirewallRule::default()
        }
    }

    pub fn config(sites: Vec<Site>) -> EdgeConfig {
        EdgeConfig {
            version: CONFIG_VERSION,
            sites,
            pages: vec![],
            firewall: vec![],
            settings: EdgeSettings::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn id_shape() {
        assert!(is_valid_id("a"));
        assert!(is_valid_id("my-site-1"));
        assert!(is_valid_id(&"a".repeat(40)));
        assert!(!is_valid_id(&"a".repeat(41)));
        assert!(!is_valid_id(""));
        assert!(!is_valid_id("-a"));
        assert!(!is_valid_id("A"));
        assert!(!is_valid_id("a_b"));
        assert!(!is_valid_id("a\n"));
    }

    #[test]
    fn hosts_reject_injection() {
        for bad in [
            "a.com\nbackend x",
            "a.com #x",
            "a\"b.com",
            "a b.com",
            "a.com'",
            "",
            "*.",
            "or",
        ] {
            assert!(validate_site(&site("s", bad)).is_err(), "{bad:?} accepted");
        }
        assert!(validate_site(&site("s", &format!("{}.com", "a".repeat(64)))).is_err());
    }

    #[test]
    fn hosts_accept_plain_and_wildcard() {
        for ok in [
            "example.com",
            "*.example.com",
            "a-b.c.example.org",
            "localhost",
        ] {
            assert!(validate_site(&site("s", ok)).is_ok(), "{ok:?} rejected");
        }
    }

    #[test]
    fn regex_rejects_unsafe_characters() {
        for bad in [
            "a b", "a#b", "a\"b", "a'b", "a\nb", "^/x\\", "a\\\\b", "$HOME", "${X}", "-m", "or",
        ] {
            assert!(
                validate_pattern("t", bad, true).is_err(),
                "{bad:?} accepted"
            );
        }
    }

    #[test]
    fn regex_must_compile_and_fit() {
        assert!(validate_pattern("t", "(unclosed", true).is_err());
        assert!(validate_pattern("t", &"a".repeat(257), true).is_err());
        assert!(validate_pattern("t", &"a".repeat(256), true).is_ok());
        assert!(validate_pattern("t", "^/api/v[0-9]+/\\.well-known$", true).is_ok());
        assert!(validate_pattern("t", "(?i)(^|/)\\.env(/|$)", true).is_ok());
    }

    #[test]
    fn path_prefix_needs_slash() {
        assert!(validate_pattern("t", "/admin", false).is_ok());
        assert!(validate_pattern("t", "admin", false).is_err());
        assert!(validate_pattern("t", "/a\\b", false).is_err());
    }

    #[test]
    fn target_addresses() {
        for ok in [
            "10.0.0.1:80",
            "app.internal:8080",
            "[2001:db8::1]:3000",
            "my_app:1",
            "h:65535",
        ] {
            assert!(valid_target_addr(ok), "{ok} rejected");
        }
        for bad in [
            "10.0.0.1",
            "10.0.0.1:0",
            "10.0.0.1:65536",
            "http://a:80",
            "u@a:80",
            "a b:80",
            "a:80\nserver x",
            "[::1:80",
            "[nope]:80",
            ":80",
            "a:",
            "a/b:80",
        ] {
            assert!(!valid_target_addr(bad), "{bad:?} accepted");
        }
    }

    #[test]
    fn targets_cannot_reach_the_control_plane() {
        for bad in [
            "172.30.250.3:9999",
            "172.30.250.3:9998",
            "172.30.250.0:80",
            "172.30.250.7:80",
            "127.0.0.1:80",
            "127.1.2.3:80",
            "0.0.0.0:80",
            "0.1.2.3:80",
            "169.254.169.254:80",
            "224.0.0.1:80",
            "255.255.255.255:80",
            "[::1]:80",
            "[::]:80",
            "[fe80::1]:80",
            "[febf::1]:80",
            "[ff02::1]:80",
            "[::ffff:127.0.0.1]:80",
            "[::ffff:7f00:1]:80",
            "[::ffff:172.30.250.3]:80",
            "[::ffff:169.254.169.254]:80",
            "[::127.0.0.1]:80",
            "[::172.30.250.3]:80",
            "[64:ff9b::7f00:1]:80",
            "2130706433:80",
            "0x7f000001:80",
            "0x7f.0.0.1:80",
            "0177.0.0.1:80",
            "127.1:80",
            "127.0.1:80",
            "017700000001:80",
            "localhost:80",
            "LocalHost:80",
            "a.localhost:80",
            "haproxy:9999",
            "connector:80",
            "dockerproxy:2375",
            "socketproxy:2375",
        ] {
            assert!(!valid_target_addr(bad), "{bad:?} accepted");
        }
        for ok in [
            "172.30.249.3:80",
            "172.30.250.8:80",
            "172.31.250.3:80",
            "8.8.8.8:53",
            "[2001:db8::1]:80",
            "[fec0::1]:80",
            "haproxy-app:80",
            "myconnector:80",
            "app1.example.com:443",
        ] {
            assert!(valid_target_addr(ok), "{ok:?} rejected");
        }
    }

    #[test]
    fn site_rejects_admin_socket_target() {
        let mut s = site("s", "a.com");
        s.blue.targets[0].addr = "172.30.250.3:9999".into();
        assert!(validate_site(&s).is_err());
    }

    #[test]
    fn target_limit_and_weight() {
        let mut s = site("s", "a.com");
        s.blue.targets = (0..33)
            .map(|i| crate::model::Target {
                addr: format!("h{i}:80"),
                weight: 1,
            })
            .collect();
        assert!(validate_site(&s).is_err());
        s.blue.targets.truncate(32);
        assert!(validate_site(&s).is_ok());
        s.blue.targets[0].weight = 257;
        assert!(validate_site(&s).is_err());
    }

    #[test]
    fn health_path_checks() {
        let mut s = site("s", "a.com");
        s.health.path = "healthz".into();
        assert!(validate_site(&s).is_err());
        s.health.path = "/a b".into();
        assert!(validate_site(&s).is_err());
        s.health.path = "/healthz?x=1".into();
        assert!(validate_site(&s).is_ok());
    }

    #[test]
    fn health_ranges_and_timeout_order() {
        let check = |f: &dyn Fn(&mut crate::model::HealthCheck)| {
            let mut s = site("s", "a.com");
            f(&mut s.health);
            validate_site(&s).is_ok()
        };
        assert!(check(&|_| {}));
        assert!(!check(&|h| h.interval_ms = 99));
        assert!(!check(&|h| h.interval_ms = 60_001));
        assert!(check(&|h| {
            h.interval_ms = 60_000;
            h.timeout_ms = 10_000;
        }));
        assert!(!check(&|h| {
            h.interval_ms = 60_000;
            h.timeout_ms = 10_001;
        }));
        assert!(!check(&|h| h.timeout_ms = 99));
        assert!(!check(&|h| {
            h.interval_ms = 1000;
            h.timeout_ms = 1001;
        }));
        assert!(!check(&|h| h.rise = 0));
        assert!(!check(&|h| h.rise = 11));
        assert!(!check(&|h| h.fall = 0));
        assert!(!check(&|h| h.fall = 11));
        assert!(check(&|h| {
            h.rise = 10;
            h.fall = 10;
        }));
    }

    #[test]
    fn regex_rejects_hex_escapes() {
        for bad in ["^/a\\x7d", "\\x20", "^/\\x{7d}"] {
            assert!(validate_pattern("t", bad, true).is_err(), "{bad:?}");
        }
        assert!(validate_pattern("t", "^/a\\s", true).is_ok());
    }

    #[test]
    fn regex_rejects_catastrophic_shapes() {
        for bad in [
            "^/(a|aa)+$",
            "^/(a|b)*c",
            "(a+)+",
            "(x*)*",
            "(?:a+)*b",
            "((a+)b)+",
            "(a+){2,}",
            "(a|b){3,}",
            "(a*)+?",
            "([a-z]+\\.)+x",
        ] {
            assert!(
                validate_pattern("t", bad, true).is_err(),
                "{bad:?} accepted"
            );
        }
        for ok in [
            "^/api/v[0-9]+/\\.well-known$",
            "(?i)(^|/)\\.env(/|$)",
            "(a|b)?c",
            "(a+)?c",
            "(ab)+",
            "[(a|b]+",
            "^/[a-z]{1,20}(;[^/]*)?(/|$)",
            "a{2}b+",
            "\\(a+\\)",
        ] {
            assert!(validate_pattern("t", ok, true).is_ok(), "{ok:?} rejected");
        }
    }

    #[test]
    fn regex_rejects_bounded_and_chained_blowups_that_used_to_pass() {
        for bad in [
            "(a|aa){2,60}[0-9]",
            "(a{1,100}){1,100}[0-9]",
            ".*.*.*.*.*.*.*.*[0-9]",
            ".*.*.*.*[0-9]",
            "(a|aa){2,40}c",
            "(a+){2,5}",
            "(a{2,30}){2,30}c",
            "a{1,1001}",
            "a{1001,}",
            "(ab){1,99999999999}",
            "(a{1,100})+",
        ] {
            assert!(
                validate_pattern("t", bad, true).is_err(),
                "{bad:?} accepted"
            );
        }
    }

    #[test]
    fn ordinary_regexes_and_all_presets_still_validate() {
        for ok in [
            "^/api/v[0-9]+/",
            "(?i)(sqlmap|nikto)",
            "(?i)(^|/)\\.(env|git)",
            "^/[a-z]{1,8}/[^/]*$",
            "(foo|bar)",
            "(\\d{1,3}\\.)",
            "a{1,1000}",
            "^.*x$",
            "(ab){1,10}",
            "^/a/.*/b$",
        ] {
            assert!(validate_pattern("t", ok, true).is_ok(), "{ok:?} rejected");
        }
        for p in crate::presets::presets() {
            for r in &p.rules {
                validate_rule(r).unwrap_or_else(|e| panic!("{}: {e}", r.id));
            }
        }
        assert!(validate_pattern("t", &crate::bot::scanner_regex(), true).is_ok());
    }

    #[test]
    fn the_blowup_checks_apply_to_every_regex_field() {
        let bad = "(a|aa){2,60}[0-9]";
        let mut s = site("s", "a.com");
        s.path_regexes = vec![bad.into()];
        assert!(validate_site(&s).is_err());
        for m in [
            Matchers {
                path_regexes: vec![bad.into()],
                ..Default::default()
            },
            Matchers {
                user_agent_regexes: vec![bad.into()],
                ..Default::default()
            },
            Matchers {
                referer_regexes: vec![bad.into()],
                ..Default::default()
            },
            Matchers {
                headers: vec![HeaderMatch {
                    name: "X-A".into(),
                    regex: Some(bad.into()),
                    ..HeaderMatch::default()
                }],
                ..Default::default()
            },
        ] {
            assert!(validate_rule(&rule("r", m)).is_err());
        }
    }

    #[test]
    fn rule_needs_a_matcher_and_valid_values() {
        assert!(validate_rule(&rule("r", Matchers::default())).is_err());
        let m = Matchers {
            cidrs: vec!["10.0.0.0/8".into(), "::1".into(), "1.2.3.4".into()],
            ..Default::default()
        };
        assert!(validate_rule(&rule("r", m)).is_ok());
        let m = Matchers {
            cidrs: vec!["10.0.0.0/33".into()],
            ..Default::default()
        };
        assert!(validate_rule(&rule("r", m)).is_err());
        let m = Matchers {
            methods: vec!["get".into()],
            ..Default::default()
        };
        assert!(validate_rule(&rule("r", m)).is_err());
        let m = Matchers {
            methods: vec!["GET\nX".into()],
            ..Default::default()
        };
        assert!(validate_rule(&rule("r", m)).is_err());
        let m = Matchers {
            user_agent_regexes: vec!["bad agent".into()],
            ..Default::default()
        };
        assert!(validate_rule(&rule("r", m)).is_err());
    }

    fn effect_rule(id: &str) -> FirewallRule {
        FirewallRule {
            id: id.into(),
            name: id.into(),
            enabled: true,
            ..FirewallRule::default()
        }
    }

    fn redirect_rule(to: &str, matchers: Matchers) -> FirewallRule {
        FirewallRule {
            matchers,
            redirect: Some(Redirect {
                to: to.into(),
                status: 301,
            }),
            ..effect_rule("r")
        }
    }

    fn header_rule(ops: Vec<HeaderOp>) -> FirewallRule {
        FirewallRule {
            headers: ops,
            ..effect_rule("r")
        }
    }

    fn op(target: HeaderTarget, kind: HeaderOpKind, name: &str, value: Option<&str>) -> HeaderOp {
        HeaderOp {
            target,
            op: kind,
            name: name.into(),
            value: value.map(String::from),
        }
    }

    fn cors_rule(c: Cors) -> FirewallRule {
        FirewallRule {
            cors: Some(c),
            ..effect_rule("r")
        }
    }

    fn origin(o: &str) -> Cors {
        Cors {
            origins: vec![o.into()],
            ..Cors::default()
        }
    }

    fn header_matcher(h: HeaderMatch) -> Matchers {
        Matchers {
            headers: vec![h],
            ..Default::default()
        }
    }

    fn path_prefix(p: &str) -> Matchers {
        Matchers {
            path_prefixes: vec![p.into()],
            ..Default::default()
        }
    }

    #[test]
    fn rules_saved_before_effects_existed_load_and_serialise_unchanged() {
        let json = r#"{"id": "r", "name": "r", "enabled": true, "action": "tarpit",
            "matchers": {"path_prefix": "/x"}, "site": null}"#;
        let r: FirewallRule = serde_json::from_str(json).expect("old rule");
        assert_eq!(r.action, Some(crate::model::FirewallAction::Tarpit));
        assert!(r.label.is_none() && r.redirect.is_none() && r.headers.is_empty());
        assert!(r.cors.is_none() && r.matchers.headers.is_empty());
        assert!(validate_rule(&r).is_ok());
        let back = serde_json::to_value(&r).expect("serialise");
        assert_eq!(
            back,
            serde_json::json!({"id": "r", "name": "r", "enabled": true, "action": "tarpit",
                "matchers": {"path_prefixes": ["/x"], "methods": [], "cidrs": []}, "site": null})
        );
    }

    #[test]
    fn a_rule_blocks_or_has_effects_never_both_and_never_nothing() {
        let mut r = redirect_rule("https://example.org/", path_prefix("/x"));
        r.action = Some(crate::model::FirewallAction::Deny);
        let err = validate_rule(&r).unwrap_err().to_string();
        assert!(
            err.starts_with("rule r:") && err.contains("not both"),
            "{err}"
        );
        let mut r = redirect_rule("https://example.org/", path_prefix("/x"));
        r.headers = vec![op(
            HeaderTarget::Response,
            HeaderOpKind::Set,
            "X-A",
            Some("1"),
        )];
        assert!(
            validate_rule(&r)
                .unwrap_err()
                .to_string()
                .contains("redirect cannot")
        );
        let mut r = header_rule(vec![op(
            HeaderTarget::Response,
            HeaderOpKind::Set,
            "X-A",
            Some("1"),
        )]);
        r.action = Some(crate::model::FirewallAction::Drop);
        r.matchers = path_prefix("/x");
        assert!(validate_rule(&r).is_err());
        let err = validate_rule(&effect_rule("none")).unwrap_err().to_string();
        assert!(err.starts_with("rule none:") && err.contains("needs an action or an effect"));
    }

    #[test]
    fn effect_rules_may_apply_to_a_whole_site_but_block_rules_still_need_a_matcher() {
        let r = header_rule(vec![op(
            HeaderTarget::Response,
            HeaderOpKind::Set,
            "X-Frame-Options",
            Some("DENY"),
        )]);
        assert!(validate_rule(&r).is_ok());
        assert!(validate_rule(&rule("b", Matchers::default())).is_err());
        let scheme = Matchers {
            scheme: Some("http".into()),
            ..Default::default()
        };
        assert!(validate_rule(&rule("b", scheme)).is_ok());
    }

    #[test]
    fn redirect_status_and_template_are_validated() {
        let www = "{scheme}://{www_host}{path}{query}";
        for status in [301, 302, 307, 308] {
            let mut r = redirect_rule(www, Matchers::default());
            r.redirect.as_mut().expect("redirect").status = status;
            assert!(validate_rule(&r).is_ok(), "{status}");
        }
        for status in [0, 200, 300, 303, 304, 404] {
            let mut r = redirect_rule(www, Matchers::default());
            r.redirect.as_mut().expect("redirect").status = status;
            assert!(validate_rule(&r).is_err(), "{status}");
        }
        for to in [
            "javascript:alert(1)",
            "//evil.example.com",
            "https://a.example.com/\r\nSet-Cookie: x=1",
            "https://a.example.com/{nope}",
            "relative",
            "",
        ] {
            let r = redirect_rule(to, path_prefix("/x"));
            let err = validate_rule(&r).unwrap_err().to_string();
            assert!(err.starts_with("rule r redirect"), "{to:?}: {err}");
        }
    }

    #[test]
    fn redirects_that_could_loop_are_refused() {
        let host_only = Matchers {
            hosts: vec!["old.example.com".into()],
            ..Default::default()
        };
        let http = Matchers {
            scheme: Some("http".into()),
            ..Default::default()
        };
        let https = Matchers {
            scheme: Some("https".into()),
            ..Default::default()
        };
        let refused = [
            ("https://other.example.org/", Matchers::default()),
            ("/new", Matchers::default()),
            ("/new", host_only.clone()),
            ("/new", path_prefix("/new")),
            ("/new", path_prefix("/ne")),
            ("{scheme}://{host}/new", host_only.clone()),
            ("https://{host}{path}{query}", Matchers::default()),
            ("https://{host}{path}{query}", https),
            ("{scheme}://{host}{path}", path_prefix("/x")),
        ];
        for (to, m) in refused {
            let r = redirect_rule(to, m);
            assert!(validate_rule(&r).is_err(), "{to} accepted");
        }
        let accepted = [
            ("{scheme}://{www_host}{path}{query}", Matchers::default()),
            ("{scheme}://{apex_host}{path}{query}", Matchers::default()),
            ("https://{host}{path}{query}", http),
            ("https://other.example.org/", host_only),
            ("/new", path_prefix("/old")),
        ];
        for (to, m) in accepted {
            let r = redirect_rule(to, m);
            assert!(validate_rule(&r).is_ok(), "{to}: {:?}", validate_rule(&r));
        }
    }

    #[test]
    fn header_changes_are_checked() {
        use HeaderOpKind::{Add, Remove, Set};
        use HeaderTarget::{Request, Response};
        let good = vec![
            op(Response, Set, "X-Frame-Options", Some("DENY")),
            op(Response, Add, "Set-Cookie", Some("a=b; Path=/; HttpOnly")),
            op(
                Response,
                Set,
                "Content-Security-Policy",
                Some("default-src 'self'"),
            ),
            op(Request, Set, "X-Env", Some("prod")),
            op(Request, Remove, "X-Debug", None),
            op(Request, Remove, "X-Forwarded-For", None),
            op(Response, Remove, "Server", None),
        ];
        assert!(validate_rule(&header_rule(good)).is_ok());
        let bad = [
            op(Request, Set, "Host", Some("x")),
            op(Response, Set, "Content-Length", Some("1")),
            op(Response, Add, "Transfer-Encoding", Some("chunked")),
            op(Request, Remove, "Connection", None),
            op(Request, Set, "Proxy-Authorization", Some("x")),
            op(Request, Remove, "Sec-Fetch-Mode", None),
            op(Request, Set, "X-Cite-Origin-Secret", Some("x")),
            op(Response, Remove, "x-cite-anything", None),
            op(Request, Set, "X-Forwarded-For", Some("1.2.3.4")),
            op(Request, Add, "CF-Connecting-IP", Some("1.2.3.4")),
            op(Request, Remove, "X-Debug", Some("x")),
            op(Response, Set, "X-A", None),
            op(Response, Set, "X-A", Some("")),
            op(Response, Set, "X-A", Some("a\r\nX-B: c")),
            op(Response, Set, "X-A", Some("a\"b")),
            op(Response, Set, "X-A", Some("a\\b")),
            op(Response, Set, "X-A", Some("$HOME")),
            op(Response, Set, "X-A", Some("caf\u{e9}")),
            op(Response, Set, "X-A", Some(&"x".repeat(513))),
            op(Response, Set, "X A", Some("1")),
            op(Response, Set, "X-A:", Some("1")),
            op(Response, Set, "", Some("1")),
            op(Response, Set, "1X", Some("1")),
        ];
        for b in bad {
            let r = header_rule(vec![b.clone()]);
            assert!(validate_rule(&r).is_err(), "{b:?} accepted");
        }
        assert!(
            validate_rule(&header_rule(vec![op(
                Response,
                Set,
                "X-A",
                Some(&"x".repeat(512))
            )]))
            .is_ok()
        );
    }

    #[test]
    fn header_changes_are_capped_at_sixteen() {
        let ops = |n: usize| -> Vec<HeaderOp> {
            (0..n)
                .map(|i| {
                    op(
                        HeaderTarget::Response,
                        HeaderOpKind::Set,
                        &format!("X-H{i}"),
                        Some("1"),
                    )
                })
                .collect()
        };
        assert!(validate_rule(&header_rule(ops(16))).is_ok());
        assert!(validate_rule(&header_rule(ops(17))).is_err());
    }

    #[test]
    fn cors_origins_credentials_and_lists_are_checked() {
        let ok = Cors {
            origins: vec![
                "https://app.example.com".into(),
                "http://localhost:3000".into(),
            ],
            methods: vec!["GET".into(), "POST".into()],
            allow_headers: vec!["Content-Type".into(), "X-Token".into()],
            expose_headers: vec!["X-Request-Id".into()],
            credentials: true,
            max_age_secs: 600,
        };
        assert!(validate_rule(&cors_rule(ok)).is_ok());
        assert!(validate_rule(&cors_rule(origin("*"))).is_ok());
        let star_creds = Cors {
            credentials: true,
            ..origin("*")
        };
        let err = validate_rule(&cors_rule(star_creds))
            .unwrap_err()
            .to_string();
        assert!(
            err.starts_with("rule r cors:") && err.contains("credentials"),
            "{err}"
        );
        let mixed = Cors {
            origins: vec!["*".into(), "https://a.example.com".into()],
            ..Cors::default()
        };
        assert!(validate_rule(&cors_rule(mixed)).is_err());
        assert!(validate_rule(&cors_rule(Cors::default())).is_err());
        for bad in [
            "app.example.com",
            "https://app.example.com/",
            "https://app.example.com/path",
            "https://*.example.com",
            "https://app.example.com:0",
            "https://app.example.com:99999",
            "https://app.example.com:+80",
            "https://app example.com",
            "ftp://app.example.com",
            "https://",
            "null",
            "https://a.example.com\r\nX: y",
            "https://user@example.com",
        ] {
            assert!(validate_rule(&cors_rule(origin(bad))).is_err(), "{bad:?}");
        }
        for ok in [
            "https://a.example.com:8443",
            "http://localhost",
            "https://xn--bcher-kva.example",
        ] {
            assert!(validate_rule(&cors_rule(origin(ok))).is_ok(), "{ok:?}");
        }
        for (field, list) in [
            ("methods", vec!["get".to_string()]),
            ("allow_headers", vec!["X Bad".to_string()]),
            ("expose_headers", vec!["X-Bad:".to_string()]),
        ] {
            let mut c = origin("https://a.example.com");
            match field {
                "methods" => c.methods = list,
                "allow_headers" => c.allow_headers = list,
                _ => c.expose_headers = list,
            }
            assert!(validate_rule(&cors_rule(c)).is_err(), "{field}");
        }
        let mut c = origin("https://a.example.com");
        c.max_age_secs = 86_400;
        assert!(validate_rule(&cors_rule(c.clone())).is_ok());
        c.max_age_secs = 86_401;
        assert!(validate_rule(&cors_rule(c)).is_err());
    }

    #[test]
    fn cors_lists_are_capped_at_thirty_two_entries() {
        let many = |n: usize| -> Vec<String> { (0..n).map(|i| format!("X-H{i}")).collect() };
        let origins = |n: usize| -> Vec<String> {
            (0..n)
                .map(|i| format!("https://a{i}.example.com"))
                .collect()
        };
        let base = Cors {
            origins: origins(32),
            allow_headers: many(32),
            expose_headers: many(32),
            methods: vec!["GET".into(); 32],
            ..Cors::default()
        };
        assert!(validate_rule(&cors_rule(base.clone())).is_ok());
        for broken in [
            Cors {
                origins: origins(33),
                ..base.clone()
            },
            Cors {
                allow_headers: many(33),
                ..base.clone()
            },
            Cors {
                expose_headers: many(33),
                ..base.clone()
            },
            Cors {
                methods: vec!["GET".into(); 33],
                ..base
            },
        ] {
            assert!(validate_rule(&cors_rule(broken)).is_err());
        }
    }

    #[test]
    fn new_matchers_are_validated() {
        let ok = Matchers {
            scheme: Some("https".into()),
            referer_regexes: vec!["^https://example[.]com/".into()],
            headers: vec![HeaderMatch {
                name: "X-Env".into(),
                regex: Some("^prod".into()),
                ..HeaderMatch::default()
            }],
            ..Default::default()
        };
        assert!(validate_rule(&rule("r", ok)).is_ok());
        for scheme in ["ftp", "HTTP", ""] {
            let m = Matchers {
                scheme: Some(scheme.into()),
                ..Default::default()
            };
            assert!(validate_rule(&rule("r", m)).is_err(), "{scheme:?}");
        }
        for re in ["(unclosed", "a b", "(a+)+", ""] {
            let m = Matchers {
                referer_regexes: vec![re.into()],
                ..Default::default()
            };
            assert!(validate_rule(&rule("r", m)).is_err(), "{re:?}");
        }
        let hm = |name: &str, regex: Option<&str>, equals: Option<&str>| HeaderMatch {
            name: name.into(),
            regex: regex.map(String::from),
            equals: equals.map(String::from),
            ..HeaderMatch::default()
        };
        let bad = [
            hm("X-A", None, None),
            hm("X-A", Some("a"), Some("a")),
            hm("X A", None, Some("a")),
            hm("X-A", Some("(unclosed"), None),
            hm("X-A", None, Some("has space")),
            hm("X-A", None, Some("quo\"te")),
            hm("X-A", None, Some("{brace}")),
            hm("X-A", None, Some("$HOME")),
            hm("X-A", None, Some("or")),
            hm("X-A", None, Some("")),
            hm("X-A", None, Some(&"a".repeat(257))),
        ];
        for h in bad {
            let r = rule("r", header_matcher(h.clone()));
            assert!(validate_rule(&r).is_err(), "{h:?}");
        }
        let negated = HeaderMatch {
            negate: true,
            ..hm("X-A", None, Some("-lead_ok.value"))
        };
        assert!(validate_rule(&rule("r", header_matcher(negated))).is_ok());
        let secret_regex = HeaderMatch {
            secret: true,
            ..hm("X-A", Some("a"), None)
        };
        assert!(validate_rule(&rule("r", header_matcher(secret_regex))).is_err());
    }

    fn ua_rule_with(list: Vec<String>) -> FirewallRule {
        rule(
            "r",
            Matchers {
                user_agent_regexes: list,
                ..Default::default()
            },
        )
    }

    #[test]
    fn matcher_lists_are_limited_and_duplicates_are_refused() {
        let many = |n: usize| (0..n).map(|i| format!("bot{i}")).collect::<Vec<_>>();
        assert!(validate_rule(&ua_rule_with(many(16))).is_ok());
        assert!(validate_rule(&ua_rule_with(many(17))).is_err());
        let twice = vec!["bot".to_string(), "other".to_string(), "bot".to_string()];
        let err = validate_rule(&ua_rule_with(twice)).unwrap_err().to_string();
        assert!(err.contains("twice"), "{err}");
        let prefixes = |n: usize| Matchers {
            path_prefixes: (0..n).map(|i| format!("/p{i}")).collect(),
            ..Default::default()
        };
        assert!(validate_rule(&rule("r", prefixes(16))).is_ok());
        assert!(validate_rule(&rule("r", prefixes(17))).is_err());
        let hosts = |n: usize| Matchers {
            hosts: (0..n).map(|i| format!("h{i}.example.com")).collect(),
            ..Default::default()
        };
        assert!(validate_rule(&rule("r", hosts(16))).is_ok());
        assert!(validate_rule(&rule("r", hosts(17))).is_err());
        let mut dup_host = hosts(2);
        dup_host.hosts[1] = dup_host.hosts[0].clone();
        assert!(validate_rule(&rule("r", dup_host)).is_err());
        let bad_prefix = Matchers {
            path_prefixes: vec!["/ok".into(), "nope".into()],
            ..Default::default()
        };
        assert!(validate_rule(&rule("r", bad_prefix)).is_err());
        let long_prefix = Matchers {
            path_prefixes: vec![format!("/{}", "a".repeat(256))],
            ..Default::default()
        };
        assert!(validate_rule(&rule("r", long_prefix)).is_err());
    }

    #[test]
    fn a_rule_holds_at_most_32_regexes_in_total() {
        let list = |tag: &str, n: usize| (0..n).map(|i| format!("{tag}{i}")).collect::<Vec<_>>();
        let ok = Matchers {
            path_regexes: list("^/p", 16),
            user_agent_regexes: list("ua", 16),
            ..Default::default()
        };
        assert!(validate_rule(&rule("r", ok)).is_ok());
        let over = Matchers {
            path_regexes: list("^/p", 16),
            user_agent_regexes: list("ua", 16),
            referer_regexes: list("^http://r", 1),
            ..Default::default()
        };
        let err = validate_rule(&rule("r", over)).unwrap_err().to_string();
        assert!(err.contains("at most 32 regexes"), "{err}");
        let headers = |n: usize| Matchers {
            headers: (0..n)
                .map(|i| HeaderMatch {
                    name: format!("X-H{i}"),
                    equals: Some("v".into()),
                    ..HeaderMatch::default()
                })
                .collect(),
            ..Default::default()
        };
        assert!(validate_rule(&rule("r", headers(16))).is_ok());
        assert!(validate_rule(&rule("r", headers(17))).is_err());
        let mut same = headers(2);
        same.headers[1] = same.headers[0].clone();
        assert!(validate_rule(&rule("r", same)).is_err());
    }

    #[test]
    fn patterns_of_one_field_share_a_work_budget() {
        let heavy = |c: char| format!("[a-z]{{1,40}}{c}[a-z]*");
        assert!(validate_rule(&ua_rule_with(vec![heavy('x')])).is_ok());
        assert!(validate_rule(&ua_rule_with(vec![heavy('y')])).is_ok());
        let err = validate_rule(&ua_rule_with(vec![heavy('x'), heavy('y')]))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("too costly") && err.contains("steps in total"),
            "{err}"
        );
        // anchored patterns are cheap in total steps but add up per start position
        let anchored: Vec<String> = ('b'..='n')
            .map(|c| format!("^[a-z]{{1,40}}{c}[a-z]*"))
            .collect();
        assert!(validate_rule(&ua_rule_with(anchored[..4].to_vec())).is_ok());
        let err = validate_rule(&ua_rule_with(anchored))
            .unwrap_err()
            .to_string();
        assert!(err.contains("per start position"), "{err}");
        // a different field has its own budget
        let spread = Matchers {
            path_regexes: vec![heavy('x').replace("[a-z]*", "[a-z]{1,40}")],
            user_agent_regexes: vec![heavy('x')],
            ..Default::default()
        };
        assert!(validate_rule(&rule("r", spread)).is_ok());
    }

    #[test]
    fn the_empty_value_test_cannot_be_one_of_several_alternatives() {
        assert!(validate_rule(&ua_rule_with(vec!["^$".into()])).is_ok());
        let err = validate_rule(&ua_rule_with(vec!["^$".into(), "bot".into()]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("only entry"), "{err}");
    }

    #[test]
    fn any_non_empty_list_counts_as_a_matcher() {
        let only_hosts = Matchers {
            hosts: vec!["a.example.com".into()],
            ..Default::default()
        };
        assert!(validate_rule(&rule("r", only_hosts)).is_ok());
        let only_headers = header_matcher(HeaderMatch {
            name: "X-A".into(),
            equals: Some("v".into()),
            ..HeaderMatch::default()
        });
        assert!(validate_rule(&rule("r", only_headers)).is_ok());
    }

    #[test]
    fn site_path_lists_follow_the_same_limits() {
        let mut s = site("s", "a.com");
        s.path_prefixes = vec!["/a".into(), "/b".into()];
        s.path_regexes = vec!["^/c[0-9]+$".into(), "^/d".into()];
        assert!(validate_site(&s).is_ok());
        s.path_prefixes = (0..17).map(|i| format!("/p{i}")).collect();
        assert!(validate_site(&s).is_err());
        s.path_prefixes = vec!["/a".into(), "/a".into()];
        assert!(validate_site(&s).is_err());
        s.path_prefixes = vec!["a".into()];
        assert!(validate_site(&s).is_err());
        s.path_prefixes = vec![];
        s.path_regexes = vec!["^/c".into(), "^/c".into()];
        assert!(validate_site(&s).is_err());
    }

    #[test]
    fn zone_lock_secrets_are_length_and_charset_checked_and_never_echoed() {
        let lock = |secret: &str, secret_flag: bool| {
            let mut r = crate::presets::zone_lock_rule("shop", secret);
            if let Some(h) = r.matchers.headers.first_mut() {
                h.secret = secret_flag;
            }
            r
        };
        assert!(validate_rule(&lock(&"a".repeat(32), true)).is_ok());
        assert!(validate_rule(&lock(&"Ab-_9".repeat(25), true)).is_ok());
        assert!(validate_rule(&lock(&"a".repeat(128), true)).is_ok());
        for bad in [
            "a".repeat(31),
            "a".repeat(129),
            format!("{}!", "a".repeat(40)),
            format!("{} {}", "a".repeat(20), "b".repeat(20)),
            format!("{}\"{}", "a".repeat(20), "b".repeat(20)),
            String::new(),
        ] {
            let err = validate_rule(&lock(&bad, true)).unwrap_err().to_string();
            assert!(err.contains("32 to 128"), "{err}");
            assert!(
                bad.is_empty() || !err.contains(&bad),
                "secret leaked: {err}"
            );
        }
        let err = validate_rule(&lock(&"a".repeat(40), false))
            .unwrap_err()
            .to_string();
        assert!(err.contains("marked secret"), "{err}");
        let regex = Matchers {
            headers: vec![HeaderMatch {
                name: ZONE_HEADER.to_ascii_lowercase(),
                regex: Some("^a".into()),
                ..HeaderMatch::default()
            }],
            ..Default::default()
        };
        assert!(validate_rule(&rule("r", regex)).is_err());
    }

    #[test]
    fn rejected_secret_values_are_redacted_in_errors() {
        let h = HeaderMatch {
            name: "X-Token".into(),
            equals: Some("top secret value".into()),
            secret: true,
            ..HeaderMatch::default()
        };
        let err = validate_rule(&rule("r", header_matcher(h.clone())))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("<redacted>") && !err.contains("top secret"),
            "{err}"
        );
        let open = HeaderMatch { secret: false, ..h };
        let err = validate_rule(&rule("r", header_matcher(open)))
            .unwrap_err()
            .to_string();
        assert!(err.contains("top secret"), "{err}");
    }

    fn www_rule(id: &str, to: &str, site: Option<&str>) -> FirewallRule {
        FirewallRule {
            id: id.into(),
            site: site.map(String::from),
            ..redirect_rule(to, Matchers::default())
        }
    }

    #[test]
    fn opposing_www_and_apex_redirects_may_not_share_a_scope() {
        let www = "{scheme}://{www_host}{path}{query}";
        let apex = "{scheme}://{apex_host}{path}{query}";
        let mut cfg = config(vec![site("a", "a.com"), site("b", "b.com")]);
        cfg.firewall = vec![
            www_rule("to-www", www, Some("a")),
            www_rule("to-apex", apex, Some("b")),
        ];
        assert!(validate_config(&cfg).is_ok());
        for (first, second) in [
            (Some("a"), Some("a")),
            (None, Some("a")),
            (Some("a"), None),
            (None, None),
        ] {
            cfg.firewall = vec![
                www_rule("to-www", www, first),
                www_rule("to-apex", apex, second),
            ];
            let err = validate_config(&cfg).unwrap_err().to_string();
            assert!(
                err.contains("to-www") && err.contains("to-apex") && err.contains("loop"),
                "{err}"
            );
        }
        cfg.firewall[1].enabled = false;
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn www_and_apex_redirects_on_different_sites_with_related_hosts_are_refused() {
        let www = "{scheme}://{www_host}{path}{query}";
        let apex = "{scheme}://{apex_host}{path}{query}";
        let mut cfg = config(vec![site("x", "Example.com"), site("y", "www.example.com")]);
        cfg.firewall = vec![
            www_rule("to-www", www, Some("x")),
            www_rule("to-apex", apex, Some("y")),
        ];
        let err = validate_config(&cfg).unwrap_err().to_string();
        assert!(
            err.contains("to-www") && err.contains("to-apex") && err.contains("example.com"),
            "{err}"
        );
        cfg.sites[1].hosts = vec!["other.com".into()];
        assert!(validate_config(&cfg).is_ok());
        cfg.sites[1].hosts = vec!["*.example.com".into()];
        cfg.sites[0].hosts = vec!["a.example.com".into()];
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn a_user_rule_reusing_a_zone_lock_id_gets_an_explicit_error() {
        let secret = "s".repeat(40);
        let mut s = site("shop", "shop.com");
        s.access.cloudflare_only = true;
        let mut cfg = config(vec![s]);
        cfg.firewall
            .push(crate::presets::zone_lock_rule("shop", &secret));
        assert!(validate_config(&cfg).is_ok());
        cfg.firewall.push(rule(
            "zone-shop",
            Matchers {
                path_prefixes: vec!["/x".into()],
                ..Default::default()
            },
        ));
        let err = validate_config(&cfg).unwrap_err().to_string();
        assert!(
            err.contains("zone-shop") && err.contains("zone lock"),
            "{err}"
        );
    }

    #[test]
    fn zone_lock_rule_ids_stay_valid_and_distinct_for_long_site_ids() {
        use crate::presets::zone_lock_rule;
        let secret = "s".repeat(40);
        let short = zone_lock_rule("shop", &secret);
        assert_eq!(short.id, "zone-shop");
        let a = "a".repeat(40);
        let b = format!("{}b", "a".repeat(39));
        let (ra, rb) = (zone_lock_rule(&a, &secret), zone_lock_rule(&b, &secret));
        assert_ne!(ra.id, rb.id);
        for r in [&ra, &rb] {
            assert!(is_valid_id(&r.id) && r.id.len() <= 40, "{}", r.id);
        }
        assert_eq!(ra.id, zone_lock_rule(&a, &secret).id);
        assert_eq!(zone_lock_rule(&"a".repeat(35), &secret).id.len(), 40);
    }

    #[test]
    fn long_cidr_lists_are_accepted_up_to_256() {
        let many = |n: usize| Matchers {
            cidrs: (0..n)
                .map(|i| format!("10.{}.{}.0/24", i / 256, i % 256))
                .collect(),
            ..Default::default()
        };
        assert!(validate_rule(&rule("r", many(256))).is_ok());
        assert!(validate_rule(&rule("r", many(257))).is_err());
    }

    #[test]
    fn config_checks_references_and_uniqueness() {
        let mut cfg = config(vec![site("a", "a.com"), site("a", "b.com")]);
        let err = validate_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("\"a\""));
        cfg.sites[1].id = "b".into();
        assert!(validate_config(&cfg).is_ok());
        cfg.sites[0].maintenance.page_id = Some("nope".into());
        assert!(
            validate_config(&cfg)
                .unwrap_err()
                .to_string()
                .contains("nope")
        );
        cfg.sites[0].maintenance.page_id = None;
        let mut r = rule(
            "r1",
            Matchers {
                path_prefixes: vec!["/x".into()],
                ..Default::default()
            },
        );
        r.site = Some("ghost".into());
        cfg.firewall.push(r);
        assert!(
            validate_config(&cfg)
                .unwrap_err()
                .to_string()
                .contains("ghost")
        );
    }

    #[test]
    fn page_limits() {
        let mut p = crate::model::MaintenancePage {
            id: "p".into(),
            name: "p".into(),
            html: "x".repeat(MAX_PAGE_BYTES),
            status: 503,
        };
        assert!(validate_page(&p).is_ok());
        p.html.push('x');
        assert!(validate_page(&p).is_err());
        p.html.clear();
        p.status = 200;
        assert!(validate_page(&p).is_err());
        p.status = 503;
        p.id = "p\nq".into();
        assert!(validate_page(&p).is_err());
    }

    #[test]
    fn settings_bounds() {
        let mut s = EdgeSettings::default();
        assert!(validate_settings(&s).is_ok());
        s.https_port = Some(80);
        assert!(validate_settings(&s).is_err());
        s.https_port = None;
        s.retention.persist_interval_secs = 4;
        assert!(validate_settings(&s).is_err());
        s.retention.persist_interval_secs = 60;
        s.retention.recent_events = 200_001;
        assert!(validate_settings(&s).is_err());
        s.retention.recent_events = 5000;
        s.retention.audit_days = 3651;
        assert!(validate_settings(&s).is_err());
    }

    fn settings_with(ranges: &[&str]) -> EdgeSettings {
        EdgeSettings {
            cloudflare_ranges: ranges.iter().map(|r| r.to_string()).collect(),
            ..EdgeSettings::default()
        }
    }

    #[test]
    fn cloudflare_ranges_accept_cidrs_and_single_addresses() {
        let ok = settings_with(&[
            "173.245.48.0/20",
            "2400:cb00::/32",
            "203.0.113.9",
            "10.0.0.0/12",
            "2a06:98c0::/29",
            "::ffff:203.0.113.0/120",
        ]);
        assert!(validate_settings(&ok).is_ok());
        assert!(validate_settings(&EdgeSettings::default()).is_ok());
    }

    #[test]
    fn cloudflare_ranges_reject_ipv6_blocks_that_also_match_ipv4_peers() {
        for bad in [
            "::ffff:0:0/96",
            "::ffff:0:0/95",
            "::/16",
            "::1/16",
            "::/96",
            "2002::/16",
            "2002:c000::/32",
            "64:ff9b::/96",
        ] {
            assert!(validate_settings(&settings_with(&[bad])).is_err(), "{bad}");
        }
        let err = validate_settings(&settings_with(&["::/96"])).unwrap_err();
        assert!(err.to_string().contains("overlaps"), "{err}");
    }

    #[test]
    fn cloudflare_ranges_judge_the_masked_network_not_the_written_address() {
        assert!(validate_settings(&settings_with(&["1.2.3.4/8"])).is_err());
        assert!(validate_settings(&settings_with(&["::ffff:10.0.0.0/104"])).is_err());
        assert!(validate_settings(&settings_with(&["10.1.2.3/24"])).is_ok());
    }

    #[test]
    fn cloudflare_ranges_reject_bad_cidrs() {
        for bad in [
            "",
            "nope",
            "1.2.3.4/33",
            "::/129",
            "1.2.3.4\nbackend x",
            "1.2.3.4 5.6.7.8",
        ] {
            let err = validate_settings(&settings_with(&[bad])).unwrap_err();
            assert!(
                err.to_string().contains("cloudflare_ranges"),
                "{bad:?}: {err}"
            );
        }
    }

    #[test]
    fn cloudflare_ranges_reject_everything_and_very_wide_ranges() {
        for bad in [
            "0.0.0.0/0",
            "::/0",
            "0.0.0.0/7",
            "10.0.0.0/8",
            "10.0.0.0/11",
            "128.0.0.0/1",
            "2000::/15",
            "2400::/27",
            "::/8",
        ] {
            assert!(validate_settings(&settings_with(&[bad])).is_err(), "{bad}");
        }
        let err = validate_settings(&settings_with(&["0.0.0.0/0"])).unwrap_err();
        assert!(err.to_string().contains("every IPv4 address"));
        let err = validate_settings(&settings_with(&["::/0"])).unwrap_err();
        assert!(err.to_string().contains("every IPv6 address"));
        let err = validate_settings(&settings_with(&["2000::/15"])).unwrap_err();
        assert!(err.to_string().contains("too wide"));
        assert!(validate_settings(&settings_with(&["10.0.0.0/12", "2400::/28"])).is_ok());
    }

    #[test]
    fn cloudflare_ranges_are_capped_at_256_entries() {
        let many = |n: u32| -> EdgeSettings {
            let ranges: Vec<String> = (0..n)
                .map(|i| format!("10.{}.{}.0/24", i / 256, i % 256))
                .collect();
            EdgeSettings {
                cloudflare_ranges: ranges,
                ..EdgeSettings::default()
            }
        };
        assert!(validate_settings(&many(256)).is_ok());
        assert!(validate_settings(&many(257)).is_err());
    }

    #[test]
    fn cloudflare_access_settings_validate_with_the_builtin_list() {
        let mut s = site("a", "a.com");
        s.access.cloudflare_only = true;
        s.access.tls = crate::model::TlsMode::Flexible;
        assert!(validate_config(&config(vec![s])).is_ok());
    }

    proptest! {
        #[test]
        fn random_hosts_never_pass_with_unsafe_chars(host in ".{0,40}") {
            if validate_site(&site("s", &host)).is_ok() {
                let name = host.strip_prefix("*.").unwrap_or(&host);
                prop_assert!(name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.'));
            }
        }
    }
}
