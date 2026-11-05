use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use cite_client::{BOT_CLASSES, ClientError, ExportFormat, ExportKind, ExportQuery, TOP_KINDS};
use cite_edge::analytics::TopItem;
use cite_edge::bot::{BotSummary, SCORE_BUCKETS};

use crate::demo::iso;
use crate::model::{merge_top, parse_rfc3339_ms};
use crate::theme::{BLUE, DIM, GREEN, RED, TOOL, YELLOW};

pub const METHODS: [&str; 7] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
pub const EXPORT_KINDS: [ExportKind; 4] = [
    ExportKind::Requests,
    ExportKind::Hourly,
    ExportKind::Bots,
    ExportKind::Top,
];
pub const MAX_EXPORT_ROWS: u64 = 10_000_000;

pub const METHOD_HELP: &str = "Detection reads the request headers first (Accept, Accept-Language, Sec-Fetch-*, Sec-CH-UA, protocol and TLS version) and then the user agent. The score from 0 to 100 is a heuristic, not proof: a determined bot can imitate a browser, and an unusual browser can look suspect.";

const MERGED_KEEP: usize = 64;
const SIGNALS_KEEP: usize = 10;

// Semantic colours follow the web dashboard: ok, warn, blue, purple and bad.
pub fn class_color(class: &str) -> u32 {
    match class.trim().to_ascii_lowercase().as_str() {
        "human" => GREEN,
        "suspect" => YELLOW,
        "crawler" => BLUE,
        "tool" => TOOL,
        "bot" => RED,
        _ => DIM,
    }
}

pub fn class_label(class: &str) -> String {
    match class.trim().to_ascii_lowercase().as_str() {
        "human" => "Human".into(),
        "suspect" => "Suspect".into(),
        "crawler" => "Crawler".into(),
        "tool" => "Tool".into(),
        "bot" => "Bot".into(),
        "" => "Unknown".into(),
        other => other.to_string(),
    }
}

pub fn class_help(class: &str) -> &'static str {
    match class.trim().to_ascii_lowercase().as_str() {
        "human" => {
            "Looks like a real browser: the headers agree with each other and with the user agent."
        }
        "suspect" => {
            "Some headers are missing or inconsistent. Could be a privacy tool, an old client or an unlabelled bot."
        }
        "crawler" => {
            "A search engine, social preview or monitoring crawler that names itself in the user agent."
        }
        "tool" => {
            "A scripting library or command line client such as curl, python-requests or a headless browser."
        }
        "bot" => "Strong evidence of automation: a high score from several independent signals.",
        _ => "This request was recorded without a bot verdict.",
    }
}

// Score bands run 0-19, 20-39, 40-59, 60-79 and 80-100, matching the connector's buckets.
pub fn band_index(score: u8) -> usize {
    usize::from(score.min(100) / 20).min(SCORE_BUCKETS.len() - 1)
}

pub fn band_color(index: usize) -> u32 {
    [GREEN, BLUE, YELLOW, TOOL, RED][index.min(4)]
}

pub fn score_color(score: u8) -> u32 {
    band_color(band_index(score))
}

// The API already sends the share as a percentage between 0 and 100.
pub fn fmt_share(pct: f64) -> String {
    if !pct.is_finite() || pct <= 0.0 {
        return "0%".into();
    }
    if pct >= 10.0 {
        format!("{pct:.1}%")
    } else {
        format!("{pct:.2}%")
    }
}

pub fn share_of(count: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        count as f64 / total as f64
    }
}

pub fn parse_signals(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for part in text.split(',') {
        let part = part.trim();
        if !part.is_empty() && !out.iter().any(|s| s == part) {
            out.push(part.to_string());
        }
    }
    out
}

pub fn signal_label(key: &str) -> String {
    match key.strip_prefix("ua_") {
        Some(rest) => format!("UA {}", rest.replace('_', " ")),
        None => key.replace('_', " "),
    }
}

pub fn signal_help(key: &str) -> String {
    let fixed = match key {
        "empty_ua" => "The request sent no user agent.",
        "missing_accept_language" => "Browsers always send Accept-Language; this request did not.",
        "missing_accept" => "No Accept header, which real browsers always send.",
        "accept_wildcard_only" => "Accept was only a wildcard, typical of scripts and libraries.",
        "missing_accept_encoding" => {
            "No Accept-Encoding, although every modern browser offers compression."
        }
        "no_sec_fetch" => {
            "A browser-style user agent without Sec-Fetch-* headers, which current browsers add themselves."
        }
        "sec_fetch_partial" => "Only some of the Sec-Fetch-* headers were present.",
        "sec_fetch_inconsistent" => "The Sec-Fetch-* values contradict each other.",
        "no_sec_ch_ua" => "A Chromium user agent without the Sec-CH-UA client hint.",
        "sec_ch_ua_mismatch" => "Sec-CH-UA does not match the browser named in the user agent.",
        "http_1_0" => "The request used HTTP/1.0, which browsers no longer send.",
        "http1_modern_browser" => {
            "A modern browser user agent over plain HTTP/1.x, which is unusual for a real browser."
        }
        "old_tls" => "The connection used an outdated TLS version.",
        "post_no_referer" => "A POST with no Referer, as many form-spamming scripts send.",
        _ => "",
    };
    if !fixed.is_empty() {
        return fixed.to_string();
    }
    match key.strip_prefix("ua_") {
        Some(rest) => format!(
            "The user agent names this client: {}.",
            rest.replace('_', " ")
        ),
        None => "A heuristic signal raised by the detector.".to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassSlice {
    pub key: String,
    pub label: String,
    pub color: u32,
    pub count: u64,
}

// The five known classes always come first in a fixed order so colours never move between windows.
pub fn class_breakdown(items: &[TopItem]) -> Vec<ClassSlice> {
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for item in items {
        *counts
            .entry(item.key.trim().to_ascii_lowercase())
            .or_default() += item.count;
    }
    let slice = |key: &str, count: u64| ClassSlice {
        key: key.to_string(),
        label: class_label(key),
        color: class_color(key),
        count,
    };
    let mut out: Vec<ClassSlice> = BOT_CLASSES
        .iter()
        .map(|k| slice(k, counts.remove(*k).unwrap_or(0)))
        .collect();
    out.extend(counts.into_iter().map(|(k, n)| slice(&k, n)));
    out
}

pub fn score_histogram(items: &[TopItem]) -> Vec<(&'static str, u64)> {
    SCORE_BUCKETS
        .iter()
        .map(|label| {
            let count: u64 = items
                .iter()
                .filter(|i| i.key == *label)
                .map(|i| i.count)
                .sum();
            (*label, count)
        })
        .collect()
}

// Per-node summaries are added up; the share is recomputed from the combined counts.
pub fn merge_bot_summaries(all: &[BotSummary]) -> BotSummary {
    if let [only] = all {
        return only.clone();
    }
    let total_requests: u64 = all.iter().map(|s| s.total_requests).sum();
    let bot_requests: u64 = all.iter().map(|s| s.bot_requests).sum();
    let merged = |pick: fn(&BotSummary) -> &Vec<TopItem>, keep: usize| {
        merge_top(all.iter().map(pick).collect(), keep)
    };
    BotSummary {
        total_requests,
        bot_requests,
        bot_share_pct: share_of(bot_requests, total_requests) * 100.0,
        classes: merged(|s| &s.classes, MERGED_KEEP),
        signals: merged(|s| &s.signals, SIGNALS_KEEP),
        agents: merged(|s| &s.agents, SIGNALS_KEEP),
        score_buckets: merged(|s| &s.score_buckets, MERGED_KEEP),
    }
}

// Nodes older than the bot analytics release answer these routes with 404.
pub fn is_unsupported(err: &ClientError) -> bool {
    matches!(err.status_code(), Some(404 | 405 | 501))
}

pub fn friendly_error(err: &ClientError) -> String {
    if is_unsupported(err) {
        "This node does not support this feature yet. Update the node to a release with bot analytics and export.".to_string()
    } else {
        err.to_string()
    }
}

// Oldest and newest storage timestamps are shown as UTC to the minute.
pub fn fmt_stamp(ms: i64) -> String {
    let text = iso(ms);
    format!("{} UTC", text[..16].replace('T', " "))
}

pub fn export_kind_label(kind: ExportKind) -> &'static str {
    match kind {
        ExportKind::Requests => "Requests",
        ExportKind::Hourly => "Hourly rollups",
        ExportKind::Bots => "Bot summary",
        ExportKind::Top => "Top list",
    }
}

pub fn export_kind_help(kind: ExportKind) -> &'static str {
    match kind {
        ExportKind::Requests => "One row per recorded request, newest first.",
        ExportKind::Hourly => "Request, byte and error totals per hour.",
        ExportKind::Bots => "Bot share, classes, signals, agents and score distribution.",
        ExportKind::Top => "The most frequent values of one field.",
    }
}

pub fn format_label(format: ExportFormat) -> &'static str {
    match format {
        ExportFormat::Csv => "CSV",
        ExportFormat::Ndjson => "NDJSON",
    }
}

pub fn top_kind_label(kind: &str) -> &'static str {
    match kind {
        "paths" => "Paths",
        "hosts" => "Hosts",
        "referers" => "Referers",
        "agents" => "User agents",
        "content_types" => "Content types",
        "statuses" => "Status codes",
        "ips" => "Client IPs",
        "languages" => "Languages",
        _ => "Other",
    }
}

pub fn window_ms(window: &str) -> Option<i64> {
    let minute = 60_000;
    Some(match window {
        "15m" => 15 * minute,
        "1h" => 60 * minute,
        "24h" => 24 * 60 * minute,
        "7d" => 7 * 24 * 60 * minute,
        "30d" => 30 * 24 * 60 * minute,
        _ => return None,
    })
}

// Accepts "2026-11-05 14:30", "2026-11-05T14:30:15", a bare date, or a full RFC 3339 stamp; no zone means UTC.
pub fn parse_datetime(text: &str) -> Option<i64> {
    let t = text.trim().replacen(' ', "T", 1);
    let (date, rest) = t.split_once('T').unwrap_or((t.as_str(), "00:00"));
    let (clock, zone) = match rest.find(['Z', 'z', '+', '-']) {
        Some(i) => rest.split_at(i),
        None => (rest, "Z"),
    };
    let clock = if clock.matches(':').count() == 1 {
        format!("{clock}:00")
    } else {
        clock.to_string()
    };
    parse_rfc3339_ms(&format!("{date}T{clock}{zone}"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportForm {
    pub kind: ExportKind,
    pub format: ExportFormat,
    pub top: String,
    pub custom_range: bool,
    pub window: String,
    pub from: String,
    pub to: String,
    pub site: String,
    pub status_min: String,
    pub status_max: String,
    pub min_score: String,
    pub bot_class: String,
    pub host: String,
    pub path_prefix: String,
    pub client_ip: String,
    pub method: String,
    pub limit: String,
}

impl ExportForm {
    pub fn new(window: &str) -> Self {
        Self {
            kind: ExportKind::Requests,
            format: ExportFormat::Csv,
            top: TOP_KINDS[0].to_string(),
            custom_range: false,
            window: window.to_string(),
            from: String::new(),
            to: String::new(),
            site: String::new(),
            status_min: String::new(),
            status_max: String::new(),
            min_score: String::new(),
            bot_class: String::new(),
            host: String::new(),
            path_prefix: String::new(),
            client_ip: String::new(),
            method: String::new(),
            limit: String::new(),
        }
    }
}

fn int_field(text: &str, label: &str, min: u64, max: u64) -> Result<Option<u64>, String> {
    let t = text.trim();
    if t.is_empty() {
        return Ok(None);
    }
    if !t.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{label} must be a whole number."));
    }
    match t.parse::<u64>() {
        Ok(n) if (min..=max).contains(&n) => Ok(Some(n)),
        _ => Err(format!("{label} must be between {min} and {max}.")),
    }
}

// Mirrors the web dashboard's form rules; the client validates again before sending.
pub fn build_query(form: &ExportForm, now_ms: i64) -> Result<ExportQuery, String> {
    let mut query = ExportQuery::new(form.kind).format(form.format);
    if form.kind == ExportKind::Top {
        let top = form.top.trim();
        if !TOP_KINDS.contains(&top) {
            return Err("Choose which top list to export.".into());
        }
        query = query.top_kind(top);
    }
    let (from, to) = if form.custom_range {
        let (Some(from), Some(to)) = (parse_datetime(&form.from), parse_datetime(&form.to)) else {
            return Err(
                "Enter both a start and an end time in UTC, for example 2026-11-05 14:30.".into(),
            );
        };
        if from >= to {
            return Err("The start time must be before the end time.".into());
        }
        (from, to)
    } else {
        let span = window_ms(&form.window).ok_or("Pick a time window.")?;
        ((now_ms - span).max(0), now_ms)
    };
    query = query.starting_at(from.max(0)).ending_at(to);
    let site = form.site.trim();
    if !site.is_empty() {
        query = query.site(site);
    }
    if matches!(form.kind, ExportKind::Requests | ExportKind::Bots) {
        query = apply_filters(query, form)?;
    }
    if let Some(limit) = int_field(&form.limit, "Row limit", 1, MAX_EXPORT_ROWS)? {
        query = query.limit(limit as usize);
    }
    query.validate().map_err(|e| e.to_string())?;
    Ok(query)
}

fn apply_filters(mut query: ExportQuery, form: &ExportForm) -> Result<ExportQuery, String> {
    let lo = int_field(&form.status_min, "Minimum status", 100, 599)?;
    let hi = int_field(&form.status_max, "Maximum status", 100, 599)?;
    let score = int_field(&form.min_score, "Minimum bot score", 0, 100)?;
    if let (Some(lo), Some(hi)) = (lo, hi)
        && lo > hi
    {
        return Err("Minimum status is above maximum status.".into());
    }
    if let Some(lo) = lo {
        query = query.status_min(lo as u16);
    }
    if let Some(hi) = hi {
        query = query.status_max(hi as u16);
    }
    if let Some(score) = score {
        query = query.min_bot_score(score as u8);
    }
    let class = form.bot_class.trim();
    if !class.is_empty() {
        if !BOT_CLASSES.contains(&class) {
            return Err("Unknown bot class.".into());
        }
        query = query.bot_class(class);
    }
    let host = form.host.trim();
    if !host.is_empty() {
        if host.len() > 253 || host.contains(|c: char| c.is_whitespace() || c == '/') {
            return Err("Host must be a plain host name.".into());
        }
        query = query.host(host);
    }
    let prefix = form.path_prefix.trim();
    if !prefix.is_empty() {
        if !prefix.starts_with('/') || prefix.len() > 512 {
            return Err("Path prefix must start with a slash.".into());
        }
        query = query.path_prefix(prefix);
    }
    let ip = form.client_ip.trim();
    if !ip.is_empty() {
        if ip.parse::<IpAddr>().is_err() {
            return Err("Client IP is not a valid address.".into());
        }
        query = query.client_ip(ip);
    }
    if !form.method.is_empty() {
        if !METHODS.contains(&form.method.as_str()) {
            return Err("Unknown method.".into());
        }
        query = query.method(form.method.as_str());
    }
    Ok(query)
}

// Used only until the node names the file; the stamp is UTC like every other time in the app.
pub fn export_file_name(form: &ExportForm, now_ms: i64) -> String {
    let stamp = iso(now_ms)[..16].replace(['-', ':'], "").replace('T', "-");
    let what = match form.kind {
        ExportKind::Top => format!("top-{}", form.top.trim()),
        other => other.as_str().to_string(),
    };
    let ext = match form.format {
        ExportFormat::Csv => "csv",
        ExportFormat::Ndjson => "ndjson",
    };
    format!("cite-{what}-{stamp}.{ext}")
}

// Adds " (n)" before the extension until the name is free, so an existing file is never replaced.
pub fn unique_name(exists: impl Fn(&str) -> bool, name: &str) -> String {
    if !exists(name) {
        return name.to_string();
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => name.split_at(i),
        _ => (name, ""),
    };
    for n in 1..10_000 {
        let candidate = format!("{stem} ({n}){ext}");
        if !exists(&candidate) {
            return candidate;
        }
    }
    format!("{stem} ({}){ext}", cite_client::fsio::new_id())
}

pub fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let taken = |n: &str| std::fs::symlink_metadata(dir.join(n)).is_ok();
    dir.join(unique_name(taken, name))
}

pub fn downloads_in(home: Option<PathBuf>) -> Option<PathBuf> {
    home.filter(|h| !h.as_os_str().is_empty())
        .map(|h| h.join("Downloads"))
}

pub fn downloads_dir() -> Option<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    downloads_in(std::env::var_os(var).map(PathBuf::from))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(q: &ExportQuery) -> BTreeMap<String, String> {
        q.pairs()
            .expect("valid")
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect()
    }

    fn item(key: &str, count: u64) -> TopItem {
        TopItem {
            key: key.into(),
            count,
            bytes: 0,
        }
    }

    const NOW: i64 = 1_700_000_000_000;

    #[test]
    fn class_colours_follow_the_dashboard_semantics() {
        assert_eq!(class_color("human"), GREEN);
        assert_eq!(class_color("Suspect"), YELLOW);
        assert_eq!(class_color("crawler"), BLUE);
        assert_eq!(class_color("tool"), TOOL);
        assert_eq!(class_color("bot"), RED);
        assert_eq!(class_color(""), DIM);
        assert_eq!(class_color("alien"), DIM);
        assert_eq!(class_label("CRAWLER"), "Crawler");
        assert_eq!(class_label(""), "Unknown");
    }

    #[test]
    fn score_bands_cover_zero_to_one_hundred() {
        assert_eq!(band_index(0), 0);
        assert_eq!(band_index(19), 0);
        assert_eq!(band_index(20), 1);
        assert_eq!(band_index(79), 3);
        assert_eq!(band_index(80), 4);
        assert_eq!(band_index(100), 4);
        assert_eq!(band_index(255), 4);
        assert_eq!(score_color(5), GREEN);
        assert_eq!(score_color(95), RED);
    }

    #[test]
    fn share_formatting_matches_the_web_dashboard() {
        assert_eq!(fmt_share(0.0), "0%");
        assert_eq!(fmt_share(f64::NAN), "0%");
        assert_eq!(fmt_share(3.456), "3.46%");
        assert_eq!(fmt_share(10.0), "10.0%");
        assert_eq!(fmt_share(26.04), "26.0%");
        assert_eq!(fmt_share(100.0), "100.0%");
    }

    #[test]
    fn signals_are_split_deduplicated_and_labelled() {
        assert_eq!(
            parse_signals(" empty_ua, ua_curl ,,empty_ua"),
            ["empty_ua", "ua_curl"]
        );
        assert!(parse_signals("").is_empty());
        assert_eq!(signal_label("ua_google_inspection"), "UA google inspection");
        assert_eq!(
            signal_label("missing_accept_language"),
            "missing accept language"
        );
        assert!(signal_help("old_tls").contains("TLS"));
        assert!(signal_help("ua_curl").contains("curl"));
        assert!(signal_help("brand_new").contains("heuristic"));
    }

    #[test]
    fn class_breakdown_keeps_a_stable_order_and_unknown_classes() {
        let slices = class_breakdown(&[item("bot", 4), item("human", 90), item("weird", 2)]);
        let keys: Vec<&str> = slices.iter().map(|s| s.key.as_str()).collect();
        assert_eq!(
            keys,
            ["human", "suspect", "crawler", "tool", "bot", "weird"]
        );
        assert_eq!(slices[0].count, 90);
        assert_eq!(slices[1].count, 0);
        assert_eq!(slices[5].color, DIM);
    }

    #[test]
    fn histogram_always_has_the_five_buckets() {
        let h = score_histogram(&[item("20-39", 7), item("80-100", 2)]);
        assert_eq!(h.len(), 5);
        assert_eq!(h[1], ("20-39", 7));
        assert_eq!(h[0], ("0-19", 0));
        assert_eq!(h[4], ("80-100", 2));
    }

    #[test]
    fn merged_summaries_recompute_the_share() {
        let a = BotSummary {
            total_requests: 100,
            bot_requests: 10,
            bot_share_pct: 10.0,
            classes: vec![item("human", 90), item("bot", 10)],
            signals: vec![item("empty_ua", 5)],
            agents: vec![item("curl/8", 10)],
            score_buckets: vec![item("0-19", 90), item("80-100", 10)],
        };
        let b = BotSummary {
            total_requests: 300,
            bot_requests: 90,
            bot_share_pct: 30.0,
            classes: vec![item("human", 210), item("bot", 90)],
            signals: vec![item("empty_ua", 7), item("old_tls", 1)],
            agents: vec![item("curl/8", 20)],
            score_buckets: vec![item("0-19", 210), item("80-100", 90)],
        };
        let m = merge_bot_summaries(&[a.clone(), b]);
        assert_eq!(m.total_requests, 400);
        assert_eq!(m.bot_requests, 100);
        assert!((m.bot_share_pct - 25.0).abs() < 1e-9);
        assert_eq!(m.signals[0], item("empty_ua", 12));
        assert_eq!(m.agents[0].count, 30);
        assert_eq!(merge_bot_summaries(std::slice::from_ref(&a)), a);
        assert_eq!(merge_bot_summaries(&[]).total_requests, 0);
    }

    #[test]
    fn old_nodes_are_reported_as_unsupported() {
        let old = ClientError::Status {
            code: 404,
            message: "not found".into(),
        };
        let broken = ClientError::Status {
            code: 500,
            message: "boom".into(),
        };
        assert!(is_unsupported(&old));
        assert!(!is_unsupported(&broken));
        assert!(friendly_error(&old).contains("Update the node"));
        assert!(friendly_error(&broken).contains("boom"));
    }

    #[test]
    fn stamps_are_utc_to_the_minute() {
        assert_eq!(fmt_stamp(1_700_000_123_000), "2023-11-14 22:15 UTC");
    }

    #[test]
    fn datetimes_default_to_utc_and_accept_several_shapes() {
        let expect = parse_rfc3339_ms("2026-11-05T14:30:00Z");
        assert!(expect.is_some());
        assert_eq!(parse_datetime("2026-11-05 14:30"), expect);
        assert_eq!(parse_datetime("2026-11-05T14:30:00"), expect);
        assert_eq!(parse_datetime("2026-11-05T14:30:00Z"), expect);
        assert_eq!(parse_datetime("2026-11-05T16:30:00+02:00"), expect);
        assert_eq!(
            parse_datetime("2026-11-05"),
            parse_rfc3339_ms("2026-11-05T00:00:00Z")
        );
        assert_eq!(parse_datetime("yesterday"), None);
        assert_eq!(parse_datetime(""), None);
    }

    #[test]
    fn window_form_builds_a_range_ending_now() {
        let form = ExportForm::new("1h");
        let got = pairs(&build_query(&form, NOW).expect("query"));
        assert_eq!(got["kind"], "requests");
        assert_eq!(got["format"], "csv");
        assert_eq!(got["to"], NOW.to_string());
        assert_eq!(got["from"], (NOW - 3_600_000).to_string());
        assert!(!got.contains_key("site"));
        assert!(!got.contains_key("limit"));
    }

    #[test]
    fn custom_range_and_filters_reach_the_query() {
        let mut form = ExportForm::new("1h");
        form.custom_range = true;
        form.from = "2026-11-05 10:00".into();
        form.to = "2026-11-05 11:00".into();
        form.format = ExportFormat::Ndjson;
        form.site = " shop ".into();
        form.status_min = "400".into();
        form.status_max = "499".into();
        form.min_score = "40".into();
        form.bot_class = "crawler".into();
        form.host = "shop.example.com".into();
        form.path_prefix = "/api".into();
        form.client_ip = "2001:db8::1".into();
        form.method = "POST".into();
        form.limit = "500".into();
        let got = pairs(&build_query(&form, NOW).expect("query"));
        let from = parse_datetime("2026-11-05 10:00").expect("from");
        assert_eq!(got["from"], from.to_string());
        assert_eq!(got["to"], (from + 3_600_000).to_string());
        assert_eq!(got["format"], "ndjson");
        assert_eq!(got["site"], "shop");
        assert_eq!(got["status_min"], "400");
        assert_eq!(got["status_max"], "499");
        assert_eq!(got["min_bot_score"], "40");
        assert_eq!(got["bot_class"], "crawler");
        assert_eq!(got["host"], "shop.example.com");
        assert_eq!(got["path_prefix"], "/api");
        assert_eq!(got["client_ip"], "2001:db8::1");
        assert_eq!(got["method"], "POST");
        assert_eq!(got["limit"], "500");
    }

    #[test]
    fn request_filters_are_ignored_for_hourly_and_top_exports() {
        let mut form = ExportForm::new("24h");
        form.kind = ExportKind::Hourly;
        form.status_min = "not a number".into();
        form.host = "bad host".into();
        let got = pairs(&build_query(&form, NOW).expect("query"));
        assert!(!got.contains_key("status_min"));
        form.kind = ExportKind::Top;
        form.top = "agents".into();
        let got = pairs(&build_query(&form, NOW).expect("query"));
        assert_eq!(got["top"], "agents");
    }

    #[test]
    fn invalid_forms_name_the_first_problem() {
        let base = ExportForm::new("1h");
        let bad = |edit: fn(&mut ExportForm)| {
            let mut f = base.clone();
            edit(&mut f);
            build_query(&f, NOW).expect_err("should fail")
        };
        assert!(bad(|f| f.window = "2y".into()).contains("window"));
        assert!(bad(|f| f.status_min = "12".into()).contains("between 100 and 599"));
        assert!(bad(|f| f.status_min = "abc".into()).contains("whole number"));
        assert!(
            bad(|f| {
                f.status_min = "500".into();
                f.status_max = "400".into();
            })
            .contains("above")
        );
        assert!(bad(|f| f.min_score = "101".into()).contains("0 and 100"));
        assert!(bad(|f| f.client_ip = "nope".into()).contains("IP"));
        assert!(bad(|f| f.path_prefix = "api".into()).contains("slash"));
        assert!(bad(|f| f.host = "a/b".into()).contains("Host"));
        assert!(bad(|f| f.bot_class = "robot".into()).contains("bot class"));
        assert!(bad(|f| f.method = "TRACE".into()).contains("method"));
        assert!(bad(|f| f.limit = "0".into()).contains("Row limit"));
        assert!(bad(|f| f.limit = "10000001".into()).contains("Row limit"));
        assert!(
            bad(|f| {
                f.kind = ExportKind::Top;
                f.top = String::new();
            })
            .contains("top list")
        );
        assert!(
            bad(|f| {
                f.custom_range = true;
                f.from = "2026-11-05 12:00".into();
                f.to = "2026-11-05 11:00".into();
            })
            .contains("before")
        );
        assert!(bad(|f| f.custom_range = true).contains("UTC"));
    }

    #[test]
    fn file_names_carry_kind_stamp_and_extension() {
        let mut form = ExportForm::new("1h");
        assert_eq!(
            export_file_name(&form, 1_700_000_123_000),
            "cite-requests-20231114-2215.csv"
        );
        form.kind = ExportKind::Top;
        form.top = "agents".into();
        form.format = ExportFormat::Ndjson;
        assert_eq!(
            export_file_name(&form, 1_700_000_123_000),
            "cite-top-agents-20231114-2215.ndjson"
        );
    }

    #[test]
    fn colliding_names_get_a_numeric_suffix() {
        let taken = ["a.csv", "a (1).csv", "noext", "noext (1)"];
        let exists = |n: &str| taken.contains(&n);
        assert_eq!(unique_name(exists, "b.csv"), "b.csv");
        assert_eq!(unique_name(exists, "a.csv"), "a (2).csv");
        assert_eq!(unique_name(exists, "noext"), "noext (2)");
        assert_eq!(unique_name(|n| n == ".hidden", ".hidden"), ".hidden (1)");
    }

    #[test]
    fn unique_path_never_returns_an_existing_file() {
        let dir = tempfile::tempdir().expect("dir");
        let first = unique_path(dir.path(), "out.csv");
        assert_eq!(first, dir.path().join("out.csv"));
        std::fs::write(&first, "x").expect("write");
        let second = unique_path(dir.path(), "out.csv");
        assert_eq!(second, dir.path().join("out (1).csv"));
        std::fs::write(&second, "x").expect("write");
        assert_eq!(
            unique_path(dir.path(), "out.csv"),
            dir.path().join("out (2).csv")
        );
    }

    #[test]
    fn downloads_directory_hangs_off_the_home_directory() {
        assert_eq!(
            downloads_in(Some(PathBuf::from("/home/ann"))),
            Some(PathBuf::from("/home/ann").join("Downloads"))
        );
        assert_eq!(downloads_in(Some(PathBuf::new())), None);
        assert_eq!(downloads_in(None), None);
    }
}
