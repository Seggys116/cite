use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use cite_client::ClientError;
use cite_client::{
    AnalyticsStats, ArchiveEntry, ArchiveKind, ArchiveList, CreatedToken, CutReport, DeployRequest,
    NodeInfo, PresetInfo, RequestQuery, RestoreReport, SiteDetail, TokenMeta,
};
use cite_edge::analytics::{Point, SizeBucket, Summary, Timeseries, TopItem, window_from_str};
use cite_edge::bot::BotSummary;
use cite_edge::model::{
    DeployAction, Deployment, EdgeSettings, FirewallAction, FirewallRule, HealthCheck, LogEvent,
    Maintenance, MaintenancePage, Matchers, Site, SiteKind, Slot, Source, Target, Upstream,
};
use cite_edge::presets::presets;
use serde_json::{Map, Value, json};

use crate::archive::{CutSpec, DAY_MS};
use crate::config::{DesktopConfig, DesktopNode};

type Res<T> = Result<T, ClientError>;

pub const HOUR_MS: i64 = 3_600_000;
const DEMO_ROWS: u64 = 1_284_906;
const DEMO_DB_BYTES: u64 = 436_207_616;
const DEMO_SPAN_DAYS: i64 = 29;

fn status_err(code: u16, message: impl Into<String>) -> ClientError {
    ClientError::Status {
        code,
        message: message.into(),
    }
}

// Formats epoch milliseconds as RFC 3339 without a date crate.
pub fn iso(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// A tiny seeded generator keeps the demo traffic stable between runs.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> f64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        ((z ^ (z >> 31)) >> 11) as f64 / (1u64 << 53) as f64
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[(self.next() * items.len() as f64) as usize % items.len()]
    }
}

const PATHS: [(&str, u64); 8] = [
    ("/", 30),
    ("/products", 22),
    ("/api/v1/orders", 18),
    ("/static/app.js", 12),
    ("/checkout", 8),
    ("/docs/getting-started", 6),
    ("/wp-login.php", 3),
    ("/.env", 1),
];
const IPS: [&str; 6] = [
    "198.51.100.23",
    "203.0.113.77",
    "192.0.2.14",
    "198.51.100.88",
    "192.0.2.201",
    "2001:db8::7a",
];
const AGENTS: [&str; 5] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "curl/8.4.0",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
];
const HOSTS: [(&str, &str); 3] = [
    ("shop.example.com", "shop"),
    ("api.example.com", "api"),
    ("docs.example.com", "docs"),
];

// Bucket widths match the connector's own resolution for each window.
fn step_for(window: &str) -> u64 {
    match window {
        "15m" | "1h" => 60,
        "24h" => 900,
        "7d" => 3600,
        _ => 21_600,
    }
}

// Request volume follows a daily curve with seeded noise so every window looks alive.
pub fn demo_series(seed: u64, scale: f64, window: &str, now: i64) -> Timeseries {
    let secs = window_from_str(window).unwrap_or(3600);
    let step = step_for(window);
    let count = (secs / step).max(2);
    let mut rng = Rng(seed ^ secs);
    let points = (0..count)
        .map(|i| {
            let ts = now / 1000 - ((count - 1 - i) * step) as i64;
            let hour = (ts % 86_400) as f64 / 3600.0;
            let curve = 0.55 + 0.45 * ((hour - 9.0) / 24.0 * std::f64::consts::TAU).sin();
            let per_min = 90.0 * scale * curve * (0.8 + 0.4 * rng.next());
            let requests = (per_min * step as f64 / 60.0) as u64;
            Point {
                ts,
                requests,
                bytes_out: requests * 18_000,
                errors: (requests as f64 * (0.02 + 0.03 * rng.next())) as u64,
                blocked: (requests as f64 * (0.01 + 0.03 * rng.next())).ceil() as u64,
                avg_ms: 30.0 + 40.0 * rng.next(),
            }
        })
        .collect();
    Timeseries {
        step_secs: step,
        points,
    }
}

fn top(items: &[(&str, u64)], total: u64, bytes_per: u64) -> Vec<TopItem> {
    let weight: u64 = items.iter().map(|i| i.1).sum();
    items
        .iter()
        .map(|(key, w)| {
            let count = total * w / weight.max(1);
            TopItem {
                key: (*key).to_string(),
                count,
                bytes: count * bytes_per,
            }
        })
        .collect()
}

// Like the API, each bucket counts every response up to its bound and the open-ended bucket holds the total.
pub fn cumulative_sizes(total: u64) -> Vec<SizeBucket> {
    let mut running = 0;
    [
        (Some(1024), 38),
        (Some(10_240), 41),
        (Some(102_400), 16),
        (None, 5),
    ]
    .into_iter()
    .map(|(le, share)| {
        running += total * share / 100;
        SizeBucket { le, count: running }
    })
    .collect()
}

// Totals derive from the series so the cards and the chart always agree.
pub fn demo_summary(seed: u64, scale: f64, window: &str, now: i64) -> Summary {
    let series = demo_series(seed, scale, window, now);
    let total: u64 = series.points.iter().map(|p| p.requests).sum();
    let blocked: u64 = series.points.iter().map(|p| p.blocked).sum();
    let e4 = total * 34 / 1000;
    let e5 = total * 6 / 1000;
    let ok = total.saturating_sub(e4 + e5);
    let ips: Vec<(&str, u64)> = IPS
        .iter()
        .zip([30, 24, 18, 12, 9, 7])
        .map(|(i, w)| (*i, w))
        .collect();
    let agents: Vec<(&str, u64)> = AGENTS
        .iter()
        .zip([40, 28, 18, 9, 5])
        .map(|(a, w)| (*a, w))
        .collect();
    let hosts: Vec<(&str, u64)> = HOSTS
        .iter()
        .zip([55, 35, 10])
        .map(|(h, w)| (h.0, w))
        .collect();
    let mut status = BTreeMap::new();
    status.insert("2xx".to_string(), ok * 94 / 100);
    status.insert("3xx".to_string(), ok - ok * 94 / 100);
    status.insert("4xx".to_string(), e4);
    status.insert("5xx".to_string(), e5);
    let mut methods = BTreeMap::new();
    methods.insert("GET".to_string(), total * 82 / 100);
    methods.insert("POST".to_string(), total * 15 / 100);
    methods.insert("HEAD".to_string(), total * 3 / 100);
    let mut content_types = BTreeMap::new();
    content_types.insert("text/html".to_string(), total * 45 / 100);
    content_types.insert("application/json".to_string(), total * 35 / 100);
    content_types.insert("application/javascript".to_string(), total * 12 / 100);
    content_types.insert("image/png".to_string(), total * 8 / 100);
    let sizes = cumulative_sizes(total);
    Summary {
        requests: total,
        bytes_in: total * 900,
        bytes_out: total * 18_000,
        blocked,
        errors_4xx: e4,
        errors_5xx: e5,
        avg_ms: 48.0,
        p50_ms: 31,
        p95_ms: 142,
        p99_ms: 380,
        status,
        methods,
        content_types,
        sizes,
        top_paths: top(&PATHS, total, 18_000),
        top_ips: top(&ips, total, 0),
        top_user_agents: top(&agents, total, 0),
        top_hosts: top(&hosts, total, 18_000),
        top_blocked: top(
            &[
                ("WordPress login probes", 14),
                ("Dotfile and VCS leaks", 11),
                ("phpMyAdmin scans", 7),
            ],
            blocked,
            0,
        ),
    }
}

// Events are seeded by the current three second slot so the recent list moves on refresh.
pub fn demo_events(seed: u64, now: i64, count: usize) -> Vec<LogEvent> {
    let mut rng = Rng(seed ^ (now / 3000) as u64);
    (0..count)
        .map(|i| {
            let (path, _) = PATHS[(rng.next() * 6.0) as usize];
            let risky = rng.next() < 0.08;
            let path = if risky {
                *rng.pick(&["/wp-login.php", "/.env", "/phpmyadmin"])
            } else {
                path
            };
            let roll = rng.next();
            let (host, site) = *rng.pick(&HOSTS);
            let status = match roll {
                _ if risky => 403,
                r if r < 0.86 => 200,
                r if r < 0.92 => 304,
                r if r < 0.97 => 404,
                _ => 502,
            };
            let ua = ((rng.next() * AGENTS.len() as f64) as usize) % AGENTS.len();
            let total_ms = 5 + (rng.next() * 140.0) as u32;
            let bot = bot_fields(ua, risky, rng.next());
            LogEvent {
                ts_ms: now - (i as i64) * 1700 - (rng.next() * 900.0) as i64,
                client_ip: (*rng.pick(&IPS)).to_string(),
                host: host.to_string(),
                method: (*rng.pick(&["GET", "GET", "GET", "POST"])).to_string(),
                path: path.to_string(),
                query_len: 0,
                status,
                bytes_in: 400,
                bytes_out: if status == 200 {
                    2_000 + (rng.next() * 40_000.0) as u64
                } else {
                    300
                },
                total_ms,
                user_agent: AGENTS[ua].to_string(),
                referer: String::new(),
                content_type: "text/html".into(),
                backend: format!("{site}_blue"),
                server: "s1".into(),
                site: site.to_string(),
                blocked: risky.then(|| "scanner".to_string()),
                http_version: (if bot.modern { "HTTP/2.0" } else { "HTTP/1.1" }).into(),
                accept: bot.accept.into(),
                accept_language: bot.lang.into(),
                accept_encoding: bot.encoding.into(),
                sec_fetch_site: bot.fetch[0].into(),
                sec_fetch_mode: bot.fetch[1].into(),
                sec_fetch_dest: bot.fetch[2].into(),
                sec_ch_ua: bot.ch_ua.into(),
                tls_version: (if risky { "TLSv1.2" } else { "TLSv1.3" }).into(),
                resp_ms: total_ms.saturating_sub(2),
                bot_score: bot.score,
                bot_class: bot.class.into(),
                bot_signals: bot.signals.into(),
            }
        })
        .collect()
}

const BROWSER_ACCEPT: &str =
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
const CHROME_HINT: &str =
    "\"Chromium\";v=\"130\", \"Google Chrome\";v=\"130\", \"Not?A_Brand\";v=\"99\"";

struct BotFields {
    modern: bool,
    accept: &'static str,
    lang: &'static str,
    encoding: &'static str,
    fetch: [&'static str; 3],
    ch_ua: &'static str,
    score: u8,
    class: &'static str,
    signals: &'static str,
}

// Header sets follow what each client really sends, so the detail view shows believable evidence.
fn bot_fields(ua: usize, risky: bool, shade: f64) -> BotFields {
    let bare = BotFields {
        modern: false,
        accept: "",
        lang: "",
        encoding: "",
        fetch: ["", "", ""],
        ch_ua: "",
        score: 0,
        class: "human",
        signals: "",
    };
    let browser = |ch_ua: &'static str| BotFields {
        modern: true,
        accept: BROWSER_ACCEPT,
        lang: "en-US,en;q=0.9",
        encoding: "gzip, deflate, br",
        fetch: ["same-origin", "navigate", "document"],
        ch_ua,
        score: 3,
        class: "human",
        signals: "",
    };
    if risky {
        return BotFields {
            score: 91,
            class: "bot",
            signals: "missing_accept,missing_accept_language,missing_accept_encoding,no_sec_fetch",
            ..bare
        };
    }
    match ua {
        0 if shade < 0.12 => BotFields {
            fetch: ["", "", ""],
            score: 45,
            class: "suspect",
            signals: "no_sec_fetch,no_sec_ch_ua",
            ..browser("")
        },
        0 => browser(CHROME_HINT),
        1 | 2 => BotFields {
            score: 5,
            ..browser("")
        },
        3 => BotFields {
            accept: "*/*",
            score: 62,
            class: "tool",
            signals: "missing_accept_language,accept_wildcard_only,missing_accept_encoding,ua_curl",
            ..bare
        },
        _ => BotFields {
            accept: "*/*",
            encoding: "gzip, deflate",
            score: 35,
            class: "crawler",
            signals: "missing_accept_language,ua_googlebot",
            ..bare
        },
    }
}

// Class, signal and agent mixes are fixed shares of the window total so they add up with the other cards.
pub fn demo_bot_summary(seed: u64, scale: f64, window: &str, now: i64) -> BotSummary {
    let total: u64 = demo_series(seed, scale, window, now)
        .points
        .iter()
        .map(|p| p.requests)
        .sum();
    let classes = top(
        &[
            ("human", 74),
            ("suspect", 8),
            ("crawler", 7),
            ("tool", 6),
            ("bot", 5),
        ],
        total,
        0,
    );
    let bot_requests: u64 = classes
        .iter()
        .filter(|c| c.key != "human")
        .map(|c| c.count)
        .sum();
    BotSummary {
        total_requests: total,
        bot_requests,
        bot_share_pct: if total == 0 {
            0.0
        } else {
            bot_requests as f64 * 100.0 / total as f64
        },
        classes,
        signals: top(
            &[
                ("missing_accept_language", 40),
                ("no_sec_fetch", 31),
                ("accept_wildcard_only", 24),
                ("ua_curl", 18),
                ("missing_accept_encoding", 15),
                ("ua_googlebot", 12),
                ("no_sec_ch_ua", 9),
                ("http1_modern_browser", 4),
            ],
            bot_requests,
            0,
        ),
        agents: top(
            &[
                ("curl/8.4.0", 30),
                ("Googlebot/2.1 (+http://www.google.com/bot.html)", 24),
                ("python-requests/2.31.0", 18),
                ("Mozilla/5.0 (compatible; bingbot/2.0)", 12),
                ("Go-http-client/2.0", 9),
                ("HeadlessChrome/130.0.0.0", 7),
            ],
            bot_requests,
            0,
        ),
        score_buckets: top(
            &[
                ("0-19", 72),
                ("20-39", 8),
                ("40-59", 8),
                ("60-79", 7),
                ("80-100", 5),
            ],
            total,
            0,
        ),
    }
}

// Each kind returns the same keys the node would, including the fixed lists the summary lacks.
pub fn demo_top(kind: &str, seed: u64, scale: f64, window: &str, now: i64) -> Vec<TopItem> {
    let summary = demo_summary(seed, scale, window, now);
    let from_map = |map: &BTreeMap<String, u64>| {
        let mut items: Vec<TopItem> = map
            .iter()
            .map(|(key, count)| TopItem {
                key: key.clone(),
                count: *count,
                bytes: 0,
            })
            .collect();
        items.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
        items
    };
    match kind {
        "paths" => summary.top_paths,
        "hosts" => summary.top_hosts,
        "agents" => summary.top_user_agents,
        "ips" => summary.top_ips,
        "statuses" => from_map(&summary.status),
        "content_types" => from_map(&summary.content_types),
        "referers" => top(
            &[
                ("-", 52),
                ("https://www.google.com/", 21),
                ("https://news.example.org/", 9),
                ("https://shop.example.com/products", 8),
                ("https://duckduckgo.com/", 6),
            ],
            summary.requests,
            0,
        ),
        "languages" => top(
            &[
                ("en-US", 46),
                ("en-GB", 14),
                ("de-DE", 12),
                ("fr-FR", 8),
                ("es-ES", 5),
                ("-", 15),
            ],
            summary.requests,
            0,
        ),
        _ => Vec::new(),
    }
}

fn csv_cell(value: &Value) -> String {
    let text = match value {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    };
    if text.contains([',', '"', '\n']) {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text
    }
}

fn render_rows(ndjson: bool, header: &[&str], rows: Vec<Vec<Value>>) -> String {
    let mut out = String::new();
    if !ndjson {
        out.push_str(&header.join(","));
        out.push('\n');
    }
    for row in rows {
        if ndjson {
            let obj: Map<String, Value> =
                header.iter().map(|h| (*h).to_string()).zip(row).collect();
            out.push_str(&Value::Object(obj).to_string());
        } else {
            let cells: Vec<String> = row.iter().map(csv_cell).collect();
            out.push_str(&cells.join(","));
        }
        out.push('\n');
    }
    out
}

// Builds a small file for the validated query pairs so the demo export flow ends in a real file.
pub fn demo_export_body(pairs: &[(&'static str, String)], seed: u64, scale: f64) -> String {
    let get = |name: &str| {
        pairs
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    };
    let ndjson = get("format") == Some("ndjson");
    let now = now_ms();
    match get("kind") {
        Some("hourly") => {
            let rows = demo_series(seed, scale, "7d", now)
                .points
                .iter()
                .map(|p| {
                    vec![
                        json!(p.ts),
                        json!(p.requests),
                        json!(p.bytes_out),
                        json!(p.errors),
                    ]
                })
                .collect();
            render_rows(
                ndjson,
                &["hour_ts", "requests", "bytes_out", "errors"],
                rows,
            )
        }
        Some("bots") => {
            let s = demo_bot_summary(seed, scale, "24h", now);
            let rows = s
                .classes
                .iter()
                .map(|c| vec![json!(c.key), json!(c.count)])
                .collect();
            render_rows(ndjson, &["class", "requests"], rows)
        }
        Some("top") => {
            let kind = get("top").unwrap_or("paths");
            let rows = demo_top(kind, seed, scale, "24h", now)
                .iter()
                .map(|t| vec![json!(t.key), json!(t.count), json!(t.bytes)])
                .collect();
            render_rows(ndjson, &["key", "requests", "bytes"], rows)
        }
        _ => {
            let limit = get("limit").and_then(|l| l.parse().ok()).unwrap_or(200);
            let rows = demo_events(seed, now, 200)
                .into_iter()
                .take(limit)
                .map(|e| {
                    vec![
                        json!(e.ts_ms),
                        json!(e.client_ip),
                        json!(e.host),
                        json!(e.method),
                        json!(e.path),
                        json!(e.status),
                        json!(e.total_ms),
                        json!(e.bot_class),
                        json!(e.bot_score),
                        json!(e.bot_signals),
                    ]
                })
                .collect();
            let header = [
                "ts_ms",
                "client_ip",
                "host",
                "method",
                "path",
                "status",
                "total_ms",
                "bot_class",
                "bot_score",
                "bot_signals",
            ];
            render_rows(ndjson, &header, rows)
        }
    }
}

// The name a node would suggest, so the demo exercises the rename step as well.
pub fn demo_export_name(pairs: &[(&'static str, String)]) -> String {
    let get = |name: &str| {
        pairs
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    };
    let what = match (get("kind"), get("top")) {
        (Some("top"), Some(top)) => format!("top-{top}"),
        (Some(kind), _) => kind.to_string(),
        _ => "requests".to_string(),
    };
    format!("cite-{what}.{}", get("format").unwrap_or("csv"))
}

fn page_html(title: &str, text: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\"><title>{title}</title></head>\n<body>\n  <main>\n    <h1>{title}</h1>\n    <p>{text}</p>\n  </main>\n</body>\n</html>\n"
    )
}

fn targets(group: i64, ports: u16, count: usize, base: i64) -> Vec<Target> {
    (0..count)
        .map(|i| Target {
            addr: format!("10.{group}.{}.{}:{ports}", base, 11 + i),
            weight: 100,
        })
        .collect()
}

fn hist(now: i64, rows: &[(i64, Slot, DeployAction, &str)]) -> Vec<Deployment> {
    rows.iter()
        .enumerate()
        .map(|(i, (hours, slot, action, note))| Deployment {
            id: format!("d-{i}-{hours}"),
            at: iso(now - hours * HOUR_MS),
            slot: *slot,
            action: *action,
            note: (*note).to_string(),
        })
        .collect()
}

// Two sites run on both slots; the third carries a repository source and a failed deploy.
fn seed_sites(node: i64, now: i64) -> Vec<Site> {
    let health = HealthCheck {
        path: "/healthz".into(),
        ..HealthCheck::default()
    };
    let site =
        |id: &str, name: &str, hosts: &[&str], kind, ports, base: i64, active, history| Site {
            id: id.into(),
            name: name.into(),
            hosts: hosts.iter().map(|h| (*h).to_string()).collect(),
            path_regex: (id == "api").then(|| "^/v1/".to_string()),
            kind,
            blue: Upstream {
                targets: targets(node, ports, if id == "shop" { 2 } else { 1 }, base * 10 + 1),
                label: (id == "shop").then(|| "v2.14.0".to_string()),
            },
            green: Upstream {
                targets: targets(node, ports, if id == "shop" { 2 } else { 1 }, base * 10 + 2),
                label: (id == "shop").then(|| "v2.13.4".to_string()),
            },
            active,
            maintenance: Maintenance {
                enabled: id == "docs" && node == 1,
                page_id: (id == "docs").then(|| "scheduled".to_string()),
            },
            health: health.clone(),
            source: (id == "docs").then(|| Source {
                repo: "https://git.example.com/docs.git".into(),
                branch: Some("main".into()),
                runtime: None,
                node_major: None,
                poll_interval: None,
                secret: None,
            }),
            history,
        };
    use DeployAction::{Failed, Promote, Rollback, Switch};
    vec![
        site(
            "shop",
            "Storefront",
            &["shop.example.com", "www.example.com"],
            SiteKind::Site,
            8080,
            1,
            Slot::Blue,
            hist(
                now,
                &[
                    (170, Slot::Green, Promote, "Release 2.13.4"),
                    (52, Slot::Blue, Promote, "Release 2.14.0-rc1"),
                    (51, Slot::Green, Rollback, "Checkout regression"),
                    (6, Slot::Blue, Promote, "Release 2.14.0"),
                ],
            ),
        ),
        site(
            "api",
            "Public API",
            &["api.example.com"],
            SiteKind::Api,
            9000,
            2,
            Slot::Green,
            hist(
                now,
                &[
                    (300, Slot::Blue, Promote, "Initial deploy"),
                    (28, Slot::Green, Promote, "Add pagination to orders"),
                    (27, Slot::Blue, Switch, "Manual flip while testing"),
                    (26, Slot::Green, Switch, "Back to green"),
                ],
            ),
        ),
        site(
            "docs",
            "Documentation",
            &["docs.example.com"],
            SiteKind::Site,
            3000,
            3,
            Slot::Blue,
            hist(
                now,
                &[
                    (400, Slot::Blue, Promote, "Initial deploy"),
                    (90, Slot::Green, Failed, "Health check timed out"),
                ],
            ),
        ),
    ]
}

fn seed_rules() -> Vec<FirewallRule> {
    let rule = |id: &str, name: &str, enabled, action, matchers: Matchers, site: Option<&str>| {
        FirewallRule {
            id: id.into(),
            name: name.into(),
            enabled,
            action,
            matchers,
            site: site.map(str::to_string),
        }
    };
    let m = Matchers::default;
    vec![
        rule(
            "r-wp-login",
            "WordPress login probes",
            true,
            FirewallAction::Deny,
            Matchers {
                path_regex: Some("^/wp-(login|admin)".into()),
                ..m()
            },
            None,
        ),
        rule(
            "r-env",
            "Dotfile and VCS leaks",
            true,
            FirewallAction::Deny,
            Matchers {
                path_regex: Some("/\\.(env|git)(/|$)".into()),
                ..m()
            },
            None,
        ),
        rule(
            "r-phpmyadmin",
            "phpMyAdmin scans",
            true,
            FirewallAction::Drop,
            Matchers {
                path_prefix: Some("/phpmyadmin".into()),
                ..m()
            },
            None,
        ),
        rule(
            "r-scanner-ua",
            "Known scanner agents",
            true,
            FirewallAction::Tarpit,
            Matchers {
                user_agent_regex: Some("(sqlmap|nikto|masscan)".into()),
                ..m()
            },
            None,
        ),
        rule(
            "r-trace",
            "Odd HTTP methods",
            true,
            FirewallAction::Deny,
            Matchers {
                methods: vec!["TRACE".into(), "CONNECT".into()],
                ..m()
            },
            None,
        ),
        rule(
            "r-badnet",
            "Abusive network",
            false,
            FirewallAction::Deny,
            Matchers {
                cidrs: vec!["203.0.113.0/24".into()],
                ..m()
            },
            Some("shop"),
        ),
    ]
}

struct DemoState {
    sites: Vec<Site>,
    rules: Vec<FirewallRule>,
    pages: Vec<MaintenancePage>,
    settings: EdgeSettings,
    tokens: Vec<TokenMeta>,
    counter: u64,
    rows: u64,
    oldest_ms: i64,
    archives: Vec<ArchiveEntry>,
}

// Short stable hex digest stand-in so demo archives show a plausible checksum column.
fn demo_sha(seed: u64) -> String {
    let mut x = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut out = String::with_capacity(64);
    for _ in 0..4 {
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        out.push_str(&format!("{:016x}", z ^ (z >> 31)));
    }
    out
}

fn file_stamp(ms: i64) -> String {
    iso(ms)[..16].replace(['-', ':'], "").replace('T', "-")
}

// Rows are spread evenly over the stored span, which is enough for a believable preview.
pub fn demo_rows_before(total: u64, oldest_ms: i64, now: i64, cutoff_ms: i64) -> u64 {
    if cutoff_ms <= oldest_ms || now <= oldest_ms {
        return 0;
    }
    let share = (cutoff_ms - oldest_ms) as f64 / (now - oldest_ms) as f64;
    ((total as f64 * share.min(1.0)) as u64).min(total)
}

fn seed_archives(now: i64) -> Vec<ArchiveEntry> {
    let from = now - 90 * DAY_MS;
    let to = now - 60 * DAY_MS;
    let (a, b) = (file_stamp(from), file_stamp(to));
    vec![
        ArchiveEntry {
            name: format!("cite-archive-{}-{}.ndjson.gz", &a[..8], &b[..8]),
            kind: ArchiveKind::Archive,
            bytes: 38_421_907,
            created_ms: now - 35 * DAY_MS,
            sha256: demo_sha(1),
            rows: Some(412_330),
            from_ms: Some(from),
            to_ms: Some(to),
        },
        ArchiveEntry {
            name: format!("cite-backup-{}.db", file_stamp(now - 3 * DAY_MS)),
            kind: ArchiveKind::Backup,
            bytes: DEMO_DB_BYTES,
            created_ms: now - 3 * DAY_MS,
            sha256: demo_sha(2),
            rows: None,
            from_ms: None,
            to_ms: None,
        },
    ]
}

pub struct DemoNode {
    name: String,
    index: i64,
    started: Instant,
    state: Mutex<DemoState>,
}

impl DemoNode {
    fn new(name: &str, index: i64) -> Self {
        let now = now_ms();
        let page = |id: &str, name: &str, title: &str, text: &str| MaintenancePage {
            id: id.into(),
            name: name.into(),
            html: page_html(title, text),
            status: 503,
        };
        let settings = EdgeSettings {
            https_port: Some(443),
            ..EdgeSettings::default()
        };
        let token = |id: &str, name: &str, days: i64, used: Option<i64>| TokenMeta {
            id: id.into(),
            name: name.into(),
            created_at: iso(now - days * 24 * HOUR_MS),
            last_used_at: used.map(|h| iso(now - h * HOUR_MS)),
        };
        Self {
            name: name.into(),
            index,
            started: Instant::now(),
            state: Mutex::new(DemoState {
                sites: seed_sites(index, now),
                rules: seed_rules(),
                pages: vec![
                    page(
                        "scheduled",
                        "Scheduled maintenance",
                        "Back soon",
                        "We are upgrading our systems and will be back in a few minutes.",
                    ),
                    page(
                        "incident",
                        "Incident notice",
                        "We are on it",
                        "Something went wrong on our side. Engineers are already working on a fix.",
                    ),
                ],
                settings,
                tokens: vec![
                    token("t-1", "ci-deploy", 40, Some(3)),
                    token("t-2", "grafana-readonly", 12, None),
                ],
                counter: 0,
                rows: DEMO_ROWS,
                oldest_ms: now - DEMO_SPAN_DAYS * DAY_MS,
                archives: seed_archives(now),
            }),
        }
    }

    fn st(&self) -> MutexGuard<'_, DemoState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn seed(&self) -> u64 {
        0xC17E ^ ((self.index as u64 + 1) * 7919)
    }

    fn scale(&self) -> f64 {
        if self.index == 0 { 1.0 } else { 0.55 }
    }

    pub fn info(&self) -> Res<NodeInfo> {
        let st = self.st();
        let mut extra = Map::new();
        let uptime =
            (if self.index == 0 { 26 } else { 9 }) * 86_400 + self.started.elapsed().as_secs();
        extra.insert("uptime_secs".into(), json!(uptime));
        extra.insert("sites".into(), json!(st.sites.len()));
        extra.insert("firewall_rules".into(), json!(st.rules.len()));
        extra.insert(
            "haproxy".into(),
            json!({"running": true, "last_reload_ok": true}),
        );
        Ok(NodeInfo {
            name: self.name.clone(),
            version: "0.2.0".into(),
            extra,
        })
    }

    pub fn list_sites(&self) -> Res<Vec<Site>> {
        Ok(self.st().sites.clone())
    }

    // One target on the second node reports DOWN so the health states are visible.
    pub fn get_site(&self, id: &str) -> Res<SiteDetail> {
        let st = self.st();
        let site = find(&st.sites, id)?.clone();
        let down = |t: &Target| t.addr.ends_with(".22:8080") && self.index == 1;
        let state = |ts: &[Target]| -> Vec<Value> {
            ts.iter()
                .map(|t| json!({"addr": t.addr, "status": if down(t) { "DOWN" } else { "UP" }}))
                .collect()
        };
        let live = json!({"blue": state(&site.blue.targets), "green": state(&site.green.targets)});
        Ok(SiteDetail {
            site,
            live: Some(live),
        })
    }

    pub fn create_site(&self, site: &Site) -> Res<Site> {
        let mut st = self.st();
        if st.sites.iter().any(|s| s.id == site.id) {
            return Err(status_err(409, format!("site {} already exists", site.id)));
        }
        st.sites.push(site.clone());
        Ok(site.clone())
    }

    pub fn update_site(&self, id: &str, site: &Site) -> Res<Site> {
        let mut st = self.st();
        let slot = find_mut(&mut st.sites, id)?;
        *slot = site.clone();
        Ok(site.clone())
    }

    pub fn delete_site(&self, id: &str) -> Res<()> {
        let mut st = self.st();
        find(&st.sites, id)?;
        st.sites.retain(|s| s.id != id);
        Ok(())
    }

    // Every mutation appends a deployment entry just as the real connector does.
    fn record(
        &self,
        st: &mut DemoState,
        id: &str,
        slot: Slot,
        action: DeployAction,
        note: &str,
    ) -> Res<Deployment> {
        st.counter += 1;
        let dep = Deployment {
            id: format!("d-live-{}", st.counter),
            at: iso(now_ms()),
            slot,
            action,
            note: note.into(),
        };
        find_mut(&mut st.sites, id)?.history.push(dep.clone());
        Ok(dep)
    }

    pub fn deploy(&self, id: &str, req: &DeployRequest) -> Res<Deployment> {
        let mut st = self.st();
        let idle = find(&st.sites, id)?.active.other();
        let site = find_mut(&mut st.sites, id)?;
        match idle {
            Slot::Blue => site.blue.targets = req.targets.clone(),
            Slot::Green => site.green.targets = req.targets.clone(),
        }
        site.active = idle;
        let note = req.note.clone().unwrap_or_default();
        self.record(&mut st, id, idle, DeployAction::Promote, &note)
    }

    pub fn switch(&self, id: &str, slot: Slot) -> Res<Deployment> {
        let mut st = self.st();
        find_mut(&mut st.sites, id)?.active = slot;
        self.record(&mut st, id, slot, DeployAction::Switch, "Manual switch")
    }

    pub fn rollback(&self, id: &str) -> Res<Deployment> {
        let mut st = self.st();
        let site = find_mut(&mut st.sites, id)?;
        let back = site.active.other();
        site.active = back;
        self.record(&mut st, id, back, DeployAction::Rollback, "Rolled back")
    }

    pub fn maintenance(&self, id: &str, enabled: bool, page_id: Option<&str>) -> Res<Site> {
        let mut st = self.st();
        let site = find_mut(&mut st.sites, id)?;
        site.maintenance = Maintenance {
            enabled,
            page_id: page_id.map(str::to_string),
        };
        Ok(site.clone())
    }

    pub fn list_pages(&self) -> Res<Vec<MaintenancePage>> {
        Ok(self.st().pages.clone())
    }

    pub fn create_page(&self, page: &MaintenancePage) -> Res<MaintenancePage> {
        let mut st = self.st();
        if st.pages.iter().any(|p| p.id == page.id) {
            return Err(status_err(409, format!("page {} already exists", page.id)));
        }
        st.pages.push(page.clone());
        Ok(page.clone())
    }

    pub fn update_page(&self, id: &str, page: &MaintenancePage) -> Res<MaintenancePage> {
        let mut st = self.st();
        match st.pages.iter_mut().find(|p| p.id == id) {
            Some(slot) => {
                *slot = page.clone();
                Ok(page.clone())
            }
            None => Err(status_err(404, format!("page {id} not found"))),
        }
    }

    pub fn delete_page(&self, id: &str) -> Res<()> {
        let mut st = self.st();
        if st
            .sites
            .iter()
            .any(|s| s.maintenance.page_id.as_deref() == Some(id))
        {
            return Err(status_err(409, "page is in use by a site"));
        }
        st.pages.retain(|p| p.id != id);
        Ok(())
    }

    pub fn list_rules(&self) -> Res<Vec<FirewallRule>> {
        Ok(self.st().rules.clone())
    }

    pub fn create_rule(&self, rule: &FirewallRule) -> Res<FirewallRule> {
        self.st().rules.push(rule.clone());
        Ok(rule.clone())
    }

    pub fn update_rule(&self, id: &str, rule: &FirewallRule) -> Res<FirewallRule> {
        let mut st = self.st();
        match st.rules.iter_mut().find(|r| r.id == id) {
            Some(slot) => {
                *slot = rule.clone();
                Ok(rule.clone())
            }
            None => Err(status_err(404, format!("rule {id} not found"))),
        }
    }

    pub fn delete_rule(&self, id: &str) -> Res<()> {
        self.st().rules.retain(|r| r.id != id);
        Ok(())
    }

    pub fn list_presets(&self) -> Res<Vec<PresetInfo>> {
        Ok(presets()
            .into_iter()
            .map(|p| PresetInfo {
                name: p.name.into(),
                title: p.title.into(),
                description: p.description.into(),
                rules: p.rules,
            })
            .collect())
    }

    pub fn apply_preset(&self, name: &str) -> Res<Vec<FirewallRule>> {
        let preset = cite_edge::presets::preset(name)
            .ok_or_else(|| status_err(404, format!("preset {name} not found")))?;
        let mut st = self.st();
        let fresh: Vec<FirewallRule> = preset
            .rules
            .into_iter()
            .filter(|r| !st.rules.iter().any(|e| e.id == r.id))
            .collect();
        st.rules.extend(fresh.clone());
        Ok(fresh)
    }

    pub fn summary(&self, window: &str) -> Res<Summary> {
        Ok(demo_summary(self.seed(), self.scale(), window, now_ms()))
    }

    pub fn series(&self, window: &str) -> Res<Timeseries> {
        Ok(demo_series(self.seed(), self.scale(), window, now_ms()))
    }

    pub fn requests(&self, site: Option<&str>, filter: &RequestQuery) -> Res<Vec<LogEvent>> {
        let mut events = demo_events(self.seed(), now_ms(), 60);
        events.retain(|e| {
            site.is_none_or(|s| e.site == s) && filter.status.is_none_or(|s| e.status == s)
        });
        events.truncate(filter.limit.unwrap_or(60));
        Ok(events)
    }

    pub fn bots(&self, window: &str) -> Res<BotSummary> {
        Ok(demo_bot_summary(
            self.seed(),
            self.scale(),
            window,
            now_ms(),
        ))
    }

    pub fn top(&self, kind: &str, window: &str, limit: Option<usize>) -> Res<Vec<TopItem>> {
        let mut items = demo_top(kind, self.seed(), self.scale(), window, now_ms());
        items.truncate(limit.unwrap_or(items.len()));
        Ok(items)
    }

    // The second node plays an older release so the missing-endpoint path is visible in screenshots.
    pub fn stats(&self) -> Res<AnalyticsStats> {
        if self.index != 0 {
            return Err(status_err(404, "not found"));
        }
        let st = self.st();
        Ok(AnalyticsStats {
            rows: st.rows,
            db_bytes: DEMO_DB_BYTES,
            oldest_ts_ms: Some(st.oldest_ms),
            newest_ts_ms: Some(now_ms()),
            write_batches: 48_211,
            write_errors: 0,
        })
    }

    fn require_archives(&self) -> Res<()> {
        if self.index == 0 {
            Ok(())
        } else {
            Err(status_err(404, "not found"))
        }
    }

    pub fn archives(&self) -> Res<ArchiveList> {
        self.require_archives()?;
        let mut items = self.st().archives.clone();
        items.sort_by_key(|e| std::cmp::Reverse(e.created_ms));
        let dir_bytes = items.iter().map(|e| e.bytes).sum();
        Ok(ArchiveList { items, dir_bytes })
    }

    pub fn backup(&self) -> Res<ArchiveEntry> {
        self.require_archives()?;
        let now = now_ms();
        let mut st = self.st();
        st.counter += 1;
        let entry = ArchiveEntry {
            name: format!("cite-backup-{}-{}.db", file_stamp(now), st.counter),
            kind: ArchiveKind::Backup,
            bytes: DEMO_DB_BYTES,
            created_ms: now,
            sha256: demo_sha(now as u64 ^ st.counter),
            rows: None,
            from_ms: None,
            to_ms: None,
        };
        st.archives.push(entry.clone());
        Ok(entry)
    }

    pub fn cut(&self, spec: &CutSpec, dry_run: bool) -> Res<CutReport> {
        self.require_archives()?;
        let now = now_ms();
        let cutoff = spec.cutoff_ms(now);
        let mut st = self.st();
        let oldest = st.oldest_ms;
        let rows = demo_rows_before(st.rows, oldest, now, cutoff);
        let mut report = CutReport {
            dry_run,
            cutoff_ms: cutoff,
            rows,
            oldest_ms: (rows > 0).then_some(oldest),
            archived_rows: 0,
            files: Vec::new(),
            archive: spec.archive,
        };
        if dry_run || rows == 0 {
            return Ok(report);
        }
        if spec.archive {
            let name = format!(
                "cite-archive-{}-{}.ndjson.gz",
                &file_stamp(oldest)[..8],
                &file_stamp(cutoff)[..8]
            );
            st.counter += 1;
            let entry = ArchiveEntry {
                name: name.clone(),
                kind: ArchiveKind::Archive,
                bytes: rows * 30,
                created_ms: now,
                sha256: demo_sha(cutoff as u64 ^ st.counter),
                rows: Some(rows),
                from_ms: Some(oldest),
                to_ms: Some(cutoff),
            };
            st.archives.push(entry);
            report.archived_rows = rows;
            report.files.push(name);
        }
        st.rows -= rows;
        st.oldest_ms = cutoff;
        Ok(report)
    }

    pub fn restore(&self, name: &str) -> Res<RestoreReport> {
        self.require_archives()?;
        let mut st = self.st();
        let Some(entry) = st.archives.iter().find(|e| e.name == name).cloned() else {
            return Err(status_err(400, "no such archive"));
        };
        if entry.kind == ArchiveKind::Backup {
            return Ok(RestoreReport { rows: st.rows });
        }
        let rows = entry.rows.unwrap_or(0);
        st.rows += rows;
        if let Some(from) = entry.from_ms {
            st.oldest_ms = st.oldest_ms.min(from);
        }
        Ok(RestoreReport { rows })
    }

    pub fn delete_archive(&self, name: &str) -> Res<()> {
        self.require_archives()?;
        let mut st = self.st();
        let before = st.archives.len();
        st.archives.retain(|e| e.name != name);
        if st.archives.len() == before {
            return Err(status_err(400, "no such archive"));
        }
        Ok(())
    }

    pub fn archive_body(&self, name: &str) -> Res<String> {
        self.require_archives()?;
        if !self.st().archives.iter().any(|e| e.name == name) {
            return Err(status_err(400, "no such archive"));
        }
        Ok(format!("demo file for {name}\n"))
    }

    pub fn export_body(&self, pairs: &[(&'static str, String)]) -> String {
        demo_export_body(pairs, self.seed(), self.scale())
    }

    pub fn get_settings(&self) -> Res<EdgeSettings> {
        Ok(self.st().settings.clone())
    }

    pub fn put_settings(&self, settings: &EdgeSettings) -> Res<EdgeSettings> {
        self.st().settings = settings.clone();
        Ok(settings.clone())
    }

    pub fn list_tokens(&self) -> Res<Vec<TokenMeta>> {
        Ok(self.st().tokens.clone())
    }

    pub fn create_token(&self, name: &str) -> Res<CreatedToken> {
        let mut st = self.st();
        st.counter += 1;
        let id = format!("t-new-{}", st.counter);
        st.tokens.push(TokenMeta {
            id: id.clone(),
            name: name.into(),
            created_at: iso(now_ms()),
            last_used_at: None,
        });
        Ok(CreatedToken {
            id,
            name: name.into(),
            token: format!("cite_demo_{}", st.counter),
        })
    }

    pub fn delete_token(&self, id: &str) -> Res<()> {
        self.st().tokens.retain(|t| t.id != id);
        Ok(())
    }
}

fn find<'a>(sites: &'a [Site], id: &str) -> Res<&'a Site> {
    sites
        .iter()
        .find(|s| s.id == id)
        .ok_or_else(|| status_err(404, format!("site {id} not found")))
}

fn find_mut<'a>(sites: &'a mut [Site], id: &str) -> Res<&'a mut Site> {
    sites
        .iter_mut()
        .find(|s| s.id == id)
        .ok_or_else(|| status_err(404, format!("site {id} not found")))
}

pub fn demo_config() -> DesktopConfig {
    let node = |name: &str, url: &str| DesktopNode {
        name: name.into(),
        url: url.into(),
        ca_pem: None,
        insecure_http: false,
    };
    DesktopConfig {
        version: crate::config::CONFIG_VERSION,
        nodes: vec![
            node("edge-fra", "https://fra.edge.example.com:7443"),
            node("edge-iad", "https://iad.edge.example.com:7443"),
        ],
    }
}

// Each demo node keeps its own mutable state so switches and edits persist while the app runs.
pub fn demo_nodes() -> Vec<(String, std::sync::Arc<DemoNode>)> {
    demo_config()
        .nodes
        .iter()
        .enumerate()
        .map(|(i, n)| {
            (
                n.name.clone(),
                std::sync::Arc::new(DemoNode::new(&n.name, i as i64)),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cite_edge::validate::{validate_rule, validate_site};

    #[test]
    fn dataset_matches_the_brief() {
        let nodes = demo_nodes();
        assert_eq!(nodes.len(), 2);
        let node = &nodes[0].1;
        assert_eq!(node.list_sites().expect("sites").len(), 3);
        assert!(node.list_rules().expect("rules").len() >= 5);
        assert_eq!(node.list_pages().expect("pages").len(), 2);
        assert!(!node.list_presets().expect("presets").is_empty());
    }

    #[test]
    fn seeded_sites_and_rules_pass_connector_validation() {
        let node = &demo_nodes()[1].1;
        for site in node.list_sites().expect("sites") {
            validate_site(&site).unwrap_or_else(|e| panic!("{}: {e}", site.id));
        }
        for rule in node.list_rules().expect("rules") {
            validate_rule(&rule).unwrap_or_else(|e| panic!("{}: {e}", rule.id));
        }
    }

    #[test]
    fn summary_is_consistent_with_series() {
        let now = 1_700_000_000_000;
        for window in ["15m", "1h", "24h", "7d", "30d"] {
            let series = demo_series(1, 1.0, window, now);
            let summary = demo_summary(1, 1.0, window, now);
            let total: u64 = series.points.iter().map(|p| p.requests).sum();
            assert_eq!(summary.requests, total, "{window}");
            assert!(summary.requests > 0, "{window}");
            assert!(summary.errors_4xx + summary.errors_5xx < summary.requests);
            let classes: u64 = summary.status.values().sum();
            assert!(classes <= summary.requests);
        }
    }

    #[test]
    fn series_points_are_ordered_and_end_now() {
        let now = 1_700_000_000_000;
        let s = demo_series(3, 1.0, "1h", now);
        assert!(s.points.windows(2).all(|w| w[0].ts < w[1].ts));
        assert_eq!(s.points.last().map(|p| p.ts), Some(now / 1000));
    }

    #[test]
    fn events_are_newest_first_and_deterministic() {
        let a = demo_events(5, 9_000_000, 20);
        assert_eq!(a, demo_events(5, 9_000_000, 20));
        assert!(a.windows(2).all(|w| w[0].ts_ms >= w[1].ts_ms));
    }

    #[test]
    fn events_carry_bot_verdicts_and_headers() {
        let events = demo_events(5, 9_000_000, 120);
        let class = |c: &str| events.iter().filter(|e| e.bot_class == c).count();
        assert!(events.iter().all(|e| !e.bot_class.is_empty()));
        for c in ["human", "tool", "crawler", "bot"] {
            assert!(class(c) > 0, "{c}");
        }
        let human = events
            .iter()
            .find(|e| e.bot_class == "human")
            .expect("human");
        assert!(human.bot_score < 20 && !human.accept_language.is_empty());
        let tool = events.iter().find(|e| e.bot_class == "tool").expect("tool");
        assert!(tool.bot_signals.contains("ua_curl") && tool.accept_language.is_empty());
    }

    #[test]
    fn bot_summary_adds_up() {
        let s = demo_bot_summary(1, 1.0, "24h", 1_700_000_000_000);
        assert!(s.total_requests > 0 && s.bot_requests < s.total_requests);
        let classes: u64 = s.classes.iter().map(|c| c.count).sum();
        assert!(classes <= s.total_requests);
        assert!(
            (s.bot_share_pct - s.bot_requests as f64 * 100.0 / s.total_requests as f64).abs()
                < 1e-9
        );
        assert_eq!(s.score_buckets.len(), 5);
        assert!(!s.signals.is_empty() && !s.agents.is_empty());
    }

    #[test]
    fn every_top_kind_has_demo_rows() {
        for kind in cite_client::TOP_KINDS {
            let rows = demo_top(kind, 1, 1.0, "24h", 1_700_000_000_000);
            assert!(!rows.is_empty(), "{kind}");
        }
    }

    #[test]
    fn older_demo_node_has_no_storage_stats() {
        let nodes = demo_nodes();
        assert!(nodes[0].1.stats().expect("stats").rows > 0);
        let err = nodes[1].1.stats().expect_err("old node");
        assert_eq!(err.status_code(), Some(404));
    }

    #[test]
    fn older_demo_node_has_no_archive_routes() {
        let nodes = demo_nodes();
        let old = &nodes[1].1;
        assert_eq!(old.archives().expect_err("old").status_code(), Some(404));
        assert_eq!(old.backup().expect_err("old").status_code(), Some(404));
    }

    #[test]
    fn demo_rows_before_scales_with_the_cutoff() {
        assert_eq!(demo_rows_before(1000, 100, 200, 100), 0);
        assert_eq!(demo_rows_before(1000, 100, 200, 150), 500);
        assert_eq!(demo_rows_before(1000, 100, 200, 900), 1000);
        assert_eq!(demo_rows_before(1000, 200, 200, 300), 0);
    }

    #[test]
    fn demo_archives_back_up_cut_restore_and_delete() {
        let nodes = demo_nodes();
        let node = &nodes[0].1;
        let start = node.archives().expect("list").items.len();
        let backup = node.backup().expect("backup");
        assert_eq!(backup.kind, ArchiveKind::Backup);
        assert_eq!(node.archives().expect("list").items.len(), start + 1);

        let spec = CutSpec {
            cutoff: crate::archive::Cutoff::Days(10),
            archive: true,
        };
        let rows_before = node.stats().expect("stats").rows;
        let preview = node.cut(&spec, true).expect("preview");
        assert!(preview.dry_run && preview.rows > 0 && preview.files.is_empty());
        assert_eq!(node.stats().expect("stats").rows, rows_before);

        let done = node.cut(&spec, false).expect("cut");
        assert_eq!(done.rows, done.archived_rows);
        assert_eq!(done.files.len(), 1);
        assert_eq!(node.stats().expect("stats").rows, rows_before - done.rows);

        let restored = node.restore(&done.files[0]).expect("restore");
        assert_eq!(restored.rows, done.rows);
        assert_eq!(node.stats().expect("stats").rows, rows_before);

        node.delete_archive(&done.files[0]).expect("delete");
        assert!(node.delete_archive(&done.files[0]).is_err());
        assert!(node.archive_body(&done.files[0]).is_err());
    }

    #[test]
    fn a_demo_cut_without_archiving_keeps_no_file() {
        let nodes = demo_nodes();
        let node = &nodes[0].1;
        let start = node.archives().expect("list").items.len();
        let spec = CutSpec {
            cutoff: crate::archive::Cutoff::Days(5),
            archive: false,
        };
        let done = node.cut(&spec, false).expect("cut");
        assert!(done.rows > 0 && done.files.is_empty() && done.archived_rows == 0);
        assert_eq!(node.archives().expect("list").items.len(), start);
    }

    #[test]
    fn export_bodies_follow_the_requested_format() {
        let csv = demo_export_body(
            &[("kind", "requests".into()), ("limit", "3".into())],
            1,
            1.0,
        );
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(lines[0].starts_with("ts_ms,client_ip"));
        let nd = demo_export_body(
            &[
                ("kind", "top".into()),
                ("top", "paths".into()),
                ("format", "ndjson".into()),
            ],
            1,
            1.0,
        );
        let first: Value = serde_json::from_str(nd.lines().next().expect("line")).expect("json");
        assert!(first["key"].is_string() && first["requests"].is_u64());
        assert_eq!(
            demo_export_name(&[
                ("kind", "top".into()),
                ("top", "agents".into()),
                ("format", "ndjson".into())
            ]),
            "cite-top-agents.ndjson"
        );
    }

    #[test]
    fn mutations_are_visible_afterwards() {
        let node = &demo_nodes()[0].1;
        let before = node.get_site("shop").expect("site").site.active;
        node.switch("shop", before.other()).expect("switch");
        assert_eq!(
            node.get_site("shop").expect("site").site.active,
            before.other()
        );
        node.rollback("shop").expect("rollback");
        assert_eq!(node.get_site("shop").expect("site").site.active, before);
        node.maintenance("shop", true, Some("incident"))
            .expect("maintenance");
        assert!(
            node.get_site("shop")
                .expect("site")
                .site
                .maintenance
                .enabled
        );
        assert!(node.get_site("nope").is_err());
    }

    #[test]
    fn pages_in_use_cannot_be_deleted_and_presets_apply_once() {
        let node = &demo_nodes()[0].1;
        assert!(node.delete_page("scheduled").is_err());
        let name = node.list_presets().expect("presets")[0].name.clone();
        let first = node.apply_preset(&name).expect("apply");
        assert!(!first.is_empty());
        assert!(node.apply_preset(&name).expect("again").is_empty());
    }

    #[test]
    fn iso_round_trips_through_the_model_parser() {
        let ms = 1_700_000_123_000;
        assert_eq!(crate::model::parse_rfc3339_ms(&iso(ms)), Some(ms));
    }
}
