use std::cmp::Reverse;
use std::collections::BTreeMap;

use cite_edge::analytics::RequestFilter;
use cite_edge::model::LogEvent;
use tempfile::TempDir;

use crate::analytics::{self, Cursor, FacetValue, PageRequest};
use crate::filter::{AnalyticsFilter, IpMatch, ParseOpts};
use crate::queries::{Source, Window};
use crate::{Error, SortBy, Store, StoreOptions, TopKind};

// aligned to an hour boundary so bucket indexes are easy to reason about
const NOW: i64 = 1_730_721_600_000;
const HOUR: i64 = 3_600_000;
const DAY: i64 = 86_400_000;

const SITES: [&str; 3] = ["a", "b", "c"];
const HOSTS: [&str; 3] = ["h0.test", "h1.test", "h2.test"];
const METHODS: [&str; 5] = ["GET", "POST", "get", "DELETE", "HEAD"];
const PATHS: [&str; 6] = [
    "/",
    "/api/v1/users",
    "/api/v2/items",
    "/img/a_b.png",
    "/100%/x",
    "/Api/case",
];
const STATUSES: [u16; 7] = [200, 201, 301, 404, 500, 503, 403];
const CLASSES: [&str; 5] = ["human", "crawler", "tool", "suspect", "bot"];
const AGENTS: [&str; 5] = [
    "curl/8.1.2",
    "Mozilla/5.0 (X11; Linux)",
    "python-requests/2.31",
    "100%_sure-bot",
    "Googlebot/2.1",
];
const REFERERS: [&str; 3] = [
    "https://example.com/a",
    "https://other.test/_x",
    "https://Example.com/B",
];
const CTYPES: [&str; 4] = [
    "text/html; charset=utf-8",
    "application/json",
    "image/png",
    "TEXT/plain",
];
const IPS: [&str; 8] = [
    "10.0.0.1",
    "10.0.0.2",
    "10.1.0.5",
    "10.1.2.3",
    "192.168.1.9",
    "203.0.113.7",
    "2001:db8::1",
    "2001:db8:1::2",
];

fn open() -> (TempDir, Store) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(&dir.path().join("events.db"), StoreOptions::default()).expect("open");
    (dir, store)
}

fn xorshift(seed: u64) -> impl FnMut() -> u64 {
    let mut state = seed;
    move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    }
}

fn n(count: usize) -> u64 {
    u64::try_from(count).expect("count")
}

// bytes_in carries the event number, so an event can be told apart from every other.
fn event(i: u64, ts: i64, r: u64) -> LogEvent {
    let pick =
        |shift: u32, len: usize| usize::try_from((r >> shift) & 0xFFFF).expect("small") % len;
    LogEvent {
        ts_ms: ts,
        site: SITES[pick(0, SITES.len())].into(),
        host: HOSTS[pick(8, HOSTS.len())].into(),
        method: METHODS[pick(16, METHODS.len())].into(),
        path: PATHS[pick(24, PATHS.len())].into(),
        status: STATUSES[pick(32, STATUSES.len())],
        bot_class: CLASSES[pick(40, CLASSES.len())].into(),
        user_agent: AGENTS[pick(4, AGENTS.len())].into(),
        referer: REFERERS[pick(12, REFERERS.len())].into(),
        content_type: CTYPES[pick(20, CTYPES.len())].into(),
        client_ip: IPS[pick(28, IPS.len())].into(),
        bytes_in: i,
        bytes_out: (r >> 20) % 10_000,
        total_ms: u32::try_from((r >> 36) % 500).expect("ms"),
        bot_score: u8::try_from((r >> 44) % 101).expect("score"),
        blocked: match (r >> 56) % 6 {
            0 => Some("rule-1".into()),
            1 => Some("rule-2".into()),
            _ => None,
        },
        backend: "be_s_blue".into(),
        server: "app1".into(),
        ..LogEvent::default()
    }
}

// Newest event first, one every step_ms, so timestamps are unique and the newest is just below NOW.
fn seed_span(count: u64, step_ms: i64) -> Vec<LogEvent> {
    let mut next = xorshift(0x9E37_79B9_7F4A_7C15);
    (0..count)
        .map(|i| {
            let back = i64::try_from(i).expect("index") * step_ms;
            event(i, NOW - 1000 - back, next())
        })
        .collect()
}

// Oldest first in batches of 50, which keeps short batches on the minute rollups.
fn insert_batches(s: &Store, mut evs: Vec<LogEvent>) {
    evs.sort_by_key(|e| e.ts_ms);
    for chunk in evs.chunks(50) {
        s.insert(chunk).expect("insert");
    }
}

fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
    items
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn filter(items: &[(&str, &str)]) -> AnalyticsFilter {
    AnalyticsFilter::parse(&pairs(items), ParseOpts::default()).expect("filter")
}

fn legacy(items: &[(&str, &str)]) -> AnalyticsFilter {
    let opts = ParseOpts {
        extras: &["limit"],
        requests: true,
    };
    AnalyticsFilter::parse(&pairs(items), opts).expect("legacy filter")
}

fn page(limit: usize) -> PageRequest {
    PageRequest {
        limit,
        offset: 0,
        before: None,
    }
}

fn ci_contains(hay: &str, needle: &str) -> bool {
    hay.to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

fn grouped(evs: &[&LogEvent], key: impl Fn(&LogEvent) -> String) -> Vec<FacetValue> {
    let mut m: BTreeMap<String, u64> = BTreeMap::new();
    for e in evs {
        *m.entry(key(e)).or_default() += 1;
    }
    let mut out: Vec<FacetValue> = m
        .into_iter()
        .map(|(key, count)| FacetValue { key, count })
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
    out
}

// Runs the filter through every endpoint over events that all lie inside the last 24 hours and compares each with a count taken straight from the events.
fn check(s: &Store, evs: &[LogEvent], items: &[(&str, &str)], pred: impl Fn(&LogEvent) -> bool) {
    let mut q = vec![("window", "24h")];
    q.extend_from_slice(items);
    let f = filter(&q);
    let want = n(evs.iter().filter(|e| pred(e)).count());
    let ctx = format!("{items:?}");

    let summary = s.analytics_summary(&f, NOW).expect("summary");
    assert_eq!(summary.data.requests, want, "summary {ctx}");
    // one site alone is still answered from the rollups
    assert!(matches!(summary.source, "raw" | "rollup_hour"), "{ctx}");
    assert!(!summary.partial, "{ctx}");
    assert_eq!(summary.filters, f, "echo {ctx}");

    let listed = s
        .analytics_requests(&f, &page(1000), NOW)
        .expect("requests");
    assert_eq!(n(listed.items.len()), want, "requests {ctx}");
    assert!(listed.items.iter().all(&pred), "requests match {ctx}");
    assert!(listed.next_cursor.is_none() && !listed.partial, "{ctx}");

    let series = s.analytics_timeseries(&f, NOW).expect("timeseries");
    let total: u64 = series.data.points.iter().map(|p| p.requests).sum();
    assert_eq!(total, want, "timeseries {ctx}");

    let bots = s.analytics_bots(&f, NOW).expect("bots");
    assert_eq!(bots.data.total_requests, want, "bots {ctx}");

    let facets = s.analytics_facets(&f, NOW).expect("facets");
    let hosts: u64 = facets.data.host.iter().map(|v| v.count).sum();
    assert_eq!(hosts, want, "facets {ctx}");

    let top = s
        .analytics_top(&f, TopKind::Paths, 1000, SortBy::Count, NOW)
        .expect("top");
    let counted: u64 = top.data.items.iter().map(|i| i.count).sum();
    assert_eq!(counted, want, "top {ctx}");
}

#[test]
fn every_filter_selects_exactly_the_matching_rows_on_every_endpoint() {
    let (_d, s) = open();
    let evs = seed_span(600, 7_000);
    insert_batches(&s, evs.clone());
    assert!(evs.iter().any(|e| e.blocked.is_some()) && evs.iter().any(|e| e.blocked.is_none()));

    check(&s, &evs, &[("site", "a")], |e| e.site == "a");
    check(&s, &evs, &[("site", "a,c")], |e| e.site != "b");
    check(&s, &evs, &[("site", "a"), ("site", "b")], |e| e.site != "c");
    check(&s, &evs, &[("site", "ghost")], |_| false);
    check(&s, &evs, &[("site", "ghost,a")], |e| e.site == "a");
    check(&s, &evs, &[("host", "h1.test")], |e| e.host == "h1.test");
    check(&s, &evs, &[("path_prefix", "/api")], |e| {
        e.path.starts_with("/api")
    });
    check(&s, &evs, &[("path_prefix", "/")], |_| true);
    check(&s, &evs, &[("path_exact", "/api/v1/users")], |e| {
        e.path == "/api/v1/users"
    });
    check(&s, &evs, &[("method", "get")], |e| {
        e.method.eq_ignore_ascii_case("GET")
    });
    check(&s, &evs, &[("method", "post,head")], |e| {
        e.method.eq_ignore_ascii_case("post") || e.method.eq_ignore_ascii_case("head")
    });
    check(&s, &evs, &[("status", "404")], |e| e.status == 404);
    check(
        &s,
        &evs,
        &[("status_min", "400"), ("status_max", "499")],
        |e| (400..=499).contains(&e.status),
    );
    check(&s, &evs, &[("status_class", "5xx")], |e| {
        e.status / 100 == 5
    });
    check(&s, &evs, &[("status_class", "2xx,3xx")], |e| {
        (2..=3).contains(&(e.status / 100))
    });
    check(&s, &evs, &[("status_class", "1xx,2xx,3xx,4xx,5xx")], |_| {
        true
    });
    check(&s, &evs, &[("blocked", "true")], |e| e.blocked.is_some());
    check(&s, &evs, &[("blocked", "unblocked")], |e| {
        e.blocked.is_none()
    });
    check(&s, &evs, &[("blocked", "rule:rule-1")], |e| {
        e.blocked.as_deref() == Some("rule-1")
    });
    check(&s, &evs, &[("bot_class", "crawler")], |e| {
        e.bot_class == "crawler"
    });
    check(&s, &evs, &[("bot_class", "tool,bot")], |e| {
        matches!(e.bot_class.as_str(), "tool" | "bot")
    });
    check(&s, &evs, &[("min_bot_score", "50")], |e| e.bot_score >= 50);
    check(&s, &evs, &[("max_bot_score", "20")], |e| e.bot_score <= 20);
    check(
        &s,
        &evs,
        &[("min_bot_score", "30"), ("max_bot_score", "60")],
        |e| (30..=60).contains(&e.bot_score),
    );
    check(&s, &evs, &[("min_duration_ms", "250")], |e| {
        e.total_ms >= 250
    });
    check(&s, &evs, &[("content_type", "text/")], |e| {
        e.content_type.to_ascii_lowercase().starts_with("text/")
    });
    check(&s, &evs, &[("content_type", "APPLICATION/json")], |e| {
        e.content_type == "application/json"
    });
}

#[test]
fn client_ip_filters_match_addresses_and_networks_per_family() {
    let (_d, s) = open();
    let evs = seed_span(600, 7_000);
    insert_batches(&s, evs.clone());
    for cidr in [
        "10.1.2.3",
        "2001:0db8:0000:0000:0000:0000:0000:0001",
        "10.0.0.0/16",
        "10.0.0.77/8",
        "10.1.2.3/32",
        "192.168.0.0/16",
        "0.0.0.0/0",
        "::/0",
        "2001:db8::/32",
        "2001:db8:1::/48",
        "203.0.113.0/24",
    ] {
        let net = IpMatch::parse(cidr).expect("network");
        check(&s, &evs, &[("client_ip", cidr)], |e| {
            net.contains(e.client_ip.parse().expect("stored address"))
        });
    }
    // expectations that do not go through the matcher under test
    check(&s, &evs, &[("client_ip", "10.0.0.0/16")], |e| {
        e.client_ip.starts_with("10.0.")
    });
    check(&s, &evs, &[("client_ip", "10.1.2.3")], |e| {
        e.client_ip == "10.1.2.3"
    });
    check(&s, &evs, &[("client_ip", "2001:db8::/32")], |e| {
        e.client_ip.starts_with("2001:db8:")
    });
}

#[test]
fn text_filters_are_case_insensitive_literal_substrings() {
    let (_d, s) = open();
    let evs = seed_span(600, 7_000);
    insert_batches(&s, evs.clone());
    for needle in ["CURL", "x11", "%_s", "%%%", "_ur", "bot", "100%", "2.31"] {
        check(&s, &evs, &[("user_agent", needle)], |e| {
            ci_contains(&e.user_agent, needle)
        });
    }
    for needle in ["example.com", "/_x", "OTHER", "%%%", "m/B"] {
        check(&s, &evs, &[("referer", needle)], |e| {
            ci_contains(&e.referer, needle)
        });
    }
    // an unescaped wildcard would have matched every row
    let none = s
        .analytics_summary(&filter(&[("window", "24h"), ("user_agent", "%%%")]), NOW)
        .expect("summary");
    assert_eq!(none.data.requests, 0);
}

#[test]
fn filters_combine_with_and() {
    let (_d, s) = open();
    let evs = seed_span(600, 7_000);
    insert_batches(&s, evs.clone());
    check(
        &s,
        &evs,
        &[
            ("site", "a,b"),
            ("host", "h0.test"),
            ("status_class", "4xx,5xx"),
            ("method", "get,post"),
            ("blocked", "unblocked"),
            ("min_bot_score", "10"),
        ],
        |e| {
            e.site != "c"
                && e.host == "h0.test"
                && e.status / 100 >= 4
                && matches!(e.method.as_str(), "get" | "GET" | "POST")
                && e.blocked.is_none()
                && e.bot_score >= 10
        },
    );
    check(
        &s,
        &evs,
        &[
            ("client_ip", "10.0.0.0/8"),
            ("user_agent", "bot"),
            ("content_type", "text"),
            ("path_prefix", "/"),
        ],
        |e| {
            e.client_ip.starts_with("10.")
                && ci_contains(&e.user_agent, "bot")
                && e.content_type.to_ascii_lowercase().starts_with("text")
        },
    );
}

#[test]
fn hostile_values_are_plain_data() {
    let (_d, s) = open();
    let evs = seed_span(300, 7_000);
    insert_batches(&s, evs.clone());
    for (key, value) in [
        ("host", "' OR 1=1 --"),
        ("host", "h0.test' OR '1'='1"),
        ("path_exact", "/' OR '1'='1"),
        ("path_prefix", "%"),
        ("path_prefix", "/100%"),
        ("user_agent", "'; DROP TABLE requests; --"),
        ("referer", "\\\\\\"),
        ("content_type", "text/%"),
    ] {
        check(&s, &evs, &[(key, value)], |e| {
            key == "path_prefix" && value == "/100%" && e.path.starts_with("/100%")
        });
    }
    let all = s
        .analytics_summary(&filter(&[("window", "24h")]), NOW)
        .expect("summary");
    assert_eq!(all.data.requests, 300);
}

#[test]
fn rollup_answers_equal_raw_answers_for_the_same_window() {
    let (_d, s) = open();
    insert_batches(&s, seed_span(600, 400_000));
    for (window, secs) in [("24h", 86_400u64), ("7d", 7 * 86_400)] {
        for site in [None, Some("a"), Some("b")] {
            let mut q = vec![("window", window)];
            if let Some(site) = site {
                q.push(("site", site));
            }
            let rolled = s.analytics_summary(&filter(&q), NOW).expect("rollup");
            assert_eq!(rolled.source, "rollup_hour", "{window} {site:?}");
            q.push(("min_bot_score", "0"));
            let raw = s.analytics_summary(&filter(&q), NOW).expect("raw");
            assert_eq!(raw.source, "raw");
            assert!(rolled.data.requests > 0);
            assert_eq!(rolled.data, raw.data, "{window} {site:?}");
            assert_eq!(
                (rolled.from_ms, rolled.to_ms),
                (NOW - secs as i64 * 1000, NOW + HOUR),
                "{window}"
            );
            assert_eq!(rolled.data, s.summary(secs, site, NOW).expect("old"));

            let rb = s
                .analytics_bots(&filter(&q[..q.len() - 1]), NOW)
                .expect("bots");
            let wb = s.analytics_bots(&filter(&q), NOW).expect("raw bots");
            assert_eq!(rb.data.total_requests, wb.data.total_requests);
            assert_eq!(rb.data.bot_requests, wb.data.bot_requests);
            assert_eq!(rb.data.classes, wb.data.classes);
            assert_eq!(rb.data.score_buckets, wb.data.score_buckets);

            for kind in [
                TopKind::Hosts,
                TopKind::ContentTypes,
                TopKind::StatusCodes,
                TopKind::Paths,
            ] {
                let a = s
                    .analytics_top(&filter(&q[..q.len() - 1]), kind, 20, SortBy::Count, NOW)
                    .expect("rollup top");
                let b = s
                    .analytics_top(&filter(&q), kind, 20, SortBy::Count, NOW)
                    .expect("raw top");
                assert_eq!(a.data, b.data, "{kind:?} {window} {site:?}");
            }
        }
    }
}

fn minute_served(s: &Store, secs: u64) -> bool {
    s.inner
        .read(|c| Ok(Window::pick(c, secs, NOW, false)?.source == Source::Minute))
        .expect("pick")
}

#[test]
fn minute_rollups_equal_raw_answers_for_short_windows() {
    let (_d, s) = open();
    insert_batches(&s, seed_span(300, 10_000));
    for (window, secs) in [("15m", 900u64), ("1h", 3600)] {
        assert!(minute_served(&s, secs), "{window}");
        let rolled = s
            .analytics_summary(&filter(&[("window", window)]), NOW)
            .expect("rollup");
        assert_eq!(rolled.source, "rollup_minute");
        let raw = s
            .analytics_summary(&filter(&[("window", window), ("min_bot_score", "0")]), NOW)
            .expect("raw");
        assert!(rolled.data.requests > 0);
        assert_eq!(rolled.data, raw.data, "{window}");
        assert_eq!((rolled.from_ms, rolled.to_ms), (raw.from_ms, raw.to_ms));
        let series = s
            .analytics_timeseries(&filter(&[("window", window)]), NOW)
            .expect("series");
        let raw_series = s
            .analytics_timeseries(&filter(&[("window", window), ("min_bot_score", "0")]), NOW)
            .expect("raw series");
        let sum = |t: &cite_edge::analytics::Timeseries| -> u64 {
            t.points.iter().map(|p| p.requests).sum()
        };
        assert_eq!(sum(&series.data), sum(&raw_series.data));
        assert_eq!(series.data.step_secs, 60);
    }
}

#[test]
fn old_queries_give_identical_results() {
    let (_d, s) = open();
    let mut evs = seed_span(500, 400_000);
    evs.extend(seed_span(200, 5_000));
    insert_batches(&s, evs);
    let windows = [
        ("15m", 900u64),
        ("1h", 3600),
        ("24h", 86_400),
        ("7d", 7 * 86_400),
        ("30d", 30 * 86_400),
    ];
    for (window, secs) in windows {
        for site in [None, Some("a"), Some("c"), Some("ghost")] {
            let mut q = vec![("window", window)];
            if let Some(site) = site {
                q.push(("site", site));
            }
            let f = filter(&q);
            let ctx = format!("{window} {site:?}");
            let summary = s.analytics_summary(&f, NOW).expect("summary");
            assert_eq!(
                summary.data,
                s.summary(secs, site, NOW).expect("old"),
                "{ctx}"
            );
            assert!(!summary.partial && summary.scanned.is_none(), "{ctx}");
            let series = s.analytics_timeseries(&f, NOW).expect("series");
            assert_eq!(
                series.data,
                s.timeseries(secs, site, NOW).expect("old"),
                "{ctx}"
            );
            let bots = s.analytics_bots(&f, NOW).expect("bots");
            assert_eq!(bots.data, s.bots(secs, site, NOW).expect("old"), "{ctx}");
            for kind in [
                TopKind::Paths,
                TopKind::Hosts,
                TopKind::Referers,
                TopKind::UserAgents,
                TopKind::ContentTypes,
                TopKind::StatusCodes,
                TopKind::ClientIps,
                TopKind::Languages,
            ] {
                for limit in [5usize, 20, 100] {
                    let top = s
                        .analytics_top(&f, kind, limit, SortBy::Count, NOW)
                        .expect("top");
                    let old = s.top(kind, secs, site, NOW, limit).expect("old");
                    assert_eq!(top.data.items, old, "{kind:?} {limit} {ctx}");
                }
            }
        }
    }
    // no window and no range is the one-hour default the endpoints always had
    let default = s.analytics_summary(&filter(&[]), NOW).expect("default");
    assert_eq!(default.data, s.summary(3600, None, NOW).expect("old"));
}

#[test]
fn the_request_list_matches_the_original_filters() {
    let (_d, s) = open();
    insert_batches(&s, seed_span(600, 7_000));
    let cases: Vec<(Vec<(&str, &str)>, RequestFilter)> = vec![
        (vec![], RequestFilter::default()),
        (
            vec![("status", "404")],
            RequestFilter {
                status: Some(404),
                ..RequestFilter::default()
            },
        ),
        (
            vec![("method", "GET")],
            RequestFilter {
                method: Some("GET".into()),
                ..RequestFilter::default()
            },
        ),
        (
            vec![("path", "api")],
            RequestFilter {
                path_contains: Some("api".into()),
                ..RequestFilter::default()
            },
        ),
        (
            vec![("ip", "10.0.0.1")],
            RequestFilter {
                ip: Some("10.0.0.1".into()),
                ..RequestFilter::default()
            },
        ),
        (
            vec![("blocked", "true")],
            RequestFilter {
                blocked_only: true,
                ..RequestFilter::default()
            },
        ),
        (vec![("blocked", "false")], RequestFilter::default()),
        (
            vec![("site", "b")],
            RequestFilter {
                site: Some("b".into()),
                ..RequestFilter::default()
            },
        ),
        (
            vec![
                ("site", "a"),
                ("status", "200"),
                ("method", "post"),
                ("blocked", "1"),
            ],
            RequestFilter {
                site: Some("a".into()),
                status: Some(200),
                method: Some("POST".into()),
                blocked_only: true,
                ..RequestFilter::default()
            },
        ),
    ];
    for (items, old) in cases {
        let f = legacy(&items);
        for limit in [1usize, 25, 100] {
            let want = s.requests(&old, limit).expect("old");
            let got = s
                .analytics_requests(&f, &page(limit), NOW)
                .expect("new")
                .items;
            assert_eq!(want, got, "{items:?} limit {limit}");
        }
    }
}

#[test]
fn explicit_ranges_use_rollups_only_on_whole_buckets() {
    let (_d, s) = open();
    insert_batches(&s, seed_span(600, 400_000));
    let now = NOW + 3 * HOUR;
    let from = (NOW - 2 * DAY).to_string();
    let to = NOW.to_string();

    let (from, to) = (from.as_str(), to.as_str());
    let aligned = filter(&[("from", from), ("to", to)]);
    let rolled = s.analytics_summary(&aligned, now).expect("aligned");
    assert_eq!(rolled.source, "rollup_hour");
    assert_eq!((rolled.from_ms, rolled.to_ms), (NOW - 2 * DAY, NOW));
    let forced = filter(&[("from", from), ("to", to), ("min_bot_score", "0")]);
    let raw = s.analytics_summary(&forced, now).expect("raw");
    assert_eq!(raw.source, "raw");
    assert_eq!((raw.from_ms, raw.to_ms), (NOW - 2 * DAY, NOW));
    assert!(rolled.data.requests > 0);
    assert_eq!(rolled.data, raw.data);

    let off = (NOW - 2 * DAY + 1).to_string();
    let shifted = s
        .analytics_summary(&filter(&[("from", off.as_str()), ("to", to)]), now)
        .expect("shifted");
    assert_eq!(shifted.source, "raw");
    assert_eq!(shifted.from_ms, NOW - 2 * DAY + 1);

    // an open end is the current bucket
    let open = s
        .analytics_summary(&filter(&[("from", from)]), now)
        .expect("open");
    assert_eq!(open.source, "rollup_hour");
    assert_eq!(open.to_ms, NOW + 4 * HOUR);
    assert_eq!(open.data, rolled.data);

    // the same range as RFC 3339 text
    let text = filter(&[
        ("from", "2024-11-02T12:00:00Z"),
        ("to", "2024-11-04T12:00:00+00:00"),
    ]);
    assert_eq!(text.from_ms, Some(NOW - 2 * DAY));
    assert_eq!(text.to_ms, Some(NOW));
}

#[test]
fn timeseries_on_raw_rows_picks_its_step_from_the_span() {
    for (span, step) in [
        (15 * 60_000, 60_000),
        (HOUR, 60_000),
        (6 * HOUR, 60_000),
        (6 * HOUR + 60_000, 300_000),
        (DAY, 300_000),
        (2 * DAY, 900_000),
        (7 * DAY, HOUR),
        (30 * DAY, 6 * HOUR),
        (400 * DAY, DAY),
    ] {
        assert_eq!(analytics::pick_step(span), step, "{span}");
    }
    let (_d, s) = open();
    let evs = seed_span(600, 7_000);
    insert_batches(&s, evs.clone());
    let f = filter(&[("window", "24h"), ("host", "h0.test")]);
    let series = s.analytics_timeseries(&f, NOW).expect("series");
    assert_eq!(series.data.step_secs, 300);
    assert!(series.data.points.iter().all(|p| p.ts % 300 == 0));
    assert!(series.data.points.len() <= 400);
    let want = evs
        .iter()
        .filter(|e| e.host == "h0.test")
        .collect::<Vec<_>>();
    let errors: u64 = series.data.points.iter().map(|p| p.errors).sum();
    assert_eq!(errors, n(want.iter().filter(|e| e.status >= 400).count()));
    let blocked: u64 = series.data.points.iter().map(|p| p.blocked).sum();
    assert_eq!(
        blocked,
        n(want.iter().filter(|e| e.blocked.is_some()).count())
    );
    let bytes: u64 = series.data.points.iter().map(|p| p.bytes_out).sum();
    assert_eq!(bytes, want.iter().map(|e| e.bytes_out).sum::<u64>());
}

#[test]
fn the_cursor_pages_through_ties_and_ignores_newer_rows() {
    let (_d, s) = open();
    let mut evs = seed_span(300, 7_000);
    // every third event shares its predecessor's timestamp
    for i in (1..evs.len()).step_by(3) {
        evs[i].ts_ms = evs[i - 1].ts_ms;
    }
    insert_batches(&s, evs);
    let f = filter(&[("window", "24h"), ("host", "h0.test")]);
    let full = s.analytics_requests(&f, &page(1000), NOW).expect("full");
    let keys = |items: &[LogEvent]| -> Vec<u64> { items.iter().map(|e| e.bytes_in).collect() };
    let want = keys(&full.items);
    assert!(want.len() > 50);

    let mut got = Vec::new();
    let mut cursor: Option<Cursor> = None;
    let mut rounds = 0;
    loop {
        let p = PageRequest {
            limit: 7,
            offset: 0,
            before: cursor,
        };
        let out = s.analytics_requests(&f, &p, NOW).expect("page");
        assert!(out.items.len() <= 7);
        got.extend(keys(&out.items));
        cursor = out.next_cursor;
        rounds += 1;
        if rounds == 2 {
            // rows newer than the cursor never reach a later page
            let fresh: Vec<LogEvent> = (0..5)
                .map(|i| {
                    let mut e = event(10_000 + i, NOW - 10 - i64::try_from(i).expect("i"), 7);
                    e.host = "h0.test".into();
                    e
                })
                .collect();
            s.insert(&fresh).expect("fresh");
        }
        if cursor.is_none() {
            break;
        }
        assert!(rounds < 100);
    }
    assert_eq!(got, want);
    let mut unique = got.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), got.len());
}

#[test]
fn offsets_and_limits_are_bounded() {
    let (_d, s) = open();
    insert_batches(&s, seed_span(1100, 1_000));
    let f = filter(&[("window", "24h")]);
    let all = s.analytics_requests(&f, &page(1000), NOW).expect("all");
    let base = s.analytics_requests(&f, &page(5000), NOW).expect("5000");
    assert_eq!(base.items.len(), 1000, "one page never exceeds 1000 rows");
    assert!(base.next_cursor.is_some());
    assert_eq!(all.items, base.items);

    let moved = s
        .analytics_requests(
            &f,
            &PageRequest {
                limit: 10,
                offset: 14,
                before: None,
            },
            NOW,
        )
        .expect("offset");
    assert_eq!(moved.items, all.items[14..24].to_vec());

    assert!(
        s.analytics_requests(&f, &page(0), NOW)
            .expect("zero")
            .items
            .is_empty()
    );
    let both = PageRequest {
        limit: 5,
        offset: 1,
        before: Some(Cursor {
            before_ts: NOW,
            before_id: 1,
        }),
    };
    assert!(matches!(
        s.analytics_requests(&f, &both, NOW),
        Err(Error::Rejected(_))
    ));
    let deep = PageRequest {
        limit: 5,
        offset: crate::MAX_OFFSET + 1,
        before: None,
    };
    assert!(matches!(
        s.analytics_requests(&f, &deep, NOW),
        Err(Error::Rejected(_))
    ));
}

#[test]
fn hitting_the_scan_cap_returns_the_newest_rows_and_says_so() {
    let (_d, s) = open();
    let evs = seed_span(400, 5_000);
    insert_batches(&s, evs.clone());
    let f = filter(&[("window", "24h"), ("method", "get")]);
    let mut newest_first = evs.clone();
    newest_first.sort_by_key(|e| Reverse(e.ts_ms));
    let seen: Vec<&LogEvent> = newest_first.iter().take(100).collect();
    let want = n(seen
        .iter()
        .filter(|e| e.method.eq_ignore_ascii_case("get"))
        .count());
    assert!(want > 0);

    let cut = s
        .inner
        .read(|c| analytics::summary(c, &f, NOW, 100))
        .expect("capped");
    assert!(cut.partial);
    assert_eq!(cut.scanned, Some(100));
    assert_eq!(cut.data.requests, want);
    assert_eq!(cut.from_ms, newest_first[100].ts_ms + 1);
    let json = serde_json::to_value(&cut).expect("json");
    assert_eq!(json["partial"], true);
    assert_eq!(json["scanned"], 100);
    assert_eq!(json["filters"]["method"], serde_json::json!(["GET"]));

    let whole = s
        .inner
        .read(|c| analytics::summary(c, &f, NOW, 400))
        .expect("exact fit");
    assert!(!whole.partial);
    assert_eq!(whole.scanned, Some(400));
    let tight = s
        .inner
        .read(|c| analytics::summary(c, &f, NOW, 399))
        .expect("one over");
    assert!(tight.partial);

    let series = s
        .inner
        .read(|c| analytics::timeseries(c, &f, NOW, 100))
        .expect("series");
    assert!(series.partial);
    assert_eq!(
        series.data.points.iter().map(|p| p.requests).sum::<u64>(),
        want
    );
    let bots = s
        .inner
        .read(|c| analytics::bots(c, &f, NOW, 100))
        .expect("bots");
    assert!(bots.partial && bots.data.total_requests == want);
    let top = s
        .inner
        .read(|c| analytics::top(c, &f, TopKind::Hosts, 10, SortBy::Count, NOW, 100))
        .expect("top");
    assert!(top.partial);
    assert_eq!(top.data.items.iter().map(|i| i.count).sum::<u64>(), want);
    let facets = s
        .inner
        .read(|c| analytics::facets(c, &f, NOW, 100))
        .expect("facets");
    assert!(facets.partial);
    assert_eq!(facets.data.site.iter().map(|v| v.count).sum::<u64>(), want);

    // a cursor resumes where the cap stopped, and the chunks add up to the full answer
    let all_keys: Vec<u64> = evs
        .iter()
        .filter(|e| e.method.eq_ignore_ascii_case("get"))
        .map(|e| e.bytes_in)
        .collect();
    let mut got = Vec::new();
    let mut cursor = None;
    let mut rounds = 0;
    loop {
        let p = PageRequest {
            limit: 1000,
            offset: 0,
            before: cursor,
        };
        let out = s
            .inner
            .read(|c| analytics::requests(c, &f, &p, NOW, 100))
            .expect("chunk");
        if rounds == 0 {
            assert!(out.partial && out.scanned == Some(100));
            assert_eq!(out.from_ms, Some(newest_first[100].ts_ms + 1));
        }
        got.extend(out.items.iter().map(|e| e.bytes_in));
        cursor = out.next_cursor;
        rounds += 1;
        if cursor.is_none() {
            break;
        }
        assert!(rounds < 20);
    }
    assert!(rounds >= 4);
    got.sort_unstable();
    let mut want_keys = all_keys;
    want_keys.sort_unstable();
    assert_eq!(got, want_keys);
}

#[test]
fn facets_list_values_with_counts_under_the_filter() {
    let (_d, s) = open();
    let evs = seed_span(600, 400_000);
    insert_batches(&s, evs.clone());
    let day: Vec<&LogEvent> = evs.iter().filter(|e| e.ts_ms >= NOW - DAY).collect();
    assert!(day.len() > 20);

    let check_facets = |extra: &[(&str, &str)], pool: &[&LogEvent], source: &str| {
        let mut q = vec![("window", "24h")];
        q.extend_from_slice(extra);
        let out = s.analytics_facets(&filter(&q), NOW).expect("facets");
        assert_eq!(out.source, source, "{extra:?}");
        assert_eq!(
            out.data.site,
            grouped(pool, |e| e.site.clone()),
            "site {extra:?}"
        );
        assert_eq!(
            out.data.host,
            grouped(pool, |e| e.host.clone()),
            "host {extra:?}"
        );
        assert_eq!(
            out.data.method,
            grouped(pool, |e| e.method.to_ascii_uppercase()),
            "method {extra:?}"
        );
        assert_eq!(
            out.data.status_class,
            grouped(pool, |e| format!("{}xx", e.status / 100)),
            "status {extra:?}"
        );
        assert_eq!(
            out.data.bot_class,
            grouped(pool, |e| e.bot_class.clone()),
            "bot {extra:?}"
        );
    };
    check_facets(&[], &day, "rollup_hour");
    let site_a: Vec<&LogEvent> = day.iter().copied().filter(|e| e.site == "a").collect();
    check_facets(&[("site", "a")], &site_a, "rollup_hour");
    check_facets(&[("site", "a"), ("min_bot_score", "0")], &site_a, "raw");
    check_facets(&[("min_bot_score", "0")], &day, "raw");
    let narrow: Vec<&LogEvent> = day
        .iter()
        .copied()
        .filter(|e| e.status / 100 == 5 && e.host == "h1.test")
        .collect();
    check_facets(
        &[("status_class", "5xx"), ("host", "h1.test")],
        &narrow,
        "raw",
    );
}

#[test]
fn compare_returns_the_previous_period_and_deltas() {
    let (_d, s) = open();
    let mut next = xorshift(42);
    let mut evs = Vec::new();
    for i in 0..50u64 {
        evs.push(event(
            i,
            NOW - HOUR + 1000 + i64::try_from(i).expect("i") * 60_000,
            next(),
        ));
    }
    for i in 0..30u64 {
        evs.push(event(
            100 + i,
            NOW - 2 * HOUR + 1000 + i64::try_from(i).expect("i") * 60_000,
            next(),
        ));
    }
    insert_batches(&s, evs.clone());
    let now = NOW + 3 * HOUR;
    let from = (NOW - HOUR).to_string();
    let to = NOW.to_string();
    let (from, to) = (from.as_str(), to.as_str());

    let out = s
        .analytics_compare(&filter(&[("from", from), ("to", to)]), now)
        .expect("compare");
    assert_eq!(out.against, "previous");
    assert_eq!(out.current.data.requests, 50);
    assert_eq!(out.previous.data.requests, 30);
    assert_eq!((out.current.from_ms, out.current.to_ms), (NOW - HOUR, NOW));
    assert_eq!(
        (out.previous.from_ms, out.previous.to_ms),
        (NOW - 2 * HOUR, NOW - HOUR)
    );
    let requests = &out.delta["requests"];
    assert_eq!(
        (requests.current, requests.previous, requests.abs),
        (50.0, 30.0, 20.0)
    );
    assert!((requests.pct.expect("pct") - 66.666_667).abs() < 0.001);

    // a row condition reads raw rows for both periods
    let host = filter(&[("from", from), ("to", to), ("host", "h0.test")]);
    let out = s.analytics_compare(&host, now).expect("raw compare");
    let in_range =
        |e: &&LogEvent, lo: i64, hi: i64| e.host == "h0.test" && e.ts_ms >= lo && e.ts_ms < hi;
    assert_eq!(
        out.current.data.requests,
        n(evs.iter().filter(|e| in_range(e, NOW - HOUR, NOW)).count())
    );
    assert_eq!(
        out.previous.data.requests,
        n(evs
            .iter()
            .filter(|e| in_range(e, NOW - 2 * HOUR, NOW - HOUR))
            .count())
    );
    assert_eq!(out.current.source, "raw");
    assert_eq!(out.current.filters, host);

    let zero = s
        .analytics_compare(
            &filter(&[("from", from), ("to", to), ("site", "ghost")]),
            now,
        )
        .expect("empty");
    assert!(zero.delta["requests"].pct.is_none());

    let early = filter(&[("from", "1000"), ("to", "7200000")]);
    assert!(matches!(
        s.analytics_compare(&early, now),
        Err(Error::Rejected(_))
    ));
}

#[test]
fn top_lists_can_rank_by_bytes() {
    let (_d, s) = open();
    let evs = seed_span(600, 7_000);
    insert_batches(&s, evs.clone());
    let f = filter(&[("window", "24h")]);
    let mut paths: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    for e in &evs {
        let slot = paths.entry(e.path.as_str()).or_default();
        slot.0 += 1;
        slot.1 += e.bytes_out;
    }
    let mut want: Vec<(&str, (u64, u64))> = paths.into_iter().collect();
    want.sort_by(|a, b| {
        b.1.1
            .cmp(&a.1.1)
            .then_with(|| b.1.0.cmp(&a.1.0))
            .then_with(|| a.0.cmp(b.0))
    });
    let by_bytes = s
        .analytics_top(&f, TopKind::Paths, 3, SortBy::Bytes, NOW)
        .expect("bytes");
    assert_eq!(by_bytes.source, "raw");
    let got: Vec<(&str, (u64, u64))> = by_bytes
        .data
        .items
        .iter()
        .map(|i| (i.key.as_str(), (i.count, i.bytes)))
        .collect();
    assert_eq!(got, want[..3].to_vec());
    let by_count = s
        .analytics_top(&f, TopKind::Paths, 3, SortBy::Count, NOW)
        .expect("count");
    assert_eq!(by_count.source, "rollup_hour");
    assert!(
        by_count
            .data
            .items
            .windows(2)
            .all(|w| w[0].count >= w[1].count)
    );
    assert!(
        s.analytics_top(&f, TopKind::Paths, 0, SortBy::Bytes, NOW)
            .expect("zero")
            .data
            .items
            .is_empty()
    );
    let types = s
        .analytics_top(&f, TopKind::ContentTypes, 10, SortBy::Bytes, NOW)
        .expect("types");
    assert!(
        types
            .data
            .items
            .windows(2)
            .all(|w| w[0].bytes >= w[1].bytes)
    );
}

#[test]
fn the_network_function_is_registered_on_readers_and_survives_bad_input() {
    let (_d, s) = open();
    s.insert(&[event(1, NOW - 5, 3)]).expect("insert");
    let hit = s
        .inner
        .read(|c| {
            Ok(c.query_row(
                "SELECT cite_in_cidr('10.1.2.3', '10.0.0.0/8'), cite_in_cidr('x', '10.0.0.0/8'), \
                 cite_in_cidr('10.1.2.3', 'junk'), cite_in_cidr('::1', '10.0.0.0/8')",
                [],
                |r| Ok([r.get::<_, bool>(0)?, r.get(1)?, r.get(2)?, r.get(3)?]),
            )?)
        })
        .expect("function");
    assert_eq!(hit, [true, false, false, false]);
}
