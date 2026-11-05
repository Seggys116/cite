use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use cite_edge::analytics::{Analytics, RequestFilter};
use cite_edge::model::{LogEvent, Retention};
use tempfile::TempDir;

use crate::queries::{self, Window};
use crate::util::iso_utc;
use crate::{
    Error, ExportFilter, ExportKind, REQUEST_COLUMNS, SCHEMA_VERSION, Store, StoreOptions, TopKind,
    Writer,
};

// aligned to an hour boundary so bucket indexes are easy to reason about
const NOW: i64 = 1_730_721_600_000;
const HOUR: i64 = 3_600_000;
const DAY: i64 = 86_400_000;

fn open() -> (TempDir, Store) {
    open_with(StoreOptions::default())
}

fn open_with(opts: StoreOptions) -> (TempDir, Store) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(&dir.path().join("events.db"), opts).expect("open");
    (dir, store)
}

fn ev(ts: i64) -> LogEvent {
    LogEvent {
        ts_ms: ts,
        client_ip: "10.0.0.1".into(),
        host: "a.test".into(),
        method: "GET".into(),
        path: "/".into(),
        status: 200,
        bytes_in: 100,
        bytes_out: 1000,
        total_ms: 10,
        user_agent: "ua".into(),
        content_type: "text/html".into(),
        backend: "be_s_blue".into(),
        server: "app1".into(),
        ..LogEvent::default()
    }
}

fn full_event() -> LogEvent {
    LogEvent {
        ts_ms: NOW - 1234,
        client_ip: "203.0.113.9".into(),
        host: "shop.example.test".into(),
        method: "POST".into(),
        path: "/cart/add".into(),
        query_len: 17,
        status: 201,
        bytes_in: 4321,
        bytes_out: 98_765,
        total_ms: 321,
        user_agent: "Mozilla/5.0 (X11; Linux x86_64) Test/1.0".into(),
        referer: "https://ref.example.test/start".into(),
        content_type: "application/json; charset=utf-8".into(),
        backend: "be_shop_green".into(),
        server: "app2".into(),
        site: "shop".into(),
        blocked: Some("rate-limit".into()),
        http_version: "HTTP/2.0".into(),
        accept: "text/html,application/xhtml+xml".into(),
        accept_language: "en-GB,en;q=0.8".into(),
        accept_encoding: "gzip, br".into(),
        sec_fetch_site: "same-origin".into(),
        sec_fetch_mode: "navigate".into(),
        sec_fetch_dest: "document".into(),
        sec_ch_ua: "\"Chromium\";v=\"126\"".into(),
        tls_version: "TLSv1.3".into(),
        resp_ms: 77,
        bot_score: 83,
        bot_class: "scraper".into(),
        bot_signals: "no_referer,headless".into(),
    }
}

fn mixed(count: u64) -> Vec<LogEvent> {
    let statuses = [200u16, 200, 200, 301, 404, 500, 503, 200];
    let sizes = [500u64, 3000, 20_000, 100_000, 5_000_000, 100_000_000];
    let ctypes = [
        "text/html; charset=utf-8",
        "TEXT/HTML",
        "application/json",
        "",
    ];
    let methods = ["GET", "get", "POST"];
    let sites = ["a", "b", ""];
    let paths = ["/", "/api", "/img/logo.png", "/x"];
    let mut out: Vec<LogEvent> = (0..count)
        .map(|i| {
            let k = usize::try_from(i).expect("index");
            let mut e = ev(NOW - 500 - 1000 * (i as i64 % 800));
            e.status = statuses[k % statuses.len()];
            e.bytes_out = sizes[k % sizes.len()];
            e.content_type = ctypes[k % ctypes.len()].into();
            e.method = methods[k % methods.len()].into();
            e.site = sites[k % sites.len()].into();
            e.path = paths[k % paths.len()].into();
            e.client_ip = format!("10.0.0.{}", k % 5);
            e.user_agent = format!("ua-{}", k % 4);
            e.host = format!("h{}.test", k % 2);
            e.total_ms = u32::try_from((k * 7) % 900).expect("ms");
            e.bytes_in = 50 + i * 3;
            if k % 11 == 0 {
                e.status = 403;
                e.blocked = Some(format!("rule-{}", k % 3));
            }
            e
        })
        .collect();
    for i in 0..40i64 {
        let mut e = ev(NOW - 2 * HOUR - 1000 * i);
        e.site = "a".into();
        out.push(e);
    }
    out.sort_by_key(|e| e.ts_ms);
    out
}

fn rows(s: &Store) -> u64 {
    s.stats().expect("stats").rows
}

fn export(s: &Store, kind: ExportKind, f: &ExportFilter) -> (u64, String) {
    let mut buf = Vec::new();
    let n = s.export_csv(&mut buf, kind, f).expect("export");
    (n, String::from_utf8(buf).expect("utf8"))
}

fn export_count(s: &Store, f: &ExportFilter) -> u64 {
    export(s, ExportKind::Requests, f).0
}

// RFC 4180 reader that rejects bare line feeds outside quotes.
fn parse_csv(s: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if quoted {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    quoted = false;
                }
            } else {
                field.push(c);
            }
            continue;
        }
        match c {
            '"' => quoted = true,
            ',' => row.push(std::mem::take(&mut field)),
            '\r' => {
                assert_eq!(chars.next(), Some('\n'), "CR must be followed by LF");
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            '\n' => panic!("bare LF outside quotes"),
            _ => field.push(c),
        }
    }
    assert!(!quoted, "unterminated quote");
    assert!(field.is_empty() && row.is_empty(), "missing final CRLF");
    rows
}

#[test]
fn store_types_are_thread_safe() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Store>();
    assert_send_sync::<Writer>();
}

#[test]
fn every_field_round_trips() {
    let (_d, s) = open();
    let e = full_event();
    assert_eq!(s.insert(std::slice::from_ref(&e)).expect("insert"), 1);
    let got = s.requests(&RequestFilter::default(), 10).expect("requests");
    assert_eq!(got, vec![e]);
}

#[test]
fn empty_fields_and_absent_block_round_trip() {
    let (_d, s) = open();
    let e = LogEvent {
        ts_ms: NOW,
        path: "/only-path".into(),
        ..LogEvent::default()
    };
    s.insert(std::slice::from_ref(&e)).expect("insert");
    let got = s.requests(&RequestFilter::default(), 10).expect("requests");
    assert_eq!(got, vec![e]);
    assert_eq!(got[0].blocked, None);
}

#[test]
fn repeated_values_share_dictionary_rows() {
    let (dir, s) = open();
    let batch: Vec<LogEvent> = (0..500).map(|_| full_event()).collect();
    s.insert(&batch).expect("insert");
    s.checkpoint().expect("checkpoint");
    let conn = rusqlite::Connection::open(dir.path().join("events.db")).expect("open");
    let total: i64 = conn
        .query_row("SELECT count(*) FROM dict", [], |r| r.get(0))
        .expect("count");
    assert!(
        total < 40,
        "dictionary holds {total} rows for one repeated event"
    );
}

#[test]
fn requests_are_newest_first_and_limited() {
    let (_d, s) = open();
    let batch: Vec<LogEvent> = (0..100).map(|i| ev(NOW - 100_000 + i)).collect();
    s.insert(&batch).expect("insert");
    let all = s.requests(&RequestFilter::default(), 1000).expect("all");
    assert_eq!(all.len(), 100);
    assert!(all.windows(2).all(|w| w[0].ts_ms > w[1].ts_ms));
    assert_eq!(
        s.requests(&RequestFilter::default(), 3).expect("3").len(),
        3
    );
    assert!(
        s.requests(&RequestFilter::default(), 0)
            .expect("0")
            .is_empty()
    );
    let huge = s
        .requests(&RequestFilter::default(), usize::MAX)
        .expect("huge");
    assert_eq!(huge.len(), 100);
}

#[test]
fn summary_and_timeseries_match_the_in_memory_analytics() {
    let (_d, s) = open();
    let events = mixed(300);
    let mut a = Analytics::new(Retention::default());
    for e in &events {
        a.record(e.clone());
    }
    s.insert(&events).expect("insert");
    for secs in [900u64, 3600, 86_400, 7 * 86_400, 30 * 86_400] {
        for site in [None, Some("a"), Some("b"), Some("missing")] {
            let got = s.summary(secs, site, NOW).expect("summary");
            assert_eq!(got, a.summary(secs, site, NOW), "summary {secs} {site:?}");
        }
    }
    for secs in [900u64, 3600, 86_400, 7 * 86_400] {
        for site in [None, Some("a"), Some("b"), Some("missing")] {
            let got = s.timeseries(secs, site, NOW).expect("series");
            assert_eq!(got, a.timeseries(secs, site, NOW), "series {secs} {site:?}");
        }
    }
}

#[test]
fn request_log_matches_the_in_memory_analytics() {
    let (_d, s) = open();
    let mut events = mixed(200);
    events[3].client_ip = "10.9.9.9".into();
    let mut a = Analytics::new(Retention::default());
    for e in &events {
        a.record(e.clone());
    }
    s.insert(&events).expect("insert");
    let base = RequestFilter::default;
    let filters = [
        base(),
        RequestFilter {
            status: Some(404),
            ..base()
        },
        RequestFilter {
            method: Some("post".into()),
            ..base()
        },
        RequestFilter {
            path_contains: Some("img".into()),
            ..base()
        },
        RequestFilter {
            path_contains: Some("IMG".into()),
            ..base()
        },
        RequestFilter {
            ip: Some("10.9.9.9".into()),
            ..base()
        },
        RequestFilter {
            blocked_only: true,
            ..base()
        },
        RequestFilter {
            site: Some("a".into()),
            ..base()
        },
        RequestFilter {
            site: Some(String::new()),
            ..base()
        },
        RequestFilter {
            site: Some("nope".into()),
            ..base()
        },
    ];
    for f in &filters {
        assert_eq!(
            s.requests(f, 1000).expect("requests"),
            a.requests(f, 1000),
            "{f:?}"
        );
    }
}

#[test]
fn rollups_agree_with_raw_rows() {
    let (_d, s) = open();
    let mut events = Vec::new();
    for i in 0..600i64 {
        let mut e = mixed(1)[0].clone();
        e.ts_ms = NOW - 1 - i * 400_000;
        e.status = [200u16, 404, 500, 302, 403][usize::try_from(i % 5).expect("idx")];
        e.bytes_out = u64::try_from(i * 977).expect("bytes");
        e.total_ms = u32::try_from(i % 250).expect("ms");
        e.site = ["a", "b", ""][usize::try_from(i % 3).expect("idx")].into();
        e.path = format!("/p{}", i % 7);
        e.method = ["GET", "post", "Put"][usize::try_from(i % 3).expect("idx")].into();
        e.host = format!("h{}.test", i % 4);
        e.content_type =
            ["text/html; charset=utf-8", "Image/PNG"][usize::try_from(i % 2).expect("idx")].into();
        if i % 9 == 0 {
            e.blocked = Some(format!("rule-{}", i % 2));
        }
        events.push(e);
    }
    s.insert(&events).expect("insert");
    let raw = Window::new(3 * 86_400, NOW, false);
    let rolled = Window::new(3 * 86_400, NOW, true);
    for site in [None, Some("a"), Some("b")] {
        s.inner
            .read(|c| {
                let a = queries::summary_in(c, &raw, site)?;
                let b = queries::summary_in(c, &rolled, site)?;
                assert_eq!(a, b, "site {site:?}");
                assert!(a.requests > 0);
                Ok(())
            })
            .expect("compare");
    }
    let minutes = Window::new(3 * 86_400, NOW, false);
    let hours = Window::new(3 * 86_400, NOW, true);
    s.inner
        .read(|c| {
            let m = queries::timeseries_in(c, &minutes, None)?;
            let h = queries::timeseries_in(c, &hours, None)?;
            assert_eq!(h.step_secs, 3600);
            for p in &h.points {
                let inside: Vec<_> = m
                    .points
                    .iter()
                    .filter(|q| q.ts >= p.ts && q.ts < p.ts + 3600)
                    .collect();
                assert_eq!(inside.iter().map(|q| q.requests).sum::<u64>(), p.requests);
                assert_eq!(inside.iter().map(|q| q.bytes_out).sum::<u64>(), p.bytes_out);
                assert_eq!(inside.iter().map(|q| q.errors).sum::<u64>(), p.errors);
                assert_eq!(inside.iter().map(|q| q.blocked).sum::<u64>(), p.blocked);
            }
            Ok(())
        })
        .expect("series");
}

#[test]
fn top_kinds_rank_values_and_rollups_match_raw() {
    let (_d, s) = open();
    let mut events = Vec::new();
    for i in 0..60usize {
        let mut e = ev(NOW - 2000);
        e.path = format!("/p{}", i % 3);
        e.host = format!("h{}.test", i % 2);
        e.referer = format!("https://r{}.test/", i % 4);
        e.user_agent = format!("ua-{}", i % 5);
        e.client_ip = format!("192.0.2.{}", i % 6);
        e.accept_language = ["en-US", "de-DE", ""][i % 3].into();
        e.status = [200u16, 404][i % 2];
        e.content_type = ["text/html; charset=utf-8", "TEXT/HTML", "image/png"][i % 3].into();
        events.push(e);
    }
    s.insert(&events).expect("insert");
    let paths = s.top(TopKind::Paths, 900, None, NOW, 10).expect("paths");
    assert_eq!(paths.len(), 3);
    assert!(paths.iter().all(|t| t.count == 20 && t.bytes == 20_000));
    assert_eq!(paths[0].key, "/p0");
    assert_eq!(
        s.top(TopKind::Paths, 900, None, NOW, 2).expect("2").len(),
        2
    );
    assert!(
        s.top(TopKind::Paths, 900, None, NOW, 0)
            .expect("0")
            .is_empty()
    );
    assert_eq!(
        s.top(TopKind::Referers, 900, None, NOW, 10)
            .expect("r")
            .len(),
        4
    );
    assert_eq!(
        s.top(TopKind::UserAgents, 900, None, NOW, 10)
            .expect("u")
            .len(),
        5
    );
    assert_eq!(
        s.top(TopKind::ClientIps, 900, None, NOW, 10)
            .expect("i")
            .len(),
        6
    );
    let langs = s.top(TopKind::Languages, 900, None, NOW, 10).expect("l");
    assert_eq!(langs.len(), 2);
    let types = s.top(TopKind::ContentTypes, 900, None, NOW, 10).expect("t");
    assert_eq!(types[0].key, "text/html");
    assert_eq!(types[0].count, 40);
    let codes = s.top(TopKind::StatusCodes, 900, None, NOW, 10).expect("c");
    assert_eq!(codes.len(), 2);
    assert_eq!(codes[0].key, "200");
    for kind in [
        TopKind::Hosts,
        TopKind::ContentTypes,
        TopKind::StatusCodes,
        TopKind::Languages,
    ] {
        let raw = s.top(kind, 900, None, NOW, 10).expect("raw");
        let rolled = s.top(kind, 7 * 86_400, None, NOW, 10).expect("rollup");
        assert_eq!(raw, rolled, "{kind:?}");
    }
}

#[test]
fn bots_breakdown_counts_classes_signals_agents_and_scores() {
    let (_d, s) = open();
    let mut events = Vec::new();
    for _ in 0..10 {
        let mut e = ev(NOW - 1000);
        e.bot_class = "human".into();
        e.bot_score = 5;
        events.push(e);
    }
    for _ in 0..6 {
        let mut e = ev(NOW - 1000);
        e.bot_class = "scraper".into();
        e.bot_score = 85;
        e.bot_signals = "headless, no_lang".into();
        e.user_agent = "badbot/1".into();
        events.push(e);
    }
    for _ in 0..4 {
        let mut e = ev(NOW - 1000);
        e.bot_class = "crawler".into();
        e.bot_score = 45;
        e.bot_signals = "known_bot".into();
        e.user_agent = "goodbot/2".into();
        events.push(e);
    }
    events.push(ev(NOW - 1000));
    events.push(ev(NOW - 1000));
    s.insert(&events).expect("insert");
    for secs in [900u64, 7 * 86_400] {
        let b = s.bots(secs, None, NOW).expect("bots");
        assert_eq!(b.total_requests, 22, "{secs}");
        assert_eq!(b.bot_requests, 10);
        assert!((b.bot_share_pct - 10.0 / 22.0 * 100.0).abs() < 1e-9);
        let class = |k: &str| b.classes.iter().find(|t| t.key == k).map(|t| t.count);
        assert_eq!(class("human"), Some(10));
        assert_eq!(class("scraper"), Some(6));
        assert_eq!(class("crawler"), Some(4));
        assert_eq!(b.classes.len(), 3);
        let sig = |k: &str| b.signals.iter().find(|t| t.key == k).map(|t| t.count);
        assert_eq!(sig("headless"), Some(6));
        assert_eq!(sig("no_lang"), Some(6));
        assert_eq!(sig("known_bot"), Some(4));
        let keys: Vec<&str> = b.score_buckets.iter().map(|t| t.key.as_str()).collect();
        assert_eq!(keys, ["0-19", "20-39", "40-59", "60-79", "80-100"]);
        let counts: Vec<u64> = b.score_buckets.iter().map(|t| t.count).collect();
        assert_eq!(counts, [10, 0, 4, 0, 6]);
        let agents: Vec<(&str, u64)> = b.agents.iter().map(|t| (t.key.as_str(), t.count)).collect();
        assert_eq!(agents, [("badbot/1", 6), ("goodbot/2", 4)]);
    }
    let empty = s.bots(900, Some("missing"), NOW).expect("missing");
    assert_eq!((empty.total_requests, empty.bot_requests), (0, 0));
    assert_eq!(empty.bot_share_pct, 0.0);
}

#[test]
fn age_retention_removes_only_expired_rows() {
    let (_d, s) = open();
    s.set_retention_days(1);
    assert_eq!(s.retention_days(), 1);
    let mut events: Vec<LogEvent> = (0..5).map(|i| ev(NOW - 3 * DAY - i)).collect();
    events.extend((0..7).map(|i| ev(NOW - 1000 - i)));
    s.insert(&events).expect("insert");
    assert_eq!(
        s.summary(30 * 86_400, None, NOW).expect("before").requests,
        12
    );
    let report = s.prune(NOW).expect("prune");
    assert_eq!(report.expired_rows, 5);
    assert_eq!(report.trimmed_rows, 0);
    assert_eq!(report.cutoff_ms, Some(NOW - DAY));
    assert!(report.rollup_rows_removed > 0);
    assert!(!report.to_string().is_empty());
    assert_eq!(rows(&s), 7);
    assert_eq!(
        s.summary(30 * 86_400, None, NOW).expect("after").requests,
        7
    );
    assert!(s.prune(NOW).expect("again").is_empty());
}

#[test]
fn zero_retention_days_keeps_everything() {
    let (_d, s) = open();
    s.set_retention_days(0);
    s.insert(&[ev(NOW - 400 * DAY)]).expect("insert");
    let report = s.prune(NOW).expect("prune");
    assert!(report.is_empty());
    assert_eq!(report.cutoff_ms, None);
    assert_eq!(rows(&s), 1);
}

#[test]
fn nothing_is_trimmed_by_size_unless_a_budget_is_set() {
    let (_d, s) = open();
    s.set_retention_days(0);
    assert_eq!(s.max_bytes(), None);
    let batch: Vec<LogEvent> = (0..5000).map(|i| ev(NOW - i)).collect();
    s.insert(&batch).expect("insert");
    assert!(s.prune(NOW).expect("prune").is_empty());
    assert_eq!(rows(&s), 5000);
}

#[test]
fn size_budget_trims_the_oldest_rows_first() {
    let (_d, s) = open();
    s.set_retention_days(0);
    let total = 30_000i64;
    for chunk in 0..6 {
        let batch: Vec<LogEvent> = (0..5000)
            .map(|j| {
                let i = chunk * 5000 + j;
                let mut e = ev(NOW - 40_000_000 + i * 1000);
                e.path = format!("/p/{i}/{}", "x".repeat(40));
                e
            })
            .collect();
        s.insert(&batch).expect("insert");
    }
    let before = s.stats().expect("stats");
    assert_eq!(before.rows, total as u64);
    let live = s.inner.live_bytes().expect("live");
    s.set_max_bytes(Some(live / 2));
    assert_eq!(s.max_bytes(), Some(live / 2));
    let report = s.prune(NOW).expect("prune");
    assert!(report.trimmed_rows > 0 && report.trimmed_rows < total as u64);
    assert_eq!(report.expired_rows, 0);
    assert!(report.bytes_after <= live / 2, "{report}");
    let after = s.stats().expect("stats");
    assert_eq!(after.rows, total as u64 - report.trimmed_rows);
    assert_eq!(after.newest_ts_ms, before.newest_ts_ms);
    assert!(after.oldest_ts_ms > before.oldest_ts_ms);
    assert!(report.trimmed_to_ms < after.oldest_ts_ms);
    assert_eq!(report.trimmed_from_ms, before.oldest_ts_ms);
    assert_eq!(
        s.summary(30 * 86_400, None, NOW).expect("rollup").requests,
        total as u64,
        "rollups keep the trimmed history"
    );
}

#[test]
fn concurrent_writers_lose_nothing() {
    let (_d, s) = open();
    let w = s.writer();
    let handles: Vec<_> = (0..8)
        .map(|t| {
            let w = w.clone();
            thread::spawn(move || {
                for i in 0..5000 {
                    let mut e = ev(NOW - 1000);
                    e.path = format!("/t{t}/{i}");
                    w.send(e).expect("send");
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("join");
    }
    w.flush().expect("flush");
    let stats = s.stats().expect("stats");
    assert_eq!(stats.rows, 40_000);
    assert_eq!(stats.write_errors, 0);
    assert!(stats.write_batches >= 1);
    assert_eq!(
        s.summary(7 * 86_400, None, NOW).expect("rollup").requests,
        40_000
    );
    assert_eq!(s.summary(900, None, NOW).expect("raw").requests, 40_000);
}

#[test]
fn full_queue_blocks_senders_instead_of_dropping() {
    // 2000 sends into a queue of 4 force senders to block on a full queue; none may be dropped.
    let (_d, s) = open_with(StoreOptions {
        queue_capacity: 4,
        batch_size: 7,
        ..StoreOptions::default()
    });
    let w = s.writer();
    for i in 0..2000 {
        w.send(ev(NOW - i)).expect("send");
    }
    w.flush().expect("flush");
    assert_eq!(rows(&s), 2000);
}

#[test]
fn dropping_the_last_writer_drains_the_queue() {
    let (_d, s) = open();
    let w = s.writer();
    for i in 0..500 {
        w.send(ev(NOW - i)).expect("send");
    }
    let second = w.clone();
    drop(w);
    drop(second);
    assert_eq!(rows(&s), 500);
    let again = s.writer();
    again.send(ev(NOW)).expect("send");
    again.close().expect("close");
    assert_eq!(rows(&s), 501);
}

#[test]
fn idle_events_are_committed_by_the_flush_timer() {
    let (_d, s) = open();
    let w = s.writer();
    for i in 0..10 {
        w.send(ev(NOW - i)).expect("send");
    }
    // 10 events are far below the default batch size, so only the flush timer can commit them.
    let deadline = Instant::now() + Duration::from_secs(10);
    while rows(&s) < 10 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(rows(&s), 10);
}

#[test]
fn synchronous_insert_is_visible_immediately_alongside_the_writer() {
    let (_d, s) = open();
    let w = s.writer();
    w.send(ev(NOW)).expect("send");
    // Direct inserts bypass the writer queue, so the queued event only becomes visible at the flush.
    assert_eq!(s.insert(&[ev(NOW - 1), ev(NOW - 2)]).expect("insert"), 2);
    w.flush().expect("flush");
    assert_eq!(rows(&s), 3);
    assert_eq!(s.insert(&[]).expect("empty"), 0);
}

#[test]
fn import_events_stores_every_event() {
    let (_d, s) = open();
    let n = s
        .import_events((0..12_345).map(|i| ev(NOW - i)))
        .expect("import");
    assert_eq!(n, 12_345);
    assert_eq!(rows(&s), 12_345);
    assert_eq!(s.import_events(std::iter::empty()).expect("none"), 0);
}

#[test]
fn stats_report_rows_span_and_counters() {
    let (_d, s) = open();
    let empty = s.stats().expect("stats");
    assert_eq!(empty.rows, 0);
    assert_eq!((empty.oldest_ts_ms, empty.newest_ts_ms), (None, None));
    assert_eq!((empty.write_batches, empty.write_errors), (0, 0));
    s.insert(&[ev(NOW - 50), ev(NOW - 10), ev(NOW - 30)])
        .expect("insert");
    let st = s.stats().expect("stats");
    assert_eq!(st.rows, 3);
    assert_eq!(st.oldest_ts_ms, Some(NOW - 50));
    assert_eq!(st.newest_ts_ms, Some(NOW - 10));
    assert_eq!(st.write_batches, 1);
    assert!(st.db_bytes > 0);
}

#[test]
fn hostile_filters_are_treated_as_plain_values() {
    let (_d, s) = open();
    let evil = "'; DROP TABLE requests; --";
    let mut e1 = ev(NOW - 4000);
    e1.site = evil.into();
    e1.host = "h%st".into();
    e1.path = "/a_b".into();
    let mut e2 = ev(NOW - 3000);
    e2.site = "s".into();
    e2.host = "hxst".into();
    e2.path = "/axb".into();
    let mut e3 = ev(NOW - 2000);
    e3.path = "/100%".into();
    let mut e4 = ev(NOW - 1000);
    e4.path = "/1000".into();
    s.insert(&[e1.clone(), e2, e3, e4]).expect("insert");

    assert_eq!(s.summary(900, Some(evil), NOW).expect("evil").requests, 1);
    assert_eq!(
        s.summary(900, Some("' OR '1'='1"), NOW)
            .expect("or")
            .requests,
        0
    );
    assert_eq!(
        s.summary(7 * 86_400, Some(evil), NOW)
            .expect("evil")
            .requests,
        1
    );
    let found = s
        .requests(
            &RequestFilter {
                site: Some(evil.into()),
                ..RequestFilter::default()
            },
            10,
        )
        .expect("requests");
    assert_eq!(found, vec![e1]);

    let contains = |p: &str| {
        s.requests(
            &RequestFilter {
                path_contains: Some(p.into()),
                ..RequestFilter::default()
            },
            10,
        )
        .expect("contains")
        .len()
    };
    assert_eq!(contains("_"), 1);
    assert_eq!(contains("%"), 1);
    assert_eq!(contains("a_b"), 1);
    assert_eq!(contains("a?b"), 0);
    assert_eq!(contains("'; DROP TABLE requests; --"), 0);

    let count = |f: ExportFilter| export_count(&s, &f);
    let base = ExportFilter::default;
    assert_eq!(
        count(ExportFilter {
            host: Some("h%st".into()),
            ..base()
        }),
        1
    );
    assert_eq!(
        count(ExportFilter {
            host: Some("h_st".into()),
            ..base()
        }),
        0
    );
    assert_eq!(
        count(ExportFilter {
            host: Some("%".into()),
            ..base()
        }),
        0
    );
    assert_eq!(
        count(ExportFilter {
            path_prefix: Some("/a_".into()),
            ..base()
        }),
        1
    );
    assert_eq!(
        count(ExportFilter {
            path_prefix: Some("/a".into()),
            ..base()
        }),
        2
    );
    assert_eq!(
        count(ExportFilter {
            path_prefix: Some("%".into()),
            ..base()
        }),
        0
    );
    assert_eq!(
        count(ExportFilter {
            path_prefix: Some("/100".into()),
            ..base()
        }),
        2
    );
    assert_eq!(
        count(ExportFilter {
            site: Some(evil.into()),
            ..base()
        }),
        1
    );
    assert_eq!(
        count(ExportFilter {
            client_ip: Some("' OR 1=1 --".into()),
            ..base()
        }),
        0
    );
    assert_eq!(
        count(ExportFilter {
            method: Some("GET'; --".into()),
            ..base()
        }),
        0
    );
    assert_eq!(
        count(ExportFilter {
            bot_class: Some("x' OR '1'='1".into()),
            ..base()
        }),
        0
    );

    assert_eq!(rows(&s), 4);
    s.integrity_check().expect("integrity");
}

#[test]
fn csv_quotes_special_characters_and_neutralises_formulas() {
    let (_d, s) = open();
    let mut tricky = ev(NOW - 3000);
    tricky.path = "/a,b\"c\nd".into();
    tricky.user_agent = "Za\u{17c}\u{f3}\u{142}\u{107} \u{65e5}\u{672c}\u{8a9e}".into();
    let mut formula = ev(NOW - 2000);
    formula.path = "=cmd|' /C calc'!A0".into();
    formula.referer = "-1+2".into();
    formula.host = "@evil".into();
    formula.user_agent = "\tstart".into();
    formula.blocked = Some("+rule".into());
    let plain = ev(NOW - 1000);
    s.insert(&[tricky.clone(), formula, plain]).expect("insert");

    let (n, text) = export(&s, ExportKind::Requests, &ExportFilter::default());
    assert_eq!(n, 3);
    assert!(text.ends_with("\r\n"));
    let table = parse_csv(&text);
    assert_eq!(table.len(), 4);
    assert_eq!(table[0], REQUEST_COLUMNS);
    assert!(table.iter().all(|r| r.len() == REQUEST_COLUMNS.len()));

    let col = |name: &str| {
        REQUEST_COLUMNS
            .iter()
            .position(|c| *c == name)
            .expect("column")
    };
    assert_eq!(table[1][col("path")], tricky.path);
    assert_eq!(table[1][col("user_agent")], tricky.user_agent);
    assert_eq!(table[1][col("timestamp")], iso_utc(NOW - 3000));
    assert_eq!(table[1][col("ts_ms")], (NOW - 3000).to_string());
    assert_eq!(table[2][col("path")], "'=cmd|' /C calc'!A0");
    assert_eq!(table[2][col("referer")], "'-1+2");
    assert_eq!(table[2][col("host")], "'@evil");
    assert_eq!(table[2][col("user_agent")], "'\tstart");
    assert_eq!(table[2][col("blocked")], "'+rule");
    assert_eq!(table[3][col("status")], "200");
    assert_eq!(table[3][col("bytes_out")], "1000");
    assert_eq!(table[3][col("blocked")], "");
}

#[test]
fn csv_header_and_width_are_stable_for_every_kind() {
    let (_d, s) = open();
    let mut events = Vec::new();
    for i in 0..30i64 {
        let mut e = ev(NOW - HOUR * (i % 3) - 1000);
        e.site = ["a", "b"][usize::try_from(i % 2).expect("idx")].into();
        e.bot_class = ["human", "scraper"][usize::try_from(i % 2).expect("idx")].into();
        e.bot_signals = "s1,s2".into();
        e.bot_score = 30;
        events.push(e);
    }
    s.insert(&events).expect("insert");
    let f = ExportFilter::default();
    let kinds = [
        (ExportKind::Requests, crate::REQUEST_COLUMNS.to_vec(), 30u64),
        (ExportKind::Hourly, crate::HOURLY_COLUMNS.to_vec(), 6),
        (ExportKind::Bots, crate::BOT_COLUMNS.to_vec(), 0),
        (
            ExportKind::Top(TopKind::Paths),
            crate::TOP_COLUMNS.to_vec(),
            1,
        ),
    ];
    for (kind, header, expected) in kinds {
        let (n, text) = export(&s, kind, &f);
        let table = parse_csv(&text);
        assert_eq!(table[0], header, "{kind:?}");
        assert!(table.iter().all(|r| r.len() == header.len()), "{kind:?}");
        assert_eq!(table.len() as u64, n + 1, "{kind:?}");
        if expected > 0 {
            assert_eq!(n, expected, "{kind:?}");
        } else {
            assert!(n > 0, "{kind:?}");
        }
    }
    let (_, text) = export(&s, ExportKind::Bots, &f);
    let table = parse_csv(&text);
    let find = |section: &str, key: &str| {
        table
            .iter()
            .find(|r| r[0] == section && r[1] == key)
            .map(|r| r[2].clone())
    };
    assert_eq!(find("summary", "total_requests").as_deref(), Some("30"));
    assert_eq!(find("summary", "bot_requests").as_deref(), Some("15"));
    assert_eq!(find("class", "scraper").as_deref(), Some("15"));
    assert_eq!(find("signal", "s1").as_deref(), Some("30"));
    assert_eq!(find("score_bucket", "20-39").as_deref(), Some("30"));
}

#[test]
fn hourly_export_lists_rollup_rows() {
    let (_d, s) = open();
    let mut events = Vec::new();
    for i in 0..10i64 {
        let mut e = ev(NOW - HOUR - 1000 - i);
        e.site = "a".into();
        e.status = if i < 4 { 500 } else { 200 };
        events.push(e);
    }
    let mut other = ev(NOW - 1000);
    other.site = "b".into();
    events.push(other);
    s.insert(&events).expect("insert");
    let (n, text) = export(&s, ExportKind::Hourly, &ExportFilter::default());
    assert_eq!(n, 2);
    let table = parse_csv(&text);
    let hour = &table[1];
    assert_eq!(hour[0], iso_utc(NOW - 2 * HOUR));
    assert_eq!(hour[1], (NOW - 2 * HOUR).to_string());
    assert_eq!(hour[2], "a");
    assert_eq!(hour[3], "10");
    assert_eq!(hour[8], "6");
    assert_eq!(hour[11], "4");
    assert_eq!(table[2][2], "b");
    let only_b = ExportFilter {
        site: Some("b".into()),
        ..ExportFilter::default()
    };
    assert_eq!(export(&s, ExportKind::Hourly, &only_b).0, 1);
    let recent = ExportFilter {
        from_ms: Some(NOW - HOUR),
        ..ExportFilter::default()
    };
    assert_eq!(export(&s, ExportKind::Hourly, &recent).0, 1);
    let capped = ExportFilter {
        limit: Some(1),
        ..ExportFilter::default()
    };
    assert_eq!(export(&s, ExportKind::Hourly, &capped).0, 1);
}

#[test]
fn export_filters_select_the_expected_rows() {
    let (_d, s) = open();
    let mut a = ev(NOW - 5000);
    a.status = 404;
    a.host = "one.test".into();
    a.path = "/docs/a".into();
    a.client_ip = "198.51.100.1".into();
    a.bot_class = "human".into();
    a.bot_score = 10;
    let mut b = ev(NOW - 4000);
    b.status = 500;
    b.host = "two.test".into();
    b.path = "/docs/b".into();
    b.method = "POST".into();
    b.bot_class = "scraper".into();
    b.bot_score = 90;
    b.site = "shop".into();
    let mut c = ev(NOW - 3000);
    c.status = 301;
    c.path = "/other".into();
    c.bot_class = "scraper".into();
    c.bot_score = 60;
    let mut d = ev(NOW - 2000);
    d.client_ip = "198.51.100.1".into();
    s.insert(&[a, b, c, d]).expect("insert");

    let base = ExportFilter::default;
    let n = |f: ExportFilter| export_count(&s, &f);
    assert_eq!(n(base()), 4);
    assert_eq!(
        n(ExportFilter {
            status_min: Some(400),
            ..base()
        }),
        2
    );
    assert_eq!(
        n(ExportFilter {
            status_max: Some(399),
            ..base()
        }),
        2
    );
    assert_eq!(
        n(ExportFilter {
            status_min: Some(404),
            status_max: Some(404),
            ..base()
        }),
        1
    );
    assert_eq!(
        n(ExportFilter {
            bot_class: Some("scraper".into()),
            ..base()
        }),
        2
    );
    assert_eq!(
        n(ExportFilter {
            bot_class: Some(String::new()),
            ..base()
        }),
        1
    );
    assert_eq!(
        n(ExportFilter {
            min_bot_score: Some(60),
            ..base()
        }),
        2
    );
    assert_eq!(
        n(ExportFilter {
            min_bot_score: Some(91),
            ..base()
        }),
        0
    );
    assert_eq!(
        n(ExportFilter {
            host: Some("one.test".into()),
            ..base()
        }),
        1
    );
    assert_eq!(
        n(ExportFilter {
            path_prefix: Some("/docs/".into()),
            ..base()
        }),
        2
    );
    assert_eq!(
        n(ExportFilter {
            client_ip: Some("198.51.100.1".into()),
            ..base()
        }),
        2
    );
    assert_eq!(
        n(ExportFilter {
            method: Some("post".into()),
            ..base()
        }),
        1
    );
    assert_eq!(
        n(ExportFilter {
            site: Some("shop".into()),
            ..base()
        }),
        1
    );
    assert_eq!(
        n(ExportFilter {
            from_ms: Some(NOW - 4000),
            ..base()
        }),
        3
    );
    assert_eq!(
        n(ExportFilter {
            to_ms: Some(NOW - 4000),
            ..base()
        }),
        1
    );
    assert_eq!(
        n(ExportFilter {
            limit: Some(2),
            ..base()
        }),
        2
    );
    assert_eq!(
        n(ExportFilter {
            limit: Some(0),
            ..base()
        }),
        0
    );
    assert_eq!(
        n(ExportFilter {
            limit: Some(10_000_000),
            ..base()
        }),
        4
    );
    let (_, text) = export(&s, ExportKind::Requests, &base());
    let table = parse_csv(&text);
    let ts: Vec<i64> = table[1..]
        .iter()
        .map(|r| r[1].parse().expect("ts"))
        .collect();
    assert!(ts.windows(2).all(|w| w[0] <= w[1]), "oldest first");
}

#[test]
fn export_pages_through_more_rows_than_one_page() {
    let (_d, s) = open();
    // Three rows share each timestamp, so the ordering check below must allow ties.
    let batch: Vec<LogEvent> = (0..5300).map(|i| ev(NOW - 10_000 + i / 3)).collect();
    s.insert(&batch).expect("insert");
    let (n, text) = export(&s, ExportKind::Requests, &ExportFilter::default());
    assert_eq!(n, 5300);
    let table = parse_csv(&text);
    assert_eq!(table.len(), 5301);
    let ts: Vec<i64> = table[1..]
        .iter()
        .map(|r| r[1].parse().expect("ts"))
        .collect();
    assert!(ts.windows(2).all(|w| w[0] <= w[1]));
    let limited = ExportFilter {
        limit: Some(4001),
        ..ExportFilter::default()
    };
    assert_eq!(export_count(&s, &limited), 4001);
}

#[test]
fn top_and_ndjson_exports() {
    let (_d, s) = open();
    let events: Vec<LogEvent> = (0..9)
        .map(|i| {
            let mut e = ev(NOW - 1000);
            e.path = format!("/p{}", i % 3);
            e
        })
        .collect();
    s.insert(&events).expect("insert");
    let (n, text) = export(
        &s,
        ExportKind::Top(TopKind::Paths),
        &ExportFilter::default(),
    );
    assert_eq!(n, 3);
    let table = parse_csv(&text);
    assert_eq!(table[1], ["/p0", "3", "3000"]);

    let mut buf = Vec::new();
    let rows = s
        .export_ndjson(&mut buf, ExportKind::Requests, &ExportFilter::default())
        .expect("ndjson");
    assert_eq!(rows, 9);
    let text = String::from_utf8(buf).expect("utf8");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 9);
    for line in lines {
        let v: serde_json::Value = serde_json::from_str(line).expect("json");
        let obj = v.as_object().expect("object");
        assert_eq!(obj.len(), REQUEST_COLUMNS.len());
        assert!(obj["ts_ms"].is_i64());
        assert_eq!(obj["status"], 200);
    }
    let mut buf = Vec::new();
    let rows = s
        .export_ndjson(
            &mut buf,
            ExportKind::Top(TopKind::Paths),
            &ExportFilter {
                limit: Some(1),
                ..ExportFilter::default()
            },
        )
        .expect("ndjson");
    assert_eq!(rows, 1);
}

#[test]
fn extreme_arguments_do_not_panic() {
    let (_d, s) = open();
    s.insert(&[ev(NOW)]).expect("insert");
    for now in [i64::MIN, -1, 0, NOW, i64::MAX] {
        for secs in [0u64, 1, 900, 7 * 86_400, u64::MAX] {
            s.summary(secs, None, now).expect("summary");
            s.timeseries(secs, Some("x"), now).expect("series");
            s.timeseries(secs, None, now).expect("series");
            s.bots(secs, None, now).expect("bots");
            s.top(TopKind::Hosts, secs, None, now, usize::MAX)
                .expect("top");
        }
    }
    let mut big = ev(NOW);
    big.bytes_in = u64::MAX;
    big.bytes_out = u64::MAX;
    big.total_ms = u32::MAX;
    big.status = u16::MAX;
    big.query_len = u32::MAX;
    big.ts_ms = i64::MIN;
    let mut late = big.clone();
    late.ts_ms = i64::MAX;
    s.insert(&[big, late]).expect("insert extremes");
    s.summary(7 * 86_400, None, NOW).expect("summary");
    s.prune(i64::MAX).expect("prune");
    s.prune(i64::MIN).expect("prune");
    let (n, _) = export(&s, ExportKind::Requests, &ExportFilter::default());
    assert!(n <= 3);
}

#[test]
fn reopening_keeps_data_and_schema_version() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("events.db");
    {
        let s = Store::open(&path, StoreOptions::default()).expect("open");
        s.insert(&[full_event()]).expect("insert");
    }
    let s = Store::open(&path, StoreOptions::default()).expect("reopen");
    assert_eq!(rows(&s), 1);
    assert_eq!(
        s.requests(&RequestFilter::default(), 1).expect("requests"),
        vec![full_event()]
    );
    s.integrity_check().expect("integrity");
    s.checkpoint().expect("checkpoint");
    let conn = rusqlite::Connection::open(&path).expect("raw");
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .expect("version");
    assert_eq!(version, SCHEMA_VERSION);
    let vacuum: i64 = conn
        .query_row("PRAGMA auto_vacuum", [], |r| r.get(0))
        .expect("auto_vacuum");
    assert_eq!(vacuum, 2);
    let mode: String = conn
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .expect("journal_mode");
    assert_eq!(mode, "wal");
}

#[test]
fn newer_database_versions_are_refused_untouched() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("future.db");
    {
        let conn = rusqlite::Connection::open(&path).expect("raw");
        conn.execute_batch("CREATE TABLE marker (x INTEGER); PRAGMA user_version = 99;")
            .expect("seed");
    }
    match Store::open(&path, StoreOptions::default()) {
        Err(Error::NewerSchema { found, supported }) => {
            assert_eq!((found, supported), (99, SCHEMA_VERSION));
        }
        Ok(_) => panic!("opened a newer database"),
        Err(e) => panic!("unexpected error {e}"),
    }
    // The refused open must not have created the schema in the future-version file.
    let conn = rusqlite::Connection::open(&path).expect("raw");
    let tables: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE name = 'requests'",
            [],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(tables, 0);
}

#[test]
fn open_errors_are_clear() {
    let dir = tempfile::tempdir().expect("tempdir");
    match Store::open(
        &dir.path().join("missing").join("x.db"),
        StoreOptions::default(),
    ) {
        Err(Error::MissingDir(p)) => assert!(p.ends_with("missing")),
        Ok(_) => panic!("opened under a missing directory"),
        Err(e) => panic!("unexpected error {e}"),
    }
    let junk = dir.path().join("junk.db");
    std::fs::write(&junk, vec![b'x'; 4096]).expect("write");
    let err = Store::open(&junk, StoreOptions::default());
    assert!(err.is_err());
    let msg = err.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(
        msg.contains("junk.db") || msg.contains("not a database"),
        "{msg}"
    );
    assert!(Store::open(dir.path(), StoreOptions::default()).is_err());
}

#[cfg(unix)]
#[test]
fn database_file_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("events.db");
    let s = Store::open(&path, StoreOptions::default()).expect("open");
    s.insert(&[ev(NOW)]).expect("insert");
    let mode = |p: &Path| std::fs::metadata(p).expect("meta").permissions().mode() & 0o777;
    assert_eq!(mode(&path), 0o600);
    let wal = dir.path().join("events.db-wal");
    if wal.exists() {
        assert_eq!(mode(&wal) & 0o077, 0);
    }
}

#[test]
fn integrity_check_and_checkpoint_succeed_on_a_busy_store() {
    let (_d, s) = open();
    let batch: Vec<LogEvent> = (0..3000).map(|i| ev(NOW - i)).collect();
    s.insert(&batch).expect("insert");
    s.integrity_check().expect("integrity");
    s.checkpoint().expect("checkpoint");
    assert_eq!(rows(&s), 3000);
}

#[test]
fn queries_run_while_the_writer_is_busy() {
    let (_d, s) = open();
    let w = s.writer();
    let feeder = {
        let w = w.clone();
        thread::spawn(move || {
            for i in 0..20_000 {
                w.send(ev(NOW - 1000 - i % 100)).expect("send");
            }
        })
    };
    let mut seen = 0;
    while !feeder.is_finished() {
        let sum = s.summary(900, None, NOW).expect("summary");
        assert!(sum.requests >= seen);
        seen = sum.requests;
        s.requests(&RequestFilter::default(), 10).expect("requests");
    }
    feeder.join().expect("join");
    w.flush().expect("flush");
    assert_eq!(rows(&s), 20_000);
}

fn file_contains(path: &Path, needle: &[u8]) -> bool {
    std::fs::read(path)
        .map(|b| b.windows(needle.len()).any(|w| w == needle))
        .unwrap_or(false)
}

// 40 events share only 3 client ips and 4 agents, so scrubbing has to clear dictionary rows many requests point at.
fn private_events() -> Vec<LogEvent> {
    (0..40i64)
        .map(|i| {
            let mut e = ev(NOW - i * 2 * HOUR);
            e.client_ip = format!("203.0.113.{}", 70 + i % 3);
            e.user_agent = format!("UniqueAgent/{}", i % 4);
            e.bot_class = "crawler".into();
            e.path = format!("/p{}", i % 5);
            e
        })
        .collect()
}

#[test]
fn scrub_erases_client_ips_and_user_agents_everywhere() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("events.db");
    let s = Store::open(&path, StoreOptions::default()).expect("open");
    s.insert(&private_events()).expect("insert");
    assert!(
        !s.top(TopKind::ClientIps, 7 * 86_400, None, NOW, 5)
            .expect("top")
            .is_empty()
    );
    assert_eq!(s.scrub_fields(true, true).expect("scrub"), 40);
    s.checkpoint().expect("checkpoint");
    for needle in [&b"203.0.113."[..], &b"UniqueAgent"[..]] {
        assert!(!file_contains(&path, needle), "db still holds {needle:?}");
        assert!(!file_contains(&dir.path().join("events.db-wal"), needle));
    }
    let rows = s
        .requests(&RequestFilter::default(), 100)
        .expect("requests");
    assert_eq!(rows.len(), 40);
    assert!(
        rows.iter()
            .all(|e| e.client_ip.is_empty() && e.user_agent.is_empty())
    );
    assert!(
        rows.iter()
            .all(|e| e.path.starts_with("/p") && e.bot_class == "crawler")
    );
    for window in [3600, 7 * 86_400] {
        assert!(
            s.top(TopKind::ClientIps, window, None, NOW, 5)
                .expect("ips")
                .is_empty()
        );
        assert!(
            s.top(TopKind::UserAgents, window, None, NOW, 5)
                .expect("uas")
                .is_empty()
        );
        assert!(s.bots(window, None, NOW).expect("bots").agents.is_empty());
        assert!(s.summary(window, None, NOW).expect("summary").requests > 0);
    }
    assert_eq!(s.scrub_fields(false, false).expect("noop"), 0);
    s.integrity_check().expect("integrity");

    let mut fresh = ev(NOW + 5);
    fresh.client_ip = "198.51.100.9".into();
    fresh.user_agent = "FreshAgent".into();
    s.insert(&[fresh.clone()]).expect("insert after scrub");
    let back = s.requests(&RequestFilter::default(), 1).expect("requests");
    assert_eq!(back, vec![fresh]);
    let ips = s
        .top(TopKind::ClientIps, 7 * 86_400, None, NOW, 5)
        .expect("ips");
    assert_eq!(
        ips.iter()
            .map(|i| (i.key.as_str(), i.count))
            .collect::<Vec<_>>(),
        [("198.51.100.9", 1)]
    );
}

#[test]
fn scrub_can_target_one_field() {
    let (_d, s) = open();
    s.insert(&private_events()).expect("insert");
    assert_eq!(s.scrub_fields(true, false).expect("scrub"), 40);
    let rows = s
        .requests(&RequestFilter::default(), 100)
        .expect("requests");
    assert!(
        rows.iter()
            .all(|e| e.client_ip.is_empty() && e.user_agent.starts_with("UniqueAgent/"))
    );
    assert!(
        s.top(TopKind::ClientIps, 7 * 86_400, None, NOW, 5)
            .expect("ips")
            .is_empty()
    );
    assert_eq!(
        s.top(TopKind::UserAgents, 7 * 86_400, None, NOW, 10)
            .expect("uas")
            .len(),
        4
    );
    assert_eq!(s.scrub_fields(true, false).expect("again"), 0);
}

#[test]
fn version_one_databases_migrate_forward() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("v1.db");
    {
        let conn = rusqlite::Connection::open(&path).expect("raw");
        conn.execute_batch(crate::schema::MIGRATIONS[0])
            .expect("v1");
        conn.execute_batch(&format!(
            "PRAGMA user_version = 1;
             INSERT INTO dict (id, kind, val) VALUES (1, 7, 'a'), (2, 20, '1.1.1.1'), (3, 2, 'agent');
             INSERT INTO requests (ts, client_ip_id, path, query_len, status, bytes_in, bytes_out, total_ms, ua_id,
                 site_id, resp_ms, bot_score)
             VALUES ({NOW}, 2, '/x', 0, 200, 1, 10, 5, 3, 1, 5, 0), ({NOW}, 2, '/x', 0, 200, 1, 10, 5, 3, 1, 5, 0),
                    ({NOW}, 2, '/y', 0, 200, 1, 10, 5, 3, 1, 5, 0);
             INSERT INTO rollup_dim (hour, site_id, dim, key_id, n, bytes) VALUES ({}, 1, 3, 5, 4, 9);",
            NOW / HOUR
        ))
        .expect("seed");
    }
    let s = Store::open(&path, StoreOptions::default()).expect("migrate");
    let conn = rusqlite::Connection::open(&path).expect("raw");
    let one = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).expect(sql) };
    assert_eq!(one("PRAGMA user_version"), SCHEMA_VERSION);
    assert_eq!(
        one("SELECT n FROM rollup_dim WHERE dim = 3 AND site_id = 1 AND key_id = 5"),
        4
    );
    assert_eq!(
        one("SELECT n FROM rollup_dim WHERE dim = 3 AND site_id = -1 AND key_id = 5"),
        4
    );
    assert_eq!(
        one("SELECT n FROM rollup_dim WHERE dim = 10 AND site_id = -1 AND key_id = 2"),
        3
    );
    assert_eq!(
        one("SELECT n FROM rollup_dim WHERE dim = 11 AND site_id = 1 AND key_id = 3"),
        3
    );
    assert_eq!(
        one("SELECT n FROM rollup_path WHERE site_id = -1 AND path = '/x'"),
        2
    );
    assert_eq!(
        one(
            "SELECT count(*) FROM sqlite_master WHERE name IN ('idx_requests_ip_ts', 'idx_requests_path')"
        ),
        0
    );
    assert_eq!(
        one("SELECT count(*) FROM sqlite_master WHERE name = 'idx_requests_ip_bucket'"),
        1
    );
    let paths = s
        .top(TopKind::Paths, 7 * 86_400, None, NOW, 5)
        .expect("paths");
    assert_eq!(
        paths
            .iter()
            .map(|i| (i.key.as_str(), i.count))
            .collect::<Vec<_>>(),
        [("/x", 2), ("/y", 1)]
    );
    let ips = s
        .top(TopKind::ClientIps, 7 * 86_400, Some("a"), NOW, 5)
        .expect("ips");
    assert_eq!(ips.len(), 1);
    assert_eq!(ips[0].count, 3);
    let f = RequestFilter {
        ip: Some("1.1.1.1".into()),
        ..RequestFilter::default()
    };
    assert_eq!(s.requests(&f, 10).expect("by ip").len(), 3);
}

#[test]
fn ip_filter_uses_the_bucket_index() {
    let (_d, s) = open();
    s.insert(&private_events()).expect("insert");
    let mut w = queries::Where::default();
    queries::ip_filter(&mut w, "203.0.113.70");
    let sql = format!(
        "EXPLAIN QUERY PLAN SELECT id FROM requests r{} ORDER BY ts DESC LIMIT 5",
        w.clause()
    );
    // Column 3 of EXPLAIN QUERY PLAN is the detail text, which names the index used.
    let plan = s
        .inner
        .read(|c| {
            let mut stmt = c.prepare(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(w.bind([]).iter()), |r| {
                r.get::<_, String>(3)
            })?;
            Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?.join("; "))
        })
        .expect("plan");
    assert!(plan.contains("idx_requests_ip_bucket"), "{plan}");
    let f = RequestFilter {
        ip: Some("203.0.113.70".into()),
        ..RequestFilter::default()
    };
    assert_eq!(s.requests(&f, 100).expect("ip").len(), 14);
}

#[test]
fn top_rollup_keeps_only_the_heaviest_keys_per_batch() {
    // One hot path among 200 one-off paths in a single batch must survive the per-batch cut.
    let (_d, s) = open();
    let mut batch: Vec<LogEvent> = (0..200)
        .map(|i| {
            let mut e = ev(NOW - 1000);
            e.path = format!("/rare/{i}");
            e
        })
        .collect();
    for _ in 0..30 {
        let mut e = ev(NOW - 1000);
        e.path = "/hot".into();
        batch.push(e);
    }
    s.insert(&batch).expect("insert");
    let top = s
        .top(TopKind::Paths, 7 * 86_400, None, NOW, 3)
        .expect("top");
    assert_eq!((top[0].key.as_str(), top[0].count), ("/hot", 30));
    let kept: i64 = s
        .inner
        .read(|c| {
            Ok(c.query_row(
                "SELECT count(*) FROM rollup_path WHERE site_id = -1",
                [],
                |r| r.get(0),
            )?)
        })
        .expect("count");
    assert_eq!(kept as usize, crate::schema::TOP_KEEP);
    assert_eq!(
        s.top(TopKind::Paths, 7 * 86_400, None, NOW, 1000)
            .expect("raw")
            .len(),
        201
    );
}

#[test]
#[ignore = "throughput benchmark; run with --release --ignored --nocapture"]
fn bench_one_million_events() {
    fn timed<T>(label: &str, f: impl FnOnce() -> T) -> T {
        let start = Instant::now();
        let out = f();
        println!("{label:<28} {:>10.2?}", start.elapsed());
        out
    }
    let (_d, s) = open();
    let total = 1_000_000u64;
    let span = 7 * DAY;
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let statuses = [200u16, 200, 200, 200, 301, 304, 404, 500];
    let start = Instant::now();
    let mut done = 0u64;
    while done < total {
        let batch: Vec<LogEvent> = (0..5000u64)
            .map(|j| {
                let i = done + j;
                let r = next();
                let mut e = ev(NOW - span + i64::try_from(i).expect("i") * span / total as i64);
                e.client_ip = format!("10.{}.{}.{}", r % 7, (r >> 8) % 250, (r >> 16) % 250);
                e.host = format!("site{}.example.test", r % 12);
                e.site = format!("site{}", r % 12);
                e.path = format!("/page/{}/item/{}", (r >> 24) % 400, (r >> 32) % 50);
                e.method = ["GET", "GET", "GET", "POST", "HEAD"][(r % 5) as usize].into();
                e.status = statuses[((r >> 5) % 8) as usize];
                e.bytes_out = (r >> 40) % 2_000_000;
                e.total_ms = u32::try_from((r >> 12) % 800).expect("ms");
                e.user_agent = format!("Mozilla/5.0 agent-{}", (r >> 20) % 300);
                e.referer = format!("https://ref{}.example.test/", (r >> 28) % 40);
                e.accept_language =
                    ["en-US,en;q=0.9", "de-DE", "fr-FR", "ja-JP"][((r >> 3) % 4) as usize].into();
                e.bot_class =
                    ["human", "human", "human", "crawler", "scraper"][(r % 5) as usize].into();
                e.bot_score = u8::try_from((r >> 9) % 100).expect("score");
                e.bot_signals = ["", "headless", "no_referer,no_lang"][(r % 3) as usize].into();
                e
            })
            .collect();
        s.insert(&batch).expect("insert");
        done += 5000;
    }
    let elapsed = start.elapsed();
    println!(
        "insert: {total} events in {elapsed:.2?} = {:.0} events/s",
        total as f64 / elapsed.as_secs_f64()
    );
    let st = s.stats().expect("stats");
    println!(
        "rows {} db_bytes {} ({:.1} bytes/event)",
        st.rows,
        st.db_bytes,
        st.db_bytes as f64 / st.rows as f64
    );
    timed("summary 1h (raw)", || {
        s.summary(3600, None, NOW).expect("q")
    });
    timed("summary 7d (rollup)", || {
        s.summary(7 * 86_400, None, NOW).expect("q")
    });
    timed("summary 7d site", || {
        s.summary(7 * 86_400, Some("site3"), NOW).expect("q")
    });
    timed("timeseries 1h (raw)", || {
        s.timeseries(3600, None, NOW).expect("q")
    });
    timed("timeseries 24h (raw)", || {
        s.timeseries(86_400, None, NOW).expect("q")
    });
    timed("timeseries 7d (rollup)", || {
        s.timeseries(7 * 86_400, None, NOW).expect("q")
    });
    timed("requests newest 100", || {
        s.requests(&RequestFilter::default(), 100).expect("q")
    });
    timed("requests status=500 x100", || {
        let f = RequestFilter {
            status: Some(500),
            ..RequestFilter::default()
        };
        s.requests(&f, 100).expect("q")
    });
    timed("bots 1h (raw)", || s.bots(3600, None, NOW).expect("q"));
    timed("bots 7d (rollup)", || {
        s.bots(7 * 86_400, None, NOW).expect("q")
    });
    timed("top paths 7d", || {
        s.top(TopKind::Paths, 7 * 86_400, None, NOW, 20).expect("q")
    });
    timed("top hosts 7d (rollup)", || {
        s.top(TopKind::Hosts, 7 * 86_400, None, NOW, 20).expect("q")
    });
    timed("export 100k csv", || {
        let f = ExportFilter {
            limit: Some(100_000),
            ..ExportFilter::default()
        };
        s.export_csv(std::io::sink(), ExportKind::Requests, &f)
            .expect("q")
    });
    assert_eq!(st.rows, total);
}

fn flood_paths(s: &Store, count: usize, width: usize) {
    let pad = "p".repeat(width);
    for chunk in 0..count.div_ceil(2500) {
        let batch: Vec<LogEvent> = (0..2500.min(count - chunk * 2500))
            .map(|j| {
                let i = chunk * 2500 + j;
                let mut e = ev(NOW - 1000 - (i as i64 % 100));
                e.path = format!("/flood/{i}/{pad}");
                e
            })
            .collect();
        s.insert(&batch).expect("insert");
    }
}

#[test]
fn readers_spill_sorts_to_disk_and_cap_memory() {
    // temp_store 2 means MEMORY; large sorts must spill to disk under a heap limit instead.
    let (_d, s) = open();
    let (temp, soft, hard): (i64, i64, i64) = s
        .inner
        .read(|c| {
            Ok((
                c.query_row("PRAGMA temp_store", [], |r| r.get(0))?,
                c.query_row("PRAGMA soft_heap_limit", [], |r| r.get(0))?,
                c.query_row("PRAGMA hard_heap_limit", [], |r| r.get(0))?,
            ))
        })
        .expect("pragmas");
    assert_ne!(temp, 2, "readers must not keep sorter spills in memory");
    assert!(soft > 0 && hard >= soft, "soft {soft} hard {hard}");
}

#[test]
fn path_tops_over_unique_long_paths_finish_within_the_budget() {
    // Unique 2000-byte paths are the worst case for grouping; the 60 s bound only guards against pathological slowdowns.
    let (_d, s) = open();
    flood_paths(&s, 20_000, 2000);
    let start = Instant::now();
    for (window, limit) in [(3600, 20), (3600, 500), (7 * 86_400, 500), (7 * 86_400, 20)] {
        let top = s
            .top(TopKind::Paths, window, None, NOW, limit)
            .expect("top paths");
        assert_eq!(top.len(), limit);
        assert_eq!(top[0].count, 1);
    }
    let sum = s.summary(3600, None, NOW).expect("summary");
    assert_eq!(sum.top_paths.len(), 20);
    assert!(
        start.elapsed() < Duration::from_secs(60),
        "{:?}",
        start.elapsed()
    );
    let f = ExportFilter::default();
    let (n, _) = export(&s, ExportKind::Top(TopKind::Paths), &f);
    assert_eq!(n, 20_000);
}

#[test]
fn a_query_past_its_deadline_is_cancelled_with_a_clear_error() {
    // A 1 microsecond budget expires on any real query; exports are covered through export_timeout.
    let (_d, s) = open_with(StoreOptions {
        query_timeout: Duration::from_micros(1),
        export_timeout: Duration::from_micros(1),
        ..StoreOptions::default()
    });
    flood_paths(&s, 5000, 200);
    let start = Instant::now();
    for result in [
        s.top(TopKind::Paths, 3600, None, NOW, 100).map(|_| ()),
        s.summary(3600, None, NOW).map(|_| ()),
        s.bots(3600, None, NOW).map(|_| ()),
        s.requests(&RequestFilter::default(), 100).map(|_| ()),
    ] {
        let err = result.expect_err("deadline");
        assert!(matches!(err, Error::Timeout), "{err:?}");
        assert!(err.to_string().contains("time limit"));
    }
    let mut sink = Vec::new();
    let err = s
        .export_csv(
            &mut sink,
            ExportKind::Top(TopKind::Paths),
            &ExportFilter::default(),
        )
        .expect_err("export deadline");
    assert!(matches!(err, Error::Timeout), "{err:?}");
    assert!(start.elapsed() < Duration::from_secs(30));
}

#[test]
fn a_cancelled_query_leaves_the_reader_usable() {
    let (_d, s) = open();
    // The self-join cannot finish within 1 microsecond; a pooled reader must still work afterwards.
    flood_paths(&s, 3000, 100);
    let err = s
        .inner
        .read_within_for_test(Duration::from_micros(1), |c| {
            Ok(c.query_row(
                "SELECT count(*) FROM requests a, requests b WHERE a.id < b.id",
                [],
                |r| r.get::<_, i64>(0),
            )?)
        })
        .expect_err("cancelled");
    assert!(matches!(err, Error::Timeout), "{err:?}");
    assert_eq!(rows(&s), 3000);
}

#[test]
fn hourly_export_pages_through_more_rows_than_one_page() {
    let (_d, s) = open();
    let batch: Vec<LogEvent> = (0..2300).map(|i| ev(NOW - i * HOUR)).collect();
    s.insert(&batch).expect("insert");
    let (n, csv) = export(&s, ExportKind::Hourly, &ExportFilter::default());
    assert_eq!(n, 2300);
    let table = parse_csv(&csv);
    assert_eq!(table.len(), 2301);
    let stamps: Vec<i64> = table[1..]
        .iter()
        .map(|r| r[1].parse().expect("ts"))
        .collect();
    assert!(stamps.windows(2).all(|w| w[0] < w[1]));
    let capped = ExportFilter {
        limit: Some(2100),
        ..ExportFilter::default()
    };
    assert_eq!(export(&s, ExportKind::Hourly, &capped).0, 2100);
}

fn db_and_wal_contain(dir: &Path, needle: &[u8]) -> bool {
    file_contains(&dir.join("events.db"), needle)
        || file_contains(&dir.join("events.db-wal"), needle)
}

#[test]
fn retention_erases_path_rollups_and_dictionary_text_of_expired_rows() {
    let dir = tempfile::tempdir().expect("tempdir");
    let s = Store::open(&dir.path().join("events.db"), StoreOptions::default()).expect("open");
    s.set_retention_days(1);
    let mut events: Vec<LogEvent> = (0..30)
        .map(|i| {
            let mut e = ev(NOW - 3 * DAY - i);
            e.client_ip = format!("198.51.100.{i}");
            e.user_agent = format!("ExpiredAgent/{i}");
            e.referer = format!("https://expired-ref.example/{i}");
            e.host = format!("expired-host-{i}.test");
            e.path = format!("/expired-path/{i}");
            e
        })
        .collect();
    events.extend((0..5).map(|i| {
        let mut e = ev(NOW - 1000 - i);
        e.client_ip = "192.0.2.77".into();
        e.user_agent = "FreshAgent/1".into();
        e.path = "/fresh".into();
        e
    }));
    s.insert(&events).expect("insert");
    s.checkpoint().expect("checkpoint");
    assert!(db_and_wal_contain(dir.path(), b"ExpiredAgent"), "sanity");

    let report = s.prune(NOW).expect("prune");
    assert_eq!(report.expired_rows, 30);
    assert!(report.dict_rows_removed >= 120, "{report}");
    s.checkpoint().expect("checkpoint");
    for needle in [
        &b"198.51.100."[..],
        b"ExpiredAgent",
        b"expired-ref.example",
        b"expired-host-",
    ] {
        assert!(
            !db_and_wal_contain(dir.path(), needle),
            "{:?} survived retention",
            String::from_utf8_lossy(needle)
        );
    }
    let (path_rows, dict_rows): (i64, i64) = s
        .inner
        .read(|c| {
            Ok((
                c.query_row(
                    "SELECT count(*) FROM rollup_path WHERE path LIKE '/expired-path/%'",
                    [],
                    |r| r.get(0),
                )?,
                c.query_row(
                    "SELECT count(*) FROM dict WHERE val LIKE 'ExpiredAgent/%'",
                    [],
                    |r| r.get(0),
                )?,
            ))
        })
        .expect("counts");
    assert_eq!((path_rows, dict_rows), (0, 0));

    let live = s.requests(&RequestFilter::default(), 100).expect("rows");
    assert_eq!(live.len(), 5);
    assert!(
        live.iter()
            .all(|e| e.client_ip == "192.0.2.77" && e.user_agent == "FreshAgent/1")
    );
    let mut again = ev(NOW + 10);
    again.client_ip = "198.51.100.3".into();
    again.user_agent = "ExpiredAgent/3".into();
    again.referer = "https://expired-ref.example/3".into();
    s.insert(&[again.clone()]).expect("reinsert");
    let back = s.requests(&RequestFilter::default(), 1).expect("newest");
    assert_eq!(back, vec![again]);
    s.integrity_check().expect("integrity");
}

#[test]
fn the_dictionary_sweep_spares_ids_inserts_used_after_tracking_began() {
    let (_d, s) = open();
    let mut a = ev(NOW);
    a.user_agent = "OrphanA".into();
    let mut b = ev(NOW);
    b.user_agent = "OrphanB".into();
    s.insert(&[a.clone(), b.clone()]).expect("insert");
    s.inner
        .lock_writer()
        .conn
        .execute_batch("DELETE FROM requests; DELETE FROM rollup_dim;")
        .expect("orphan");
    s.inner.lock_writer().track_ids();
    let candidates = s.inner.read_long(crate::gc::unreferenced).expect("scan");
    // OrphanA is re-inserted after the scan and orphaned again; tracking must still spare it.
    s.insert(&[a.clone()]).expect("insert during sweep");
    s.inner
        .lock_writer()
        .conn
        .execute_batch("DELETE FROM requests; DELETE FROM rollup_dim;")
        .expect("orphan again");
    let swept = s.inner.delete_unreferenced(&candidates).expect("sweep");
    s.inner.lock_writer().finish_tracking();
    let present = |val: &str| -> i64 {
        s.inner
            .read(|c| {
                Ok(
                    c.query_row("SELECT count(*) FROM dict WHERE val = ?1", [val], |r| {
                        r.get(0)
                    })?,
                )
            })
            .expect("count")
    };
    assert_eq!((present("OrphanA"), present("OrphanB")), (1, 0));
    assert!(swept.removed >= 1);
    s.insert(&[a.clone(), b.clone()]).expect("reinsert");
    let back = s.requests(&RequestFilter::default(), 2).expect("rows");
    assert!(back.iter().any(|e| e.user_agent == "OrphanA"));
    assert!(back.iter().any(|e| e.user_agent == "OrphanB"));
}

#[test]
fn a_budget_below_the_data_trim_cannot_remove_deletes_nothing() {
    let (_d, s) = open();
    s.set_retention_days(0);
    // 2500 unique 1 KB agents put the dictionary alone far above the 1 MiB budget, which row trimming cannot shrink.
    let pad = "u".repeat(1000);
    let batch: Vec<LogEvent> = (0..2500)
        .map(|i| {
            let mut e = ev(NOW - 1000 - i);
            e.user_agent = format!("ua-{i}-{pad}");
            e
        })
        .collect();
    s.insert(&batch).expect("insert");
    s.set_max_bytes(Some(1024 * 1024));
    let report = s.prune(NOW).expect("prune");
    assert!(report.trim_blocked, "{report:?}");
    assert_eq!(report.trimmed_rows, 0);
    assert_eq!(rows(&s), 2500);
}

#[test]
fn a_burst_over_the_budget_is_trimmed_across_passes_not_in_one() {
    let (_d, s) = open();
    s.set_retention_days(0);
    for chunk in 0..6 {
        let batch: Vec<LogEvent> = (0..5000)
            .map(|j| {
                let i = chunk * 5000 + j;
                let mut e = ev(NOW - 40_000_000 + i * 1000);
                e.path = format!("/p/{i}/{}", "x".repeat(40));
                e
            })
            .collect();
        s.insert(&batch).expect("insert");
    }
    let live = s.inner.live_bytes().expect("live");
    // At two thirds of the size the database is under 2x over the cap, so the per-pass share limit applies: 25% of 30000 rows.
    let cap = live / 3 * 2;
    s.set_max_bytes(Some(cap));
    let first = s.prune(NOW).expect("first pass");
    assert!(first.trim_limited, "{first:?}");
    assert_eq!(first.trimmed_rows, 7500);
    assert_eq!(rows(&s), 22_500);
    let mut passes = 1;
    let mut last = first;
    while last.bytes_after > cap && passes < 10 {
        last = s.prune(NOW).expect("later pass");
        passes += 1;
    }
    assert!(last.bytes_after <= cap, "{last:?}");
    assert!(passes >= 2 && rows(&s) > 10_000);
}

#[test]
fn switched_off_fields_are_stripped_when_events_commit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let s = Store::open(&dir.path().join("events.db"), StoreOptions::default()).expect("open");
    s.set_privacy(false, true);
    // The address is dropped at commit, so it must not reach the file even through the WAL.
    let mut e = ev(NOW);
    e.client_ip = "203.0.113.200".into();
    e.user_agent = "KeptAgent".into();
    s.insert(&[e]).expect("insert");
    let back = s.requests(&RequestFilter::default(), 1).expect("rows");
    assert_eq!(
        (back[0].client_ip.as_str(), back[0].user_agent.as_str()),
        ("", "KeptAgent")
    );
    s.checkpoint().expect("checkpoint");
    assert!(!db_and_wal_contain(dir.path(), b"203.0.113.200"));
    s.set_privacy(true, true);
    let mut e = ev(NOW);
    e.client_ip = "203.0.113.201".into();
    s.insert(&[e]).expect("insert");
    assert_eq!(
        s.requests(&RequestFilter::default(), 1).expect("rows")[0].client_ip,
        "203.0.113.201"
    );
}

#[test]
fn events_queued_before_a_privacy_switch_leave_no_trace_after_a_scrub() {
    let dir = tempfile::tempdir().expect("tempdir");
    // A huge batch size and a 30 s timer keep the 3000 events queued until scrub_fields flushes the writer.
    let opts = StoreOptions {
        flush_interval: Duration::from_secs(30),
        batch_size: 100_000,
        ..StoreOptions::default()
    };
    let s = Store::open(&dir.path().join("events.db"), opts).expect("open");
    s.insert(&private_events()).expect("history");
    let w = s.writer();
    for i in 0..3000 {
        let mut e = ev(NOW - 1000);
        e.client_ip = format!("203.0.113.{}", 100 + i % 50);
        e.user_agent = format!("QueuedAgent/{}", i % 7);
        w.send(e).expect("send");
    }
    s.set_privacy(false, false);
    s.scrub_fields(true, true).expect("scrub");
    w.flush().expect("flush");
    s.checkpoint().expect("checkpoint");
    for needle in [&b"203.0.113."[..], b"QueuedAgent", b"UniqueAgent"] {
        assert!(!db_and_wal_contain(dir.path(), needle), "{needle:?}");
    }
    assert_eq!(rows(&s), 3040);
    let all = s.requests(&RequestFilter::default(), 5000).expect("rows");
    assert!(
        all.iter()
            .all(|e| e.client_ip.is_empty() && e.user_agent.is_empty())
    );
}

#[cfg(unix)]
#[test]
fn loose_modes_on_existing_files_and_directory_are_tightened_on_open() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().expect("tempdir");
    let folder = root.path().join("data");
    std::fs::create_dir(&folder).expect("mkdir");
    let path = folder.join("events.db");
    let side = [
        path.clone(),
        folder.join("events.db-wal"),
        folder.join("events.db-shm"),
    ];
    for p in &side {
        std::fs::write(p, b"").expect("create");
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    }
    std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o755)).expect("chmod dir");
    let s = Store::open(&path, StoreOptions::default()).expect("open");
    s.insert(&[ev(NOW)]).expect("insert");
    let mode = |p: &Path| std::fs::metadata(p).expect("meta").permissions().mode() & 0o777;
    assert_eq!(mode(&folder), 0o700);
    for p in &side {
        if p.exists() {
            assert_eq!(mode(p) & 0o077, 0, "{}", p.display());
        }
    }
}

#[test]
fn an_incomplete_checkpoint_is_reported_and_retried_by_the_next_prune() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("events.db");
    let s = Store::open(&path, StoreOptions::default()).expect("open");
    s.insert(&private_events()).expect("insert");
    // An open read transaction pins a WAL snapshot, so truncating the log cannot finish while it is held.
    let holder = rusqlite::Connection::open(&path).expect("reader");
    holder.execute_batch("BEGIN").expect("begin");
    holder
        .query_row("SELECT count(*) FROM requests", [], |r| r.get::<_, i64>(0))
        .expect("pin snapshot");
    let mut more = ev(NOW + 1);
    more.client_ip = "203.0.113.250".into();
    s.insert(&[more]).expect("insert while pinned");
    let err = s
        .scrub_fields(true, true)
        .expect_err("scrub must report the stuck log");
    assert!(matches!(err, Error::Incomplete(_)), "{err:?}");
    assert!(s.inner.wal_dirty.load(std::sync::atomic::Ordering::Relaxed));
    holder.execute_batch("COMMIT").expect("release");
    drop(holder);
    s.prune(NOW).expect("prune");
    assert!(!s.inner.wal_dirty.load(std::sync::atomic::Ordering::Relaxed));
    assert!(!db_and_wal_contain(dir.path(), b"203.0.113."));
}
