use cite_client::{
    AnalyticsMeta, AnalyticsQuery, BlockedFilter, CompareDelta, DeltaValue, FacetValue, Facets,
};
use cite_edge::analytics::{Summary, Timeseries, TopItem};
use cite_edge::bot::BotSummary;
use cite_edge::model::LogEvent;

const METHOD_SHARE: [(&str, f64); 6] = [
    ("GET", 0.78),
    ("POST", 0.14),
    ("PUT", 0.03),
    ("PATCH", 0.02),
    ("DELETE", 0.02),
    ("HEAD", 0.01),
];
const CLASS_SHARE: [(&str, f64); 4] = [("2xx", 0.86), ("3xx", 0.06), ("4xx", 0.06), ("5xx", 0.02)];
const BOT_SHARE: [(&str, f64); 5] = [
    ("human", 0.62),
    ("suspect", 0.08),
    ("crawler", 0.14),
    ("tool", 0.10),
    ("bot", 0.06),
];
const REFERERS: [&str; 5] = [
    "",
    "https://www.google.com/",
    "https://news.ycombinator.com/",
    "https://www.example.com/blog",
    "",
];
const CONTENT_TYPES: [&str; 5] = [
    "text/html",
    "application/json",
    "text/css",
    "image/webp",
    "application/javascript",
];

fn share_of(table: &[(&str, f64)], picked: &[String]) -> f64 {
    if picked.is_empty() {
        return 1.0;
    }
    table
        .iter()
        .filter(|(k, _)| picked.iter().any(|p| p.eq_ignore_ascii_case(k)))
        .map(|(_, s)| s)
        .sum()
}

// The smallest generated window that covers the asked span, so a custom range gets data of about the right size.
pub fn preset_for(span_secs: u64) -> &'static str {
    [("15m", 900), ("1h", 3600), ("24h", 86_400), ("7d", 604_800)]
        .into_iter()
        .find(|(_, secs)| span_secs <= *secs)
        .map_or("30d", |(name, _)| name)
}

pub fn delta_value(current: f64, previous: f64) -> DeltaValue {
    DeltaValue {
        current,
        previous,
        abs: current - previous,
        pct: (previous != 0.0).then(|| (current - previous) / previous * 100.0),
    }
}

pub fn compare_delta(cur: &Summary, prev: &Summary) -> CompareDelta {
    let d = |c: f64, p: f64| delta_value(c, p);
    CompareDelta {
        requests: d(cur.requests as f64, prev.requests as f64),
        bytes_in: d(cur.bytes_in as f64, prev.bytes_in as f64),
        bytes_out: d(cur.bytes_out as f64, prev.bytes_out as f64),
        blocked: d(cur.blocked as f64, prev.blocked as f64),
        errors_4xx: d(cur.errors_4xx as f64, prev.errors_4xx as f64),
        errors_5xx: d(cur.errors_5xx as f64, prev.errors_5xx as f64),
        avg_ms: d(cur.avg_ms, prev.avg_ms),
        p50_ms: d(cur.p50_ms as f64, prev.p50_ms as f64),
        p95_ms: d(cur.p95_ms as f64, prev.p95_ms as f64),
        p99_ms: d(cur.p99_ms as f64, prev.p99_ms as f64),
    }
}

pub fn scale_top(items: &[TopItem], f: f64) -> Vec<TopItem> {
    scale_items(items, f)
}

fn sc(n: u64, f: f64) -> u64 {
    (n as f64 * f).round() as u64
}

// The fraction of traffic a filter keeps, so every number on the demo page shrinks the way a real filter would.
pub fn selectivity(q: &AnalyticsQuery, site_count: usize) -> f64 {
    let mut f = 1.0;
    if !q.sites.is_empty() && site_count > 0 {
        f *= q.sites.len().min(site_count) as f64 / site_count as f64;
    }
    f *= share_of(&METHOD_SHARE, &q.methods);
    f *= share_of(&CLASS_SHARE, &q.status_classes);
    if let Some(s) = q.status {
        let class = format!("{}xx", s / 100);
        f *= share_of(&CLASS_SHARE, &[class]) / 3.0;
    }
    f *= match &q.blocked {
        None => 1.0,
        Some(BlockedFilter::Blocked) => 0.04,
        Some(BlockedFilter::Unblocked) => 0.96,
        Some(BlockedFilter::Rule(_)) => 0.02,
    };
    f *= share_of(&BOT_SHARE, &q.bot_classes);
    if let Some(min) = q.min_bot_score {
        f *= (1.0 - f64::from(min) / 100.0).max(0.02);
    }
    if let Some(max) = q.max_bot_score {
        f *= (f64::from(max) / 100.0).max(0.02);
    }
    for (set, share) in [
        (q.host.is_some(), 0.35),
        (q.path_prefix.is_some(), 0.4),
        (q.path_exact.is_some(), 0.05),
        (q.user_agent.is_some(), 0.1),
        (q.referer.is_some(), 0.15),
        (q.content_type.is_some(), 0.3),
    ] {
        if set {
            f *= share;
        }
    }
    if let Some(ip) = &q.client_ip {
        f *= if ip.contains('/') { 0.1 } else { 0.02 };
    }
    if let Some(ms) = q.min_duration_ms {
        f *= (1.0 - f64::from(ms) / 400.0).clamp(0.02, 1.0);
    }
    f.clamp(0.0005, 1.0)
}

fn scale_items(items: &[TopItem], f: f64) -> Vec<TopItem> {
    items
        .iter()
        .map(|t| TopItem {
            key: t.key.clone(),
            count: sc(t.count, f),
            bytes: sc(t.bytes, f),
        })
        .filter(|t| t.count > 0)
        .collect()
}

fn excludes_errors(q: &AnalyticsQuery) -> bool {
    !q.status_classes.is_empty() && !q.status_classes.iter().any(|c| c == "4xx" || c == "5xx")
}

// A full summary reduced to what the filter keeps.
pub fn narrow_summary(base: &Summary, q: &AnalyticsQuery, f: f64) -> Summary {
    let mut s = base.clone();
    s.requests = sc(base.requests, f);
    s.bytes_in = sc(base.bytes_in, f);
    s.bytes_out = sc(base.bytes_out, f);
    s.blocked = sc(base.blocked, f);
    s.status = base
        .status
        .iter()
        .map(|(k, v)| (k.clone(), sc(*v, f)))
        .filter(|(k, _)| {
            let by_class = q.status_classes.is_empty() || q.status_classes.contains(k);
            let by_code = q.status.is_none_or(|c| *k == format!("{}xx", c / 100));
            by_class && by_code
        })
        .collect();
    s.errors_4xx = s.status.get("4xx").copied().unwrap_or(0);
    s.errors_5xx = s.status.get("5xx").copied().unwrap_or(0);
    s.methods = base
        .methods
        .iter()
        .map(|(k, v)| (k.clone(), sc(*v, f)))
        .filter(|(k, _)| {
            q.methods.is_empty() || q.methods.iter().any(|m| m.eq_ignore_ascii_case(k))
        })
        .collect();
    s.content_types = base
        .content_types
        .iter()
        .map(|(k, v)| (k.clone(), sc(*v, f)))
        .filter(|(k, _)| q.content_type.as_deref().is_none_or(|t| k.starts_with(t)))
        .collect();
    for b in &mut s.sizes {
        b.count = sc(b.count, f);
    }
    s.top_paths = scale_items(&base.top_paths, f);
    if let Some(prefix) = &q.path_prefix {
        s.top_paths.retain(|t| t.key.starts_with(prefix.as_str()));
    }
    if let Some(path) = &q.path_exact {
        s.top_paths = vec![TopItem {
            key: path.clone(),
            count: s.requests,
            bytes: s.bytes_out,
        }];
    }
    s.top_ips = scale_items(&base.top_ips, f);
    if let Some(ip) = q.client_ip.as_ref().filter(|ip| !ip.contains('/')) {
        s.top_ips = vec![TopItem {
            key: ip.clone(),
            count: s.requests,
            bytes: s.bytes_out,
        }];
    }
    s.top_user_agents = scale_items(&base.top_user_agents, f);
    if let Some(ua) = &q.user_agent {
        let needle = ua.to_lowercase();
        s.top_user_agents
            .retain(|t| t.key.to_lowercase().contains(&needle));
    }
    s.top_hosts = scale_items(&base.top_hosts, f);
    if let Some(host) = &q.host {
        s.top_hosts = vec![TopItem {
            key: host.clone(),
            count: s.requests,
            bytes: s.bytes_out,
        }];
    }
    s.top_blocked = scale_items(&base.top_blocked, f);
    match &q.blocked {
        Some(BlockedFilter::Unblocked) => {
            s.blocked = 0;
            s.top_blocked.clear();
        }
        Some(BlockedFilter::Blocked) => s.blocked = s.requests,
        _ => {}
    }
    if let Some(min) = q.min_duration_ms {
        let min = u64::from(min);
        s.p50_ms = s.p50_ms.max(min);
        s.p95_ms = s.p95_ms.max(min * 2);
        s.p99_ms = s.p99_ms.max(min * 3);
        s.avg_ms = s.avg_ms.max(min as f64 * 1.3);
    }
    s
}

pub fn narrow_series(base: &Timeseries, q: &AnalyticsQuery, f: f64) -> Timeseries {
    let no_errors = excludes_errors(q);
    let mut out = base.clone();
    for p in &mut out.points {
        p.requests = sc(p.requests, f);
        p.bytes_out = sc(p.bytes_out, f);
        p.errors = if no_errors { 0 } else { sc(p.errors, f) };
        p.blocked = match &q.blocked {
            Some(BlockedFilter::Unblocked) => 0,
            _ => sc(p.blocked, f),
        };
    }
    out
}

pub fn narrow_bots(base: &BotSummary, q: &AnalyticsQuery, f: f64) -> BotSummary {
    let mut b = base.clone();
    b.classes = scale_items(&base.classes, f);
    if !q.bot_classes.is_empty() {
        b.classes
            .retain(|c| q.bot_classes.iter().any(|k| k.eq_ignore_ascii_case(&c.key)));
        b.total_requests = b.classes.iter().map(|c| c.count).sum();
    } else {
        b.total_requests = sc(base.total_requests, f);
    }
    b.bot_requests = b
        .classes
        .iter()
        .filter(|c| !c.key.eq_ignore_ascii_case("human"))
        .map(|c| c.count)
        .sum();
    b.bot_share_pct = if b.total_requests == 0 {
        0.0
    } else {
        b.bot_requests as f64 * 100.0 / b.total_requests as f64
    };
    b.signals = scale_items(&base.signals, f);
    b.agents = scale_items(&base.agents, f);
    b.score_buckets = scale_items(&base.score_buckets, f);
    b
}

// The period before: a bit quieter, with more errors and slower tails, so the deltas show both colours.
pub fn previous_of(cur: &Summary) -> Summary {
    let mut p = cur.clone();
    p.requests = sc(cur.requests, 0.87);
    p.bytes_in = sc(cur.bytes_in, 0.9);
    p.bytes_out = sc(cur.bytes_out, 0.88);
    p.blocked = sc(cur.blocked, 0.7);
    p.errors_4xx = sc(cur.errors_4xx, 1.3);
    p.errors_5xx = sc(cur.errors_5xx, 0.6);
    p.avg_ms = cur.avg_ms * 0.92;
    p.p50_ms = sc(cur.p50_ms, 0.95);
    p.p95_ms = sc(cur.p95_ms, 0.9);
    p.p99_ms = sc(cur.p99_ms, 1.1);
    p
}

fn facet_list(total: u64, shares: &[(String, f64)]) -> Vec<FacetValue> {
    let mut out: Vec<FacetValue> = shares
        .iter()
        .map(|(k, s)| FacetValue {
            key: k.clone(),
            count: sc(total, *s),
        })
        .filter(|v| v.count > 0)
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
    out
}

fn weights(n: usize) -> Vec<f64> {
    let raw: Vec<f64> = (0..n).map(|i| 1.0 / (i as f64 + 2.0)).collect();
    let sum: f64 = raw.iter().sum();
    raw.into_iter().map(|w| w / sum).collect()
}

// Sites and hosts get falling shares of the traffic; methods, status classes and bot classes use fixed ones.
pub fn facets_for(total: u64, sites: &[(String, Vec<String>)]) -> Facets {
    let w = weights(sites.len());
    let site: Vec<(String, f64)> = sites
        .iter()
        .zip(&w)
        .map(|((id, _), w)| (id.clone(), *w))
        .collect();
    let host: Vec<(String, f64)> = sites
        .iter()
        .zip(&w)
        .flat_map(|((_, hosts), w)| {
            let n = hosts.len().max(1) as f64;
            hosts.iter().map(move |h| (h.clone(), w / n))
        })
        .collect();
    let fixed = |t: &[(&str, f64)]| {
        t.iter()
            .map(|(k, s)| (k.to_string(), *s))
            .collect::<Vec<_>>()
    };
    Facets {
        site: facet_list(total, &site),
        host: facet_list(total, &host),
        method: facet_list(total, &fixed(&METHOD_SHARE)),
        status_class: facet_list(total, &fixed(&CLASS_SHARE)),
        bot_class: facet_list(total, &fixed(&BOT_SHARE)),
        meta: AnalyticsMeta::default(),
    }
}

// Events seeded for the current minute, spread over the asked range and given the variety the generator leaves out.
pub fn spread_events(mut events: Vec<LogEvent>, from: i64, to: i64) -> Vec<LogEvent> {
    let n = events.len().max(1) as i64;
    let span = (to - from).max(n);
    for (i, e) in events.iter_mut().enumerate() {
        let i = i as i64;
        e.ts_ms = to - span * i / n - (i * 37) % 900;
        if e.referer.is_empty() {
            e.referer = REFERERS[i as usize % REFERERS.len()].to_string();
        }
        e.content_type = CONTENT_TYPES[(i as usize * 7) % CONTENT_TYPES.len()].to_string();
        if i % 9 == 4 {
            e.method = "POST".into();
        }
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use cite_edge::analytics::Point;

    fn base() -> Summary {
        Summary {
            requests: 10_000,
            bytes_in: 1_000_000,
            bytes_out: 50_000_000,
            blocked: 400,
            errors_4xx: 600,
            errors_5xx: 200,
            avg_ms: 48.0,
            p50_ms: 31,
            p95_ms: 142,
            p99_ms: 380,
            status: [("2xx", 8600u64), ("3xx", 600), ("4xx", 600), ("5xx", 200)]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            methods: [("GET", 7800u64), ("POST", 1400), ("PUT", 800)]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            top_paths: vec![
                TopItem {
                    key: "/".into(),
                    count: 4000,
                    bytes: 100,
                },
                TopItem {
                    key: "/api/items".into(),
                    count: 3000,
                    bytes: 100,
                },
            ],
            top_hosts: vec![TopItem {
                key: "shop.example.com".into(),
                count: 9000,
                bytes: 100,
            }],
            top_blocked: vec![TopItem {
                key: "scanner".into(),
                count: 400,
                bytes: 0,
            }],
            ..Summary::default()
        }
    }

    fn q(edit: fn(AnalyticsQuery) -> AnalyticsQuery) -> AnalyticsQuery {
        edit(AnalyticsQuery::new().window("1h"))
    }

    #[test]
    fn filters_keep_a_plausible_fraction_of_traffic() {
        let all = selectivity(&q(|q| q), 3);
        assert_eq!(all, 1.0);
        let one_site = selectivity(&q(|q| q.site("a")), 3);
        assert!((one_site - 1.0 / 3.0).abs() < 1e-9);
        let narrow = selectivity(
            &q(|q| q.method("POST").status_class("5xx").host("a.com")),
            3,
        );
        assert!(narrow < 0.01 && narrow > 0.0005 - 1e-12);
        assert!(selectivity(&q(|q| q.method("get")), 3) > 0.7);
        assert_eq!(
            selectivity(
                &q(|q| q.path_exact("/x").client_ip("1.2.3.4").min_bot_score(100)),
                3
            ),
            0.0005
        );
        assert!(selectivity(&q(|q| q.site("a").site("b").site("c")), 3) > 0.99);
    }

    #[test]
    fn narrowing_a_summary_follows_the_filter() {
        let f = 0.5;
        let s = narrow_summary(&base(), &q(|q| q), f);
        assert_eq!((s.requests, s.errors_4xx, s.errors_5xx), (5000, 300, 100));
        let five = narrow_summary(&base(), &q(|q| q.status_class("5xx")), 0.02);
        assert_eq!(five.status.len(), 1);
        assert_eq!(five.errors_4xx, 0);
        assert_eq!(five.errors_5xx, 4);
        let post = narrow_summary(&base(), &q(|q| q.method("post")), 0.14);
        assert_eq!(post.methods.len(), 1);
        let host = narrow_summary(&base(), &q(|q| q.host("blog.example.com")), 0.3);
        assert_eq!(host.top_hosts.len(), 1);
        assert_eq!(host.top_hosts[0].key, "blog.example.com");
        assert_eq!(host.top_hosts[0].count, 3000);
        let api = narrow_summary(&base(), &q(|q| q.path_prefix("/api")), 0.4);
        assert_eq!(api.top_paths.len(), 1);
        let unblocked = narrow_summary(&base(), &q(|q| q.blocked(BlockedFilter::Unblocked)), 0.96);
        assert_eq!((unblocked.blocked, unblocked.top_blocked.len()), (0, 0));
        let blocked = narrow_summary(&base(), &q(|q| q.blocked(BlockedFilter::Blocked)), 0.04);
        assert_eq!(blocked.blocked, blocked.requests);
        let slow = narrow_summary(&base(), &q(|q| q.min_duration_ms(500)), 0.1);
        assert!(slow.p50_ms >= 500 && slow.p95_ms >= 1000 && slow.p99_ms >= 1500);
        let exact = narrow_summary(&base(), &q(|q| q.path_exact("/a").status(404)), 0.03);
        assert_eq!(exact.top_paths[0].key, "/a");
        assert_eq!(exact.status.len(), 1);
    }

    #[test]
    fn series_and_bots_narrow_with_the_summary() {
        let series = Timeseries {
            step_secs: 60,
            points: vec![Point {
                ts: 1,
                requests: 100,
                bytes_out: 1000,
                errors: 10,
                blocked: 5,
                avg_ms: 3.0,
            }],
        };
        let all = narrow_series(&series, &q(|q| q), 0.5);
        assert_eq!(
            (
                all.points[0].requests,
                all.points[0].errors,
                all.points[0].blocked
            ),
            (50, 5, 3)
        );
        let ok = narrow_series(
            &series,
            &q(|q| q.status_class("2xx").blocked(BlockedFilter::Unblocked)),
            1.0,
        );
        assert_eq!((ok.points[0].errors, ok.points[0].blocked), (0, 0));
        let bots = BotSummary {
            total_requests: 1000,
            bot_requests: 380,
            bot_share_pct: 38.0,
            classes: vec![
                TopItem {
                    key: "human".into(),
                    count: 620,
                    bytes: 0,
                },
                TopItem {
                    key: "crawler".into(),
                    count: 140,
                    bytes: 0,
                },
                TopItem {
                    key: "tool".into(),
                    count: 100,
                    bytes: 0,
                },
            ],
            ..BotSummary::default()
        };
        let only = narrow_bots(&bots, &q(|q| q.bot_class("crawler")), 0.5);
        assert_eq!((only.total_requests, only.bot_requests), (70, 70));
        assert!((only.bot_share_pct - 100.0).abs() < 1e-9);
        let half = narrow_bots(&bots, &q(|q| q), 0.5);
        assert_eq!(half.total_requests, 500);
        assert_eq!(half.bot_requests, 120);
        let none = narrow_bots(&bots, &q(|q| q.bot_class("bot")), 0.5);
        assert_eq!((none.total_requests, none.bot_share_pct), (0, 0.0));
    }

    #[test]
    fn the_previous_period_differs_in_both_directions() {
        let cur = base();
        let prev = previous_of(&cur);
        assert!(prev.requests < cur.requests);
        assert!(prev.errors_4xx > cur.errors_4xx);
        assert!(prev.errors_5xx < cur.errors_5xx);
        assert!(prev.p99_ms > cur.p99_ms);
    }

    #[test]
    fn spans_pick_the_smallest_covering_window() {
        assert_eq!(preset_for(60), "15m");
        assert_eq!(preset_for(900), "15m");
        assert_eq!(preset_for(901), "1h");
        assert_eq!(preset_for(90_000), "7d");
        assert_eq!(preset_for(10_000_000), "30d");
    }

    #[test]
    fn deltas_have_no_percentage_from_zero() {
        let d = delta_value(150.0, 100.0);
        assert_eq!((d.abs, d.pct), (50.0, Some(50.0)));
        assert_eq!(delta_value(5.0, 0.0).pct, None);
        let all = compare_delta(&base(), &previous_of(&base()));
        assert!(all.requests.pct.unwrap() > 0.0);
        assert!(all.errors_5xx.pct.unwrap() > 0.0 || all.errors_5xx.abs > 0.0);
        assert_eq!(scale_top(&base().top_paths, 0.5)[0].count, 2000);
    }

    #[test]
    fn facets_are_sorted_and_cover_every_dimension() {
        let sites = vec![
            (
                "shop".to_string(),
                vec![
                    "shop.example.com".to_string(),
                    "www.example.com".to_string(),
                ],
            ),
            ("blog".to_string(), vec!["blog.example.com".to_string()]),
        ];
        let f = facets_for(10_000, &sites);
        assert_eq!(f.site[0].key, "shop");
        assert!(f.site[0].count > f.site[1].count);
        assert_eq!(f.host.len(), 3);
        assert_eq!(f.method[0].key, "GET");
        assert_eq!(f.status_class.len(), 4);
        assert_eq!(f.bot_class[0].key, "human");
        assert!(facets_for(100, &[]).site.is_empty());
    }

    #[test]
    fn spread_events_cover_the_range_with_variety() {
        let ev = LogEvent {
            method: "GET".into(),
            ..LogEvent::default()
        };
        let out = spread_events(vec![ev; 100], 1_000_000, 2_000_000);
        assert!(
            out.iter()
                .all(|e| e.ts_ms <= 2_000_000 && e.ts_ms >= 1_000_000)
        );
        assert!(out.windows(2).all(|w| w[0].ts_ms >= w[1].ts_ms));
        assert!(out.iter().any(|e| e.referer.starts_with("https://")));
        assert!(out.iter().any(|e| e.method == "POST"));
        assert!(
            out.iter()
                .map(|e| e.content_type.clone())
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                > 2
        );
    }
}
