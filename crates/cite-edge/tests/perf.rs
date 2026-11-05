// Release-mode timings, run with: cargo test -p cite-edge --release --test perf -- --ignored --nocapture
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use cite_edge::analytics::{Analytics, RequestFilter, write_snapshot};
use cite_edge::logparse::parse_datagram;
use cite_edge::model::{EdgeConfig, FirewallAction, FirewallRule, Matchers, Retention};
use cite_edge::render::{RenderOptions, render};
use cite_edge::validate::validate_config;

struct Counting;
static ALLOCS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}

#[global_allocator]
static A: Counting = Counting;

const NOW: i64 = 1_800_000_000_000;

fn datagram(i: usize, ts: i64) -> Vec<u8> {
    format!(
        "<134>Nov  4 12:00:00 edge haproxy[812]: {ts} 203.0.{}.{} be_site{}_blue app1 GET 200 {} 311 {} 7  site{} HTTP/1.1 TLSv1.3 5 site{}.example.com /p/{}/item%20{} Mozilla%2F5.0+%28X11%3B+Linux%29+AppleWebKit%2F537.36 https%3A%2F%2Fexample.org%2Fa text%2Fhtml%3B+charset%3Dutf-8 text%2Fhtml en-GB gzip same-origin navigate document -",
        (i / 250) % 250,
        i % 250,
        i % 20,
        1000 + (i % 9000),
        5 + (i % 400),
        i % 20,
        i % 20,
        i % 97,
        i % 31,
    )
    .into_bytes()
}

fn filled() -> Analytics {
    let mut a = Analytics::new(Retention::default());
    let start = NOW - 90 * 86_400_000;
    let mut i = 0usize;
    for m in 0..(90 * 1440) {
        for k in 0..12 {
            let ts = start + m as i64 * 60_000 + k * 4000;
            a.record(parse_datagram(&datagram(i, ts), NOW).expect("parse"));
            i += 1;
        }
    }
    a
}

fn lat(label: &str, iters: usize, mut f: impl FnMut()) {
    let mut v = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = Instant::now();
        f();
        v.push(t.elapsed().as_secs_f64() * 1e3);
    }
    v.sort_by(|a, b| a.total_cmp(b));
    println!(
        "{label}: p50 {:.3} ms p99 {:.3} ms",
        v[v.len() / 2],
        v[v.len() * 99 / 100]
    );
}

// Events per second for parsing, recording, and both together; the best of 5 rounds is kept because scheduler noise only ever slows a round down
#[test]
#[ignore]
fn ingest() {
    let n = std::env::var("CITE_PERF_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300_000);
    let dgs: Vec<Vec<u8>> = (0..n)
        .map(|i| datagram(i, NOW - 1000 + (i as i64 % 1000)))
        .collect();
    let (mut best_p, mut best_r, mut best_pr) = (0f64, 0f64, 0f64);
    let (mut ap, mut ar, mut apr) = (0.0, 0.0, 0.0);
    for _ in 0..5 {
        let t = Instant::now();
        let a0 = ALLOCS.load(Ordering::Relaxed);
        let mut evs = Vec::with_capacity(n);
        for d in &dgs {
            evs.push(parse_datagram(d, NOW).expect("parse"));
        }
        let a1 = ALLOCS.load(Ordering::Relaxed);
        best_p = best_p.max(n as f64 / t.elapsed().as_secs_f64());
        ap = (a1 - a0) as f64 / n as f64;
        let mut an = Analytics::new(Retention::default());
        let t = Instant::now();
        for ev in evs {
            an.record(ev);
        }
        best_r = best_r.max(n as f64 / t.elapsed().as_secs_f64());
        ar = (ALLOCS.load(Ordering::Relaxed) - a1) as f64 / n as f64;
        let mut an = Analytics::new(Retention::default());
        let a3 = ALLOCS.load(Ordering::Relaxed);
        let t = Instant::now();
        for d in &dgs {
            an.record(parse_datagram(d, NOW).expect("parse"));
        }
        best_pr = best_pr.max(n as f64 / t.elapsed().as_secs_f64());
        apr = (ALLOCS.load(Ordering::Relaxed) - a3) as f64 / n as f64;
    }
    println!("parse_datagram best {best_p:.0}/s, {ap:.1} allocs/event");
    println!("record best {best_r:.0}/s, {ar:.1} allocs/event");
    println!("parse+record best {best_pr:.0}/s, {apr:.1} allocs/event");
}

// Dashboard query latency over 90 days of retained events, as p50 and p99 across repeated runs, plus snapshot write and restore cost
#[test]
#[ignore]
fn queries() {
    let t = Instant::now();
    let a = filled();
    println!(
        "fill 1.5M events: {:.2} s, retained {} MiB",
        t.elapsed().as_secs_f64(),
        a.retained_bytes() >> 20
    );
    for (name, w) in [("24h", 86_400u64), ("7d", 7 * 86_400), ("30d", 30 * 86_400)] {
        lat(&format!("summary {name}"), 200, || {
            std::hint::black_box(a.summary(w, None, NOW));
        });
        lat(&format!("summary {name} site"), 200, || {
            std::hint::black_box(a.summary(w, Some("site3"), NOW));
        });
        lat(&format!("timeseries {name}"), 200, || {
            std::hint::black_box(a.timeseries(w, None, NOW));
        });
    }
    let f = RequestFilter {
        status: Some(200),
        method: Some("get".into()),
        path_contains: Some("item%".into()),
        ip: None,
        blocked_only: false,
        site: Some("site7".into()),
    };
    lat("requests 5000 (no match path)", 200, || {
        std::hint::black_box(a.requests(&f, 100));
    });
    let f2 = RequestFilter {
        path_contains: Some("zzz".into()),
        ..f
    };
    lat("requests 5000 full scan", 200, || {
        std::hint::black_box(a.requests(&f2, 100));
    });
    let mut big = Analytics::new(Retention {
        recent_events: 200_000,
        ..Retention::default()
    });
    for i in 0..200_000 {
        big.record(
            parse_datagram(&datagram(i, NOW - 1000 + (i as i64 % 1000)), NOW).expect("parse"),
        );
    }
    let f3 = RequestFilter {
        status: Some(200),
        method: Some("get".into()),
        path_contains: Some("zzz".into()),
        ip: None,
        blocked_only: false,
        site: Some("site7".into()),
    };
    lat("requests 200k full scan", 50, || {
        std::hint::black_box(big.requests(&f3, 100));
    });
    let shared = Mutex::new(a);
    let t = Instant::now();
    let mut buf = Vec::new();
    write_snapshot(&shared, &mut buf).expect("snapshot");
    println!(
        "snapshot write: {:.3} s, {} MiB, peak extra ~ out buffer",
        t.elapsed().as_secs_f64(),
        buf.len() >> 20
    );
    let t = Instant::now();
    let snap = serde_json::from_slice(&buf).expect("decode");
    let d1 = t.elapsed().as_secs_f64();
    let r = Analytics::restore(Retention::default(), snap);
    println!(
        "restore: decode {:.3} s total {:.3} s, retained {} MiB",
        d1,
        t.elapsed().as_secs_f64(),
        r.retained_bytes() >> 20
    );
}

fn opts() -> RenderOptions {
    RenderOptions {
        maps_dir: "/conf/haproxy/maps".into(),
        pages_dir: "/conf/haproxy/pages".into(),
        runtime_addr: "unix@/conf/haproxy/admin.sock".into(),
        log_addr: "/conf/haproxy/log.sock".into(),
        tls_dir: None,
    }
}

pub fn big_config(sites: usize, rules: usize) -> EdgeConfig {
    let mut v = serde_json::json!({"version": 1, "sites": [], "firewall": []});
    for i in 0..sites {
        v["sites"].as_array_mut().unwrap().push(serde_json::json!({
            "id": format!("s{i}"), "name": format!("S{i}"),
            "hosts": [format!("s{i}.example.com"), format!("www.s{i}.example.com")],
            "kind": "site",
            "blue": {"targets": [{"addr": "10.0.0.5:8080", "weight": 100}]},
            "green": {"targets": []}, "active": "blue"
        }));
    }
    let mut cfg: EdgeConfig = serde_json::from_value(v).expect("cfg");
    for i in 0..rules {
        let m = match i % 4 {
            0 => Matchers {
                path_regex: Some(format!("^/admin{i}/.*")),
                ..Default::default()
            },
            1 => Matchers {
                cidrs: vec![format!("198.51.{}.0/24", i % 250)],
                ..Default::default()
            },
            2 => Matchers {
                user_agent_regex: Some(format!("(?i)bot{i}")),
                methods: vec!["POST".into()],
                ..Default::default()
            },
            _ => Matchers {
                path_prefix: Some(format!("/private{i}")),
                ..Default::default()
            },
        };
        cfg.firewall.push(FirewallRule {
            id: format!("r{i}"),
            name: format!("r{i}"),
            enabled: true,
            action: FirewallAction::Deny,
            matchers: m,
            site: if i % 5 == 0 {
                Some(format!("s{}", i % sites.max(1)))
            } else {
                None
            },
        });
    }
    cfg
}

#[test]
#[ignore]
fn render_validate() {
    for sites in [1, 100, 1000] {
        let cfg = big_config(sites, 200);
        lat(&format!("validate_config {sites} sites"), 10, || {
            validate_config(&cfg).expect("valid");
        });
        let mut size = 0;
        lat(
            &format!("render (incl. validate) {sites} sites"),
            10,
            || {
                size = render(&cfg, &opts()).expect("render").config.len();
            },
        );
        println!("  config bytes {size}");
    }
}

// Writes a rendered config tree for a real HAProxy run. Env: CITE_PERF_DUMP (dir), CITE_PERF_SITES, CITE_PERF_RULES, CITE_PERF_RATE (per-IP limit, 0 for none), CITE_PERF_UPSTREAM (host:port every site points at).
#[test]
#[ignore]
fn dump_config() {
    let env = |k: &str, d: usize| {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    let mut cfg = big_config(env("CITE_PERF_SITES", 1000), env("CITE_PERF_RULES", 200));
    let rate = env("CITE_PERF_RATE", 0) as u32;
    cfg.settings.per_ip_rate_limit = (rate > 0).then_some(rate);
    if let Ok(up) = std::env::var("CITE_PERF_UPSTREAM") {
        for site in &mut cfg.sites {
            site.blue.targets[0].addr = up.clone();
        }
    }
    let r = render(&cfg, &opts()).expect("render");
    let Ok(dir) = std::env::var("CITE_PERF_DUMP") else {
        return;
    };
    std::fs::create_dir_all(format!("{dir}/maps")).expect("dir");
    std::fs::create_dir_all(format!("{dir}/pages")).expect("dir");
    std::fs::write(format!("{dir}/haproxy.cfg"), &r.config).expect("write");
    std::fs::write(format!("{dir}/maps/active.map"), &r.active_map).expect("write");
    std::fs::write(format!("{dir}/maps/maint.map"), &r.maint_map).expect("write");
    for (name, body) in &r.pages {
        std::fs::write(format!("{dir}/pages/{name}"), body).expect("write");
    }
}
