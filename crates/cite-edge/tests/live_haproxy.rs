// Needs docker and the haproxy:3.2-bookworm, nginx:alpine and curlimages/curl images; run with --ignored.
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use cite_edge::logparse::parse_line;
use cite_edge::model::{
    Cors, EdgeConfig, FirewallAction, FirewallRule, HeaderMatch, HeaderOp, HeaderOpKind,
    HeaderTarget, Matchers,
};
use cite_edge::pattern::{HEADER_CAP, PATH_CAP, REFERER_CAP, UA_CAP};
use cite_edge::presets::{preset, zone_lock_rule};
use cite_edge::render::{RenderOptions, render};

fn config() -> EdgeConfig {
    let target = r#"{"targets": [{"addr": "echo:80", "weight": 100}]}"#;
    let empty = r#"{"targets": []}"#;
    let site = |id: &str, host: &str, extra: &str| {
        format!(
            r#"{{"id": "{id}", "name": "{id}", "hosts": ["{host}"], "kind": "site", {extra}
               "blue": {target}, "green": {empty}, "active": "blue"}}"#
        )
    };
    let wild_maint = r#""maintenance": {"enabled": true, "page_id": null},"#;
    let json = format!(
        r#"{{"version": 1,
        "sites": [{}, {}, {}],
        "pages": [],
        "firewall": [
            {{"id": "admin", "name": "admin", "enabled": true, "action": "deny",
              "matchers": {{"path_prefix": "/admin"}}}},
            {{"id": "secret-re", "name": "secret", "enabled": true, "action": "deny",
              "matchers": {{"path_regex": "^/secret/"}}}},
            {{"id": "scoped", "name": "scoped", "enabled": true, "action": "deny", "site": "shop",
              "matchers": {{"path_prefix": "/private"}}}}
        ],
        "settings": {{"http_port": 80, "https_port": null, "max_conn": 2000, "client_timeout_ms": 30000,
            "server_timeout_ms": 60000, "connect_timeout_ms": 3000, "per_ip_rate_limit": null,
            "max_body_bytes": null,
            "retention": {{"recent_events": 5000, "minute_buckets_hours": 48, "hour_buckets_days": 90,
                          "audit_days": 365, "persist_interval_secs": 60,
                          "store_user_agents": true, "store_client_ips": true}}}}}}"#,
        site("shop", "shop.example.com", ""),
        site("wild", "*.example.com", wild_maint),
        site("other", "other.example.net", ""),
    );
    let mut cfg: EdgeConfig = serde_json::from_str(&json).expect("config json");
    for name in ["sensitive-files", "cms-probes"] {
        cfg.firewall.extend(preset(name).expect("preset").rules);
    }
    cfg
}

// (host, path, expected status; 000 is a dropped connection, echo bodies must equal the expected path)
fn cases() -> Vec<(&'static str, &'static str, &'static str, &'static str)> {
    let shop = "shop.example.com";
    let mut v = Vec::new();
    for p in [
        "/admin",
        "/admin/x",
        "/;x/admin",
        "/x/..;/admin",
        "/.;/admin",
        "/%3Bx/admin",
        "/%3bx/admin",
        "/\\admin",
        "/%5cadmin",
        "/../admin",
        "/a/../admin",
        "/%2e%2e/admin",
        "//admin",
        "/;/admin",
        "/x;y/../admin",
        "/secret/x",
        "/;x/secret/x",
        "/x/..;/secret/x",
        "/\\secret/x",
    ] {
        v.push((shop, p, "403", ""));
    }
    for p in [
        "/.env",
        "/.env~",
        "/.env-prod",
        "/.env.local",
        "/.env.bak",
        "/.git/config",
        "/%2egit/config",
        "/;x/.env",
        "/x/..;/.env",
        "/\\.env",
        "/%5c.env",
        "/.aws/credentials",
        "/.npmrc",
        "/docker-compose.yml",
        "/Dockerfile",
        "/certs/server.key",
        "/config.php~",
        "/wp-login.php",
        "/;x/actuator/env",
    ] {
        v.push((shop, p, "000", ""));
    }
    for p in [
        "/",
        "/api/v1/users",
        "/a%20b",
        "/static/app.js",
        "/docs/environment.html",
        "/blog/dotenv-guide",
        "/x/%5Cadmin",
        "/a/;x/b",
    ] {
        v.push((shop, p, "200", p));
    }
    // the normalised path is what the origin receives
    v.push((shop, "/a/../b", "200", "/b"));
    v.push((shop, "/a//b", "200", "/a/b"));
    v.push((shop, "/a/./b", "200", "/a/b"));
    // a scoped rule hits only its site, and maintenance only the site that receives the request
    v.push((shop, "/private/x", "403", ""));
    v.push(("other.example.net", "/private/x", "200", "/private/x"));
    v.push(("foo.example.com", "/private/x", "503", ""));
    v.push((shop, "/", "200", "/"));
    v.push(("foo.example.com", "/", "503", ""));
    v.push(("other.example.net", "/", "200", "/"));
    v
}

struct Env {
    dir: PathBuf,
    id: String,
}

impl Drop for Env {
    fn drop(&mut self) {
        for name in ["hap", "echo"] {
            let _ = docker(&["rm", "-f", &format!("cite-live-{}-{name}", self.id)]);
        }
        let _ = docker(&["network", "rm", &format!("cite-live-{}", self.id)]);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn docker(args: &[&str]) -> (bool, String) {
    let out = Command::new("docker")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("docker is not available");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

fn write(dir: &Path, name: &str, body: &str) {
    std::fs::write(dir.join(name), body).expect("write");
}

// the rendered servers resolve through the control network, so they are pointed at plain docker DNS here
fn for_docker(config: &str) -> String {
    docker_config(config, false)
}

// With log_stdout the node's log sink becomes the container's stdout in raw format, so the log-format line can be read back.
fn docker_config(config: &str, log_stdout: bool) -> String {
    config
        .lines()
        .filter_map(|l| {
            let t = l.trim_start();
            if t.starts_with("log ") {
                if !log_stdout {
                    return None;
                }
                if t.contains("len 8192") {
                    return Some("    log stdout format raw local0\n".to_string());
                }
                return Some(format!("{l}\n"));
            }
            Some(match t.strip_prefix("server ") {
                Some(rest) => format!(
                    "    server {} echo:80\n",
                    rest.split(' ').next().unwrap_or("t")
                ),
                None => format!("{l}\n"),
            })
        })
        .collect()
}

#[test]
#[ignore = "needs docker and real haproxy 3.2"]
fn rules_see_the_canonical_path_on_real_haproxy() {
    let id = std::process::id().to_string();
    let dir = std::env::temp_dir().join(format!("cite-live-{id}"));
    std::fs::create_dir_all(dir.join("maps")).expect("dir");
    std::fs::create_dir_all(dir.join("pages")).expect("dir");
    let env = Env {
        dir: dir.clone(),
        id: id.clone(),
    };
    let opts = RenderOptions {
        maps_dir: "/conf/haproxy/maps".into(),
        pages_dir: "/conf/haproxy/pages".into(),
        runtime_addr: "unix@/tmp/admin.sock".into(),
        log_addr: "/tmp/log.sock".into(),
        tls_dir: None,
        cloudflare_file: None,
    };
    let rendered = render(&config(), &opts).expect("render");
    let cfg = for_docker(&rendered.config);
    write(&dir, "haproxy.cfg", &cfg);
    write(&dir, "maps/active.map", &rendered.active_map);
    write(&dir, "maps/maint.map", &rendered.maint_map);
    for (name, html) in &rendered.pages {
        write(&dir.join("pages"), name, html);
    }
    write(
        &dir,
        "nginx.conf",
        "server { listen 80; location / { default_type text/plain; return 200 \"$request_uri\"; } }\n",
    );
    let mut script = String::new();
    let mut paths = String::new();
    for (h, p, _, _) in cases() {
        paths.push_str(&format!("{h}|{p}\n"));
    }
    write(&dir, "paths.txt", &paths);
    script.push_str(
        "while IFS='|' read -r h p; do c=$(curl -s --path-as-is -o /tmp/o -w '%{http_code}' -H \"Host: $h\" \"http://$HAP$p\"); printf '%s|%s|%s|%s\\n' \"$h\" \"$p\" \"$c\" \"$(head -n 1 /tmp/o 2>/dev/null)\"; rm -f /tmp/o; done < /conf/paths.txt\n",
    );
    write(&dir, "probe.sh", &script);

    let net = format!("cite-live-{id}");
    let d = dir.to_str().expect("utf8 path").to_string();
    let run = |args: &[&str]| {
        let (ok, text) = docker(args);
        assert!(ok, "docker {args:?}: {text}");
    };
    run(&["network", "create", &net]);
    run(&[
        "run",
        "-d",
        "--name",
        &format!("cite-live-{id}-echo"),
        "--network",
        &net,
        "--network-alias",
        "echo",
        "-v",
        &format!("{d}/nginx.conf:/etc/nginx/conf.d/default.conf:ro"),
        "nginx:alpine",
    ]);
    let (ok, text) = docker(&[
        "run",
        "--rm",
        "--network",
        &net,
        "-v",
        &format!("{d}:/conf/haproxy:ro"),
        "haproxy:3.2-bookworm",
        "haproxy",
        "-c",
        "-f",
        "/conf/haproxy/haproxy.cfg",
    ]);
    assert!(ok, "haproxy -c: {text}");
    assert!(!text.contains("will never match"), "haproxy -c: {text}");
    run(&[
        "run",
        "-d",
        "--name",
        &format!("cite-live-{id}-hap"),
        "--network",
        &net,
        "-v",
        &format!("{d}:/conf/haproxy:ro"),
        "haproxy:3.2-bookworm",
        "haproxy",
        "-db",
        "-f",
        "/conf/haproxy/haproxy.cfg",
    ]);
    std::thread::sleep(std::time::Duration::from_secs(2));
    let (ok, out) = docker(&[
        "run",
        "--rm",
        "--network",
        &net,
        "-e",
        &format!("HAP=cite-live-{id}-hap"),
        "-v",
        &format!("{d}:/conf:ro"),
        "--entrypoint",
        "sh",
        "curlimages/curl",
        "/conf/probe.sh",
    ]);
    assert!(ok, "probe: {out}");
    drop(env);
    let got: Vec<&str> = out.lines().collect();
    let want = cases();
    assert_eq!(got.len(), want.len(), "{out}");
    let mut bad = Vec::new();
    for (line, (h, p, code, body)) in got.iter().zip(want) {
        let mut f = line.splitn(4, '|');
        let (gh, gp, gc, gb) = (f.next(), f.next(), f.next(), f.next().unwrap_or(""));
        let body_ok = body.is_empty() || gb == body;
        if gh != Some(h) || gp != Some(p) || gc != Some(code) || !body_ok {
            bad.push(format!("{h} {p}: want {code} {body:?}, got {line}"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

fn cloudflare_config(ranges: Vec<String>) -> EdgeConfig {
    let json = r#"{"version": 1, "pages": [], "firewall": [], "sites": [
        {"id": "cf", "name": "cf", "hosts": ["cf.example.com"], "kind": "site",
         "blue": {"targets": [{"addr": "echo:80", "weight": 100}]}, "green": {"targets": []},
         "active": "blue", "access": {"cloudflare_only": true, "tls": "flexible"}},
        {"id": "flex", "name": "flex", "hosts": ["flex.example.com"], "kind": "site",
         "blue": {"targets": [{"addr": "echo:80", "weight": 100}]}, "green": {"targets": []},
         "active": "blue", "access": {"cloudflare_only": false, "tls": "flexible"}}]}"#;
    let mut cfg: EdgeConfig = serde_json::from_str(json).expect("config json");
    cfg.settings.cloudflare_ranges = ranges;
    cfg.settings.per_ip_rate_limit = Some(20);
    cfg
}

// The echo body is "X-Forwarded-For|X-Forwarded-Proto|CF-Connecting-IP|CF-Visitor" as the origin received them.
const CLOUDFLARE_PROBE: &str = r#"probe() { h=$1; shift; c=$(curl -s -o /tmp/o -w '%{http_code}' -H "Host: $h" "$@" "http://$HAP/"); printf '%s|%s\n' "$c" "$(head -n 1 /tmp/o)"; }
rate() { n=0; last=; while [ $n -lt 25 ]; do last=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: cf.example.com' -H "CF-Connecting-IP: $1" "http://$HAP/"); n=$((n+1)); done; printf 'rate|%s|%s\n' "$1" "$last"; }
probe cf.example.com -H 'CF-Connecting-IP: 203.0.113.7' -H 'X-Forwarded-Proto: https'
probe cf.example.com -H 'CF-Connecting-IP: 203.0.113.7' -H 'X-Forwarded-Proto: gopher'
probe cf.example.com -H 'CF-Connecting-IP: 203.0.113.7, 198.51.100.9'
probe cf.example.com -H 'CF-Connecting-IP: not-an-ip'
probe flex.example.com -H 'CF-Connecting-IP: 203.0.113.7' -H 'CF-Visitor: {"scheme":"https"}' -H 'X-Forwarded-Proto: https'
rate 2001:db8::7
rate 198.51.100.9
"#;

#[test]
#[ignore = "needs docker and real haproxy"]
fn cloudflare_only_gates_on_the_tcp_peer_on_real_haproxy() {
    let id = format!("{}-cf", std::process::id());
    let dir = std::env::temp_dir().join(format!("cite-live-{id}"));
    std::fs::create_dir_all(dir.join("maps")).expect("dir");
    std::fs::create_dir_all(dir.join("pages")).expect("dir");
    let _env = Env {
        dir: dir.clone(),
        id: id.clone(),
    };
    let opts = RenderOptions {
        maps_dir: "/conf/haproxy/maps".into(),
        pages_dir: "/conf/haproxy/pages".into(),
        runtime_addr: "unix@/tmp/admin.sock".into(),
        log_addr: "/tmp/log.sock".into(),
        tls_dir: None,
        cloudflare_file: Some("/conf/haproxy/maps/cloudflare.lst".into()),
    };
    write(
        &dir,
        "nginx.conf",
        "server { listen 80; location / { default_type text/plain; return 200 \"$http_x_forwarded_for|$http_x_forwarded_proto|$http_cf_connecting_ip|$http_cf_visitor\"; } }\n",
    );
    write(&dir, "probe.sh", CLOUDFLARE_PROBE);
    // ranges that would also match every IPv4 peer must be refused before anything is rendered
    for open in ["::ffff:0:0/96", "::/16", "::1/16", "2002::/16", "0.0.0.0/0"] {
        let err = render(&cloudflare_config(vec![open.into()]), &opts);
        assert!(err.is_err(), "{open} was accepted");
    }
    let net = format!("cite-live-{id}");
    let d = dir.to_str().expect("utf8 path").to_string();
    let hap = format!("cite-live-{id}-hap");
    let run = |args: &[&str]| {
        let (ok, text) = docker(args);
        assert!(ok, "docker {args:?}: {text}");
        text
    };
    run(&["network", "create", &net]);
    run(&[
        "run",
        "-d",
        "--name",
        &format!("cite-live-{id}-echo"),
        "--network",
        &net,
        "--network-alias",
        "echo",
        "-v",
        &format!("{d}/nginx.conf:/etc/nginx/conf.d/default.conf:ro"),
        "nginx:alpine",
    ]);
    // the probe container sits on this network, so its address is the TCP peer HAProxy sees
    let subnet = run(&[
        "network",
        "inspect",
        "-f",
        "{{(index .IPAM.Config 0).Subnet}}",
        &net,
    ])
    .trim()
    .to_string();
    assert!(subnet.contains('/'), "subnet {subnet:?}");

    let phase = |ranges: Vec<String>| -> String {
        let rendered = render(&cloudflare_config(ranges), &opts).expect("render");
        write(&dir, "haproxy.cfg", &for_docker(&rendered.config));
        write(&dir, "maps/active.map", &rendered.active_map);
        write(&dir, "maps/maint.map", &rendered.maint_map);
        write(&dir, "maps/cloudflare.lst", &rendered.cloudflare_list);
        for (name, html) in &rendered.pages {
            write(&dir.join("pages"), name, html);
        }
        let (ok, text) = docker(&[
            "run",
            "--rm",
            "--network",
            &net,
            "-v",
            &format!("{d}:/conf/haproxy:ro"),
            "haproxy:3.2-bookworm",
            "haproxy",
            "-c",
            "-f",
            "/conf/haproxy/haproxy.cfg",
        ]);
        assert!(ok, "haproxy -c: {text}");
        assert!(!text.contains("will never match"), "haproxy -c: {text}");
        let _ = docker(&["rm", "-f", &hap]);
        run(&[
            "run",
            "-d",
            "--name",
            &hap,
            "--network",
            &net,
            "-v",
            &format!("{d}:/conf/haproxy:ro"),
            "haproxy:3.2-bookworm",
            "haproxy",
            "-db",
            "-f",
            "/conf/haproxy/haproxy.cfg",
        ]);
        std::thread::sleep(std::time::Duration::from_secs(2));
        run(&[
            "run",
            "--rm",
            "--network",
            &net,
            "-e",
            &format!("HAP={hap}"),
            "-v",
            &format!("{d}:/conf:ro"),
            "--entrypoint",
            "sh",
            "curlimages/curl",
            "/conf/probe.sh",
        ])
    };

    // the built-in list does not contain a docker network address, so every request is refused
    let refused = phase(vec![]);
    let lines: Vec<&str> = refused.lines().collect();
    assert_eq!(lines.len(), 7, "{refused}");
    assert!(
        lines[..4].iter().all(|l| l.starts_with("403|")),
        "{refused}"
    );
    // a Flexible site that is not cloudflare_only still drops forged Cloudflare headers from a non-Cloudflare peer
    let mut f = lines[4].splitn(5, '|');
    let (code, xff, xfp, cf_ip, cf_visitor) = (
        f.next(),
        f.next().unwrap_or(""),
        f.next(),
        f.next(),
        f.next(),
    );
    assert_eq!(code, Some("200"), "{refused}");
    assert!(!xff.is_empty() && !xff.contains("203.0.113.7"), "{refused}");
    assert_eq!(xfp, Some("http"), "{refused}");
    assert_eq!(cf_ip, Some(""), "{refused}");
    assert_eq!(cf_visitor, Some(""), "{refused}");

    // with the probe's network listed, the peer is Cloudflare and the header carries the visitor
    let served = phase(vec![subnet]);
    let lines: Vec<&str> = served.lines().collect();
    assert_eq!(lines.len(), 7, "{served}");
    assert_eq!(lines[0], "200|203.0.113.7|https|203.0.113.7|", "{served}");
    assert_eq!(lines[1], "200|203.0.113.7|http|203.0.113.7|", "{served}");
    // the flex site is not cloudflare_only, so its source stays the peer, but the scheme comes from Cloudflare
    assert!(lines[4].starts_with("200|"), "{served}");
    assert_eq!(lines[4].split('|').nth(2), Some("https"), "{served}");
    // the rate limit counts the visitor from the header, for IPv6 and IPv4 alike
    assert_eq!(lines[5], "rate|2001:db8::7|429", "{served}");
    assert_eq!(lines[6], "rate|198.51.100.9|429", "{served}");
    for line in &lines[2..4] {
        let mut f = line.splitn(5, '|');
        let (code, xff) = (f.next(), f.next().unwrap_or(""));
        assert_eq!(code, Some("200"), "{served}");
        assert!(!xff.is_empty(), "{served}");
        for forged in ["203.0.113.7", "198.51.100.9", "not-an-ip"] {
            assert!(!xff.contains(forged), "{forged} reached XFF: {served}");
        }
    }
}

// A pattern that PCRE2 would abort on (and HAProxy then counts as no match, failing a deny rule open) never reaches the renderer.
#[test]
fn catastrophic_deny_patterns_are_refused_before_rendering() {
    let opts = RenderOptions {
        maps_dir: "/conf/haproxy/maps".into(),
        pages_dir: "/conf/haproxy/pages".into(),
        runtime_addr: "unix@/tmp/admin.sock".into(),
        log_addr: "/tmp/log.sock".into(),
        tls_dir: None,
        cloudflare_file: None,
    };
    for pattern in [
        "(a|aa){2,60}[0-9]",
        "(a{1,100}){1,100}[0-9]",
        ".*.*.*.*.*.*.*.*[0-9]",
    ] {
        let mut cfg = rules_config();
        cfg.firewall.push(FirewallRule {
            id: "evil".into(),
            name: "evil".into(),
            enabled: true,
            action: Some(FirewallAction::Deny),
            matchers: Matchers {
                user_agent_regex: Some(pattern.into()),
                ..Matchers::default()
            },
            ..FirewallRule::default()
        });
        let err = render(&cfg, &opts).expect_err(pattern).to_string();
        assert!(err.contains("is refused"), "{pattern}: {err}");
    }
}

// (field, pattern): the costliest shapes the validator accepts for each subject.
const BATTERY: [(&str, &str); 19] = [
    ("ua", "[a-z]+!"),
    ("ua", "a?a?a?aaaa!"),
    ("ua", "[a-z]{1,500}!"),
    ("ua", "(ab)+c"),
    // the strongest shapes the validator accepts at each cap, found by the search in pattern.rs
    ("ua", "^[a-z]{1,60}[a-z]{1,60}[a-z]{1,60}!"),
    ("ua", "[a-z]{1,60}[a-z]{1,60}!"),
    // eight nested groups, the deepest the validator allows, to exercise the JIT stack
    ("ua", "((((((((ab))))))))c"),
    ("path", "[a-z]+!"),
    ("path", "a?a?a?aaaa!"),
    ("path", "[a-z]{1,90}[a-z]{1,90}!"),
    ("path", "^/[a-z]{1,60}[a-z]{1,60}[a-z]{1,60}!"),
    ("path", "^/[a-z]*!"),
    ("hdr", "[a-z]+!"),
    ("hdr", "a?a?a?aaaa!"),
    ("hdr", "[a-z]{1,120}[a-z]{1,120}!"),
    ("hdr", "^[a-z]{1,60}[a-z]{1,60}[a-z]{1,60}!"),
    ("ref", "[a-z]+!"),
    ("ref", "[a-z]{1,120}[a-z]{1,120}!"),
    ("ref", "^[a-z]{1,60}[a-z]{1,60}[a-z]{1,60}!"),
];
const BATTERY_LENGTHS: [usize; 4] = [100, 512, 513, 7000];
// (label letter, the final character of the subject): all a, a near miss, a true match
const BATTERY_TAILS: [(&str, &str); 3] = [("a", "a"), ("x", "x"), ("m", "!")];
const STALL_LIMIT_SECS: f64 = 0.05;

fn battery_cap(field: &str) -> usize {
    match field {
        "ua" => UA_CAP,
        "path" => PATH_CAP,
        "ref" => REFERER_CAP,
        _ => HEADER_CAP,
    }
}

// Only user agent and path rules fail closed on an oversized value; referer and header regexes judge the prefix.
fn battery_fails_closed(field: &str) -> bool {
    matches!(field, "ua" | "path")
}

fn battery_config() -> EdgeConfig {
    let target = r#"{"targets": [{"addr": "echo:80", "weight": 100}]}"#;
    let sites: Vec<String> = (0..BATTERY.len())
        .map(|i| {
            format!(
                r#"{{"id": "t{i}", "name": "t{i}", "hosts": ["t{i}.example.com"], "kind": "site",
                   "blue": {target}, "green": {{"targets": []}}, "active": "blue"}}"#
            )
        })
        .collect();
    let json = format!(
        r#"{{"version": 1, "sites": [{}], "pages": [], "firewall": []}}"#,
        sites.join(",")
    );
    let mut cfg: EdgeConfig = serde_json::from_str(&json).expect("config json");
    cfg.settings.per_ip_rate_limit = None;
    for (i, (field, pattern)) in BATTERY.iter().enumerate() {
        let mut matchers = Matchers::default();
        match *field {
            "ua" => matchers.user_agent_regex = Some(pattern.to_string()),
            "path" => matchers.path_regex = Some(pattern.to_string()),
            "ref" => matchers.referer_regex = Some(pattern.to_string()),
            _ => {
                matchers.header = Some(HeaderMatch {
                    name: "X-Probe".into(),
                    regex: Some(pattern.to_string()),
                    ..HeaderMatch::default()
                })
            }
        }
        cfg.firewall.push(FirewallRule {
            id: format!("deny-{i}"),
            name: format!("deny-{i}"),
            enabled: true,
            action: Some(FirewallAction::Deny),
            site: Some(format!("t{i}")),
            matchers,
            ..FirewallRule::default()
        });
    }
    cfg
}

fn battery_subject(field: &str, n: usize, tail: &str) -> String {
    match field {
        "path" => format!("/{}{tail}", "a".repeat(n - 2)),
        _ => format!("{}{tail}", "a".repeat(n - 1)),
    }
}

const BATTERY_FUNCS: &str = r##"mk() { head -c "$1" /dev/zero | tr '\0' a; }
probe() {
  label=$1; host=$2; field=$3; n=$4; t=$5
  case $field in
    ua) r=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' -H "Host: $host" -A "$(mk $((n-1)))$t" "http://$HAP/") ;;
    path) r=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' -H "Host: $host" --path-as-is "http://$HAP/$(mk $((n-2)))$t") ;;
    ref) r=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' -H "Host: $host" -e "$(mk $((n-1)))$t" "http://$HAP/") ;;
    *) r=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' -H "Host: $host" -H "X-Probe: $(mk $((n-1)))$t" "http://$HAP/") ;;
  esac
  echo "$label|$r"
}
"##;

#[test]
#[ignore = "needs docker and real haproxy 3.2"]
fn validated_patterns_never_stall_or_fail_open() {
    let id = format!("{}-battery", std::process::id());
    let dir = std::env::temp_dir().join(format!("cite-live-{id}"));
    std::fs::create_dir_all(dir.join("maps")).expect("dir");
    std::fs::create_dir_all(dir.join("pages")).expect("dir");
    let _env = Env {
        dir: dir.clone(),
        id: id.clone(),
    };
    let opts = RenderOptions {
        maps_dir: "/conf/haproxy/maps".into(),
        pages_dir: "/conf/haproxy/pages".into(),
        runtime_addr: "unix@/tmp/admin.sock".into(),
        log_addr: "/tmp/log.sock".into(),
        tls_dir: None,
        cloudflare_file: None,
    };
    // every battery pattern must be accepted by the validator, or the test would prove nothing
    let rendered = render(&battery_config(), &opts).expect("the battery is valid");
    write(&dir, "haproxy.cfg", &docker_config(&rendered.config, false));
    write(&dir, "maps/active.map", &rendered.active_map);
    write(&dir, "maps/maint.map", &rendered.maint_map);
    for (name, html) in &rendered.pages {
        write(&dir.join("pages"), name, html);
    }
    write(
        &dir,
        "nginx.conf",
        "server { listen 80; large_client_header_buffers 4 16k; location / { default_type text/plain; return 200 \"ok\"; } }\n",
    );
    let mut script = String::from(BATTERY_FUNCS);
    for (i, (field, _)) in BATTERY.iter().enumerate() {
        for n in BATTERY_LENGTHS {
            for (letter, tail) in BATTERY_TAILS {
                script.push_str(&format!(
                    "probe {i}-{n}-{letter} t{i}.example.com {field} {n} '{tail}'\n"
                ));
            }
        }
    }
    write(&dir, "probe.sh", &script);

    let net = format!("cite-live-{id}");
    let d = dir.to_str().expect("utf8 path").to_string();
    let hap = format!("cite-live-{id}-hap");
    let run = |args: &[&str]| {
        let (ok, text) = docker(args);
        assert!(ok, "docker {args:?}: {text}");
        text
    };
    run(&["network", "create", &net]);
    run(&[
        "run",
        "-d",
        "--name",
        &format!("cite-live-{id}-echo"),
        "--network",
        &net,
        "--network-alias",
        "echo",
        "-v",
        &format!("{d}/nginx.conf:/etc/nginx/conf.d/default.conf:ro"),
        "nginx:alpine",
    ]);
    let (ok, text) = docker(&[
        "run",
        "--rm",
        "--network",
        &net,
        "-v",
        &format!("{d}:/conf/haproxy:ro"),
        "haproxy:3.2-bookworm",
        "haproxy",
        "-c",
        "-f",
        "/conf/haproxy/haproxy.cfg",
    ]);
    assert!(ok, "haproxy -c: {text}");
    assert!(!text.contains("will never match"), "haproxy -c: {text}");
    run(&[
        "run",
        "-d",
        "--name",
        &hap,
        "--network",
        &net,
        "-v",
        &format!("{d}:/conf/haproxy:ro"),
        "haproxy:3.2-bookworm",
        "haproxy",
        "-db",
        "-f",
        "/conf/haproxy/haproxy.cfg",
    ]);
    std::thread::sleep(std::time::Duration::from_secs(2));
    let out = run(&[
        "run",
        "--rm",
        "--network",
        &net,
        "-e",
        &format!("HAP={hap}"),
        "-v",
        &format!("{d}:/conf:ro"),
        "--entrypoint",
        "sh",
        "curlimages/curl",
        "/conf/probe.sh",
    ]);
    let (_, state) = docker(&["inspect", "-f", "{{.State.Running}}", &hap]);
    let (_, logs) = docker(&["logs", &hap]);

    let rows: std::collections::HashMap<&str, &str> =
        out.lines().filter_map(|l| l.split_once('|')).collect();
    let mut bad = Vec::new();
    for (i, (field, pattern)) in BATTERY.iter().enumerate() {
        let re = regex::Regex::new(pattern).expect("battery pattern compiles");
        let cap = battery_cap(field);
        for n in BATTERY_LENGTHS {
            for (letter, tail) in BATTERY_TAILS {
                let subject = battery_subject(field, n, tail);
                let seen = &subject[..subject.len().min(cap)];
                // an oversized user agent or path must be denied however the pattern judges its prefix; other fields follow the prefix
                let deny =
                    (battery_fails_closed(field) && subject.len() > cap) || re.is_match(seen);
                let want = if deny { "403" } else { "200" };
                let label = format!("{i}-{n}-{letter}");
                let Some(row) = rows.get(label.as_str()) else {
                    bad.push(format!("{label}: no answer"));
                    continue;
                };
                let mut f = row.split(' ');
                let (code, secs) = (
                    f.next().unwrap_or(""),
                    f.next().unwrap_or("9").parse::<f64>().unwrap_or(9.0),
                );
                if code != want || secs > STALL_LIMIT_SECS {
                    bad.push(format!(
                        "{label} {field} {pattern:?}: want {want} fast, got {code} in {secs}s"
                    ));
                }
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    assert!(state.contains("true"), "haproxy is not running: {state}");
    let lower = logs.to_lowercase();
    assert!(
        !lower.contains("watchdog") && !lower.contains("panic"),
        "{logs}"
    );
}

const AGREEMENT_SEED: u64 = 0x9E37_79B9_7F4A_7C15;
const PER_FIELD: usize = 42;
const REQUEST_LIMIT_SECS: f64 = 0.1;
const P99_LIMIT_SECS: f64 = 0.05;

// xorshift64: deterministic and dependency free, so a failure is reproducible from the printed seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }
}

const GEN_LITS: &[u8] = b"abcdefxyz0129_-/=:;,@&~!ABC%";
const GEN_ESCAPES: [&str; 24] = [
    ".", "/", "-", "_", "+", "*", "?", "(", ")", "|", "[", "]", "{", "}", "^", "$", ",", ":", ";",
    "=", "!", "@", "%", "&",
];
const GEN_QUANTS: [&str; 12] = [
    "", "", "", "?", "*", "+", "{0}", "{0,0}", "{1,3}", "{2}", "{1,40}", "{2,}",
];
const GEN_CLASSES: [&str; 12] = [
    "[a-z]",
    "[0-9a-f]",
    "[^/]",
    "[\\w.-]",
    "[a-c0-9_]",
    "[\\]]",
    "[-a]",
    "[a-]",
    "[A-Z]",
    "[^a-z]",
    "[\\.\\-]",
    "[\\d\\s]",
];

fn gen_lit(rng: &mut Rng) -> String {
    (GEN_LITS[rng.below(GEN_LITS.len())] as char).to_string()
}

fn gen_text(rng: &mut Rng, max: usize) -> String {
    (0..=rng.below(max)).map(|_| gen_lit(rng)).collect()
}

fn gen_simple(rng: &mut Rng) -> String {
    match rng.below(6) {
        0 => gen_lit(rng),
        1 => format!("\\{}", rng.pick(&GEN_ESCAPES)),
        2 => ".".to_string(),
        3 => rng
            .pick(&["\\d", "\\w", "\\s", "\\D", "\\W", "\\S"])
            .to_string(),
        _ => rng.pick(&GEN_CLASSES).to_string(),
    }
}

fn gen_alt(rng: &mut Rng) -> String {
    let branches: Vec<String> = (0..=rng.below(3))
        .map(|_| {
            if rng.below(10) == 0 {
                String::new()
            } else {
                gen_text(rng, 3)
            }
        })
        .collect();
    branches.join("|")
}

fn gen_item(rng: &mut Rng) -> String {
    match rng.below(12) {
        0..=4 => format!("{}{}", gen_simple(rng), rng.pick(&GEN_QUANTS)),
        5 | 6 => gen_text(rng, 3),
        7 => {
            let open = rng.pick(&["(", "(?:"]);
            format!("{open}{}){}", gen_alt(rng), rng.pick(&["", "?"]))
        }
        8 => format!(
            "({}){}",
            gen_text(rng, 3),
            rng.pick(&["", "?", "+", "{2}", "{1,3}"])
        ),
        9 => {
            let n = 2 + rng.below(7);
            format!("{}{}{}", "(".repeat(n), gen_text(rng, 2), ")".repeat(n))
        }
        10 => rng.pick(&["^", "$", "\\b"]).to_string(),
        _ => gen_simple(rng),
    }
}

fn gen_pattern(rng: &mut Rng) -> String {
    let mut p = String::new();
    if rng.below(3) == 0 {
        p.push_str("(?i)");
    }
    if rng.below(3) == 0 {
        p.push('^');
    }
    for _ in 0..=rng.below(5) {
        p.push_str(&gen_item(rng));
    }
    if rng.below(4) == 0 {
        p.push('$');
    }
    p
}

fn matchers_for(field: &str, pattern: &str) -> Matchers {
    let mut m = Matchers::default();
    match field {
        "ua" => m.user_agent_regex = Some(pattern.to_string()),
        "path" => m.path_regex = Some(pattern.to_string()),
        "ref" => m.referer_regex = Some(pattern.to_string()),
        _ => {
            m.header = Some(HeaderMatch {
                name: "X-Probe".into(),
                regex: Some(pattern.to_string()),
                ..HeaderMatch::default()
            })
        }
    }
    m
}

// The validator is the gate: only what it accepts under the field's cap is ever sent to HAProxy.
fn accepted(field: &str, pattern: &str) -> bool {
    let rule = FirewallRule {
        id: "probe".into(),
        name: "probe".into(),
        enabled: true,
        action: Some(FirewallAction::Deny),
        matchers: matchers_for(field, pattern),
        ..FirewallRule::default()
    };
    cite_edge::validate::validate_rule(&rule).is_ok()
}

const AGREEMENT_FIELDS: [&str; 4] = ["ua", "path", "ref", "hdr"];

fn generated_patterns() -> Vec<(&'static str, String)> {
    let mut rng = Rng(AGREEMENT_SEED);
    let mut out: Vec<(&'static str, String)> = Vec::new();
    for field in AGREEMENT_FIELDS {
        let mut seen = std::collections::HashSet::new();
        let mut attempts = 0;
        while seen.len() < PER_FIELD && attempts < 400_000 {
            attempts += 1;
            let p = gen_pattern(&mut rng);
            if p.len() <= 256 && accepted(field, &p) && seen.insert(p.clone()) {
                out.push((field, p));
            }
        }
        assert!(
            seen.len() >= 40,
            "seed {AGREEMENT_SEED:#x}: only {} patterns for {field}",
            seen.len()
        );
    }
    out
}

// Constructs where PCRE2 and the regex crate could differ; whatever the validator accepts is tested live.
const EDGE_PATTERNS: [&str; 24] = [
    "(?i)[a-z]+x",
    "(?i)[A-Z]{1,5}!",
    "\\bfoo\\b",
    "foo\\b",
    "\\bfoo",
    "a|^b",
    "a$b",
    "x{0}y",
    "x{0,0}y",
    "(?:)a",
    "()a",
    "(a|)b",
    "(|a)b",
    "a^b",
    "^$",
    "(?i)^[^a-z]+$",
    "\\.\\-\\_\\!\\@",
    "[\\.\\-\\_]x",
    "[\\]\\[]x",
    "[a\\^]x",
    "x\\,\\:\\;\\=\\&\\~\\%y",
    "[z-a]",
    "x{3,1}",
    "[[:alpha:]]",
];

fn edge_patterns() -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    for p in EDGE_PATTERNS {
        if accepted("ua", p) {
            out.push(("ua", p.to_string()));
        } else {
            eprintln!("edge pattern {p:?} is refused by the validator");
        }
    }
    out
}

fn config_for(patterns: &[(&str, String)]) -> EdgeConfig {
    let target = r#"{"targets": [{"addr": "echo:80", "weight": 100}]}"#;
    let sites: Vec<String> = (0..patterns.len())
        .map(|i| {
            format!(
                r#"{{"id": "g{i}", "name": "g{i}", "hosts": ["g{i}.example.com"], "kind": "site",
                   "blue": {target}, "green": {{"targets": []}}, "active": "blue"}}"#
            )
        })
        .collect();
    let json = format!(
        r#"{{"version": 1, "sites": [{}], "pages": [], "firewall": []}}"#,
        sites.join(",")
    );
    let mut cfg: EdgeConfig = serde_json::from_str(&json).expect("config json");
    cfg.settings.per_ip_rate_limit = None;
    for (i, (field, pattern)) in patterns.iter().enumerate() {
        cfg.firewall.push(FirewallRule {
            id: format!("deny-{i}"),
            name: format!("deny-{i}"),
            enabled: true,
            action: Some(FirewallAction::Deny),
            site: Some(format!("g{i}")),
            matchers: matchers_for(field, pattern),
            ..FirewallRule::default()
        });
    }
    cfg
}

struct Stack {
    _env: Env,
    net: String,
    hap: String,
    d: String,
    dir: PathBuf,
}

fn live_options() -> RenderOptions {
    RenderOptions {
        maps_dir: "/conf/haproxy/maps".into(),
        pages_dir: "/conf/haproxy/pages".into(),
        runtime_addr: "unix@/tmp/admin.sock".into(),
        log_addr: "/tmp/log.sock".into(),
        tls_dir: None,
        cloudflare_file: None,
    }
}

// Writes the rendered config, starts an nginx stand-in on a fresh network and returns handles; containers are removed when the Stack drops.
fn stack(tag: &str, cfg: &EdgeConfig) -> Stack {
    let id = format!("{}-{tag}", std::process::id());
    let dir = std::env::temp_dir().join(format!("cite-live-{id}"));
    for sub in ["maps", "pages", "subj"] {
        std::fs::create_dir_all(dir.join(sub)).expect("dir");
    }
    let env = Env {
        dir: dir.clone(),
        id: id.clone(),
    };
    let rendered =
        render(cfg, &live_options()).expect("every pattern was validated, so rendering works");
    write(&dir, "haproxy.cfg", &docker_config(&rendered.config, false));
    write(&dir, "maps/active.map", &rendered.active_map);
    write(&dir, "maps/maint.map", &rendered.maint_map);
    for (name, html) in &rendered.pages {
        write(&dir.join("pages"), name, html);
    }
    write(
        &dir,
        "nginx.conf",
        "server { listen 80; large_client_header_buffers 4 16k; location / { default_type text/plain; return 200 \"ok\"; } }\n",
    );
    let net = format!("cite-live-{id}");
    let d = dir.to_str().expect("utf8 path").to_string();
    let run = |args: &[&str]| {
        let (ok, text) = docker(args);
        assert!(ok, "docker {args:?}: {text}");
    };
    run(&["network", "create", &net]);
    run(&[
        "run",
        "-d",
        "--name",
        &format!("cite-live-{id}-echo"),
        "--network",
        &net,
        "--network-alias",
        "echo",
        "-v",
        &format!("{d}/nginx.conf:/etc/nginx/conf.d/default.conf:ro"),
        "nginx:alpine",
    ]);
    Stack {
        _env: env,
        net,
        hap: format!("cite-live-{id}-hap"),
        d,
        dir,
    }
}

fn haproxy_check(s: &Stack) -> (bool, String) {
    docker(&[
        "run",
        "--rm",
        "--network",
        &s.net,
        "-v",
        &format!("{}:/conf/haproxy:ro", s.d),
        "haproxy:3.2-bookworm",
        "haproxy",
        "-c",
        "-f",
        "/conf/haproxy/haproxy.cfg",
    ])
}

// Starts HAProxy, runs /conf/probe.sh from a curl container and returns its output, whether HAProxy still runs, and its logs.
fn serve_and_probe(s: &Stack) -> (String, String, String) {
    let (ok, text) = docker(&[
        "run",
        "-d",
        "--name",
        &s.hap,
        "--network",
        &s.net,
        "-v",
        &format!("{}:/conf/haproxy:ro", s.d),
        "haproxy:3.2-bookworm",
        "haproxy",
        "-db",
        "-f",
        "/conf/haproxy/haproxy.cfg",
    ]);
    assert!(ok, "start haproxy: {text}");
    std::thread::sleep(std::time::Duration::from_secs(2));
    let (ok, out) = docker(&[
        "run",
        "--rm",
        "--network",
        &s.net,
        "-e",
        &format!("HAP={}", s.hap),
        "-v",
        &format!("{}:/conf:ro", s.d),
        "--entrypoint",
        "sh",
        "curlimages/curl",
        "/conf/probe.sh",
    ]);
    assert!(ok, "probe: {out}");
    let (_, state) = docker(&["inspect", "-f", "{{.State.Running}}", &s.hap]);
    let (_, logs) = docker(&["logs", &s.hap]);
    (out, state, logs)
}

const AGREEMENT_SCRIPT: &str = r##"while IFS='|' read -r id host field file; do
  v=$(cat "/conf/subj/$file")
  case $field in
    ua) r=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' -H "Host: $host" -A "$v" "http://$HAP/") ;;
    path) r=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' -H "Host: $host" --path-as-is "http://$HAP$v") ;;
    ref) r=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' -H "Host: $host" -e "$v" "http://$HAP/") ;;
    *) r=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' -H "Host: $host" -H "X-Probe: $v" "http://$HAP/") ;;
  esac
  echo "$id|$r"
done < /conf/cases.txt
"##;

// Subjects for one pattern: runs of a character it accepts, near misses, a tail that spells its literals, and short values.
fn subjects_for(
    field: &str,
    pattern: &str,
    re: &regex::Regex,
    cap: usize,
) -> Vec<(String, String)> {
    let c = ['a', 'b', '0', 'x', 'A', '_', '-']
        .into_iter()
        .find(|c| re.is_match(&c.to_string().repeat(8)))
        .unwrap_or('a');
    let skel: String = pattern
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .take(10)
        .collect();
    let lead = if field == "path" { "/" } else { "" };
    let wrap = |n: usize, tail: &str| {
        let fill = n.saturating_sub(lead.len() + tail.len());
        format!("{lead}{}{tail}", c.to_string().repeat(fill))
    };
    let mut out = Vec::new();
    for n in [cap, cap + 1, 7000] {
        out.push((format!("run{n}"), wrap(n, "")));
        out.push((format!("near{n}"), wrap(n, "Z")));
        out.push((format!("tail{n}"), wrap(n, &skel)));
    }
    let short = if skel.is_empty() { "a" } else { skel.as_str() };
    out.push(("short".into(), format!("{lead}{short}")));
    out.push(("three".into(), format!("{lead}{}", c.to_string().repeat(3))));
    out
}

#[test]
#[ignore = "needs docker and real haproxy 3.2"]
fn random_accepted_patterns_agree_with_the_regex_crate_and_stay_fast() {
    let mut patterns = generated_patterns();
    patterns.extend(edge_patterns());
    eprintln!("seed {AGREEMENT_SEED:#x}, {} patterns", patterns.len());
    let s = stack("agree", &config_for(&patterns));
    let mut cases = String::new();
    let mut wants: Vec<(String, bool)> = Vec::new();
    for (i, (field, pattern)) in patterns.iter().enumerate() {
        let re = regex::Regex::new(pattern).expect("an accepted pattern compiles");
        let cap = battery_cap(field);
        for (label, subject) in subjects_for(field, pattern, &re, cap) {
            let idx = wants.len();
            let seen = &subject[..subject.len().min(cap)];
            // the empty-agent rule is exempt from the oversize guard: padding only makes the agent non-empty
            let guarded = battery_fails_closed(field) && !(field == &"ua" && pattern == "^$");
            let deny = (guarded && subject.len() > cap) || re.is_match(seen);
            std::fs::write(s.dir.join("subj").join(idx.to_string()), &subject).expect("subject");
            cases.push_str(&format!("{idx}|g{i}.example.com|{field}|{idx}\n"));
            wants.push((
                format!("{field} {pattern:?} {label} len {}", subject.len()),
                deny,
            ));
        }
    }
    write(&s.dir, "cases.txt", &cases);
    write(&s.dir, "probe.sh", AGREEMENT_SCRIPT);
    let (out, state, logs) = serve_and_probe(&s);
    let answers: std::collections::HashMap<usize, (&str, f64)> = out
        .lines()
        .filter_map(|l| {
            let (id, rest) = l.split_once('|')?;
            let (code, secs) = rest.split_once(' ')?;
            Some((id.parse().ok()?, (code, secs.parse().ok()?)))
        })
        .collect();
    let (mut bad, mut times) = (Vec::new(), Vec::new());
    for (idx, (what, deny)) in wants.iter().enumerate() {
        let want = if *deny { "403" } else { "200" };
        match answers.get(&idx) {
            None => bad.push(format!("{what}: no answer")),
            Some((code, secs)) => {
                times.push(*secs);
                if *code != want || *secs > REQUEST_LIMIT_SECS {
                    bad.push(format!("{what}: want {want}, got {code} in {secs}s"));
                }
            }
        }
    }
    times.sort_by(|a, b| a.total_cmp(b));
    let p99 = times
        .get(times.len().saturating_sub(1) * 99 / 100)
        .copied()
        .unwrap_or(0.0);
    assert!(
        bad.is_empty(),
        "seed {AGREEMENT_SEED:#x}:\n{}",
        bad.join("\n")
    );
    assert!(
        p99 <= P99_LIMIT_SECS,
        "seed {AGREEMENT_SEED:#x}: p99 {p99}s over {} requests",
        times.len()
    );
    assert!(state.contains("true"), "haproxy is not running: {state}");
    let lower = logs.to_lowercase();
    assert!(
        !lower.contains("watchdog") && !lower.contains("panic"),
        "{logs}"
    );
}

#[test]
#[ignore = "needs docker and real haproxy 3.2"]
fn every_accepted_pattern_passes_haproxy_check() {
    for bad in [
        "[z-a]",
        "x{3,1}",
        "[a",
        "(a",
        "a)",
        "[[:alpha:]]",
        "x{,3}",
        "(?=a)",
    ] {
        assert!(!accepted("ua", bad), "{bad} should be refused");
    }
    let mut patterns = generated_patterns();
    patterns.extend(edge_patterns());
    let s = stack("check", &config_for(&patterns));
    let (ok, text) = haproxy_check(&s);
    assert!(
        ok,
        "seed {AGREEMENT_SEED:#x}: haproxy -c rejected an accepted pattern: {text}"
    );
    assert!(!text.contains("will never match"), "{text}");
}

const ZONE_SECRET: &str = "live-zone-secret-0123456789-abcdefghijklmnop";

fn rules_config() -> EdgeConfig {
    let target = r#"{"targets": [{"addr": "echo:80", "weight": 100}]}"#;
    let site = |id: &str, hosts: &str, extra: &str| {
        format!(
            r#"{{"id": "{id}", "name": "{id}", "hosts": {hosts}, "kind": "site", {extra}
               "blue": {target}, "green": {{"targets": []}}, "active": "blue"}}"#
        )
    };
    let bots = |policy: &str| format!(r#""access": {{"bots": "{policy}"}},"#);
    let sites = [
        site("wwwsite", r#"["a.example.com", "www.a.example.com"]"#, ""),
        site("apexsite", r#"["b.example.com", "www.b.example.com"]"#, ""),
        site("corssite", r#"["c.example.com"]"#, ""),
        site("badsite", r#"["bad.example.com"]"#, &bots("block_bad")),
        site("allsite", r#"["all.example.com"]"#, &bots("block_all")),
        site(
            "zonesite",
            r#"["z.example.com"]"#,
            r#""path_regex": "^/zone","#,
        ),
        site(
            "plain",
            r#"["z.example.com"]"#,
            r#""path_regex": "^/open","#,
        ),
        site("hdrsite", r#"["h.example.com"]"#, ""),
        site("negsite", r#"["n.example.com"]"#, ""),
    ];
    let json = format!(
        r#"{{"version": 1, "sites": [{}], "pages": [], "firewall": []}}"#,
        sites.join(",")
    );
    let mut cfg: EdgeConfig = serde_json::from_str(&json).expect("config json");
    cfg.settings.per_ip_rate_limit = None;
    let scoped = |name: &str, site_id: &str| {
        let mut rule = preset(name).expect("preset").rules.remove(0);
        rule.site = Some(site_id.to_string());
        rule
    };
    cfg.firewall.push(scoped("redirect-to-www", "wwwsite"));
    cfg.firewall.push(scoped("redirect-to-apex", "apexsite"));
    cfg.firewall.push(FirewallRule {
        id: "cors-app".into(),
        name: "cors-app".into(),
        enabled: true,
        site: Some("corssite".into()),
        cors: Some(Cors {
            origins: vec!["https://app.example.com".into()],
            methods: vec!["GET".into(), "POST".into()],
            allow_headers: vec!["Content-Type".into()],
            expose_headers: vec!["X-Id".into()],
            credentials: true,
            max_age_secs: 600,
        }),
        ..FirewallRule::default()
    });
    cfg.firewall.push(zone_lock_rule("zonesite", ZONE_SECRET));
    // response rules judged on request data: a negated header, a plain header and the scheme
    let response_rule = |id: &str, matchers: Matchers, header: &str| FirewallRule {
        id: id.into(),
        name: id.into(),
        enabled: true,
        site: Some("hdrsite".into()),
        matchers,
        headers: vec![HeaderOp {
            target: HeaderTarget::Response,
            op: HeaderOpKind::Set,
            name: header.into(),
            value: Some("1".into()),
        }],
        ..FirewallRule::default()
    };
    let gate = |negate: bool| Matchers {
        header: Some(HeaderMatch {
            name: "X-Gate".into(),
            equals: Some("open".into()),
            negate,
            ..HeaderMatch::default()
        }),
        ..Matchers::default()
    };
    cfg.firewall
        .push(response_rule("resp-neg", gate(true), "X-Neg"));
    cfg.firewall
        .push(response_rule("resp-pos", gate(false), "X-Pos"));
    let http = Matchers {
        scheme: Some("http".into()),
        ..Matchers::default()
    };
    cfg.firewall
        .push(response_rule("resp-http", http, "X-Http"));
    // a redirect for every request whose X-Gate header is not exactly "open", including requests without the header
    cfg.firewall.push(FirewallRule {
        id: "not-open".into(),
        name: "not-open".into(),
        enabled: true,
        site: Some("negsite".into()),
        matchers: Matchers {
            header: Some(HeaderMatch {
                name: "X-Gate".into(),
                regex: Some("^open$".into()),
                negate: true,
                ..HeaderMatch::default()
            }),
            ..Matchers::default()
        },
        redirect: Some(cite_edge::model::Redirect {
            to: "https://other.example.org/".into(),
            status: 302,
        }),
        ..FirewallRule::default()
    });
    // every matcher at once, in each role, to prove haproxy -c accepts the longest lines the renderer can produce
    let maximal = || Matchers {
        path_regex: Some("^/never/v[0-9]+/".into()),
        path_prefix: Some("/never".into()),
        methods: (0..16).map(|i| format!("M{}", "X".repeat(i + 1))).collect(),
        user_agent_regex: Some("(?i)never-matches".into()),
        cidrs: (0..8).map(|i| format!("198.19.0.{i}")).collect(),
        host: Some("*.example.com".into()),
        header: Some(HeaderMatch {
            name: "X-Never".into(),
            equals: Some("v".into()),
            negate: false,
            ..HeaderMatch::default()
        }),
        scheme: Some("http".into()),
        referer_regex: Some("^https://never[.]example[.]com/".into()),
    };
    let max_block = FirewallRule {
        id: "max-block".into(),
        name: "max-block".into(),
        enabled: true,
        action: Some(FirewallAction::Deny),
        site: Some("hdrsite".into()),
        matchers: maximal(),
        ..FirewallRule::default()
    };
    cfg.firewall.push(max_block);
    cfg.firewall.push(FirewallRule {
        id: "max-cors".into(),
        name: "max-cors".into(),
        enabled: true,
        site: Some("hdrsite".into()),
        matchers: maximal(),
        cors: Some(Cors {
            origins: vec!["https://never.example.com".into()],
            methods: vec!["GET".into()],
            allow_headers: vec!["X-A".into()],
            expose_headers: vec!["X-B".into()],
            credentials: true,
            max_age_secs: 60,
        }),
        ..FirewallRule::default()
    });
    // 200 CIDRs must still pass haproxy -c (64 words per line); the probe client is not in them
    cfg.firewall.push(FirewallRule {
        id: "big-cidrs".into(),
        name: "big-cidrs".into(),
        enabled: true,
        action: Some(FirewallAction::Deny),
        site: Some("hdrsite".into()),
        matchers: Matchers {
            cidrs: (0..200).map(|i| format!("198.18.{i}.0/24")).collect(),
            ..Matchers::default()
        },
        ..FirewallRule::default()
    });
    cfg
}

// Fields: label|status|location|allow-origin|allow-methods|allow-headers|max-age|vary|allow-credentials|first body line.
const RULES_PROBE: &str = r##"hdr() { grep -i "^$1:" /tmp/h | head -n 1 | tr -d '\r' | cut -d' ' -f2-; }
req() {
  label=$1; host=$2; shift 2
  code=$(curl -s -o /tmp/o -D /tmp/h -w '%{http_code}' -H "Host: $host" "$@")
  printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$label" "$code" "$(hdr location)" "$(hdr access-control-allow-origin)" "$(hdr access-control-allow-methods)" "$(hdr access-control-allow-headers)" "$(hdr access-control-max-age)" "$(hdr vary)" "$(hdr access-control-allow-credentials)" "$(head -n 1 /tmp/o)"
}
mk() { head -c "$1" /dev/zero | tr '\0' a; }
req neg-absent n.example.com "http://$HAP/"
req neg-other n.example.com -H 'X-Gate: nomatch' "http://$HAP/"
req neg-match n.example.com -H 'X-Gate: open' "http://$HAP/"
req neg-long n.example.com -H "X-Gate: $(mk 2000)" "http://$HAP/"
hx() {
  label=$1; host=$2; shift 2
  code=$(curl -s -o /dev/null -D /tmp/h -w '%{http_code}' -H "Host: $host" "$@")
  printf '%s|%s|%s|%s|%s\n' "$label" "$code" "$(hdr x-neg)" "$(hdr x-pos)" "$(hdr x-http)"
}
hx resp-closed h.example.com "http://$HAP/"
hx resp-open h.example.com -H 'X-Gate: open' "http://$HAP/"
hx resp-other h.example.com -H 'X-Gate: other' "http://$HAP/"
req cors-dup c.example.com -H 'Origin: https://app.example.com' -H 'Origin: https://evil.example.org' "http://$HAP/api"
req zone-open-path z.example.com -H 'X-Cite-Origin-Secret: @SECRET@' "http://$HAP/open"
req zone-open-plain z.example.com "http://$HAP/open"
CHROME='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
GOOGLEBOT='Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
req www-redirect a.example.com "http://$HAP/x/y?q=1"
req www-canonical www.a.example.com "http://$HAP/x/y?q=1"
req www-no-query a.example.com "http://$HAP/only"
req apex-redirect www.b.example.com "http://$HAP/p?z=2"
req apex-canonical b.example.com "http://$HAP/p?z=2"
req preflight c.example.com -X OPTIONS -H 'Origin: https://app.example.com' -H 'Access-Control-Request-Method: POST' "http://$HAP/api"
req preflight-evil c.example.com -X OPTIONS -H 'Origin: https://evil.example.org' -H 'Access-Control-Request-Method: POST' "http://$HAP/api"
req cors-get c.example.com -H 'Origin: https://app.example.com' "http://$HAP/api"
req cors-get-evil c.example.com -H 'Origin: https://evil.example.org' "http://$HAP/api"
req cors-get-none c.example.com "http://$HAP/api"
req bad-curl bad.example.com -A 'curl/8.5.0' "http://$HAP/"
req bad-python bad.example.com -A 'python-requests/2.31.0' "http://$HAP/"
req bad-sqlmap bad.example.com -A 'sqlmap/1.7.2' "http://$HAP/"
req bad-browser bad.example.com -A "$CHROME" "http://$HAP/"
req bad-googlebot bad.example.com -A "$GOOGLEBOT" "http://$HAP/"
req bad-empty-ua bad.example.com -H 'User-Agent:' "http://$HAP/"
req all-googlebot all.example.com -A "$GOOGLEBOT" "http://$HAP/"
req all-curl all.example.com -A 'curl/8.5.0' "http://$HAP/"
req all-browser all.example.com -A "$CHROME" "http://$HAP/"
req zone-missing z.example.com "http://$HAP/zone"
req zone-wrong z.example.com -H 'X-Cite-Origin-Secret: nope' "http://$HAP/zone"
req zone-ok z.example.com -H 'X-Cite-Origin-Secret: @SECRET@' "http://$HAP/zone"
req path-2048 z.example.com --path-as-is "http://$HAP/open$(mk 2043)"
req path-2049 z.example.com --path-as-is "http://$HAP/open$(mk 2044)"
req path-3000 z.example.com --path-as-is "http://$HAP/open$(mk 2995)"
req path-enc-2048 z.example.com --path-as-is "http://$HAP/%6fpen$(mk 2043)"
req path-enc-3000 z.example.com --path-as-is "http://$HAP/%6fpen$(mk 2995)"
req path-zone-2048 z.example.com --path-as-is "http://$HAP/zone$(mk 2043)"
req path-zone-3000 z.example.com --path-as-is -H 'X-Cite-Origin-Secret: @SECRET@' "http://$HAP/zone$(mk 2995)"
"##;

#[test]
#[ignore = "needs docker and real haproxy 3.2"]
fn redirects_cors_bot_policy_and_zone_lock_behave_on_real_haproxy() {
    let id = format!("{}-rules", std::process::id());
    let dir = std::env::temp_dir().join(format!("cite-live-{id}"));
    std::fs::create_dir_all(dir.join("maps")).expect("dir");
    std::fs::create_dir_all(dir.join("pages")).expect("dir");
    let _env = Env {
        dir: dir.clone(),
        id: id.clone(),
    };
    let opts = RenderOptions {
        maps_dir: "/conf/haproxy/maps".into(),
        pages_dir: "/conf/haproxy/pages".into(),
        runtime_addr: "unix@/tmp/admin.sock".into(),
        log_addr: "/tmp/log.sock".into(),
        tls_dir: None,
        cloudflare_file: None,
    };
    let rendered = render(&rules_config(), &opts).expect("render");
    assert!(rendered.config.contains(ZONE_SECRET));
    write(&dir, "haproxy.cfg", &docker_config(&rendered.config, true));
    write(&dir, "maps/active.map", &rendered.active_map);
    write(&dir, "maps/maint.map", &rendered.maint_map);
    for (name, html) in &rendered.pages {
        write(&dir.join("pages"), name, html);
    }
    // the body shows what the origin received: the request target and the zone header it must never see
    write(
        &dir,
        "nginx.conf",
        "server { listen 80; location / { default_type text/plain; return 200 \"$request_uri|$http_x_cite_origin_secret\"; } }\n",
    );
    write(
        &dir,
        "probe.sh",
        &RULES_PROBE.replace("@SECRET@", ZONE_SECRET),
    );

    let net = format!("cite-live-{id}");
    let d = dir.to_str().expect("utf8 path").to_string();
    let hap = format!("cite-live-{id}-hap");
    let run = |args: &[&str]| {
        let (ok, text) = docker(args);
        assert!(ok, "docker {args:?}: {text}");
        text
    };
    run(&["network", "create", &net]);
    run(&[
        "run",
        "-d",
        "--name",
        &format!("cite-live-{id}-echo"),
        "--network",
        &net,
        "--network-alias",
        "echo",
        "-v",
        &format!("{d}/nginx.conf:/etc/nginx/conf.d/default.conf:ro"),
        "nginx:alpine",
    ]);
    let (ok, text) = docker(&[
        "run",
        "--rm",
        "--network",
        &net,
        "-v",
        &format!("{d}:/conf/haproxy:ro"),
        "haproxy:3.2-bookworm",
        "haproxy",
        "-c",
        "-f",
        "/conf/haproxy/haproxy.cfg",
    ]);
    assert!(ok, "haproxy -c: {text}");
    assert!(!text.contains("will never match"), "haproxy -c: {text}");
    run(&[
        "run",
        "-d",
        "--name",
        &hap,
        "--network",
        &net,
        "-v",
        &format!("{d}:/conf/haproxy:ro"),
        "haproxy:3.2-bookworm",
        "haproxy",
        "-db",
        "-f",
        "/conf/haproxy/haproxy.cfg",
    ]);
    std::thread::sleep(std::time::Duration::from_secs(2));
    let out = run(&[
        "run",
        "--rm",
        "--network",
        &net,
        "-e",
        &format!("HAP={hap}"),
        "-v",
        &format!("{d}:/conf:ro"),
        "--entrypoint",
        "sh",
        "curlimages/curl",
        "/conf/probe.sh",
    ]);
    std::thread::sleep(std::time::Duration::from_millis(500));
    let logs = run(&["logs", &hap]);

    let rows: std::collections::HashMap<&str, Vec<&str>> = out
        .lines()
        .map(|l| {
            let f: Vec<&str> = l.splitn(10, '|').collect();
            (f[0], f)
        })
        .collect();
    let row = |label: &str| {
        rows.get(label)
            .unwrap_or_else(|| panic!("no row {label}: {out}"))
    };
    let status = |label: &str| row(label)[1];

    // redirects: Location keeps path and query, and the canonical host answers instead of redirecting again
    assert_eq!(status("www-redirect"), "301", "{out}");
    assert_eq!(
        row("www-redirect")[2],
        "http://www.a.example.com/x/y?q=1",
        "{out}"
    );
    assert_eq!(status("www-canonical"), "200", "{out}");
    assert_eq!(row("www-canonical")[2], "", "{out}");
    assert_eq!(row("www-canonical")[9], "/x/y?q=1|", "{out}");
    assert_eq!(status("www-no-query"), "301", "{out}");
    assert_eq!(
        row("www-no-query")[2],
        "http://www.a.example.com/only",
        "{out}"
    );
    assert_eq!(status("apex-redirect"), "301", "{out}");
    assert_eq!(
        row("apex-redirect")[2],
        "http://b.example.com/p?z=2",
        "{out}"
    );
    assert_eq!(status("apex-canonical"), "200", "{out}");

    // CORS: the preflight is answered by the edge for the listed origin, and nobody else gets a header
    let pre = row("preflight");
    assert_eq!(pre[1], "204", "{out}");
    assert_eq!(
        (pre[3], pre[4], pre[5], pre[6], pre[7], pre[8]),
        (
            "https://app.example.com",
            "GET, POST",
            "Content-Type",
            "600",
            "Origin",
            "true"
        ),
        "{out}"
    );
    let evil = row("preflight-evil");
    assert_eq!(
        (evil[1], evil[3], evil[7], evil[8]),
        ("200", "", "Origin", ""),
        "{out}"
    );
    assert_eq!(evil[9], "/api|", "{out}");
    let get = row("cors-get");
    assert_eq!(
        (get[1], get[3], get[7], get[8]),
        ("200", "https://app.example.com", "Origin", "true"),
        "{out}"
    );
    for label in ["cors-get-evil", "cors-get-none"] {
        let r = row(label);
        // no CORS headers, but caches are still told the answer depends on Origin
        assert_eq!(
            (r[1], r[3], r[7], r[8]),
            ("200", "", "Origin", ""),
            "{label}: {out}"
        );
    }
    // two Origin headers must not make the edge echo the unlisted one
    let dup = row("cors-dup");
    assert_eq!((dup[1], dup[3], dup[8]), ("200", "", ""), "{out}");

    // a negated header regex fires without the header, with a non-matching value and with a long one (judged on its prefix), and not with a match
    for label in ["neg-absent", "neg-other", "neg-long"] {
        assert_eq!(
            (row(label)[1], row(label)[2]),
            ("302", "https://other.example.org/"),
            "{label}: {out}"
        );
    }
    assert_eq!(status("neg-match"), "200", "{out}");

    // response rules judged on request data: the negated header, the plain header and the scheme
    let hx = |label: &str| {
        let r = row(label);
        (r[1], r[2], r[3], r[4])
    };
    assert_eq!(hx("resp-closed"), ("200", "1", "", "1"), "{out}");
    assert_eq!(hx("resp-open"), ("200", "", "1", "1"), "{out}");
    assert_eq!(hx("resp-other"), ("200", "1", "", "1"), "{out}");

    // bot policy: tools and scanners are denied, a browser passes, search engines pass until block_all
    for label in [
        "bad-curl",
        "bad-python",
        "bad-sqlmap",
        "all-googlebot",
        "all-curl",
    ] {
        assert_eq!(status(label), "403", "{label}: {out}");
    }
    for label in [
        "bad-browser",
        "bad-googlebot",
        "bad-empty-ua",
        "all-browser",
    ] {
        assert_eq!(status(label), "200", "{label}: {out}");
    }

    // zone lock: refused without the secret, served with it, and the origin never sees the header
    assert_eq!(status("zone-missing"), "403", "{out}");
    assert_eq!(status("zone-wrong"), "403", "{out}");
    assert_eq!(status("zone-ok"), "200", "{out}");
    assert_eq!(
        row("zone-ok")[9],
        "/zone|",
        "the origin saw the zone header: {out}"
    );
    assert!(!logs.contains(ZONE_SECRET), "the secret reached the logs");
    // Cloudflare sends the secret for the whole hostname, so a second site on it must not receive it either
    assert_eq!(status("zone-open-path"), "200", "{out}");
    assert_eq!(row("zone-open-path")[9], "/open|", "{out}");
    assert_eq!(status("zone-open-plain"), "200", "{out}");

    // a site path_regex judges a path of exactly the cap, and a longer path routes nowhere and gets the documented 404
    assert_eq!(status("path-2048"), "200", "{out}");
    assert_eq!(status("path-2049"), "404", "{out}");
    assert_eq!(status("path-3000"), "404", "{out}");
    assert_eq!(row("path-3000")[9], "not found", "{out}");
    // the zone-locked site is reached by the same rule, so its lock still applies at the cap and it is not reached beyond it
    assert_eq!(status("path-zone-2048"), "403", "{out}");
    assert_eq!(status("path-zone-3000"), "404", "{out}");
    // a percent-encoded path is judged on its decoded bytes, exactly like the same path written plainly
    assert_eq!(status("path-enc-2048"), status("path-2048"), "{out}");
    assert_eq!(status("path-enc-3000"), "404", "{out}");

    // blocked requests are still logged with their user agent and scored, so analytics keep counting them
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as i64;
    let events: Vec<_> = logs.lines().filter_map(|l| parse_line(l, now)).collect();
    let find = |rule: &str, ua: &str| {
        events
            .iter()
            .find(|e| e.blocked.as_deref() == Some(rule) && e.user_agent == ua)
            .unwrap_or_else(|| panic!("no {rule} event for {ua:?} in:\n{logs}"))
    };
    let curl = find("bots-bad", "curl/8.5.0");
    assert_eq!(
        (curl.status, curl.site.as_str(), curl.host.as_str()),
        (403, "badsite", "bad.example.com")
    );
    assert_eq!(curl.bot_class, "tool");
    assert!(curl.bot_score >= 70, "{}", curl.bot_score);
    assert!(
        curl.bot_signals.ends_with("ua_curl"),
        "{}",
        curl.bot_signals
    );
    let google = find(
        "bots-all",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    );
    assert_eq!((google.status, google.site.as_str()), (403, "allsite"));
    assert_eq!(google.bot_class, "crawler");
    let zone = events
        .iter()
        .find(|e| e.blocked.as_deref() == Some("cloudflare-zone"))
        .unwrap_or_else(|| panic!("no cloudflare-zone event in:\n{logs}"));
    assert_eq!((zone.status, zone.site.as_str()), (403, "zonesite"));
    // allowed requests are not labelled as blocked
    assert!(
        events
            .iter()
            .any(|e| e.host == "bad.example.com" && e.blocked.is_none() && e.status == 200)
    );
}
