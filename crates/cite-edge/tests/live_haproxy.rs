// Needs docker and the haproxy:3.2-bookworm, nginx:alpine and curlimages/curl images; run with --ignored.
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use cite_edge::model::EdgeConfig;
use cite_edge::presets::preset;
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

#[test]
#[ignore = "needs docker and real haproxy 3.0"]
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
    };
    let rendered = render(&config(), &opts).expect("render");
    // the rendered servers resolve through the control network, so they are pointed at plain docker DNS here
    let cfg: String = rendered
        .config
        .lines()
        .filter(|l| !l.trim_start().starts_with("log "))
        .map(|l| match l.trim_start().strip_prefix("server ") {
            Some(rest) => format!(
                "    server {} echo:80\n",
                rest.split(' ').next().unwrap_or("t")
            ),
            None => format!("{l}\n"),
        })
        .collect();
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
