use cite_edge::model::EdgeConfig;
use cite_edge::presets::presets;
use cite_edge::render::{RenderOptions, render};

fn sample() -> EdgeConfig {
    let mut cfg: EdgeConfig = serde_json::from_value(serde_json::json!({
        "version": 1,
        "sites": [
            {
                "id": "shop", "name": "Shop", "hosts": ["shop.example.com", "*.shop.example.org"],
                "kind": "site",
                "blue": {"targets": [{"addr": "shop-blue-1:8080", "weight": 100}, {"addr": "shop-blue-2:8080", "weight": 50}]},
                "green": {"targets": [{"addr": "shop-green-1:8080", "weight": 100}]},
                "active": "blue",
                "maintenance": {"enabled": true, "page_id": "down"},
                "health": {"path": "/healthz", "interval_ms": 2000, "rise": 2, "fall": 3, "timeout_ms": 1500}
            },
            {
                "id": "api", "name": "API", "hosts": ["api.example.com"], "path_regex": "^/v[0-9]+/",
                "kind": "api",
                "blue": {"targets": [{"addr": "10.0.0.5:9000", "weight": 100}]},
                "green": {"targets": []},
                "active": "blue"
            }
        ],
        "pages": [{"id": "down", "name": "Down", "html": "<html><body>back soon</body></html>", "status": 503}],
        "firewall": [
            {"id": "scoped", "name": "scoped", "enabled": true, "action": "deny", "site": "shop",
             "matchers": {"cidrs": ["203.0.113.0/24", "198.51.100.7"], "methods": ["POST"], "host": "shop.example.com"}}
        ],
        "settings": {
            "http_port": 80, "https_port": null, "max_conn": 20000, "client_timeout_ms": 30000,
            "server_timeout_ms": 60000, "connect_timeout_ms": 3000, "per_ip_rate_limit": 600,
            "max_body_bytes": 1048576,
            "retention": {"recent_events": 5000, "minute_buckets_hours": 48, "hour_buckets_days": 90,
                          "audit_days": 365, "persist_interval_secs": 60,
                          "store_user_agents": true, "store_client_ips": true}
        }
    }))
    .expect("sample json");
    for p in presets() {
        cfg.firewall.extend(p.rules);
    }
    cfg
}

fn opts_unix() -> RenderOptions {
    RenderOptions {
        runtime_addr: "unix@/conf/haproxy/admin.sock".into(),
        log_addr: "/conf/haproxy/log.sock".into(),
        ..opts()
    }
}

fn opts() -> RenderOptions {
    RenderOptions {
        maps_dir: "/conf/haproxy/maps".into(),
        pages_dir: "/conf/haproxy/pages".into(),
        runtime_addr: "ipv4@172.30.250.3:9999".into(),
        log_addr: "172.30.250.2:5140".into(),
        tls_dir: None,
    }
}

#[test]
fn sample_config_renders_and_optionally_dumps() {
    let rendered = render(&sample(), &opts()).expect("render");
    assert!(rendered.config.contains("be_shop_blue"));
    assert!(rendered.config.contains("be_api_green"));
    let unix = render(&sample(), &opts_unix()).expect("render unix");
    assert!(
        unix.config
            .contains("stats socket unix@/conf/haproxy/admin.sock mode 600 level admin")
    );
    assert!(
        unix.config
            .contains("log /conf/haproxy/log.sock len 8192 format rfc5424 local0")
    );
    if let Ok(dir) = std::env::var("CITE_SAMPLE_OUT") {
        let dir = std::path::Path::new(&dir);
        std::fs::create_dir_all(dir.join("maps")).expect("maps dir");
        std::fs::create_dir_all(dir.join("pages")).expect("pages dir");
        std::fs::write(dir.join("haproxy.cfg"), &rendered.config).expect("cfg");
        std::fs::write(dir.join("haproxy-unix.cfg"), &unix.config).expect("unix cfg");
        std::fs::write(dir.join("maps/active.map"), &rendered.active_map).expect("active");
        std::fs::write(dir.join("maps/maint.map"), &rendered.maint_map).expect("maint");
        for (name, html) in &rendered.pages {
            std::fs::write(dir.join("pages").join(name), html).expect("page");
        }
    }
}
