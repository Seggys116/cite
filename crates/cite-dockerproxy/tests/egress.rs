mod common;

use cite_connector::egress::Egress;
use cite_connector::orchestrator::{SpecSet, StackEnv, stack_specs};
use cite_dockerproxy::policy::{Policy, Route};
use cite_dockerproxy::target::normalise;
use cite_edge::model::{OutboundMode, OutboundRules, Site, Slot};
use serde_json::{Value, json};

const TOKEN: &str = "ghp_secrettoken123";

fn site(rules: OutboundRules) -> Site {
    let mut s: Site = serde_json::from_value(json!({
        "id": "shop",
        "name": "shop",
        "hosts": ["shop.example.com"],
        "blue": { "targets": [] },
        "green": { "targets": [] },
        "active": "blue",
        "source": { "repo": "acme/shop", "runtime": "node" },
    }))
    .unwrap();
    s.outbound_rules = rules;
    s
}

const NODE: [(&str, &str); 3] = [
    ("CITE_STACK_EGRESS_ALLOW_CIDRS", "192.168.10.0/24"),
    ("CITE_STACK_EGRESS_DENY_HOSTS", "evil.example"),
    ("CITE_STACK_EGRESS_ALLOW_PORTS", "80,443"),
];

fn lookup<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |k| {
        pairs
            .iter()
            .find(|(key, _)| *key == k)
            .map(|(_, v)| v.to_string())
    }
}

type Mutation = Box<dyn Fn(&mut Value)>;

fn m(f: impl Fn(&mut Value) + 'static) -> Mutation {
    Box::new(f)
}

fn specs(rules: OutboundRules, egress: &Egress) -> SpecSet {
    let env = StackEnv {
        registry: common::REGISTRY,
        version: "0.2.0",
        edge_network: "cite_edge",
        isolate: true,
        github_api_url: None,
        egress,
    };
    stack_specs(&site(rules), Slot::Blue, None, TOKEN, &env).unwrap()
}

fn check(policy: &Policy, name: &str, body: &Value) -> Result<(), String> {
    let target = normalise(&format!("/v1.45/containers/create?name={name}"))?;
    let route = policy.classify("POST", &target)?;
    policy.validate_body(&route, body)
}

fn rules() -> OutboundRules {
    OutboundRules {
        mode: OutboundMode::Allowlist,
        allow: vec![
            "api.github.com".into(),
            "*.apple.com".into(),
            "10.0.0.0/8".into(),
        ],
        deny: vec!["10.0.0.66".into()],
        block_mail: false,
    }
}

#[test]
fn the_egress_proxy_the_orchestrator_emits_is_accepted() {
    let egress = Egress::from_lookup(lookup(&NODE)).unwrap();
    let policy = common::policy_with(&NODE);
    for r in [OutboundRules::default(), rules()] {
        let s = specs(r, &egress);
        let proxy = s.egress_proxy.as_ref().unwrap();
        check(&policy, &s.egress_proxy_name, proxy).unwrap();
        check(&policy, &s.executor_name, &s.executor).unwrap();
        let image = s.egress_proxy_image.as_ref().unwrap();
        let (repo, tag) = image.rsplit_once(':').unwrap();
        let pull = normalise(&format!("/v1.45/images/create?fromImage={repo}&tag={tag}")).unwrap();
        assert_eq!(policy.classify("POST", &pull), Ok(Route::ImagePull));
        let inspect = normalise(&format!("/v1.45/images/{image}/json")).unwrap();
        assert_eq!(policy.classify("GET", &inspect), Ok(Route::ImageInspect));
    }
}

#[test]
fn the_node_lists_must_equal_the_proxy_settings() {
    let egress = Egress::from_lookup(lookup(&NODE)).unwrap();
    let s = specs(OutboundRules::default(), &egress);
    let proxy = s.egress_proxy.as_ref().unwrap();
    let plain = common::policy();
    let err = check(&plain, &s.egress_proxy_name, proxy).unwrap_err();
    assert!(err.contains("CITE_EGRESS_ALLOW_CIDRS"), "{err}");
    let wider = common::policy_with(&[
        ("CITE_STACK_EGRESS_ALLOW_CIDRS", "192.168.10.0/24"),
        ("CITE_STACK_EGRESS_DENY_HOSTS", "evil.example,worse.example"),
        ("CITE_STACK_EGRESS_ALLOW_PORTS", "80,443"),
    ]);
    assert!(check(&wider, &s.egress_proxy_name, proxy).is_err());
    let unlisted = specs(OutboundRules::default(), &Egress::default());
    let err = check(
        &common::policy_with(&NODE),
        &unlisted.egress_proxy_name,
        unlisted.egress_proxy.as_ref().unwrap(),
    )
    .unwrap_err();
    assert!(
        err.contains("missing"),
        "a node deny list cannot be dropped: {err}"
    );
}

#[test]
fn the_egress_proxy_body_is_pinned() {
    let egress = Egress::from_lookup(lookup(&NODE)).unwrap();
    let policy = common::policy_with(&NODE);
    let s = specs(rules(), &egress);
    let base = s.egress_proxy.clone().unwrap();
    let mutate = |f: &dyn Fn(&mut Value)| {
        let mut b = base.clone();
        f(&mut b);
        check(&policy, &s.egress_proxy_name, &b)
    };
    let refused: Vec<(&str, Mutation)> = vec![
        (
            "privileged",
            m(|b| b["HostConfig"]["Privileged"] = json!(true)),
        ),
        (
            "caps",
            m(|b| b["HostConfig"]["CapAdd"] = json!(["NET_ADMIN"])),
        ),
        (
            "rootfs",
            m(|b| b["HostConfig"]["ReadonlyRootfs"] = json!(false)),
        ),
        ("memory", m(|b| b["HostConfig"]["Memory"] = json!(1 << 30))),
        (
            "cpus",
            m(|b| b["HostConfig"]["NanoCpus"] = json!(4_000_000_000i64)),
        ),
        ("pids", m(|b| b["HostConfig"]["PidsLimit"] = json!(4096))),
        ("root", m(|b| b["User"] = json!("0:0"))),
        ("bind", m(|b| b["HostConfig"]["Binds"] = json!(["/:/host"]))),
        (
            "image",
            m(|b| b["Image"] = json!("ghcr.io/seggys116/cite-manager:0.2.0-node22")),
        ),
        (
            "foreign image",
            m(|b| b["Image"] = json!("docker.io/library/squid:6")),
        ),
        ("cmd", m(|b| b["Cmd"] = json!(["sh"]))),
        (
            "host net",
            m(|b| b["HostConfig"]["NetworkMode"] = json!("host")),
        ),
        (
            "edge net",
            m(|b| b["HostConfig"]["NetworkMode"] = json!("cite_edge")),
        ),
        (
            "manager net",
            m(|b| b["HostConfig"]["NetworkMode"] = json!("cite-shop-blue-egress")),
        ),
        (
            "extra network",
            m(|b| b["NetworkingConfig"]["EndpointsConfig"]["cite-shop-blue-net"] = json!({})),
        ),
        (
            "other bridge",
            m(|b| {
                let eps = b["NetworkingConfig"]["EndpointsConfig"]
                    .as_object_mut()
                    .unwrap();
                eps.remove("cite-egress");
                eps.insert("bridge".into(), json!({}));
            }),
        ),
        (
            "alias",
            m(|b| {
                b["NetworkingConfig"]["EndpointsConfig"]["cite-egress"] =
                    json!({ "Aliases": ["github.com"] })
            }),
        ),
        (
            "unknown env",
            m(|b| {
                b["Env"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!("RUST_LOG=trace"))
            }),
        ),
        (
            "bad mode",
            m(|b| {
                for e in b["Env"].as_array_mut().unwrap() {
                    if e == "CITE_EGRESS_MODE=allowlist" {
                        *e = json!("CITE_EGRESS_MODE=open");
                    }
                }
            }),
        ),
        (
            "numeric host trick",
            m(|b| {
                b["Env"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!("CITE_EGRESS_DENY=2130706433"))
            }),
        ),
        (
            "no mode",
            m(|b| {
                b["Env"]
                    .as_array_mut()
                    .unwrap()
                    .retain(|e| !e.as_str().unwrap().starts_with("CITE_EGRESS_MODE="))
            }),
        ),
        (
            "allowlist without allow",
            m(|b| {
                b["Env"]
                    .as_array_mut()
                    .unwrap()
                    .retain(|e| !e.as_str().unwrap().starts_with("CITE_EGRESS_ALLOW="))
            }),
        ),
        (
            "widened node list",
            m(|b| {
                for e in b["Env"].as_array_mut().unwrap() {
                    if e.as_str().unwrap().starts_with("CITE_EGRESS_ALLOW_CIDRS=") {
                        *e = json!("CITE_EGRESS_ALLOW_CIDRS=0.0.0.0/0");
                    }
                }
            }),
        ),
    ];
    mutate(&|_| {}).unwrap();
    for (what, f) in &refused {
        assert!(mutate(f.as_ref()).is_err(), "{what}");
    }
}

#[test]
fn only_filtered_nodes_create_egress_proxies_and_proxy_env_is_tied_to_the_stack() {
    let s = specs(OutboundRules::default(), &Egress::default());
    let proxy = s.egress_proxy.as_ref().unwrap();
    for mode in ["open", "off"] {
        let policy = common::policy_with(&[("CITE_STACK_EGRESS_MODE", mode)]);
        let err = check(&policy, &s.egress_proxy_name, proxy).unwrap_err();
        assert!(err.contains("filtered"), "{mode}: {err}");
    }
    let policy = common::policy();
    assert!(
        check(&policy, "cite-shop-green-egress-proxy", proxy).is_err(),
        "another slot's name"
    );
    assert!(
        check(&policy, "cite-other-blue-egress-proxy", proxy).is_err(),
        "another site's name"
    );
    let swap = |from: &str, to: &str| {
        let mut b = s.executor.clone();
        for e in b["Env"].as_array_mut().unwrap() {
            if e.as_str() == Some(from) {
                *e = json!(to);
            }
        }
        check(&policy, &s.executor_name, &b)
    };
    let url = "http://cite-shop-blue-egress-proxy:3128";
    swap("", "").unwrap();
    assert!(
        swap(
            &format!("HTTPS_PROXY={url}"),
            "HTTPS_PROXY=http://cite-other-blue-egress-proxy:3128"
        )
        .is_err()
    );
    assert!(
        swap(
            &format!("http_proxy={url}"),
            "http_proxy=http://evil.example:3128"
        )
        .is_err()
    );
    assert!(swap("NO_PROXY=localhost,127.0.0.1", "NO_PROXY=*").is_err());
    assert!(swap("NODE_USE_ENV_PROXY=1", "NODE_USE_ENV_PROXY=0").is_err());
    let mut missing = s.executor.clone();
    missing["Env"]
        .as_array_mut()
        .unwrap()
        .retain(|e| e.as_str() != Some("NODE_USE_ENV_PROXY=1"));
    assert!(check(&policy, &s.executor_name, &missing).is_err());
    let open = specs_open();
    let mut smuggled = open.executor.clone();
    smuggled["Env"].as_array_mut().unwrap().push(json!(format!(
        "HTTP_PROXY={}",
        "http://cite-shop-blue-egress-proxy:3128"
    )));
    let open_policy = common::policy_with(&[("CITE_STACK_EGRESS_MODE", "open")]);
    check(&open_policy, &open.executor_name, &open.executor).unwrap();
    assert!(check(&open_policy, &open.executor_name, &smuggled).is_err());
}

fn specs_open() -> SpecSet {
    specs(
        OutboundRules::default(),
        &Egress::with_mode(cite_connector::egress::EgressMode::Open),
    )
}

#[test]
fn stack_xnets_are_internal_and_the_bridge_is_the_only_extra_network() {
    let policy = common::policy();
    let labels = json!({ "cite.managed": "true", "cite.site": "shop", "cite.slot": "blue", "cite.role": "network" });
    let xnet = json!({ "Name": "cite-shop-blue-xnet", "Driver": "bridge", "Internal": true, "Labels": labels });
    policy.validate_body(&Route::NetworkCreate, &xnet).unwrap();
    let mut open_xnet = xnet.clone();
    open_xnet["Internal"] = json!(false);
    assert!(
        policy
            .validate_body(&Route::NetworkCreate, &open_xnet)
            .is_err()
    );
    let bridge_labels = json!({ "cite.managed": "true", "cite.role": "egress-bridge" });
    let icc_off = json!({ "com.docker.network.bridge.enable_icc": "false" });
    let bridge = json!({
        "Name": "cite-egress", "Driver": "bridge", "Internal": false, "Options": icc_off.clone(), "Labels": bridge_labels,
    });
    policy
        .validate_body(&Route::NetworkCreate, &bridge)
        .unwrap();
    for (key, value) in [
        ("Internal", json!(true)),
        ("Name", json!("other-egress")),
        ("Labels", json!({ "cite.managed": "true" })),
        ("Driver", json!("macvlan")),
        (
            "Options",
            json!({ "com.docker.network.bridge.enable_icc": "true" }),
        ),
        ("Options", json!({})),
        (
            "Options",
            json!({ "com.docker.network.bridge.enable_icc": "false", "com.docker.network.bridge.enable_ip_masquerade": "false" }),
        ),
    ] {
        let mut bad = bridge.clone();
        bad[key] = value;
        assert!(
            policy.validate_body(&Route::NetworkCreate, &bad).is_err(),
            "{key}"
        );
    }
    let mut no_options = bridge.clone();
    no_options.as_object_mut().unwrap().remove("Options");
    assert!(
        policy
            .validate_body(&Route::NetworkCreate, &no_options)
            .is_err(),
        "ICC must be off"
    );
    let mut xnet_options = xnet.clone();
    xnet_options["Options"] = icc_off.clone();
    assert!(
        policy
            .validate_body(&Route::NetworkCreate, &xnet_options)
            .is_err(),
        "only the bridge takes options"
    );
    let route = |method: &str, raw: &str| policy.classify(method, &normalise(raw).unwrap());
    assert!(route("GET", "/v1.45/networks/cite-egress").is_ok());
    assert!(route("DELETE", "/v1.45/networks/cite-egress").is_err());
    assert!(route("POST", "/v1.45/networks/cite-egress/connect").is_err());
    assert!(route("POST", "/v1.45/networks/cite-shop-blue-xnet/connect").is_err());
    assert!(route("DELETE", "/v1.45/networks/cite-shop-blue-xnet").is_ok());
    for action in ["start", "stop", "wait"] {
        assert!(
            route(
                "POST",
                &format!("/v1.45/containers/cite-shop-blue-egress-proxy/{action}")
            )
            .is_ok()
        );
    }
    assert!(route("DELETE", "/v1.45/containers/cite-shop-blue-egress-proxy").is_ok());
    assert!(
        route(
            "POST",
            "/v1.45/images/create?fromImage=ghcr.io/seggys116/cite-egress&tag=0.2.0-node22"
        )
        .is_err()
    );
    assert!(
        route(
            "POST",
            "/v1.45/images/create?fromImage=ghcr.io/seggys116/cite-egressx&tag=0.2.0"
        )
        .is_err()
    );
}
