use cite_edge::model::{OutboundMode, OutboundRules, Site};
use cite_edge::validate::{
    MAX_EGRESS_ENTRIES, is_egress_cidr, is_egress_host, normalise_outbound_rules, validate_site,
    validate_site_strict,
};
use serde_json::json;

fn site(rules: serde_json::Value) -> Site {
    let mut v = json!({
        "id": "shop",
        "name": "Shop",
        "hosts": ["shop.example.com"],
        "blue": { "targets": [] },
        "green": { "targets": [] },
        "active": "blue",
        "source": { "repo": "acme/shop", "runtime": "node" },
    });
    if !rules.is_null() {
        v["outbound_rules"] = rules;
    }
    serde_json::from_value(v).expect("site")
}

#[test]
fn rules_default_to_public_with_mail_blocked_and_are_left_out_of_the_json() {
    let s = site(serde_json::Value::Null);
    assert_eq!(s.outbound_rules, OutboundRules::default());
    assert_eq!(s.outbound_rules.mode, OutboundMode::Public);
    assert!(s.outbound_rules.block_mail);
    let text = serde_json::to_value(&s).unwrap();
    assert!(text.get("outbound_rules").is_none());
    let partial = site(json!({ "allow": ["db.lan"] }));
    assert!(partial.outbound_rules.block_mail, "a missing block_mail stays on");
    let text = serde_json::to_value(&partial).unwrap();
    assert_eq!(text["outbound_rules"]["mode"], "public");
    let unknown: Result<Site, _> = serde_json::from_value(json!({
        "id": "shop", "name": "Shop", "hosts": ["shop.example.com"],
        "blue": { "targets": [] }, "green": { "targets": [] }, "active": "blue",
        "outbound_rules": { "mode": "open" },
    }));
    assert!(unknown.is_err());
}

#[test]
fn entry_shapes() {
    for ok in ["10.0.0.0/8", "192.168.1.5", "fd00::/8", "2001:db8::1", "0.0.0.0/0"] {
        assert!(is_egress_cidr(ok), "{ok}");
    }
    for bad in ["010.0.0.1", "10.0.0.0/33", "10.1/8", "10.0.0.0/08", "example.com", "fd00::/200"] {
        assert!(!is_egress_cidr(bad), "{bad}");
    }
    for ok in ["api.github.com", ".apple.com", "db.lan", "localhost"] {
        assert!(is_egress_host(ok), "{ok}");
    }
    for bad in ["API.github.com", "*.apple.com", "a..b", "-a.b", "2130706433", "x.0x1f", " db.lan", ""] {
        assert!(!is_egress_host(bad), "{bad:?}");
    }
}

#[test]
fn strict_validation_table() {
    for ok in [
        json!({}),
        json!({ "allow": ["10.0.0.0/8", "db.lan", ".apple.com", "*.icloud.com"], "deny": ["10.0.0.66", "ads.example"] }),
        json!({ "mode": "allowlist", "allow": ["api.github.com"], "block_mail": false }),
    ] {
        validate_site_strict(&site(ok.clone())).unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
    let cases = [
        (json!({ "mode": "allowlist" }), "at least one allow"),
        (json!({ "allow": ["db.lan", "db.lan"] }), "twice"),
        (json!({ "deny": ["0177.0.0.1"] }), "deny entry"),
        (json!({ "allow": ["Exa mple.com"] }), "allow entry"),
        (json!({ "allow": ["**.apple.com"] }), "allow entry"),
        (json!({ "allow": ["http://x.com"] }), "allow entry"),
    ];
    for (rules, needle) in cases {
        let err = validate_site_strict(&site(rules.clone())).expect_err("refused").0;
        assert!(err.contains(needle), "{rules}: {err}");
    }
    let many: Vec<String> = (0..=MAX_EGRESS_ENTRIES).map(|i| format!("h{i}.example")).collect();
    let err = validate_site_strict(&site(json!({ "allow": many }))).expect_err("65").0;
    assert!(err.contains("more than 64"), "{err}");
    let bad = site(json!({ "mode": "allowlist" }));
    validate_site(&bad).expect("loading a stored config stays lenient");
}

#[test]
fn normalising_trims_and_rewrites_wildcards() {
    let mut rules = OutboundRules {
        mode: OutboundMode::Public,
        allow: vec![" *.apple.com ".into(), "db.lan".into()],
        deny: vec!["*.ads.example".into()],
        block_mail: true,
    };
    normalise_outbound_rules(&mut rules);
    assert_eq!(rules.allow, vec![".apple.com", "db.lan"]);
    assert_eq!(rules.deny, vec![".ads.example"]);
}
