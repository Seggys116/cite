use cite_edge::model::{LinkTarget, Site};
use cite_edge::validate::{
    MAX_ENV_LINKS, MAX_EXTERNAL_POSTGRES, MAX_GENERATED_SECRETS, MAX_PG_DATABASES,
    MAX_PG_USERS_PER_DATABASE, MAX_S3_ATTACHMENTS, PG_MAJORS, parse_s3_endpoint, validate_site,
    validate_site_data, validate_site_strict,
};
use serde_json::{Value, json};

fn base() -> Value {
    json!({
        "id": "shop",
        "name": "Shop",
        "hosts": ["shop.example.com"],
        "blue": { "targets": [] },
        "green": { "targets": [] },
        "active": "blue",
        "source": { "repo": "acme/shop", "runtime": "node" },
    })
}

fn pg_json() -> Value {
    json!({
        "mode": "dedicated",
        "major": 18,
        "databases": [{
            "name": "app",
            "users": [
                {"name": "app", "level": "readwrite"},
                {"name": "migrate", "level": "owner"}
            ]
        }]
    })
}

fn with_data(data: Value) -> Site {
    let mut v = base();
    v["data"] = data;
    serde_json::from_value(v).expect("site")
}

fn with_data_and(extra: Value, data: Value) -> Site {
    let mut v = base();
    for (k, val) in extra.as_object().unwrap() {
        v[k] = val.clone();
    }
    v["data"] = data;
    serde_json::from_value(v).expect("site")
}

fn err(site: &Site) -> String {
    validate_site_strict(site).expect_err("must be refused").0
}

fn link(var: &str, target: &str, source: Value) -> Value {
    json!({"var": var, "target": target, "source": source})
}

fn pg_url() -> Value {
    json!({"kind": "postgres", "database": "app", "user": "app", "field": "url"})
}

fn data_with_link(l: Value) -> Value {
    json!({"postgres": pg_json(), "links": [l]})
}

fn external() -> Value {
    json!({"name": "billing", "host": "db.example.com", "port": 5432, "database": "bill"})
}

fn s3() -> Value {
    json!({"name": "media", "endpoint": "https://s3.example.com", "bucket": "media-bucket", "region": "eu-west-1"})
}

#[test]
fn sites_without_data_serialize_exactly_as_before() {
    let site: Site = serde_json::from_value(base()).unwrap();
    assert!(site.data.is_empty());
    let value = serde_json::to_value(&site).unwrap();
    assert!(value.get("data").is_none(), "{value}");
    let text = serde_json::to_string(&site).unwrap();
    assert!(!text.contains("\"data\""), "{text}");
    let again: Site = serde_json::from_str(&text).unwrap();
    assert_eq!(again, site);
    assert_eq!(serde_json::to_string(&again).unwrap(), text);
}

#[test]
fn an_explicit_empty_data_object_is_dropped_on_write() {
    let site = with_data(json!({}));
    assert!(site.data.is_empty());
    assert!(serde_json::to_value(&site).unwrap().get("data").is_none());
}

#[test]
fn sites_with_data_keep_it_and_still_refuse_unknown_site_fields() {
    let site = with_data(json!({"postgres": pg_json()}));
    let value = serde_json::to_value(&site).unwrap();
    assert!(value["data"]["postgres"]["databases"][0]["name"] == "app");
    let back: Site = serde_json::from_value(value).unwrap();
    assert_eq!(back, site);
    let mut v = base();
    v["unknown_field"] = json!(1);
    assert!(serde_json::from_value::<Site>(v).is_err());
    let mut v = base();
    v["data"] = json!({"surprise": true});
    assert!(serde_json::from_value::<Site>(v).is_err());
}

#[test]
fn a_valid_full_configuration_passes() {
    let site = with_data(json!({
        "postgres": pg_json(),
        "external_postgres": [external()],
        "s3": [s3()],
        "secrets": [{"name": "auth-secret", "bytes": 32, "encoding": "base64url", "rotated_at": "2026-11-20T00:00:00Z"}],
        "links": [
            link("DATABASE_URL", "runtime", pg_url()),
            link("DATABASE_URL", "build", json!({"kind": "postgres", "database": "app", "user": "migrate", "field": "url"})),
            link("AUTH_SECRET", "runtime", json!({"kind": "secret", "name": "auth-secret"})),
            link("BILLING_URL", "runtime", json!({"kind": "external", "name": "billing", "field": "url"})),
            link("BILLING_SNI", "runtime", json!({"kind": "external", "name": "billing", "field": "tls_servername"})),
            link("S3_KEY", "runtime", json!({"kind": "s3", "name": "media", "field": "access_key_id"})),
            link("APP_URL", "runtime", json!({"kind": "site_url"}))
        ]
    }));
    validate_site_strict(&site).unwrap();
}

#[test]
fn empty_data_is_always_fine_even_without_a_server_runtime() {
    let mut v = base();
    v["source"] = json!({"repo": "acme/shop", "runtime": "static"});
    let site: Site = serde_json::from_value(v).unwrap();
    validate_site_strict(&site).unwrap();
    validate_site_data(&site).unwrap();
}

#[test]
fn data_needs_a_server_runtime() {
    for source in [
        json!({"repo": "acme/shop", "runtime": "static"}),
        Value::Null,
    ] {
        let site = with_data_and(json!({"source": source}), json!({"postgres": pg_json()}));
        assert!(err(&site).contains("server runtime"), "{}", err(&site));
    }
}

#[test]
fn lenient_validation_never_judges_stored_data() {
    let mut pg = pg_json();
    pg["major"] = json!(99);
    let site = with_data(json!({"postgres": pg}));
    validate_site(&site).unwrap();
    assert!(validate_site_strict(&site).is_err());
}

#[test]
fn external_and_s3_need_outbound_but_managed_postgres_does_not() {
    let off = json!({"outbound": false});
    let site = with_data_and(off.clone(), json!({"external_postgres": [external()]}));
    assert!(err(&site).contains("outbound"), "{}", err(&site));
    let site = with_data_and(off.clone(), json!({"s3": [s3()]}));
    assert!(err(&site).contains("outbound"));
    let site = with_data_and(off, json!({"postgres": pg_json()}));
    validate_site_strict(&site).unwrap();
}

#[test]
fn postgres_major_and_tls_rules() {
    assert_eq!(PG_MAJORS, [17, 18]);
    for major in PG_MAJORS {
        let mut pg = pg_json();
        pg["major"] = json!(major);
        validate_site_strict(&with_data(json!({"postgres": pg}))).unwrap();
    }
    for bad in [0, 16, 19, 255] {
        let mut pg = pg_json();
        pg["major"] = json!(bad);
        let site = with_data(json!({"postgres": pg}));
        assert!(err(&site).contains("major"), "{bad}");
    }
    let mut pg = pg_json();
    pg["tls"] = json!(true);
    assert!(err(&with_data(json!({"postgres": pg}))).contains("tls"));
}

#[test]
fn postgres_numeric_ranges() {
    let cases = [
        ("memory_mb", json!(255), false),
        ("memory_mb", json!(256), true),
        ("memory_mb", json!(65_536), true),
        ("memory_mb", json!(65_537), false),
        ("max_connections", json!(9), false),
        ("max_connections", json!(10), true),
        ("max_connections", json!(1000), true),
        ("max_connections", json!(1001), false),
    ];
    for (field, value, ok) in cases {
        let mut pg = pg_json();
        pg[field] = value.clone();
        let site = with_data(json!({"postgres": pg}));
        assert_eq!(validate_site_strict(&site).is_ok(), ok, "{field}={value}");
    }
}

#[test]
fn database_names_and_limits() {
    for bad in [
        "",
        "App",
        "1app",
        "a_b",
        "a-b",
        "postgres",
        "template0",
        "template1",
        "abcdefghijklmnopq",
    ] {
        let mut pg = pg_json();
        pg["databases"][0]["name"] = json!(bad);
        let site = with_data(json!({"postgres": pg}));
        assert!(validate_site_strict(&site).is_err(), "{bad:?}");
    }
    let mut pg = pg_json();
    pg["databases"][0]["name"] = json!("abcdefghijklmnop");
    validate_site_strict(&with_data(json!({"postgres": pg}))).unwrap();

    let mut pg = pg_json();
    pg["databases"] = json!([]);
    assert!(err(&with_data(json!({"postgres": pg}))).contains("databases"));

    let dbs: Vec<Value> = (0..=MAX_PG_DATABASES)
        .map(|i| json!({"name": format!("db{i}"), "users": [{"name": "a", "level": "owner"}]}))
        .collect();
    let mut pg = pg_json();
    pg["databases"] = json!(dbs[..MAX_PG_DATABASES]);
    validate_site_strict(&with_data(json!({"postgres": pg.clone()}))).unwrap();
    pg["databases"] = json!(dbs);
    assert!(err(&with_data(json!({"postgres": pg}))).contains("databases"));

    let mut pg = pg_json();
    let dup = pg["databases"][0].clone();
    pg["databases"] = json!([dup.clone(), dup]);
    assert!(err(&with_data(json!({"postgres": pg}))).contains("twice"));
}

#[test]
fn user_names_limits_and_ranges() {
    let user = |name: &str| json!({"name": name, "level": "readonly"});
    let mut pg = pg_json();
    pg["databases"][0]["users"] = json!([]);
    assert!(err(&with_data(json!({"postgres": pg}))).contains("users"));

    let users: Vec<Value> = (0..=MAX_PG_USERS_PER_DATABASE)
        .map(|i| user(&format!("u{i}")))
        .collect();
    let mut pg = pg_json();
    pg["databases"][0]["users"] = json!(users[..MAX_PG_USERS_PER_DATABASE]);
    validate_site_strict(&with_data(json!({"postgres": pg.clone()}))).unwrap();
    pg["databases"][0]["users"] = json!(users);
    assert!(err(&with_data(json!({"postgres": pg}))).contains("users"));

    for bad in ["", "A", "1u", "u_1", "u-1", "abcdefghijklmnopq"] {
        let mut pg = pg_json();
        pg["databases"][0]["users"] = json!([user(bad)]);
        assert!(
            validate_site_strict(&with_data(json!({"postgres": pg}))).is_err(),
            "{bad:?}"
        );
    }
    let mut pg = pg_json();
    pg["databases"][0]["users"] = json!([user("same"), user("same")]);
    assert!(err(&with_data(json!({"postgres": pg}))).contains("twice"));

    let ranged = [
        ("connection_limit", 0u64, false),
        ("connection_limit", 1, true),
        ("connection_limit", 500, true),
        ("connection_limit", 501, false),
        ("statement_timeout_ms", 0, true),
        ("statement_timeout_ms", 3_600_000, true),
        ("statement_timeout_ms", 3_600_001, false),
        ("idle_in_transaction_timeout_ms", 999, false),
        ("idle_in_transaction_timeout_ms", 1_000, true),
        ("idle_in_transaction_timeout_ms", 3_600_000, true),
        ("idle_in_transaction_timeout_ms", 3_600_001, false),
    ];
    for (field, value, ok) in ranged {
        let mut pg = pg_json();
        pg["databases"][0]["users"][0][field] = json!(value);
        let site = with_data(json!({"postgres": pg}));
        assert_eq!(validate_site_strict(&site).is_ok(), ok, "{field}={value}");
    }
}

#[test]
fn backup_policy_rules() {
    for every in [1, 2, 3, 4, 6, 8, 12, 24] {
        let mut pg = pg_json();
        pg["backup"] = json!({"schedule": {"every_hours": every, "minute": 59}});
        validate_site_strict(&with_data(json!({"postgres": pg}))).unwrap();
    }
    for every in [0, 5, 7, 9, 10, 11, 13, 25] {
        let mut pg = pg_json();
        pg["backup"] = json!({"schedule": {"every_hours": every, "minute": 0}});
        assert!(
            validate_site_strict(&with_data(json!({"postgres": pg}))).is_err(),
            "{every}"
        );
    }
    let mut pg = pg_json();
    pg["backup"] = json!({"schedule": {"every_hours": 6, "minute": 60}});
    assert!(err(&with_data(json!({"postgres": pg}))).contains("minute"));

    let limits = [
        ("keep_all_hours", 720u64),
        ("daily_days", 366),
        ("weekly_weeks", 260),
        ("monthly_months", 120),
        ("pre_restore_days", 366),
    ];
    for (field, max) in limits {
        for (value, ok) in [(0, true), (max, true), (max + 1, false)] {
            let mut pg = pg_json();
            pg["backup"] = json!({"local": {field: value}});
            let site = with_data(json!({"postgres": pg}));
            assert_eq!(validate_site_strict(&site).is_ok(), ok, "{field}={value}");
        }
    }
    let mut pg = pg_json();
    pg["backup"] = json!({"s3": {"target": "01J0TARGET", "retention": {"daily_days": 30}}});
    validate_site_strict(&with_data(json!({"postgres": pg}))).unwrap();
    let mut pg = pg_json();
    pg["backup"] = json!({"s3": {"target": "bad target!"}});
    assert!(err(&with_data(json!({"postgres": pg}))).contains("target"));
    let mut pg = pg_json();
    pg["backup"] = json!({"s3": {"target": "t", "retention": {"daily_days": 367}}});
    assert!(validate_site_strict(&with_data(json!({"postgres": pg}))).is_err());
}

#[test]
fn external_postgres_rules() {
    let with = |patch: Value| {
        let mut e = external();
        for (k, v) in patch.as_object().unwrap() {
            e[k] = v.clone();
        }
        with_data(json!({"external_postgres": [e]}))
    };
    validate_site_strict(&with(json!({}))).unwrap();
    validate_site_strict(&with(json!({"host": "203.0.113.7"}))).unwrap();
    validate_site_strict(&with(
        json!({"host": "2001:db8::1", "sslmode": "verify-full"}),
    ))
    .unwrap();
    for bad in [
        "",
        "DB.example.com",
        ".example.com",
        "db example.com",
        "1.2.3",
        "010.0.0.1",
        "db.example.com:5432",
        "10.0.0.1/8",
    ] {
        assert!(
            validate_site_strict(&with(json!({"host": bad}))).is_err(),
            "{bad:?}"
        );
    }
    for bad in ["", "Billing", "1b", "b_c", &"b".repeat(32)] {
        assert!(
            validate_site_strict(&with(json!({"name": bad}))).is_err(),
            "{bad:?}"
        );
    }
    assert!(validate_site_strict(&with(json!({"port": 0}))).is_err());
    assert!(validate_site_strict(&with(json!({"database": ""}))).is_err());
    assert!(validate_site_strict(&with(json!({"sslmode": "yes"}))).is_err());
    for ok in [
        "disable",
        "allow",
        "prefer",
        "require",
        "verify-ca",
        "verify-full",
    ] {
        validate_site_strict(&with(json!({"sslmode": ok}))).unwrap();
    }

    let many: Vec<Value> = (0..=MAX_EXTERNAL_POSTGRES)
        .map(|i| {
            let mut e = external();
            e["name"] = json!(format!("db-{i}"));
            e
        })
        .collect();
    validate_site_strict(&with_data(
        json!({"external_postgres": many[..MAX_EXTERNAL_POSTGRES]}),
    ))
    .unwrap();
    assert!(validate_site_strict(&with_data(json!({"external_postgres": many}))).is_err());
    assert!(
        err(&with_data(
            json!({"external_postgres": [external(), external()]})
        ))
        .contains("twice")
    );
}

#[test]
fn s3_attachment_rules() {
    let with = |patch: Value| {
        let mut e = s3();
        for (k, v) in patch.as_object().unwrap() {
            e[k] = v.clone();
        }
        with_data(json!({"s3": [e]}))
    };
    validate_site_strict(&with(json!({}))).unwrap();
    validate_site_strict(&with(
        json!({"endpoint": "https://minio.example.com:9000", "path_style": true}),
    ))
    .unwrap();
    for bad in [
        "http://minio.example.com:9000",
        "http://s3.example.com",
        "s3.example.com",
        "ftp://s3.example.com",
        "https://s3.example.com/",
        "https://s3.example.com/bucket",
        "https://s3.example.com?x=1",
        "https://user:pw@s3.example.com",
        "https://S3.Example.com",
        "https://s3.example.com:0",
        "https://s3.example.com:65536",
        "https://s3.example.com:",
        "https://127.0.0.1:9000",
        "https://10.0.0.5",
        "https://localhost",
        "https://[::1]",
        "https://2130706433",
        "",
    ] {
        assert!(
            validate_site_strict(&with(json!({"endpoint": bad}))).is_err(),
            "{bad:?}"
        );
    }
    for bad in [
        "ab",
        "Bucket-1",
        "-bucket",
        "bucket-",
        "bu_cket",
        &"b".repeat(64),
    ] {
        assert!(
            validate_site_strict(&with(json!({"bucket": bad}))).is_err(),
            "{bad:?}"
        );
    }
    for ok in ["abc", "my.bucket-1", &"b".repeat(63)] {
        validate_site_strict(&with(json!({"bucket": ok}))).unwrap();
    }
    for bad in ["", "EU", "eu_west", &"r".repeat(33)] {
        assert!(
            validate_site_strict(&with(json!({"region": bad}))).is_err(),
            "{bad:?}"
        );
    }
    assert!(validate_site_strict(&with(json!({"name": "Media"}))).is_err());

    let many: Vec<Value> = (0..=MAX_S3_ATTACHMENTS)
        .map(|i| {
            let mut e = s3();
            e["name"] = json!(format!("s3-{i}"));
            e
        })
        .collect();
    validate_site_strict(&with_data(json!({"s3": many[..MAX_S3_ATTACHMENTS]}))).unwrap();
    assert!(validate_site_strict(&with_data(json!({"s3": many}))).is_err());
    assert!(err(&with_data(json!({"s3": [s3(), s3()]}))).contains("twice"));
}

#[test]
fn s3_endpoint_parts() {
    let e = parse_s3_endpoint("https://s3.eu-west-1.amazonaws.com").unwrap();
    assert!(e.https && e.host == "s3.eu-west-1.amazonaws.com" && e.port.is_none());
    let e = parse_s3_endpoint("http://minio.example.com:9000").unwrap();
    assert!(!e.https && e.port == Some(9000));
    let e = parse_s3_endpoint("https://[2606:4700::1111]:8443").unwrap();
    assert_eq!((e.host.as_str(), e.port), ("2606:4700::1111", Some(8443)));
    assert!(parse_s3_endpoint("https://s3.example.com:+80").is_err());
}

#[test]
fn generated_secret_rules() {
    let with = |secrets: Value| with_data(json!({"secrets": secrets}));
    validate_site_strict(&with(
        json!([{"name": "a-b", "bytes": 32}, {"name": "c", "bytes": 128, "encoding": "hex"}]),
    ))
    .unwrap();
    for bytes in [0, 31, 129, 1000] {
        assert!(
            validate_site_strict(&with(json!([{"name": "a", "bytes": bytes}]))).is_err(),
            "{bytes}"
        );
    }
    for bad in ["", "A", "1a", "a_b", &"a".repeat(32)] {
        assert!(
            validate_site_strict(&with(json!([{"name": bad}]))).is_err(),
            "{bad:?}"
        );
    }
    assert!(err(&with(json!([{"name": "a"}, {"name": "a"}]))).contains("twice"));
    let many: Vec<Value> = (0..=MAX_GENERATED_SECRETS)
        .map(|i| json!({"name": format!("s{i}")}))
        .collect();
    validate_site_strict(&with(json!(many[..MAX_GENERATED_SECRETS]))).unwrap();
    assert!(validate_site_strict(&with(json!(many))).is_err());
}

#[test]
fn link_sources_must_exist() {
    validate_site_strict(&with_data(data_with_link(link(
        "DATABASE_URL",
        "runtime",
        pg_url(),
    ))))
    .unwrap();
    let missing = [
        link(
            "X",
            "runtime",
            json!({"kind": "postgres", "database": "nope", "user": "app", "field": "url"}),
        ),
        link(
            "X",
            "runtime",
            json!({"kind": "postgres", "database": "app", "user": "nope", "field": "url"}),
        ),
        link(
            "X",
            "runtime",
            json!({"kind": "external", "name": "nope", "field": "url"}),
        ),
        link(
            "X",
            "runtime",
            json!({"kind": "s3", "name": "nope", "field": "bucket"}),
        ),
        link("X", "runtime", json!({"kind": "secret", "name": "nope"})),
    ];
    for l in missing {
        let site = with_data(json!({"postgres": pg_json(), "links": [l.clone()]}));
        assert!(err(&site).contains("unknown"), "{l}: {}", err(&site));
    }
    // Managed Postgres not enabled at all.
    let site = with_data(json!({"links": [link("X", "runtime", pg_url())]}));
    assert!(err(&site).contains("not enabled"));
    // The user must belong to the named database, not just exist elsewhere.
    let site = with_data(json!({
        "postgres": {
            "mode": "dedicated", "major": 18,
            "databases": [
                {"name": "app", "users": [{"name": "app", "level": "owner"}]},
                {"name": "auth", "users": [{"name": "other", "level": "owner"}]}
            ]
        },
        "links": [link("X", "runtime", json!({"kind": "postgres", "database": "app", "user": "other", "field": "url"}))]
    }));
    assert!(err(&site).contains("unknown user"));
    // tls_servername only exists for external databases.
    let site = with_data(data_with_link(link(
        "X",
        "runtime",
        json!({"kind": "postgres", "database": "app", "user": "app", "field": "tls_servername"}),
    )));
    assert!(err(&site).contains("tls_servername"));
}

#[test]
fn duplicate_links_are_per_var_and_target() {
    let a = link("DATABASE_URL", "runtime", pg_url());
    let b = link(
        "DATABASE_URL",
        "build",
        json!({"kind": "postgres", "database": "app", "user": "migrate", "field": "url"}),
    );
    validate_site_strict(&with_data(
        json!({"postgres": pg_json(), "links": [a.clone(), b]}),
    ))
    .unwrap();
    let dup = with_data(json!({"postgres": pg_json(), "links": [a.clone(), a]}));
    assert!(err(&dup).contains("linked twice"), "{}", err(&dup));
    let same_target_other_source = with_data(json!({"postgres": pg_json(), "links": [
        link("DATABASE_URL", "runtime", pg_url()),
        link("DATABASE_URL", "runtime", json!({"kind": "postgres", "database": "app", "user": "migrate", "field": "url"}))
    ]}));
    assert!(validate_site_strict(&same_target_other_source).is_err());
}

#[test]
fn link_vars_follow_the_key_rules_of_their_target() {
    let site_url = json!({"kind": "site_url"});
    let ok = |var: &str, target: &str| {
        validate_site_strict(&with_data(
            json!({"postgres": pg_json(), "links": [link(var, target, site_url.clone())]}),
        ))
        .is_ok()
    };
    assert!(ok("APP_URL", "runtime") && ok("APP_URL", "build"));
    assert!(ok("_X1", "runtime"));
    for bad in [
        "",
        "lower",
        "1A",
        "A-B",
        "A B",
        "CITE_TOKEN",
        "A".repeat(65).as_str(),
    ] {
        assert!(!ok(bad, "runtime"), "{bad:?}");
        assert!(!ok(bad, "build"), "{bad:?}");
    }
    // Runtime reserves the names the executor sets; build reserves tool and path variables.
    for runtime_only in ["PORT", "NODE_ENV", "HOST", "HOSTNAME", "NITRO_HOST"] {
        assert!(!ok(runtime_only, "runtime"), "{runtime_only}");
    }
    assert!(ok("PORT", "build"));
    for build_only in [
        "TERM",
        "CARGO_HOME",
        "LD_SOMETHING",
        "DYLD_X",
        "GIT_DIR",
        "XDG_HOME",
    ] {
        assert!(!ok(build_only, "build"), "{build_only}");
    }
    assert!(ok("TERM", "runtime"));
    // Names both targets deny.
    for both in ["PATH", "NODE_OPTIONS", "HTTP_PROXY", "LD_PRELOAD"] {
        assert!(!ok(both, "runtime") && !ok(both, "build"), "{both}");
    }
    let site =
        with_data(json!({"postgres": pg_json(), "links": [link("PORT", "runtime", site_url)]}));
    assert!(err(&site).contains("PORT"));
}

#[test]
fn link_count_limit() {
    let links: Vec<Value> = (0..=MAX_ENV_LINKS)
        .map(|i| link(&format!("VAR_{i}"), "runtime", json!({"kind": "site_url"})))
        .collect();
    let at = with_data(json!({"postgres": pg_json(), "links": links[..MAX_ENV_LINKS]}));
    validate_site_strict(&at).unwrap();
    let over = with_data(json!({"postgres": pg_json(), "links": links}));
    assert!(err(&over).contains("links"));
}

#[test]
fn retired_database_rules() {
    let mut pg = pg_json();
    pg["retired"] = json!({"mode": "shared", "major": 17, "since": "2026-11-20T00:00:00Z"});
    validate_site_strict(&with_data(json!({"postgres": pg}))).unwrap();
    let mut pg = pg_json();
    pg["retired"] = json!({"mode": "shared", "major": 12, "since": "2026-11-20T00:00:00Z"});
    assert!(validate_site_strict(&with_data(json!({"postgres": pg}))).is_err());
    let mut pg = pg_json();
    pg["retired"] = json!({"mode": "shared", "major": 17, "since": ""});
    assert!(validate_site_strict(&with_data(json!({"postgres": pg}))).is_err());
}

#[test]
fn error_messages_never_contain_values() {
    // Link vars are named in errors; nothing else of a link (there is no value) can leak.
    let site = with_data(
        json!({"postgres": pg_json(), "links": [link("CITE_X", "runtime", json!({"kind": "site_url"}))]}),
    );
    let msg = err(&site);
    assert!(msg.contains("CITE_X") && msg.contains("runtime"), "{msg}");
}

#[test]
fn link_target_names() {
    assert_eq!(LinkTarget::Runtime.as_str(), "runtime");
    assert_eq!(LinkTarget::Build.as_str(), "build");
}
