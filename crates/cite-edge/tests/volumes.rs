use cite_edge::model::{Site, Volume, volume_docker_name};
use cite_edge::validate::{
    MAX_VOLUMES, is_valid_volume_name, mount_path_problem, validate_site, validate_site_strict,
};
use serde_json::{Value, json};

fn site_with(source: Value, volumes: &[(&str, &str)]) -> Site {
    let mut v = json!({
        "id": "shop",
        "name": "Shop",
        "hosts": ["shop.example.com"],
        "blue": { "targets": [] },
        "green": { "targets": [] },
        "active": "blue",
        "source": source,
    });
    v["volumes"] = volumes
        .iter()
        .map(|(n, p)| json!({ "name": n, "mount_path": p }))
        .collect();
    serde_json::from_value(v).expect("site")
}

fn node(volumes: &[(&str, &str)]) -> Site {
    site_with(json!({ "repo": "acme/shop", "runtime": "node" }), volumes)
}

#[test]
fn volume_names_follow_the_slug_rule() {
    for ok in ["a", "data", "uploads-2", "0", &"a".repeat(31)] {
        assert!(is_valid_volume_name(ok), "{ok}");
    }
    for bad in ["", "-a", "Data", "a_b", "a.b", "a/b", "a b", &"a".repeat(32)] {
        assert!(!is_valid_volume_name(bad), "{bad}");
    }
}

#[test]
fn mount_paths_are_absolute_normalised_and_clear_of_the_executor() {
    for ok in [
        "/data",
        "/srv/uploads",
        "/home/nonroot/.cache",
        "/var/lib/app",
        "/app/storage",
        "/mnt/a_b-c.d",
    ] {
        assert_eq!(mount_path_problem(ok), None, "{ok}");
    }
    for bad in [
        "/",
        "",
        "data",
        "./data",
        "/data/",
        "/data//x",
        "/data/./x",
        "/data/../etc",
        "/da ta",
        "/data$x",
        "/var/lib/cite",
        "/var/lib/cite/releases",
        "/var/lib",
        "/var",
        "/tmp",
        "/tmp/x",
        "/proc",
        "/sys/fs",
        "/dev/shm",
        "/etc",
        "/run/x",
        "/var/run",
        "/usr/local/data",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/root",
        "/nodejs",
        "/cite-executor",
    ] {
        assert!(mount_path_problem(bad).is_some(), "{bad}");
    }
    let long = format!("/{}", "a".repeat(255));
    assert!(mount_path_problem(&long).is_some());
    let max = format!("/{}", "a".repeat(254));
    assert_eq!(mount_path_problem(&max), None);
}

#[test]
fn server_runtimes_accept_volumes() {
    for source in [
        json!({ "repo": "acme/shop" }),
        json!({ "repo": "acme/shop", "runtime": "bun" }),
        json!({ "repo": "acme/shop", "runtime": "rust", "rendering": "ssr" }),
        json!({ "repo": "acme/shop", "runtime": "node", "start_command": "node server.js" }),
    ] {
        let s = site_with(source.clone(), &[("data", "/data")]);
        assert!(validate_site_strict(&s).is_ok(), "{source}");
    }
}

#[test]
fn static_sites_and_sites_without_a_source_refuse_volumes() {
    for source in [
        json!({ "repo": "acme/shop", "runtime": "static" }),
        json!({ "repo": "acme/shop", "runtime": "node", "rendering": "static" }),
        Value::Null,
    ] {
        let s = site_with(source.clone(), &[("data", "/data")]);
        let err = validate_site_strict(&s).expect_err("refused").0;
        assert!(err.contains("server runtime"), "{source}: {err}");
    }
    let plain = site_with(json!({ "repo": "acme/shop", "runtime": "static" }), &[]);
    assert!(validate_site_strict(&plain).is_ok());
}

#[test]
fn the_volume_set_is_checked_as_a_whole() {
    let table: [(&[(&str, &str)], &str); 6] = [
        (&[("data", "/data"), ("data", "/other")], "used twice"),
        (&[("a", "/data"), ("b", "/data")], "overlapping"),
        (&[("a", "/data"), ("b", "/data/sub")], "overlapping"),
        (&[("a", "/data/sub"), ("b", "/data")], "overlapping"),
        (&[("Bad", "/data")], "name"),
        (&[("a", "/etc/app")], "mount_path"),
    ];
    for (vols, needle) in table {
        let err = validate_site_strict(&node(vols)).expect_err("refused").0;
        assert!(err.contains(needle), "{vols:?}: {err}");
    }
    assert!(validate_site_strict(&node(&[("a", "/data"), ("b", "/data2")])).is_ok());
}

#[test]
fn at_most_eight_volumes_fit_a_site() {
    let names: Vec<(String, String)> = (0..=MAX_VOLUMES)
        .map(|i| (format!("v{i}"), format!("/data{i}")))
        .collect();
    let refs: Vec<(&str, &str)> = names
        .iter()
        .map(|(n, p)| (n.as_str(), p.as_str()))
        .collect();
    assert!(validate_site_strict(&node(&refs[..MAX_VOLUMES])).is_ok());
    let err = validate_site_strict(&node(&refs)).expect_err("nine").0;
    assert!(err.contains("at most 8"), "{err}");
}

#[test]
fn loading_a_stored_site_does_not_judge_its_volumes() {
    let s = site_with(
        json!({ "repo": "acme/shop", "runtime": "static" }),
        &[("Bad", "/etc")],
    );
    assert!(validate_site(&s).is_ok());
}

#[test]
fn volumes_round_trip_and_stay_out_of_the_json_when_empty() {
    let s = node(&[("data", "/data")]);
    let text = serde_json::to_string(&s).unwrap();
    let back: Site = serde_json::from_str(&text).unwrap();
    assert_eq!(
        back.volumes,
        vec![Volume {
            name: "data".into(),
            mount_path: "/data".into()
        }]
    );
    let none = serde_json::to_value(node(&[])).unwrap();
    assert!(none.get("volumes").is_none());
    let bad: Result<Site, _> = serde_json::from_value(json!({
        "id": "shop", "name": "Shop", "hosts": ["shop.example.com"],
        "blue": { "targets": [] }, "green": { "targets": [] }, "active": "blue",
        "volumes": [{ "name": "a", "mount_path": "/a", "driver": "local" }],
    }));
    assert!(bad.is_err(), "unknown volume keys are refused");
}

#[test]
fn outbound_defaults_to_on_for_old_sites_and_is_always_written() {
    let old = node(&[]);
    assert!(old.outbound, "a site saved before the field gets outbound access");
    let text = serde_json::to_value(&old).unwrap();
    assert_eq!(text["outbound"], true);
    let mut closed = old.clone();
    closed.outbound = false;
    let back: Site = serde_json::from_value(serde_json::to_value(&closed).unwrap()).unwrap();
    assert!(!back.outbound);
    let mut static_closed = site_with(json!({ "repo": "acme/shop", "runtime": "static" }), &[]);
    static_closed.outbound = false;
    assert!(validate_site_strict(&static_closed).is_ok());
}

#[test]
fn docker_names_cannot_collide_between_sites() {
    assert_eq!(volume_docker_name("shop", "data"), "cite-vol-shop_data");
    assert_ne!(volume_docker_name("a", "b-c"), volume_docker_name("a-b", "c"));
}
