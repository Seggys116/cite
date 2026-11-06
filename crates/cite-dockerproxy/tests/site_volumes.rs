mod common;

use cite_connector::orchestrator::{SpecSet, StackEnv, stack_specs};
use cite_dockerproxy::policy::{Policy, Route};
use cite_dockerproxy::target::normalise;
use cite_edge::model::{Site, Slot, Volume};
use serde_json::{Value, json};

const TOKEN: &str = "ghp_secrettoken123";

fn site(id: &str, runtime: &str, volumes: &[(&str, &str)], outbound: bool) -> Site {
    let mut s: Site = serde_json::from_value(json!({
        "id": id,
        "name": id,
        "hosts": [format!("{id}.example.com")],
        "blue": { "targets": [] },
        "green": { "targets": [] },
        "active": "blue",
        "source": { "repo": "acme/shop", "runtime": runtime },
    }))
    .unwrap();
    s.volumes = volumes
        .iter()
        .map(|(n, p)| Volume {
            name: (*n).to_string(),
            mount_path: (*p).to_string(),
        })
        .collect();
    s.outbound = outbound;
    s
}

fn specs_for(s: &Site, slot: Slot, isolate: bool) -> SpecSet {
    let env = StackEnv {
        registry: common::REGISTRY,
        version: "0.2.0",
        edge_network: "cite_edge",
        isolate,
        github_api_url: None,
    };
    stack_specs(s, slot, None, TOKEN, &env).unwrap()
}

fn check(policy: &Policy, name: &str, body: &Value) -> Result<(), String> {
    let target = normalise(&format!("/v1.45/containers/create?name={name}"))?;
    let route = policy.classify("POST", &target)?;
    policy.validate_body(&route, body)
}

fn volumed() -> SpecSet {
    specs_for(
        &site("shop", "node", &[("data", "/data"), ("up", "/srv/up")], true),
        Slot::Blue,
        true,
    )
}

fn executor(mutate: impl FnOnce(&mut Value)) -> Result<(), String> {
    let s = volumed();
    let mut body = s.executor.clone();
    mutate(&mut body);
    check(&common::policy(), &s.executor_name, &body)
}

fn init(mutate: impl FnOnce(&mut Value)) -> Result<(), String> {
    let s = volumed();
    let mut body = s.init.clone();
    mutate(&mut body);
    check(&common::policy(), &s.init_name, &body)
}

fn mounts(b: &mut Value) -> &mut Vec<Value> {
    b["HostConfig"]["Mounts"].as_array_mut().unwrap()
}

#[test]
fn every_volume_and_outbound_variant_the_orchestrator_emits_is_accepted() {
    let policy = common::policy();
    for runtime in ["node", "bun", "rust"] {
        for outbound in [true, false] {
            for isolate in [true, false] {
                for slot in [Slot::Blue, Slot::Green] {
                    let vols: [(&str, &str); 3] =
                        [("data", "/data"), ("cache-2", "/home/nonroot/.cache"), ("x", "/var/lib/app")];
                    let s = specs_for(&site("shop-2", runtime, &vols, outbound), slot, isolate);
                    for (name, body) in [
                        (&s.manager_name, &s.manager),
                        (&s.executor_name, &s.executor),
                        (&s.init_name, &s.init),
                    ] {
                        check(&policy, name, body)
                            .unwrap_or_else(|e| panic!("{name} {runtime} {outbound}: {e}"));
                    }
                    assert_eq!(s.site_volumes.len(), 3);
                }
            }
        }
    }
}

#[test]
fn site_volume_mounts_are_volumes_of_this_site_only() {
    executor(|_| {}).unwrap();
    init(|_| {}).unwrap();
    for bad in [
        json!({ "Type": "bind", "Source": "/", "Target": "/host" }),
        json!({ "Type": "tmpfs", "Target": "/scratch" }),
        json!({ "Type": "volume", "Source": "cite-vol-other_data", "Target": "/other", "ReadOnly": false }),
        json!({ "Type": "volume", "Source": "cite-vol-shop_x", "Target": "/etc/x", "ReadOnly": false }),
        json!({ "Type": "volume", "Source": "cite-vol-shop_x", "Target": "/var/lib/cite/x", "ReadOnly": false }),
        json!({ "Type": "volume", "Source": "cite-vol-shop_x", "Target": "/data/inner", "ReadOnly": false }),
        json!({ "Type": "volume", "Source": "cite-vol-shop_data", "Target": "/again", "ReadOnly": false }),
        json!({ "Type": "volume", "Source": "cite-vol-shop_x", "Target": "/x/../etc", "ReadOnly": false }),
        json!({ "Type": "volume", "Source": "cite-vol-shop_x", "Target": "/x", "ReadOnly": true }),
        json!({ "Type": "volume", "Source": "cite-vol-shop_x", "Target": "/x", "ReadOnly": false, "VolumeOptions": { "NoCopy": true } }),
        json!({ "Type": "volume", "Source": "cite-vol-shop_x", "Target": "/x", "ReadOnly": false, "VolumeOptions": { "DriverConfig": { "Name": "local", "Options": { "o": "bind", "device": "/" } } } }),
        json!({ "Type": "volume", "Source": "cite-shop-green-data", "Target": "/x", "ReadOnly": false }),
        json!({ "Type": "volume", "Source": "cite-vol-SHOP_x", "Target": "/x", "ReadOnly": false }),
    ] {
        let shown = bad.to_string();
        assert!(executor(|b| mounts(b).push(bad)).is_err(), "{shown}");
    }
    assert!(executor(|b| mounts(b)[3]["Target"] = json!("/tmp")).is_err());
    assert!(executor(|b| mounts(b)[4]["ReadOnly"] = json!(true)).is_err());
}

#[test]
fn at_most_eight_site_volumes_are_accepted() {
    let names: Vec<(String, String)> = (0..8).map(|i| (format!("v{i}"), format!("/d{i}"))).collect();
    let refs: Vec<(&str, &str)> = names.iter().map(|(n, p)| (n.as_str(), p.as_str())).collect();
    let s = specs_for(&site("shop", "node", &refs, true), Slot::Blue, true);
    check(&common::policy(), &s.executor_name, &s.executor).unwrap();
    let mut body = s.executor.clone();
    mounts(&mut body).push(json!({ "Type": "volume", "Source": "cite-vol-shop_v8", "Target": "/d8", "ReadOnly": false }));
    assert!(check(&common::policy(), &s.executor_name, &body).is_err());
}

#[test]
fn the_init_container_only_chowns_this_sites_volumes_at_fixed_targets() {
    assert!(init(|b| mounts(b)[1]["Target"] = json!("/data/x")).is_err());
    assert!(init(|b| mounts(b)[1]["Target"] = json!("/vols/up")).is_err());
    assert!(init(|b| mounts(b)[1]["Source"] = json!("cite-vol-other_data")).is_err());
    assert!(init(|b| {
        let script = b["Cmd"][0].as_str().unwrap().replace("chown -R", "chmod -R 777");
        b["Cmd"] = json!([script]);
    })
    .is_err());
    assert!(init(|b| {
        mounts(b).pop();
    })
    .is_err(), "the script must match the mounts");
    assert!(init(|b| b["HostConfig"]["NetworkMode"] = json!("cite-shop-blue-egress")).is_err());
}

#[test]
fn site_volume_bodies_and_routes_are_pinned() {
    let policy = common::policy();
    let ok = json!({ "Name": "cite-vol-shop_data", "Labels": { "cite.managed": "true", "cite.site": "shop", "cite.volume": "data" } });
    policy.validate_body(&Route::VolumeCreate, &ok).unwrap();
    for bad in [
        json!({ "Name": "cite-vol-shop_data", "Labels": { "cite.managed": "true", "cite.site": "other", "cite.volume": "data" } }),
        json!({ "Name": "cite-vol-shop_data", "Labels": { "cite.managed": "true", "cite.site": "shop", "cite.volume": "other" } }),
        json!({ "Name": "cite-vol-shop_data", "Labels": { "cite.site": "shop", "cite.volume": "data" } }),
        json!({ "Name": "cite-vol-shop_data", "Labels": ok["Labels"], "Driver": "local" }),
        json!({ "Name": "cite-vol-shop_data", "Labels": ok["Labels"], "DriverOpts": { "o": "bind", "device": "/" } }),
        json!({ "Name": "cite-vol-shop_Data", "Labels": ok["Labels"] }),
        json!({ "Name": "cite-vol-shop-data", "Labels": ok["Labels"] }),
        json!({ "Name": "other", "Labels": ok["Labels"] }),
    ] {
        assert!(policy.validate_body(&Route::VolumeCreate, &bad).is_err(), "{bad}");
    }
    let route = |method: &str, raw: &str| policy.classify(method, &normalise(raw).unwrap());
    assert_eq!(
        route("GET", "/v1.45/volumes/cite-vol-shop_data").unwrap(),
        Route::VolumeInspect("cite-vol-shop_data".into())
    );
    assert_eq!(
        route("DELETE", "/v1.45/volumes/cite-vol-shop_data").unwrap(),
        Route::VolumeDelete("cite-vol-shop_data".into())
    );
    assert!(route("DELETE", "/v1.45/volumes/someone-elses").is_err());
    assert!(route("DELETE", "/v1.45/volumes/cite-vol-shop_data?force=true").is_err());
    let pinned = "/v1.45/volumes?filters=%7B%22label%22%3A%5B%22cite.managed%3Dtrue%22%2C%22cite.site%3Dshop%22%5D%7D";
    assert_eq!(route("GET", pinned).unwrap(), Route::VolumeList);
    assert!(route("GET", "/v1.45/volumes").is_err(), "a listing needs the label filter");
    let unpinned = "/v1.45/volumes?filters=%7B%22label%22%3A%5B%22cite.site%3Dshop%22%5D%7D";
    assert!(route("GET", unpinned).is_err());
    let dangling = "/v1.45/volumes?filters=%7B%22dangling%22%3A%5B%22true%22%5D%7D";
    assert!(route("GET", dangling).is_err());
    assert!(route("POST", "/v1.45/volumes/prune").is_err());
}

#[test]
fn executor_egress_follows_the_operator_switch() {
    let open = specs_for(&site("shop", "node", &[], true), Slot::Blue, true);
    let closed = specs_for(&site("shop", "node", &[], false), Slot::Blue, true);
    let eps = &open.executor["NetworkingConfig"]["EndpointsConfig"];
    assert_eq!(eps["cite-shop-blue-net"]["Aliases"], json!(["cite-shop-blue-executor"]));
    assert_eq!(eps["cite-shop-blue-egress"], json!({}));
    assert!(closed.executor["NetworkingConfig"]["EndpointsConfig"]
        .get("cite-shop-blue-egress")
        .is_none());
    let allowed = common::policy();
    let denied = common::policy_with(&[("CITE_STACK_EXECUTOR_EGRESS", "false")]);
    check(&allowed, &open.executor_name, &open.executor).unwrap();
    check(&allowed, &closed.executor_name, &closed.executor).unwrap();
    check(&denied, &closed.executor_name, &closed.executor).unwrap();
    let err = check(&denied, &open.executor_name, &open.executor).unwrap_err();
    assert!(err.contains("CITE_STACK_EXECUTOR_EGRESS"), "{err}");
    let mut aliased = open.executor.clone();
    aliased["NetworkingConfig"]["EndpointsConfig"]["cite-shop-blue-egress"] =
        json!({ "Aliases": ["cite-shop-blue-executor"] });
    assert!(check(&allowed, &open.executor_name, &aliased).is_err());
    let mut foreign = closed.executor.clone();
    foreign["NetworkingConfig"]["EndpointsConfig"]["cite-shop-green-egress"] = json!({});
    assert!(check(&allowed, &closed.executor_name, &foreign).is_err());
    let mut manager = open.manager.clone();
    manager["NetworkingConfig"]["EndpointsConfig"]["cite-shop-blue-net"] = json!({});
    assert!(check(&allowed, &open.manager_name, &manager).is_err());
}
