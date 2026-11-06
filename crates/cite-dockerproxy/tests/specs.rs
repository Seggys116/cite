mod common;

use cite_connector::orchestrator::{SpecSet, StackEnv, stack_specs};
use cite_dockerproxy::policy::Route;
use cite_dockerproxy::target::normalise;
use cite_edge::model::{HealthCheck, Maintenance, Site, SiteKind, Slot, Source, Upstream};
use serde_json::{Value, json};

// A fake token; specs carry it only in the manager environment.
const TOKEN: &str = "ghp_secrettoken123";

const GITHUB_URLS: [Option<&str>; 3] = [
    None,
    Some("https://ghe.example.com/api/v3"),
    Some("http://host.docker.internal:18080"),
];

fn site(id: &str, runtime: &str, node_major: Option<u8>) -> Site {
    Site {
        id: id.to_string(),
        name: id.to_string(),
        hosts: vec![format!("{id}.example.com")],
        path_regex: None,
        kind: SiteKind::Site,
        blue: Upstream::default(),
        green: Upstream::default(),
        active: Slot::Blue,
        maintenance: Maintenance::default(),
        health: HealthCheck::default(),
        source: Some(Source {
            repo: "acme/shop".to_string(),
            branch: None,
            runtime: Some(runtime.to_string()),
            node_major,
            poll_interval: Some("10m".to_string()),
            secret: None,
        }),
        history: Vec::new(),
        access: Default::default(),
    }
}

fn specs(id: &str, runtime: &str, slot: Slot, isolate: bool) -> SpecSet {
    let env = StackEnv {
        registry: common::REGISTRY,
        version: "0.2.0",
        edge_network: "cite_edge",
        isolate,
        github_api_url: None,
    };
    stack_specs(&site(id, runtime, None), slot, None, TOKEN, &env).unwrap()
}

// Runs a body through the same classify and validate steps the HTTP layer uses.
fn accepts(name: &str, body: &Value) -> Result<(), String> {
    let policy = common::policy();
    let target = normalise(&format!("/v1.45/containers/create?name={name}"))?;
    let route = policy.classify("POST", &target)?;
    policy.validate_body(&route, body)
}

fn executor(mutate: impl FnOnce(&mut Value)) -> Result<(), String> {
    let s = specs("shop", "node", Slot::Blue, true);
    let mut body = s.executor.clone();
    mutate(&mut body);
    accepts(&s.executor_name, &body)
}

fn manager(mutate: impl FnOnce(&mut Value)) -> Result<(), String> {
    let s = specs("shop", "node", Slot::Blue, true);
    let mut body = s.manager.clone();
    mutate(&mut body);
    accepts(&s.manager_name, &body)
}

fn init(mutate: impl FnOnce(&mut Value)) -> Result<(), String> {
    let s = specs("shop", "node", Slot::Blue, true);
    let mut body = s.init.clone();
    mutate(&mut body);
    accepts(&s.init_name, &body)
}

fn denied(result: Result<(), String>) {
    assert!(result.is_err(), "mutation was accepted");
}

#[test]
// Covers each runtime, slot, node major, git ref, network mode and GitHub API URL the orchestrator can produce.
fn every_spec_the_orchestrator_emits_is_accepted() {
    let mut checked = 0;
    for api_url in GITHUB_URLS {
        let policy = common::policy_with_github(api_url);
        for runtime in ["node", "bun", "static", "rust"] {
            for slot in [Slot::Blue, Slot::Green] {
                for isolate in [true, false] {
                    for major in [None, Some(24)] {
                        let env = StackEnv {
                            registry: common::REGISTRY,
                            version: "0.2.0",
                            edge_network: "cite_edge",
                            isolate,
                            github_api_url: api_url,
                        };
                        for git_ref in [None, Some("release/1.2")] {
                            let s = stack_specs(
                                &site("shop-2", runtime, major),
                                slot,
                                git_ref,
                                TOKEN,
                                &env,
                            )
                            .unwrap();
                            for (name, body) in [
                                (&s.manager_name, &s.manager),
                                (&s.executor_name, &s.executor),
                                (&s.init_name, &s.init),
                            ] {
                                let target =
                                    normalise(&format!("/v1.45/containers/create?name={name}"))
                                        .unwrap();
                                let route = policy.classify("POST", &target).unwrap();
                                policy.validate_body(&route, body).unwrap_or_else(|e| {
                                    panic!("{name} {runtime} {api_url:?}: {e}")
                                });
                                checked += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(checked, GITHUB_URLS.len() * 4 * 2 * 2 * 2 * 2 * 3);
}

#[test]
fn the_github_api_url_is_accepted_only_when_it_equals_the_operator_setting() {
    let url = "https://ghe.example.com/api/v3";
    let with_url = |url: Option<&'static str>| {
        let env = StackEnv {
            registry: common::REGISTRY,
            version: "0.2.0",
            edge_network: "cite_edge",
            isolate: true,
            github_api_url: url,
        };
        stack_specs(&site("shop", "node", None), Slot::Blue, None, TOKEN, &env).unwrap()
    };
    let check = |policy: &cite_dockerproxy::policy::Policy, s: &SpecSet, body: &Value| {
        let target =
            normalise(&format!("/v1.45/containers/create?name={}", s.manager_name)).unwrap();
        let route = policy.classify("POST", &target).unwrap();
        policy.validate_body(&route, body)
    };
    let s = with_url(Some(url));
    assert!(s.manager["Env"].to_string().contains("CITE_GITHUB_API_URL"));
    check(&common::policy_with_github(Some(url)), &s, &s.manager).unwrap();
    for other in [
        "https://evil.example.com/api/v3",
        "https://ghe.example.com/api/v3/",
        "http://ghe.example.com/api/v3",
        "https://ghe.example.com/api/v4",
    ] {
        denied(check(
            &common::policy_with_github(Some(other)),
            &s,
            &s.manager,
        ));
    }
    denied(check(&common::policy_with_github(None), &s, &s.manager));
    // A site created without the setting still works next to a proxy that has one.
    let plain = with_url(None);
    check(
        &common::policy_with_github(Some(url)),
        &plain,
        &plain.manager,
    )
    .unwrap();
}

#[test]
fn a_manager_cannot_redirect_the_github_token() {
    let push = |value: &'static str| {
        manager(move |b| {
            b["Env"]
                .as_array_mut()
                .unwrap()
                .push(json!(format!("CITE_GITHUB_API_URL={value}")))
        })
    };
    denied(push("https://evil.example.com"));
    denied(push(""));
    denied(manager(|b| {
        b["Env"].as_array_mut().unwrap().extend([
            json!("CITE_GITHUB_API_URL=a"),
            json!("CITE_GITHUB_API_URL=a"),
        ])
    }));
    denied(executor(|b| {
        b["Env"]
            .as_array_mut()
            .unwrap()
            .push(json!("CITE_GITHUB_API_URL=https://evil.example.com"))
    }));
    denied(init(|b| {
        b["Env"] = json!(["CITE_GITHUB_API_URL=https://evil.example.com"])
    }));
}

#[test]
fn volume_and_network_bodies_of_the_orchestrator_are_accepted() {
    let policy = common::policy();
    let s = specs("shop", "node", Slot::Green, true);
    let labels = |role: &str| json!({ "cite.managed": "true", "cite.site": "shop", "cite.slot": "green", "cite.role": role });
    for volume in &s.volumes {
        let body = json!({ "Name": volume, "Labels": labels("volume") });
        policy.validate_body(&Route::VolumeCreate, &body).unwrap();
    }
    for network in &s.networks {
        let internal = network.ends_with("-net");
        let body = json!({ "Name": network, "Driver": "bridge", "Internal": internal, "Labels": labels("network") });
        policy.validate_body(&Route::NetworkCreate, &body).unwrap();
    }
}

#[test]
fn the_real_images_and_tags_match_the_pull_policy() {
    let policy = common::policy();
    for runtime in ["node", "bun", "static", "rust"] {
        let s = specs("shop", runtime, Slot::Blue, true);
        for image in [&s.manager_image, &s.executor_image] {
            let (repo, tag) = image.rsplit_once(':').unwrap();
            let target =
                normalise(&format!("/v1.45/images/create?fromImage={repo}&tag={tag}")).unwrap();
            assert_eq!(
                policy.classify("POST", &target),
                Ok(Route::ImagePull),
                "{image}"
            );
        }
    }
}

#[test]
// Each mutation starts from a spec the orchestrator really emits and adds one forbidden thing.
fn privileged_and_host_access_are_refused() {
    denied(manager(|b| b["HostConfig"]["Privileged"] = json!(true)));
    denied(manager(|b| b["HostConfig"]["Binds"] = json!(["/:/host"])));
    denied(manager(|b| b["HostConfig"]["PidMode"] = json!("host")));
    denied(manager(|b| b["HostConfig"]["IpcMode"] = json!("host")));
    denied(manager(|b| b["HostConfig"]["UsernsMode"] = json!("host")));
    denied(manager(|b| b["HostConfig"]["UTSMode"] = json!("host")));
    denied(manager(|b| b["HostConfig"]["CgroupnsMode"] = json!("host")));
    denied(manager(
        |b| b["HostConfig"]["Devices"] = json!([{ "PathOnHost": "/dev/sda", "PathInContainer": "/dev/sda", "CgroupPermissions": "rwm" }]),
    ));
    denied(manager(|b| {
        b["HostConfig"]["DeviceRequests"] = json!([{ "Count": -1 }])
    }));
}

#[test]
fn network_escapes_are_refused() {
    denied(manager(|b| b["HostConfig"]["NetworkMode"] = json!("host")));
    denied(executor(|b| b["HostConfig"]["NetworkMode"] = json!("host")));
    denied(executor(|b| {
        b["HostConfig"]["NetworkMode"] = json!("container:other")
    }));
    denied(executor(|b| {
        b["HostConfig"]["NetworkMode"] = json!("bridge")
    }));
    denied(init(|b| {
        b["HostConfig"]["NetworkMode"] = json!("cite_edge")
    }));
    denied(manager(|b| {
        b["HostConfig"]["NetworkMode"] = json!("cite_edge")
    }));
    denied(executor(|b| {
        b["HostConfig"]["NetworkMode"] = json!("cite-other-blue-net")
    }));
    denied(executor(|b| {
        b["HostConfig"]["NetworkMode"] = json!("cite-shop-green-net")
    }));
    denied(executor(|b| {
        b["HostConfig"]["PortBindings"] = json!({ "8080/tcp": [{ "HostPort": "80" }] })
    }));
    denied(executor(|b| {
        b["HostConfig"]["PublishAllPorts"] = json!(true)
    }));
    denied(executor(|b| b["ExposedPorts"] = json!({ "8080/tcp": {} })));
}

#[test]
fn executor_may_join_only_its_own_or_the_edge_network() {
    let s = specs("shop", "node", Slot::Blue, false);
    accepts(&s.executor_name, &s.executor).unwrap();
    let mut body = s.executor.clone();
    body["NetworkingConfig"]["EndpointsConfig"] =
        json!({ "cite_edge": {}, "cite-shop-blue-egress": {} });
    denied(accepts(&s.executor_name, &body));
}

#[test]
fn capability_changes_are_refused() {
    denied(manager(|b| b["HostConfig"]["CapAdd"] = json!(["ALL"])));
    denied(manager(|b| {
        b["HostConfig"]["CapAdd"] =
            json!(["CHOWN", "SETUID", "SETGID", "DAC_READ_SEARCH", "SYS_ADMIN"])
    }));
    denied(executor(|b| {
        b["HostConfig"]["CapAdd"] = json!(["NET_ADMIN"])
    }));
    denied(init(|b| {
        b["HostConfig"]["CapAdd"] = json!(["CHOWN", "FOWNER", "SYS_PTRACE"])
    }));
    denied(executor(|b| b["HostConfig"]["CapDrop"] = json!([])));
    denied(executor(|b| {
        b["HostConfig"]["CapDrop"] = json!(["NET_RAW"])
    }));
    denied(executor(|b| {
        b["HostConfig"].as_object_mut().unwrap().remove("CapDrop");
    }));
}

#[test]
fn hardening_flags_cannot_be_relaxed() {
    denied(executor(|b| {
        b["HostConfig"]["ReadonlyRootfs"] = json!(false)
    }));
    denied(executor(|b| {
        b["HostConfig"]["SecurityOpt"] = json!(["seccomp=unconfined"])
    }));
    denied(executor(|b| {
        b["HostConfig"]["SecurityOpt"] = json!(["no-new-privileges:true", "apparmor=unconfined"])
    }));
    denied(executor(|b| b["HostConfig"]["SecurityOpt"] = json!([])));
    denied(executor(|b| {
        b["HostConfig"]["Sysctls"] = json!({ "net.ipv4.ip_forward": "1" })
    }));
    denied(executor(|b| b["HostConfig"]["Runtime"] = json!("runc2")));
    denied(executor(|b| {
        b["HostConfig"]["StorageOpt"] = json!({ "size": "1T" })
    }));
    denied(executor(|b| {
        b["HostConfig"]["CgroupParent"] = json!("/system.slice")
    }));
}

#[test]
// A mount may only name volumes of its own stack, with the exact subpaths and flags.
fn mounts_are_pinned_to_the_stack() {
    denied(executor(|b| {
        b["HostConfig"]["Mounts"][0]["Type"] = json!("bind")
    }));
    denied(executor(|b| {
        b["HostConfig"]["Mounts"][0]["Source"] = json!("/")
    }));
    denied(executor(|b| {
        b["HostConfig"]["Mounts"][0]["Source"] = json!("cite-other-blue-data")
    }));
    denied(executor(|b| {
        b["HostConfig"]["Mounts"][0]["Source"] = json!("cite-shop-green-data")
    }));
    denied(executor(|b| {
        b["HostConfig"]["Mounts"][0]["ReadOnly"] = json!(false)
    }));
    denied(executor(|b| {
        b["HostConfig"]["Mounts"][0]["BindOptions"] = json!({ "Propagation": "shared" })
    }));
    denied(executor(|b| {
        b["HostConfig"]["Mounts"][0]["VolumeOptions"]["DriverConfig"] =
            json!({ "Name": "local", "Options": { "o": "bind", "device": "/" } })
    }));
    denied(executor(|b| {
        b["HostConfig"]["Mounts"][0]["VolumeOptions"]["Subpath"] = json!("../..")
    }));
    denied(executor(|b| {
        b["HostConfig"]["Mounts"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "Type": "volume", "Source": "cite-shop-blue-work", "Target": "/w" }))
    }));
    denied(executor(|b| {
        b["HostConfig"]["VolumesFrom"] = json!(["cite-other-blue-executor"])
    }));
    denied(executor(|b| b["Volumes"] = json!({ "/host": {} })));
    denied(executor(|b| {
        b["HostConfig"]["Tmpfs"]["/tmp"] = json!("size=64g,mode=1777")
    }));
}

#[test]
fn environment_is_restricted_to_known_keys() {
    denied(manager(|b| {
        b["Env"]
            .as_array_mut()
            .unwrap()
            .push(json!("LD_PRELOAD=/tmp/x.so"))
    }));
    denied(manager(|b| {
        b["Env"].as_array_mut().unwrap().push(json!("CITE_EXTRA=1"))
    }));
    denied(manager(|b| {
        b["Env"]
            .as_array_mut()
            .unwrap()
            .push(json!("CITE_REPO=other/repo"))
    }));
    denied(manager(|b| {
        b["Env"].as_array_mut().unwrap().push(json!("PATH=/tmp"))
    }));
    denied(manager(|b| b["Env"] = json!(["CITE_DATA_DIR=/host"])));
    denied(manager(|b| b["Env"] = json!(["CITE_REPO=a/b;rm -rf /"])));
    denied(manager(|b| {
        b["Env"] = json!(["CITE_BRANCH=--upload-pack=x"])
    }));
    denied(manager(|b| b["Env"] = json!(["CITE_BRANCH=a..b"])));
    denied(manager(|b| {
        b["Env"] = json!(["CITE_GITHUB_TOKEN=has space"])
    }));
    denied(manager(|b| {
        b["Env"] = json!(["CITE_GITHUB_TOKEN=line\nbreak"])
    }));
    denied(manager(|b| b["Env"] = json!(["CITE_NODE=18"])));
    denied(manager(|b| b["Env"] = json!(["RUST_LOG=trace"])));
    denied(manager(|b| b["Env"] = json!([1])));
    denied(manager(|b| b["Env"] = json!("CITE_REPO=a/b")));
    denied(executor(|b| {
        b["Env"]
            .as_array_mut()
            .unwrap()
            .push(json!("CITE_GITHUB_TOKEN=x"))
    }));
    denied(init(|b| b["Env"] = json!(["CITE_REPO=a/b"])));
}

#[test]
fn duplicate_and_oversized_environments_are_refused() {
    denied(manager(|b| {
        b["Env"]
            .as_array_mut()
            .unwrap()
            .push(json!("CITE_REPO=acme/shop"))
    }));
    denied(manager(|b| {
        let filler: Vec<Value> = (0..40).map(|_| json!("RUST_LOG=info")).collect();
        b["Env"] = Value::Array(filler);
    }));
    denied(manager(|b| {
        b["Env"] = json!([format!("CITE_GITHUB_TOKEN={}", "a".repeat(513))])
    }));
}

#[test]
fn images_must_come_from_the_registry_and_fit_the_role() {
    denied(manager(|b| {
        b["Image"] = json!("evil.example.com/cite-manager:0.2.0-node22")
    }));
    denied(manager(|b| {
        b["Image"] = json!("ghcr.io/other/cite-manager:0.2.0-node22")
    }));
    denied(manager(|b| {
        b["Image"] = json!("ghcr.io/seggys116/cite-manager:latest")
    }));
    denied(manager(|b| {
        b["Image"] = json!(
            "ghcr.io/seggys116/cite-manager@sha256:0000000000000000000000000000000000000000000000000000000000000000"
        )
    }));
    denied(manager(|b| {
        b["Image"] = json!("ghcr.io/seggys116/cite-manager:0.2.0")
    }));
    denied(manager(|b| {
        b["Image"] = json!("ghcr.io/seggys116/cite-executor-node:0.2.0-node22")
    }));
    denied(manager(|b| {
        b["Image"] = json!("ghcr.io/seggys116/cite-manager:0.2.0-node18")
    }));
    denied(manager(|b| {
        b["Image"] = json!("ghcr.io/seggys116/cite-manager:0.2.0-node22 ")
    }));
    denied(manager(|b| {
        b["Image"] = json!("ghcr.io/seggys116xcite-manager:0.2.0-node22")
    }));
    denied(executor(|b| {
        b["Image"] = json!("ghcr.io/seggys116/cite-manager:0.2.0-node22")
    }));
    denied(executor(|b| b["Image"] = json!("alpine")));
    denied(init(|b| {
        b["Image"] = json!("ghcr.io/seggys116/cite-executor-bun:0.2.0")
    }));
    denied(init(|b| b["Image"] = json!(7)));
}

#[test]
fn names_and_labels_must_agree() {
    let s = specs("shop", "node", Slot::Blue, true);
    denied(accepts("cite-shop-green-executor", &s.executor));
    denied(accepts("cite-other-blue-executor", &s.executor));
    denied(accepts("cite-shop-blue-manager", &s.executor));
    denied(accepts("Cite-shop-blue-executor", &s.executor));
    denied(accepts("cite-SHOP-blue-executor", &s.executor));
    denied(accepts("cite-shop-blue-executor-2", &s.executor));
    denied(accepts("shop", &s.executor));
    denied(executor(|b| b["Labels"]["cite.site"] = json!("other")));
    denied(executor(|b| b["Labels"]["cite.slot"] = json!("green")));
    denied(executor(|b| b["Labels"]["cite.role"] = json!("manager")));
    denied(executor(|b| b["Labels"]["cite.managed"] = json!("false")));
    denied(executor(|b| b["Labels"]["cite.extra"] = json!("1")));
    denied(executor(|b| b["Labels"]["traefik.enable"] = json!("true")));
    denied(executor(|b| {
        b["Labels"].as_object_mut().unwrap().remove("cite.managed");
    }));
}

#[test]
fn only_the_known_top_level_keys_are_accepted() {
    denied(manager(|b| b["Entrypoint"] = json!(["/bin/sh"])));
    denied(manager(|b| b["Cmd"] = json!(["id"])));
    denied(executor(|b| b["Hostname"] = json!("x")));
    denied(executor(|b| b["Domainname"] = json!("x")));
    denied(executor(|b| b["WorkingDir"] = json!("/")));
    denied(executor(|b| b["StopSignal"] = json!("SIGKILL")));
    denied(executor(|b| b["Tty"] = json!(true)));
    denied(executor(|b| b["OpenStdin"] = json!(true)));
    denied(executor(|b| b["AttachStdin"] = json!(true)));
    denied(executor(|b| b["MacAddress"] = json!("02:42:ac:11:00:02")));
    denied(executor(|b| b["User"] = json!("0:0")));
    denied(executor(|b| b["User"] = json!("root")));
    denied(manager(|b| b["User"] = json!("0")));
    denied(executor(|b| {
        b.as_object_mut().unwrap().remove("User");
    }));
    denied(manager(|b| {
        b["Healthcheck"]["Test"] = json!(["CMD", "sh", "-c", "id"])
    }));
    denied(executor(|b| b["Healthcheck"]["Retries"] = json!(1000)));
}

#[test]
fn init_container_is_pinned_to_its_script() {
    denied(init(|b| b["Cmd"] = json!(["chmod -R 777 /data"])));
    denied(init(|b| b["Cmd"] = json!(["chmod -R 777 /data", "extra"])));
    denied(init(|b| b["Entrypoint"] = json!(["/bin/bash", "-c"])));
    denied(init(|b| b["User"] = json!("65532:65532")));
    denied(init(|b| {
        b["HostConfig"]["Mounts"][0]["Target"] = json!("/")
    }));
    denied(init(|b| {
        b["HostConfig"]["Mounts"][0]["Source"] = json!("cite-shop-blue-work")
    }));
    denied(init(|b| {
        b["HostConfig"]["RestartPolicy"] = json!({ "Name": "always" })
    }));
    denied(init(|b| b["HostConfig"]["Init"] = json!(true)));
}

#[test]
fn resource_limits_are_bounded() {
    denied(executor(|b| b["HostConfig"]["Memory"] = json!(1i64 << 40)));
    denied(executor(|b| b["HostConfig"]["Memory"] = json!(0)));
    denied(executor(|b| b["HostConfig"]["Memory"] = json!(-1)));
    denied(executor(|b| b["HostConfig"]["MemorySwap"] = json!(-1)));
    denied(executor(|b| b["HostConfig"]["PidsLimit"] = json!(-1)));
    denied(executor(|b| b["HostConfig"]["PidsLimit"] = json!(0)));
    denied(executor(|b| {
        b["HostConfig"]["NanoCpus"] = json!(64_000_000_000i64)
    }));
    denied(executor(|b| b["HostConfig"]["Memory"] = json!(1.5e9)));
    denied(manager(|b| {
        b["HostConfig"].as_object_mut().unwrap().remove("PidsLimit");
    }));
    denied(init(|b| b["HostConfig"]["Memory"] = json!(1i64 << 31)));
}

#[test]
// The engine matches JSON keys case-insensitively, so look-alike keys must be rejected too.
fn case_variants_and_duplicates_cannot_smuggle_keys() {
    denied(executor(|b| {
        b["hostconfig"] = json!({ "Privileged": true })
    }));
    denied(executor(|b| b["HostConfig"]["privileged"] = json!(true)));
    denied(executor(|b| b["image"] = json!("alpine")));
    denied(executor(|b| b["HOSTCONFIG"] = json!({})));
    denied(accepts("cite-shop-blue-executor", &json!([])));
    denied(accepts("cite-shop-blue-executor", &json!("string")));
    denied(accepts("cite-shop-blue-executor", &json!({})));
}

#[test]
// A bind-style local volume would expose the host root, so driver options must never pass.
fn volume_creation_cannot_bind_the_host() {
    let policy = common::policy();
    let labels = json!({ "cite.managed": "true", "cite.site": "shop", "cite.slot": "blue", "cite.role": "volume" });
    let ok = json!({ "Name": "cite-shop-blue-data", "Labels": labels });
    policy.validate_body(&Route::VolumeCreate, &ok).unwrap();
    for (key, value) in [
        ("Driver", json!("local")),
        (
            "DriverOpts",
            json!({ "type": "none", "o": "bind", "device": "/" }),
        ),
        ("name", json!("x")),
    ] {
        let mut bad = ok.clone();
        bad[key] = value;
        assert!(
            policy.validate_body(&Route::VolumeCreate, &bad).is_err(),
            "{key}"
        );
    }
    for name in [
        "cite-shop-blue-other",
        "cite-SHOP-blue-data",
        "other",
        "cite-shop-red-data",
        "cite-shop-blue-data/../x",
    ] {
        let bad = json!({ "Name": name, "Labels": labels });
        assert!(
            policy.validate_body(&Route::VolumeCreate, &bad).is_err(),
            "{name}"
        );
    }
    let mismatched = json!({ "Name": "cite-shop-blue-data", "Labels": { "cite.managed": "true", "cite.site": "other", "cite.slot": "blue", "cite.role": "volume" } });
    assert!(
        policy
            .validate_body(&Route::VolumeCreate, &mismatched)
            .is_err()
    );
    assert!(
        policy
            .validate_body(
                &Route::VolumeCreate,
                &json!({ "Name": "cite-shop-blue-data" })
            )
            .is_err()
    );
}

#[test]
fn network_creation_is_restricted() {
    let policy = common::policy();
    let labels = json!({ "cite.managed": "true", "cite.site": "shop", "cite.slot": "blue", "cite.role": "network" });
    let net = json!({ "Name": "cite-shop-blue-net", "Driver": "bridge", "Internal": true, "Labels": labels });
    policy.validate_body(&Route::NetworkCreate, &net).unwrap();
    let mut no_driver = net.clone();
    no_driver.as_object_mut().unwrap().remove("Driver");
    policy
        .validate_body(&Route::NetworkCreate, &no_driver)
        .unwrap();
    for (key, value) in [
        ("Driver", json!("macvlan")),
        ("Driver", json!("host")),
        ("Options", json!({ "parent": "eth0" })),
        ("IPAM", json!({ "Config": [{ "Subnet": "10.0.0.0/8" }] })),
        ("Attachable", json!(true)),
        ("Internal", json!(false)),
        ("EnableIPv6", json!(true)),
        ("Name", json!("cite-shop-blue-egress")),
        ("Name", json!("bridge")),
        ("Name", json!("host")),
    ] {
        let mut bad = net.clone();
        bad[key] = value;
        assert!(
            policy.validate_body(&Route::NetworkCreate, &bad).is_err(),
            "{key}"
        );
    }
    let egress = json!({ "Name": "cite-shop-blue-egress", "Driver": "bridge", "Internal": false, "Labels": labels });
    policy
        .validate_body(&Route::NetworkCreate, &egress)
        .unwrap();
}

#[test]
fn only_haproxy_may_be_attached_to_stack_networks() {
    let policy = common::policy();
    let connect = Route::NetworkConnect("cite-shop-blue-net".to_string());
    policy
        .validate_body(&connect, &json!({ "Container": common::HAPROXY }))
        .unwrap();
    for bad in [
        json!({ "Container": "cite-shop-blue-manager" }),
        json!({ "Container": "other" }),
        json!({ "Container": common::HAPROXY, "EndpointConfig": { "Aliases": ["cite-other-blue-executor"] } }),
        json!({ "Container": common::HAPROXY, "Force": true }),
        json!({}),
        json!({ "Container": 1 }),
    ] {
        assert!(policy.validate_body(&connect, &bad).is_err(), "{bad}");
    }
}
