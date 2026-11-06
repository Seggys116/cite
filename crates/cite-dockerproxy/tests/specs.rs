mod common;

use cite_connector::orchestrator::{SpecSet, StackEnv, stack_specs};
use cite_dockerproxy::policy::{MAX_BODY, Route};
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
        path_regexes: Vec::new(),
        path_prefixes: Vec::new(),
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
            ..Default::default()
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

fn with_entries(entries: &[String]) -> Result<(), String> {
    manager(|b| {
        b["Env"]
            .as_array_mut()
            .unwrap()
            .extend(entries.iter().map(|e| json!(e)))
    })
}

fn with_entry(key: &str, value: &str) -> Result<(), String> {
    with_entries(&[format!("{key}={value}")])
}

fn refuse_all(key: &str, values: &[&str]) {
    for value in values {
        assert!(
            with_entry(key, value).is_err(),
            "{key}={value:?} was accepted"
        );
    }
}

fn accept_all(key: &str, values: &[&str]) {
    for value in values {
        if let Err(e) = with_entry(key, value) {
            panic!("{key}={value:?} was refused: {e}");
        }
    }
}

// Text of exactly `total` bytes whose escaped quotes make it grow the most inside a create body; every value stays within 4096 characters.
fn build_env_json_of(total: usize) -> String {
    let len = |m: &serde_json::Map<String, Value>| serde_json::to_string(m).unwrap().len();
    let mut map = serde_json::Map::new();
    for i in 0.. {
        let mut next = map.clone();
        next.insert(format!("K{i}"), json!("\"".repeat(2048)));
        if len(&next) + ",\"Z\":\"\"".len() > total {
            break;
        }
        map = next;
    }
    map.insert("Z".into(), json!(""));
    let rest = total - len(&map);
    let tail = format!("{}{}", "\"".repeat(rest / 2), "x".repeat(rest % 2));
    map.insert("Z".into(), json!(tail));
    let text = serde_json::to_string(&map).unwrap();
    assert_eq!(text.len(), total);
    text
}

#[test]
fn every_new_build_setting_is_accepted_with_a_valid_value() {
    accept_all("CITE_ROOT_DIR", &[".", "apps/web", "a.b_c-d/e", "./site"]);
    accept_all(
        "CITE_OUTPUT_DIR",
        &["dist", "build/client", ".output/public"],
    );
    accept_all("CITE_SPA_FALLBACK", &["index.html", "app/200.html"]);
    accept_all("CITE_PACKAGE_MANAGER", &["npm", "pnpm", "yarn", "bun"]);
    accept_all("CITE_RENDERING", &["static", "ssr"]);
    accept_all("CITE_FRAMEWORK", &["react-router", "next", "svelte-kit2"]);
    accept_all("CITE_PRUNE", &["true", "false"]);
    accept_all(
        "CITE_INSTALL_COMMAND",
        &[
            "npm ci",
            "pnpm install --frozen-lockfile && echo 'done' | cat",
        ],
    );
    accept_all(
        "CITE_BUILD_COMMAND",
        &["npm run build", "cd web && npm run build > build.log"],
    );
    accept_all(
        "CITE_START_COMMAND",
        &[
            "node build/server/index.js",
            "react-router-serve ./build/server/index.js",
            "node \"my server.js\" --port 8080",
        ],
    );
    accept_all("CITE_DEPLOY_ID", &["01HZX3K9M2N4P5Q6R7S8T9V0WX"]);
    accept_all(
        "CITE_BUILD_ENV_JSON",
        &[
            "{}",
            "{\"API_URL\":\"https://api.example.com\",\"FLAG\":\"1\"}",
        ],
    );
}

#[test]
fn relative_path_settings_refuse_anything_that_could_leave_the_checkout() {
    let hostile = [
        "",
        "/",
        "/etc/passwd",
        "..",
        "../x",
        "a/../b",
        "a/..",
        "a\nb",
        "a\0b",
        "a b",
        "a;b",
        "`id`",
        "$(id)",
        "a'b",
        "a\"b",
        "a\\b",
        "a%2e%2e",
        "~/x",
        "\u{ff44}ist",
        "d\u{0456}st",
        "\u{2024}\u{2024}/x",
    ];
    for key in ["CITE_ROOT_DIR", "CITE_OUTPUT_DIR", "CITE_SPA_FALLBACK"] {
        refuse_all(key, &hostile);
        assert!(with_entry(key, &"a".repeat(255)).is_ok());
        assert!(with_entry(key, &"a".repeat(256)).is_err());
    }
}

#[test]
fn choice_settings_refuse_everything_off_the_list() {
    refuse_all(
        "CITE_PACKAGE_MANAGER",
        &[
            "",
            "NPM",
            "npm ",
            "npm\n",
            "pip",
            "bunx",
            "npm;id",
            "npm,pnpm",
            "\u{ff4e}\u{ff50}\u{ff4d}",
        ],
    );
    refuse_all(
        "CITE_RENDERING",
        &["", "SSR", "static\n", "hybrid", "ssr ", "\u{ff53}sr"],
    );
    refuse_all(
        "CITE_PRUNE",
        &[
            "", "True", "TRUE", "1", "0", "yes", "true\n", "true ", "false;",
        ],
    );
    refuse_all(
        "CITE_FRAMEWORK",
        &[
            "",
            "React",
            "re_act",
            "a b",
            "a;b",
            "$(id)",
            "a\n",
            "a/b",
            "re\u{0430}ct",
            "a.b",
        ],
    );
    assert!(with_entry("CITE_FRAMEWORK", &"a".repeat(32)).is_ok());
    assert!(with_entry("CITE_FRAMEWORK", &"a".repeat(33)).is_err());
}

#[test]
fn deploy_ids_are_exactly_twenty_six_uppercase_characters() {
    refuse_all(
        "CITE_DEPLOY_ID",
        &[
            "",
            "01HZX3K9M2N4P5Q6R7S8T9V0W",
            "01HZX3K9M2N4P5Q6R7S8T9V0WXY",
            "01hzx3k9m2n4p5q6r7s8t9v0wx",
            "01HZX3K9M2N4P5Q6R7S8T9V0W\n",
            "01HZX3K9M2N4P5Q6R7S8T9V0W;",
            "01HZX3K9M2N4P5Q6R7S8T9V0W\0",
            "\u{ff10}\u{ff11}HZX3K9M2N4P5Q6R7S8T9V0W",
        ],
    );
}

#[test]
fn install_and_build_commands_refuse_control_characters_and_excess_length() {
    for key in ["CITE_INSTALL_COMMAND", "CITE_BUILD_COMMAND"] {
        refuse_all(
            key,
            &[
                "",
                "a\nb",
                "a\rb",
                "a\0b",
                "a\tb",
                "a\x1bb",
                "a\x7fb",
                "a\u{85}b",
                "a\nrm -rf /",
            ],
        );
        assert!(with_entry(key, &"a".repeat(1024)).is_ok());
        assert!(with_entry(key, &"a".repeat(1025)).is_err());
    }
}

#[test]
fn start_commands_are_plain_argv_without_shell_syntax() {
    refuse_all(
        "CITE_START_COMMAND",
        &[
            "",
            "   ",
            "node a; id",
            "node a && id",
            "node a | tee x",
            "node a > x",
            "node a < x",
            "node `id`",
            "node $(id)",
            "node $HOME",
            "node \"$HOME\"",
            "node (a)",
            "node {a,b}",
            "node *.js",
            "node a?",
            "node ~/x",
            "node !x",
            "node #x",
            "node a\\ b",
            "node a\nb",
            "node a\0b",
            "node 'unterminated",
            "npm start",
            "npx serve",
            "pnpm start",
            "yarn start",
            "cargo run",
            "sh -c id",
            "bash -c id",
            "env A=1 node x.js",
            "/bin/sh -c id",
            "/usr/bin/env node x.js",
        ],
    );
    assert!(with_entry("CITE_START_COMMAND", &format!("node {}", "a".repeat(1019))).is_ok());
    assert!(with_entry("CITE_START_COMMAND", &format!("node {}", "a".repeat(1020))).is_err());
}

#[test]
fn build_environment_json_is_bounded_and_cannot_set_dangerous_variables() {
    refuse_all(
        "CITE_BUILD_ENV_JSON",
        &[
            "",
            "[]",
            "null",
            "{\"A\":1}",
            "{\"A\":null}",
            "{\"A\":[\"x\"]}",
            "{\"a\":\"1\"}",
            "{\"CITE_X\":\"1\"}",
            "{\"CITE_BUILD_UID\":\"0\"}",
            "{\"LD_PRELOAD\":\"/tmp/x.so\"}",
            "{\"LD_LIBRARY_PATH\":\"/tmp\"}",
            "{\"LD_AUDIT\":\"/tmp/x.so\"}",
            "{\"NODE_OPTIONS\":\"--require /tmp/x.js\"}",
            "{\"NODE_EXTRA_CA_CERTS\":\"/tmp/ca.pem\"}",
            "{\"HOME\":\"/\"}",
            "{\"PATH\":\"/tmp\"}",
            "{\"TMPDIR\":\"/\"}",
            "{\"XDG_CONFIG_HOME\":\"/\"}",
            "{\"SSL_CERT_FILE\":\"/tmp/ca.pem\"}",
            "{\"SSL_CERT_DIR\":\"/tmp\"}",
            "{\"HTTP_PROXY\":\"http://evil\"}",
            "{\"HTTPS_PROXY\":\"http://evil\"}",
            "{\"NO_PROXY\":\"*\"}",
            "{\"ALL_PROXY\":\"http://evil\"}",
            "{\"http_proxy\":\"http://evil\"}",
            "{\"GIT_SSH_COMMAND\":\"sh\"}",
            "{\"GIT_ASKPASS\":\"/tmp/x\"}",
            "{\"PNPM_HOME\":\"/tmp\"}",
            "{\"npm_config_registry\":\"http://evil\"}",
            "{\"NPM_CONFIG_REGISTRY\":\"http://evil\"}",
            "{\"A\":\"1\",\"A\":\"2\"}",
            "{\"A\":\"line\\nbreak\"}",
            "{\"A\":\"nul\\u0000byte\"}",
            "{\"A\":\"1\"}\n",
            "{\"A\":\"1\"} {\"B\":\"2\"}",
            "{\"A\":\"1\"",
        ],
    );
    let value = |n: usize| format!("{{\"A\":\"{}\"}}", "x".repeat(n));
    assert!(with_entry("CITE_BUILD_ENV_JSON", &value(4096)).is_ok());
    assert!(with_entry("CITE_BUILD_ENV_JSON", &value(4097)).is_err());
    let keys = |n: usize| {
        let items: Vec<String> = (0..n).map(|i| format!("\"K{i}\":\"v\"")).collect();
        format!("{{{}}}", items.join(","))
    };
    assert!(with_entry("CITE_BUILD_ENV_JSON", &keys(128)).is_ok());
    assert!(with_entry("CITE_BUILD_ENV_JSON", &keys(129)).is_err());
}

// The quoted literals of one `const NAME: &[&str] = &[...];` in the manager's config source.
fn core_list(name: &str) -> Vec<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../cite-core/src/config.rs");
    let source = std::fs::read_to_string(&path).expect("cite-core config source");
    let marker = format!("const {name}: &[&str] = &[");
    let start = source
        .find(&marker)
        .unwrap_or_else(|| panic!("{name} not found"))
        + marker.len();
    let body = &source[start..];
    let body = &body[..body.find("];").expect("end of list")];
    body.split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect()
}

#[test]
fn build_environment_json_refuses_every_name_the_manager_reserves() {
    let keys = core_list("RESERVED_BUILD_KEYS");
    assert!(keys.len() >= 39, "{} keys parsed", keys.len());
    let mut names = keys;
    for prefix in core_list("RESERVED_BUILD_PREFIXES") {
        names.push(format!("{prefix}EXAMPLE"));
    }
    for name in names {
        for variant in [name.clone(), name.to_ascii_lowercase()] {
            let text = format!("{{\"{variant}\":\"1\"}}");
            assert!(
                with_entry("CITE_BUILD_ENV_JSON", &text).is_err(),
                "{variant} was accepted"
            );
        }
    }
}

#[test]
fn settings_the_manager_must_never_receive_stay_forbidden() {
    for entry in [
        "CITE_BUILD_UID=0",
        "CITE_BUILD_GID=0",
        "CITE_DEV_SAME_USER=1",
        "CITE_BUILD_ENV_FILE=/etc/shadow",
        "CITE_MAX_ARCHIVE_BYTES=1",
        "CITE_MAX_FILES=1",
        "CITE_MAX_FILE_BYTES=1",
        "CITE_BUILD_TIMEOUT=1",
        "CITE_SITE_API_URL=http://169.254.169.254",
        "CITE_API_URL=http://evil",
        "CITE_BUILD_DIR=/",
        "CITE_TMP_DIR=/",
        "CITE_HOME_DIR=/",
        "CITE_DEPLOY_DIR=/",
        "CITE_ROOT_DIR_EXTRA=x",
        "cite_root_dir=x",
        "CITE_ROOT_DIR =x",
        "CITE_ROOT_DIR",
    ] {
        assert!(
            with_entries(&[entry.to_string()]).is_err(),
            "{entry} was accepted"
        );
    }
}

#[test]
fn new_settings_are_manager_only_and_cannot_repeat() {
    for entry in [
        "CITE_ROOT_DIR=dist",
        "CITE_PACKAGE_MANAGER=npm",
        "CITE_START_COMMAND=node x.js",
        "CITE_BUILD_ENV_JSON={}",
        "CITE_DEPLOY_ID=01HZX3K9M2N4P5Q6R7S8T9V0WX",
    ] {
        denied(executor(|b| {
            b["Env"].as_array_mut().unwrap().push(json!(entry))
        }));
        denied(init(|b| b["Env"] = json!([entry])));
    }
    denied(with_entries(&[
        "CITE_ROOT_DIR=a".to_string(),
        "CITE_ROOT_DIR=b".to_string(),
    ]));
    denied(with_entries(&[
        "CITE_BUILD_ENV_JSON={}".to_string(),
        "CITE_BUILD_ENV_JSON={}".to_string(),
    ]));
}

// Every manager key at its longest value, with the characters that grow most when escaped.
fn maximal_manager_env(build_env_json: &str) -> Vec<String> {
    let mut start = String::from("x");
    while start.len() + 4 <= 1024 {
        start.push_str(" '\"'");
    }
    start.push_str(&"y".repeat(1024 - start.len()));
    let long_path = "d".repeat(255);
    let quotes = |n: usize| "\"".repeat(n);
    let pairs: Vec<(&str, String)> = vec![
        (
            "CITE_REPO",
            format!("{}/{}", "a".repeat(100), "b".repeat(100)),
        ),
        ("CITE_BRANCH", "c".repeat(100)),
        ("CITE_POLL_INTERVAL", "9".repeat(16)),
        ("CITE_NODE", "24".to_string()),
        ("CITE_GITHUB_TOKEN", quotes(512)),
        ("CITE_GITHUB_API_URL", max_github_url()),
        ("CITE_DATA_DIR", "/var/lib/cite".to_string()),
        ("CITE_RELEASES_DIR", "/var/lib/cite/releases".to_string()),
        ("CITE_CONTROL_DIR", "/var/lib/cite/control".to_string()),
        ("CITE_STATUS_DIR", "/var/lib/cite/status".to_string()),
        ("CITE_STATE_DIR", "/var/lib/cite/state".to_string()),
        ("CITE_WORK_DIR", "/var/lib/cite/work".to_string()),
        ("CITE_CACHE_DIR", "/var/lib/cite/cache".to_string()),
        ("CITE_SOCKET", "/run/cite/manager.sock".to_string()),
        ("RUST_LOG", "info".to_string()),
        ("CITE_ROOT_DIR", long_path.clone()),
        ("CITE_OUTPUT_DIR", long_path.clone()),
        ("CITE_SPA_FALLBACK", long_path),
        ("CITE_PACKAGE_MANAGER", "pnpm".to_string()),
        ("CITE_RENDERING", "static".to_string()),
        ("CITE_FRAMEWORK", "a".repeat(32)),
        ("CITE_PRUNE", "false".to_string()),
        ("CITE_INSTALL_COMMAND", quotes(1024)),
        ("CITE_BUILD_COMMAND", quotes(1024)),
        ("CITE_START_COMMAND", start),
        ("CITE_DEPLOY_ID", "9".repeat(26)),
        ("CITE_BUILD_ENV_JSON", build_env_json.to_string()),
        ("CITE_FORGE", "gitlab".to_string()),
        ("CITE_FORGE_API_URL", max_github_url()),
    ];
    pairs.into_iter().map(|(k, v)| format!("{k}={v}")).collect()
}

// The longest URL the proxy's own configuration accepts.
fn max_github_url() -> String {
    format!("https://{}", "a".repeat(192))
}

fn create_with_env(env: &[String]) -> (usize, Result<(), String>) {
    let url = max_github_url();
    let policy = common::policy_with(&[
        ("CITE_PROXY_GITHUB_API_URL", url.as_str()),
        ("CITE_STACK_FORGE", "gitlab"),
        ("CITE_STACK_FORGE_API_URL", url.as_str()),
    ]);
    let s = specs("shop", "node", Slot::Blue, true);
    let mut body = s.manager.clone();
    body["Env"] = json!(env);
    let bytes = serde_json::to_vec(&body).unwrap();
    let parsed = cite_dockerproxy::strict::parse(&bytes).unwrap();
    let target = normalise(&format!("/v1.45/containers/create?name={}", s.manager_name)).unwrap();
    let route = policy.classify("POST", &target).unwrap();
    (bytes.len(), policy.validate_body(&route, &parsed))
}

#[test]
fn the_largest_legal_create_body_fits_the_body_cap() {
    assert_eq!(max_github_url().len(), 200);
    let env = maximal_manager_env(&build_env_json_of(24 * 1024));
    assert_eq!(env.len(), 29);
    let (size, result) = create_with_env(&env);
    result.unwrap();
    assert!(size < MAX_BODY, "{size} bytes");
    assert!(size > 55_000, "{size} bytes is not the worst case");
}

#[test]
fn one_byte_more_than_the_largest_legal_build_environment_is_refused() {
    let (_, result) = create_with_env(&maximal_manager_env(&build_env_json_of(24 * 1024 + 1)));
    assert!(result.is_err());
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

fn limits_accepted(
    policy: &cite_dockerproxy::policy::Policy,
    role: &str,
    mem: i64,
    cpus: i64,
) -> bool {
    let s = specs("shop", "node", Slot::Blue, true);
    let (name, mut body) = match role {
        "manager" => (s.manager_name.clone(), s.manager.clone()),
        _ => (s.executor_name.clone(), s.executor.clone()),
    };
    body["HostConfig"]["Memory"] = json!(mem);
    body["HostConfig"]["MemorySwap"] = json!(mem);
    body["HostConfig"]["NanoCpus"] = json!(cpus);
    let target = normalise(&format!("/v1.45/containers/create?name={name}")).unwrap();
    let route = policy.classify("POST", &target).unwrap();
    policy.validate_body(&route, &body).is_ok()
}

#[test]
fn memory_and_cpu_follow_the_operator_bounds() {
    const MIB: i64 = 1 << 20;
    const GIB: i64 = 1 << 30;
    let default = common::policy();
    let tuned = common::policy_with_limits("32g", "12");
    for role in ["manager", "executor"] {
        assert!(limits_accepted(&default, role, 256 * MIB, 250_000_000));
        assert!(limits_accepted(&default, role, 3 * GIB, 7_500_000_000));
        assert!(limits_accepted(&default, role, 16 * GIB, 8_000_000_000));
        assert!(!limits_accepted(&default, role, 256 * MIB - 1, 250_000_000));
        assert!(!limits_accepted(&default, role, 256 * MIB, 249_999_999));
        assert!(!limits_accepted(
            &default,
            role,
            16 * GIB + 1,
            8_000_000_000
        ));
        assert!(!limits_accepted(&default, role, 16 * GIB, 8_000_000_001));
        assert!(!limits_accepted(&default, role, 0, 250_000_000));
        assert!(!limits_accepted(&default, role, 256 * MIB, 0));
        assert!(limits_accepted(&tuned, role, 32 * GIB, 12_000_000_000));
        assert!(!limits_accepted(&tuned, role, 32 * GIB + 1, 12_000_000_000));
        assert!(!limits_accepted(&tuned, role, 32 * GIB, 12_000_000_001));
    }
}

fn executor_with_env(extra: &[String]) -> Result<(), String> {
    executor(|b| {
        b["Env"]
            .as_array_mut()
            .unwrap()
            .extend(extra.iter().map(|e| json!(e)))
    })
}

#[test]
fn runtime_environment_json_follows_the_build_environment_rules() {
    let ok = |text: &str| executor_with_env(&[format!("CITE_RUNTIME_ENV_JSON={text}")]);
    ok("{}").unwrap();
    ok("{\"API_URL\":\"https://api.example.com\"}").unwrap();
    for bad in [
        "",
        "[]",
        "{\"A\":1}",
        "{\"a\":\"1\"}",
        "{\"CITE_X\":\"1\"}",
        "{\"LD_PRELOAD\":\"/tmp/x.so\"}",
        "{\"NODE_OPTIONS\":\"--require x\"}",
        "{\"PATH\":\"/tmp\"}",
        "{\"GIT_ASKPASS\":\"x\"}",
        "{\"HTTP_PROXY\":\"http://evil\"}",
        "{\"PORT\":\"1\"}",
        "{\"NODE_ENV\":\"development\"}",
        "{\"HOST\":\"x\"}",
        "{\"HOSTNAME\":\"x\"}",
        "{\"NITRO_HOST\":\"x\"}",
        "{\"A\":\"1\",\"A\":\"2\"}",
        "{\"A\":\"line\\nbreak\"}",
        "{\"A\":\"nul\\u0000byte\"}",
    ] {
        assert!(ok(bad).is_err(), "{bad:?} was accepted");
    }
    let value = |n: usize| format!("{{\"A\":\"{}\"}}", "x".repeat(n));
    ok(&value(4096)).unwrap();
    assert!(ok(&value(4097)).is_err());
    assert!(
        executor_with_env(&[
            "CITE_RUNTIME_ENV_JSON={}".to_string(),
            "CITE_RUNTIME_ENV_JSON={}".to_string()
        ])
        .is_err()
    );
    denied(manager(|b| {
        b["Env"]
            .as_array_mut()
            .unwrap()
            .push(json!("CITE_RUNTIME_ENV_JSON={}"))
    }));
}

fn executor_with_runtime_json(text: &str) -> (usize, Result<(), String>) {
    let s = specs("shop", "node", Slot::Blue, true);
    let mut body = s.executor.clone();
    body["Env"] = json!([
        "CITE_LISTEN=0.0.0.0:8080",
        "CITE_DATA_DIR=/var/lib/cite",
        "CITE_RELEASES_DIR=/var/lib/cite/releases",
        "CITE_CONTROL_DIR=/var/lib/cite/control",
        "CITE_STATUS_DIR=/var/lib/cite/status",
        "RUST_LOG=info",
        "CITE_NODE_BIN=/nodejs/bin/node",
        "CITE_NODE=24",
        format!("CITE_RUNTIME_ENV_JSON={text}"),
    ]);
    let bytes = serde_json::to_vec(&body).unwrap();
    let parsed = cite_dockerproxy::strict::parse(&bytes).unwrap();
    let target = normalise(&format!(
        "/v1.45/containers/create?name={}",
        s.executor_name
    ))
    .unwrap();
    let policy = common::policy();
    let route = policy.classify("POST", &target).unwrap();
    (bytes.len(), policy.validate_body(&route, &parsed))
}

#[test]
fn the_largest_legal_executor_body_fits_the_body_cap() {
    let (size, result) = executor_with_runtime_json(&build_env_json_of(24 * 1024));
    result.unwrap();
    assert!(size < MAX_BODY, "{size} bytes");
    assert!(size > 45_000, "{size} bytes is not the worst case");
    let (_, result) = executor_with_runtime_json(&build_env_json_of(24 * 1024 + 1));
    assert!(result.is_err());
}

#[test]
fn executor_and_manager_limits_share_the_configured_bounds() {
    const GIB: i64 = 1 << 30;
    let tuned = common::policy_with_limits("32g", "12");
    for (mem, cpus) in [(4 * GIB, 2_000_000_000), (2 * GIB, 2_000_000_000)] {
        assert!(limits_accepted(&common::policy(), "manager", mem, cpus));
        assert!(limits_accepted(&common::policy(), "executor", mem, cpus));
    }
    assert!(limits_accepted(
        &tuned,
        "executor",
        32 * GIB,
        12_000_000_000
    ));
    assert!(!limits_accepted(
        &tuned,
        "executor",
        32 * GIB + 1,
        12_000_000_000
    ));
    assert!(!limits_accepted(
        &common::policy(),
        "executor",
        17 * GIB,
        2_000_000_000
    ));
    denied(executor(|b| b["HostConfig"]["PidsLimit"] = json!(1025)));
    assert!(executor(|b| b["HostConfig"]["PidsLimit"] = json!(1024)).is_ok());
}

#[test]
fn forge_keys_are_accepted_only_when_equal_to_the_operator_setting() {
    let url = "https://gitlab.example.com/api/v4";
    let entries = |kind: &str, api: &str| {
        vec![
            format!("CITE_FORGE={kind}"),
            format!("CITE_FORGE_API_URL={api}"),
        ]
    };
    let check = |policy: &cite_dockerproxy::policy::Policy, extra: &[String]| {
        let s = specs("shop", "node", Slot::Blue, true);
        let mut body = s.manager.clone();
        body["Env"]
            .as_array_mut()
            .unwrap()
            .extend(extra.iter().map(|e| json!(e)));
        let target =
            normalise(&format!("/v1.45/containers/create?name={}", s.manager_name)).unwrap();
        let route = policy.classify("POST", &target).unwrap();
        policy.validate_body(&route, &body)
    };
    let set = common::policy_with(&[
        ("CITE_STACK_FORGE", "gitlab"),
        ("CITE_STACK_FORGE_API_URL", url),
    ]);
    check(&set, &entries("gitlab", url)).unwrap();
    check(&set, &[]).unwrap();
    for (kind, api) in [
        ("github", url),
        ("gitea", url),
        ("bitbucket", url),
        ("GitLab", url),
        ("gitlab ", url),
        ("", url),
        ("gitlab", "https://evil.example.com/api/v4"),
        ("gitlab", "https://gitlab.example.com/api/v4/"),
        ("gitlab", "http://gitlab.example.com/api/v4"),
        ("gitlab", "https://gitlab.example.com/api/v4\n"),
        ("gitlab", ""),
    ] {
        assert!(
            check(&set, &entries(kind, api)).is_err(),
            "{kind:?} {api:?} was accepted"
        );
    }
    assert!(
        check(
            &set,
            &[
                "CITE_FORGE=gitlab".to_string(),
                "CITE_FORGE=gitlab".to_string()
            ]
        )
        .is_err()
    );
    let unset = common::policy();
    for entry in [
        "CITE_FORGE=gitlab".to_string(),
        format!("CITE_FORGE_API_URL={url}"),
    ] {
        assert!(
            check(&unset, std::slice::from_ref(&entry)).is_err(),
            "{entry}"
        );
    }
    denied(executor(|b| {
        b["Env"]
            .as_array_mut()
            .unwrap()
            .push(json!("CITE_FORGE=gitlab"))
    }));
}

#[test]
fn memory_swap_must_still_equal_memory() {
    denied(executor(|b| {
        b["HostConfig"]["Memory"] = json!(2i64 << 30);
        b["HostConfig"]["MemorySwap"] = json!(4i64 << 30);
    }));
    denied(manager(|b| {
        b["HostConfig"]["Memory"] = json!(2i64 << 30);
        b["HostConfig"]["MemorySwap"] = json!(-1);
    }));
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
