//! Shared library for the Cite manager and executor.

#![forbid(unsafe_code)]

pub mod argv;
pub mod atomic;
pub mod config;
pub mod detect;
pub mod duration;
pub mod error;
pub mod extract;
pub mod pack;
pub mod pathsafe;
pub mod redact;
pub mod schema;
pub mod volume;

pub use argv::{render_argv, split_command, validate_start_argv};
pub use atomic::{AtomicPoint, ensure_dir, set_tight_umask, write_atomic, write_atomic_failpoint};
pub use config::{
    ExecutorConfig, GithubToken, ManagerConfig, RenderingSetting, SiteEnv, parse_env_file,
};
pub use detect::{Detection, detect_site, detect_site_configured, detect_site_with};
pub use duration::{PollInterval, parse_byte_size, parse_duration, parse_poll_interval};
pub use error::{Error, Result};
pub use extract::{ExtractLimits, ExtractReport, extract_archive};
pub use pack::{PackLimits, PackReport, hash_tree, normalized_mode, pack_dir};
pub use pathsafe::{ContainedOpen, UrlPath, host_allowed, open_contained, request_path};
pub use redact::{Redactor, secrets_equal};
pub use schema::{
    ControlRequest, ControlResponse, DeployRecord, Desired, DesiredAction, ExecutorStatus, Health,
    HealthExpect, LastResult, ManagerState, Outcome, ReleaseManifest, RuntimeKind, SCHEMA_VERSION,
    Slot, SlotState, SlotStatus, decode_desired, decode_release, decode_state, decode_status,
    escape_control, new_id, now_rfc3339, read_desired, read_release, read_state, read_status,
    write_desired, write_release, write_state, write_status,
};
pub use volume::{
    filesystem_free_bytes, layout_violations, remove_dir_contents, slot_is_sealed,
    sweep_atomic_temps, sweep_dir,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod workspace_invariants {
    #[test]
    fn no_docker_api_client_in_the_workspace() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let lock = std::fs::read_to_string(root.join("Cargo.lock")).unwrap();
        let client = chars(&[98, 111, 108, 108, 97, 114, 100]);
        let sock = chars(&[100, 111, 99, 107, 101, 114, 46, 115, 111, 99, 107]);
        for name in [
            client.clone(),
            chars(&[115, 104, 105, 112, 108, 105, 102, 116]),
            chars(&[100, 111, 99, 107, 101, 114, 45, 97, 112, 105]),
            chars(&[112, 111, 100, 109, 97, 110, 45, 97, 112, 105, 45, 114, 115]),
        ] {
            assert!(
                !lock.contains(&format!("name = \"{name}\"")),
                "{name} must not be a dependency"
            );
        }
        fn chars(codes: &[u8]) -> String {
            String::from_utf8(codes.to_vec()).unwrap()
        }
        fn scan(dir: &std::path::Path, client: &str, sock: &str) {
            for entry in std::fs::read_dir(dir).unwrap().flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().into_owned();
                if name == "target" || name.starts_with('.') {
                    continue;
                }
                if path.is_dir() {
                    scan(&path, client, sock);
                } else if name.ends_with(".rs") || name == "Cargo.toml" {
                    let text = std::fs::read_to_string(&path).unwrap();
                    assert!(
                        !text.contains(client) && !text.contains(sock),
                        "{}",
                        path.display()
                    );
                }
            }
        }
        scan(&root.join("crates"), &client, &sock);
    }

    #[test]
    fn executor_releases_mount_is_read_only() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let text = std::fs::read_to_string(root.join("docker-compose.yml")).unwrap();
        let executor = text
            .split("\n  executor:")
            .nth(1)
            .expect("executor service");
        let mount = executor
            .split("target: /var/lib/cite/releases")
            .nth(1)
            .expect("releases mount");
        let head = mount.split("target:").next().unwrap();
        assert!(
            head.contains("read_only: true"),
            "executor releases mount must be read-only"
        );
    }

    #[test]
    fn first_party_crates_forbid_unsafe_code() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for name in ["cite-core", "cite-manager", "cite-executor"] {
            let lib =
                std::fs::read_to_string(root.join(format!("crates/{name}/src/lib.rs"))).unwrap();
            assert!(
                lib.contains("#![forbid(unsafe_code)]"),
                "{name} lib.rs must forbid unsafe"
            );
            let manifest =
                std::fs::read_to_string(root.join(format!("crates/{name}/Cargo.toml"))).unwrap();
            assert!(
                manifest.contains("unsafe_code = \"forbid\""),
                "{name} Cargo.toml must forbid unsafe"
            );
        }
    }

    #[test]
    fn deny_toml_bans_openssl_and_denies_advisories() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let text = std::fs::read_to_string(root.join("deny.toml")).unwrap();
        assert!(text.contains("version = 2"));
        assert!(text.contains("yanked = \"deny\""));
        assert!(text.contains("multiple-versions = \"warn\""));
        assert!(text.contains("\"MIT\""));
        assert!(text.contains("\"Apache-2.0\""));
        assert!(text.contains("name = \"openssl\""));
        assert!(text.contains("name = \"openssl-sys\""));
    }

    #[test]
    fn source_fetch_leaves_lfs_pointers_and_skips_submodules() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let docs = std::fs::read_to_string(root.join("docs/how-it-works.md")).unwrap();
        assert!(docs.contains("LFS pointers stay pointer files"));
        assert!(docs.contains("submodules are not fetched"));
        let github =
            std::fs::read_to_string(root.join("crates/cite-manager/src/github.rs")).unwrap();
        assert!(github.contains("/tarball/"));
        assert!(!github.contains("git clone"));
        assert!(!github.contains("git submodule"));
    }

    #[test]
    fn security_docs_cover_disclosure_firewall_metadata_and_limits() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let security = std::fs::read_to_string(root.join("SECURITY.md")).unwrap();
        assert!(security.contains("GitHub Security Advisories"));
        let threat = std::fs::read_to_string(root.join("docs/threat-model.md")).unwrap();
        assert!(threat.contains("rootless"));
        let hardening = std::fs::read_to_string(root.join("docs/hardening.md")).unwrap();
        assert!(hardening.contains("Host firewall"));
        assert!(hardening.contains("169.254.169.254"));
        assert!(hardening.contains("rootless Docker"));
        assert!(hardening.contains("Resource limits"));
        assert!(hardening.contains("1 GB"));
    }

    #[test]
    fn healthchecks_are_exec_form_subcommands() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let files = [
            "images/manager/Dockerfile",
            "images/executor-node/Dockerfile",
            "images/executor-bun/Dockerfile",
            "images/executor-static/Dockerfile",
            "docker-compose.yml",
            "docker-compose.dev.yml",
        ];
        for file in files {
            let text = std::fs::read_to_string(root.join(file)).unwrap();
            assert!(text.contains("healthcheck"), "{file}");
            assert!(
                text.contains("[\"cite-manager\", \"healthcheck\"]")
                    || text.contains("[\"/cite-executor\", \"healthcheck\"]")
                    || text.contains("[\"CMD\", \"cite-manager\", \"healthcheck\"]")
                    || text.contains("[\"CMD\", \"/cite-executor\", \"healthcheck\"]"),
                "{file} healthcheck must be exec form"
            );
            assert!(!text.contains("HEALTHCHECK CMD cite"), "{file}");
        }
    }

    #[test]
    fn cargo_builds_are_locked_and_the_toolchain_is_pinned() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let toolchain = std::fs::read_to_string(root.join("rust-toolchain.toml")).unwrap();
        let channel = toolchain
            .lines()
            .find_map(|line| line.trim().strip_prefix("channel = "))
            .unwrap()
            .trim_matches('"');
        assert!(
            channel.split('.').count() == 3 && channel.chars().next().unwrap().is_ascii_digit(),
            "toolchain must be a pinned version, got {channel}"
        );
        for file in [
            "images/manager/Dockerfile",
            "images/executor-node/Dockerfile",
            "images/executor-bun/Dockerfile",
            "images/executor-static/Dockerfile",
            "images/mock-github/Dockerfile",
        ] {
            let text = std::fs::read_to_string(root.join(file)).unwrap();
            for line in text.lines().filter(|line| line.contains("cargo build")) {
                assert!(line.contains("--locked"), "{file}: {line}");
            }
        }
        for entry in std::fs::read_dir(root.join(".github/workflows"))
            .unwrap()
            .flatten()
        {
            let text = std::fs::read_to_string(entry.path()).unwrap();
            for line in text.lines() {
                let trimmed = line.trim();
                let builds = trimmed.contains("cargo clippy")
                    || trimmed.contains("cargo nextest")
                    || trimmed.contains("cargo llvm-cov")
                    || trimmed.contains("cargo doc ")
                    || trimmed.contains("cargo build")
                    || trimmed.contains("cargo test ")
                    || trimmed.contains("cargo install");
                if builds {
                    assert!(
                        trimmed.contains("--locked"),
                        "{}: {trimmed}",
                        entry.path().display()
                    );
                }
            }
        }
    }

    #[test]
    fn dependabot_covers_every_ecosystem() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let dep = std::fs::read_to_string(root.join(".github/dependabot.yml")).unwrap();
        assert!(dep.contains("package-ecosystem: cargo"));
        assert!(dep.contains("directory: \"/fuzz\""));
        assert!(dep.contains("package-ecosystem: github-actions"));
        assert!(dep.contains("package-ecosystem: docker-compose"));
        assert!(dep.contains("interval: weekly"));
        for dir in std::fs::read_dir(root.join("images")).unwrap().flatten() {
            if dir.path().join("Dockerfile").is_file() {
                let name = dir.file_name().to_string_lossy().into_owned();
                assert!(
                    dep.contains(&format!("directory: \"/images/{name}\"")),
                    "dependabot missing {name}"
                );
            }
        }
    }

    fn workspace_version(root: &std::path::Path) -> String {
        let cargo = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
        cargo
            .lines()
            .find_map(|line| line.trim().strip_prefix("version = "))
            .unwrap()
            .trim_matches('"')
            .to_string()
    }

    #[test]
    fn version_comes_from_the_workspace_manifest() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let version = workspace_version(&root);
        assert_eq!(crate::VERSION, version);
        for file in [
            "images/manager/Dockerfile",
            "images/executor-node/Dockerfile",
            "images/executor-bun/Dockerfile",
            "images/executor-static/Dockerfile",
        ] {
            let text = std::fs::read_to_string(root.join(file)).unwrap();
            assert!(
                text.contains("org.opencontainers.image.version=\"${VERSION}\""),
                "{file}"
            );
            assert!(
                !text
                    .lines()
                    .any(|line| line.trim().starts_with("ARG VERSION=")),
                "{file} must not hardcode a version default"
            );
        }
        let release = std::fs::read_to_string(root.join(".github/workflows/release.yml")).unwrap();
        assert!(release.contains("Cargo.toml"));
        assert!(release.contains("VERSION=${{ needs.version.outputs.version }}"));
        let compose = std::fs::read_to_string(root.join("docker-compose.yml")).unwrap();
        let pin = format!("${{CITE_VERSION:-{version}}}");
        assert!(compose.contains(&format!("cite-manager:{pin}")));
        assert!(compose.contains(&format!("cite-executor-node:{pin}")));
        let example = std::fs::read_to_string(root.join(".env.example")).unwrap();
        assert!(example.contains(&format!("CITE_VERSION={version}")));
        let schema = std::fs::read_to_string(root.join("crates/cite-core/src/schema.rs")).unwrap();
        assert!(schema.contains("Err(Error::Version { found: v })"));
    }

    #[test]
    fn manager_and_executor_share_debian_node_lines() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let matrix = std::fs::read_to_string(root.join("images/images.toml")).unwrap();
        assert!(matrix.contains("major = 22"));
        assert!(matrix.contains("major = 24"));
        assert_eq!(matrix.matches("lts = true").count(), 2);
        assert!(!matrix.contains("lts = false"));
        let manager = std::fs::read_to_string(root.join("images/manager/Dockerfile")).unwrap();
        let executor =
            std::fs::read_to_string(root.join("images/executor-node/Dockerfile")).unwrap();
        let bun = std::fs::read_to_string(root.join("images/executor-bun/Dockerfile")).unwrap();
        let static_image =
            std::fs::read_to_string(root.join("images/executor-static/Dockerfile")).unwrap();
        assert!(manager.contains("bookworm"));
        assert!(executor.contains("debian12"));
        assert!(manager.contains("rust:1.98-bookworm"));
        assert!(executor.contains("rust:1.98-bookworm"));
        let release = std::fs::read_to_string(root.join(".github/workflows/release.yml")).unwrap();
        let builds = format!("{manager}{executor}{bun}{static_image}{release}");
        for digest in matrix
            .lines()
            .filter(|line| line.contains("_digest = "))
            .filter_map(|line| line.split('"').nth(1))
        {
            assert!(
                builds.contains(digest),
                "digest {digest} is not pinned in an image build"
            );
        }
    }

    #[test]
    fn env_file_and_compose_do_not_carry_the_pat() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let example = std::fs::read_to_string(root.join(".env.example")).unwrap();
        assert!(!example.contains("ghp_"));
        assert!(!example.contains("github_pat_"));
        let token_line = example
            .lines()
            .find_map(|line| line.trim().strip_prefix("CITE_GITHUB_TOKEN="))
            .expect("CITE_GITHUB_TOKEN line");
        assert!(
            token_line.trim().is_empty(),
            ".env.example must not carry a token value"
        );
        let compose = std::fs::read_to_string(root.join("docker-compose.yml")).unwrap();
        assert!(
            compose.contains("CITE_GITHUB_TOKEN: ${CITE_GITHUB_TOKEN:?"),
            "the manager token must be interpolated, never a literal"
        );
        let executor = compose
            .split("\n  executor:")
            .nth(1)
            .expect("executor service");
        let executor = executor.split("\nvolumes:").next().unwrap();
        assert!(
            !executor.contains("CITE_GITHUB_TOKEN"),
            "the executor must not see the PAT"
        );
        assert!(
            !compose.contains("- frontend"),
            "the executor must not join a masquerading frontend network"
        );
        assert!(!compose.contains("ghp_"));
        assert!(!compose.contains("github_pat_"));
    }

    #[test]
    fn hardening_doc_covers_metadata_blocking() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let hardening = std::fs::read_to_string(root.join("docs/hardening.md")).unwrap();
        assert!(hardening.contains("169.254.169.254"));
        assert!(hardening.contains("iptables"));
        assert!(hardening.contains("nft"));
    }

    #[test]
    fn fuzz_targets_cover_the_parsers() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let targets = root.join("fuzz/fuzz_targets");
        let required = [
            ("extract_tar.rs", "extract_archive"),
            ("pack_tree.rs", "pack_dir"),
            ("start_command.rs", "split_command"),
            ("request_path.rs", "request_path"),
            ("host_header.rs", "host_allowed"),
            ("release_json.rs", "decode_release"),
            ("desired_json.rs", "decode_desired"),
            ("status_json.rs", "decode_status"),
            ("detect_package.rs", "detect_site"),
            ("redact_line.rs", "Redactor"),
            ("duration_parser.rs", "parse_duration"),
        ];
        for (file, needle) in required {
            let text = std::fs::read_to_string(targets.join(file)).unwrap();
            assert!(text.contains(needle), "{file} must exercise {needle}");
            assert!(text.contains("fuzz_target!"), "{file} is not a fuzz target");
        }
    }

    #[test]
    fn rust_tests_do_not_retry_and_e2e_retries_at_most_once() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let nextest = std::fs::read_to_string(root.join(".config/nextest.toml")).unwrap();
        assert!(nextest.contains("retries = 0"));
        if let Ok(e2e) = std::fs::read_to_string(root.join(".github/workflows/e2e.yml")) {
            assert!(
                !e2e.contains("retry:"),
                "e2e must not configure a retry above the one-shot job"
            );
        }
    }
}
