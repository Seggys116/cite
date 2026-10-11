use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use cite_core::schema::Rendering;
use cite_core::{ExtractLimits, ManagerConfig, RuntimeKind, extract_archive};
use cite_manager::build::run_build_classified;

#[tokio::test]
async fn rust_build_packs_the_release_binary_only() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/runtime-rust");
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("src.tgz");
    let packed = std::process::Command::new("tar")
        .env("COPYFILE_DISABLE", "1")
        .arg("-czf")
        .arg(&archive)
        .arg("-C")
        .arg(fixture.parent().unwrap())
        .arg(fixture.file_name().unwrap())
        .status()
        .unwrap();
    assert!(packed.success());
    let bytes = std::fs::read(&archive).unwrap();
    let work = tmp.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let mut env = HashMap::new();
    env.insert("CITE_REPO".into(), "owner/name".into());
    env.insert(
        "CITE_DATA_DIR".into(),
        tmp.path().join("data").display().to_string(),
    );
    env.insert("CITE_WORK_DIR".into(), work.display().to_string());
    env.insert("CITE_DEV_SAME_USER".into(), "true".into());
    env.insert("CITE_MIN_FREE_BYTES".into(), "1".into());
    env.insert("CITE_RUNTIME".into(), "rust".into());
    env.insert("CITE_BUILD_CACHE".into(), "off".into());
    env.insert(
        "CITE_INSTALL_COMMAND".into(),
        "cargo fetch --locked --offline".into(),
    );
    env.insert(
        "CITE_BUILD_COMMAND".into(),
        "cargo build --release --locked --offline".into(),
    );
    env.insert("CITE_NODE".into(), "22".into());
    let rustup = std::env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".rustup")));
    if let Some(rustup) = rustup.filter(|path| path.is_dir()) {
        let file = tmp.path().join("build.env");
        std::fs::write(&file, format!("RUSTUP_HOME={}\n", rustup.display())).unwrap();
        env.insert("CITE_BUILD_ENV_FILE".into(), file.display().to_string());
    }
    let cfg = ManagerConfig::load_from(&env, None).unwrap();
    let built = run_build_classified(
        &cfg,
        &bytes,
        &"c".repeat(40),
        "msg",
        "dev",
        &cite_core::Redactor::new(),
    )
    .await
    .expect("rust build");
    assert_eq!(built.runtime, RuntimeKind::Rust);
    assert_eq!(built.rendering, Rendering::Ssr);
    assert_eq!(built.start_argv, ["bin/hello"]);
    let unpacked = tmp.path().join("unpacked");
    extract_archive(
        std::fs::File::open(&built.tar_path).unwrap(),
        &unpacked,
        &ExtractLimits::default(),
        0,
    )
    .unwrap();
    let hello = unpacked.join("bin/hello");
    assert!(hello.is_file(), "packed tree missing bin/hello");
    let mode = std::fs::metadata(&hello).unwrap().permissions().mode();
    assert_ne!(mode & 0o111, 0, "bin/hello is not executable: {mode:o}");
    let mut names = Vec::new();
    let mut stack = vec![unpacked.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            names.push(path.strip_prefix(&unpacked).unwrap().to_path_buf());
            if entry.file_type().unwrap().is_dir() {
                stack.push(path);
            }
        }
    }
    assert!(
        names.iter().all(|path| {
            path.file_name().and_then(|name| name.to_str()) != Some("Cargo.toml")
                && path
                    .components()
                    .all(|component| component.as_os_str() != "target")
        }),
        "{names:?}"
    );
}
