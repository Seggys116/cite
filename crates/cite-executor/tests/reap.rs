use std::process::Command;
use std::time::Duration;

#[test]
fn reap_collects_a_zombie_and_init_gate_leaves_a_live_child() {
    let mut exited = Command::new("/usr/bin/true").spawn().unwrap();
    std::thread::sleep(Duration::from_millis(50));
    cite_executor::reap_exited_children();
    let collected = exited.wait().unwrap_err();
    assert_eq!(
        collected.raw_os_error(),
        Some(10),
        "an exited child should already have been reaped: {collected}"
    );

    let mut live = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    cite_executor::reap_if_init();
    assert!(
        live.try_wait().unwrap().is_none(),
        "a non-init process must not collect its children"
    );
    let _ = live.kill();
    let _ = live.wait();

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let compose = std::fs::read_to_string(root.join("docker-compose.yml")).unwrap();
    let manager = compose.split("\n  manager:").nth(1).unwrap();
    let executor = manager.split("\n  executor:").nth(1).unwrap();
    let manager_head = manager.split("\n  executor:").next().unwrap();
    assert!(
        manager_head.contains("init: true"),
        "manager must set init: true"
    );
    assert!(
        executor.contains("init: true"),
        "executor must set init: true"
    );

    if Command::new("node")
        .arg("-v")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .is_none()
    {
        eprintln!("skipping signal-forwarding check: node not on PATH");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("releases/blue/app")).unwrap();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    std::fs::write(data.join("runtime.env"), "").unwrap();
    std::fs::write(
        data.join("releases/blue/app/server.js"),
        b"const http=require('http');const s=http.createServer((q,r)=>r.end('ok'));s.listen(process.env.PORT,'127.0.0.1');\n",
    )
    .unwrap();
    let manifest = cite_core::ReleaseManifest {
        v: cite_core::SCHEMA_VERSION,
        release_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
        slot: cite_core::Slot::Blue,
        sha: "a".repeat(40),
        branch: "main".into(),
        commit_message: "hi".into(),
        commit_author: "dev".into(),
        built_at: "2026-01-01T00:00:00Z".into(),
        rendering: cite_core::schema::Rendering::Ssr,
        runtime: cite_core::RuntimeKind::Node,
        node_major: "22".into(),
        start_argv: vec!["node".into(), "server.js".into()],
        port_env: "PORT".into(),
        health: cite_core::Health {
            path: "/".into(),
            expect: cite_core::HealthExpect::Non2xxOk,
            timeout_s: 5,
            consecutive: 1,
        },
        spa_fallback: None,
        root: "app".into(),
        bytes: 10,
        file_count: 1,
        tree_sha256: "b".repeat(64),
    };
    cite_core::write_release(&data.join("releases/blue/release.json"), &manifest).unwrap();
    let desired = cite_core::Desired {
        v: cite_core::SCHEMA_VERSION,
        generation: 1,
        live_slot: cite_core::Slot::Blue,
        action: cite_core::DesiredAction::Activate,
        evict_slot: None,
        warm_grace_s: 30,
        restart_nonce: String::new(),
        written_at: "2026-01-01T00:00:00Z".into(),
    };
    cite_core::write_desired(&data.join("control/desired.json"), &desired).unwrap();

    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let bin = env!("CARGO_BIN_EXE_cite-executor");
    let mut exe = Command::new(bin)
        .env("CITE_LISTEN", "127.0.0.1:0")
        .env("CITE_DATA_DIR", data)
        .env("CITE_RELEASES_DIR", data.join("releases"))
        .env("CITE_CONTROL_DIR", data.join("control"))
        .env("CITE_STATUS_DIR", data.join("status"))
        .env("CITE_RUNTIME_ENV_FILE", data.join("runtime.env"))
        .env("CITE_PORT_BASE", port.to_string())
        .env("CITE_NODE", "22")
        .env("CITE_RUNTIME", "node")
        .env("CITE_CHILD_TERM_GRACE", "200ms")
        .env("RUST_LOG", "error")
        .spawn()
        .unwrap();

    let status_path = data.join("status/executor.json");
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut live = false;
    while std::time::Instant::now() < deadline {
        if let Ok(status) = cite_core::read_status(&status_path)
            && status.active_slot == Some(cite_core::Slot::Blue)
        {
            live = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(live, "executor did not activate the child");

    let child = listener_pid(port);
    let _ = Command::new("kill")
        .args(["-TERM", &exe.id().to_string()])
        .status();
    let finished = exe.wait().unwrap();
    assert!(
        finished.success(),
        "SIGTERM should shut the executor down cleanly"
    );
    std::thread::sleep(Duration::from_millis(200));
    let still = Command::new("kill")
        .args(["-0", &child.to_string()])
        .status()
        .unwrap();
    assert!(
        !still.success(),
        "SIGTERM to the executor must stop the child"
    );
}

fn listener_pid(port: u16) -> u32 {
    let out = Command::new("lsof")
        .args(["-nP", "-t", &format!("-iTCP:{port}"), "-sTCP:LISTEN"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|line| line.trim().parse().ok())
        .unwrap_or_else(|| panic!("nothing listening on {port}"))
}
