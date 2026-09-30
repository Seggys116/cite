#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 8 * 1024 {
        return;
    }
    let dir = std::env::temp_dir().join(format!("cite-fuzz-pack-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(dir.join("file"), data);
    let limits = cite_core::PackLimits {
        max_bytes: 64 * 1024,
        max_files: 16,
    };
    let mut buf = Vec::new();
    let _ = cite_core::pack_dir(&dir, &mut buf, &limits);
    let _ = cite_core::hash_tree(&dir);
    let _ = std::fs::remove_dir_all(&dir);
});
