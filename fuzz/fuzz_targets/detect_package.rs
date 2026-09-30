#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 8 * 1024 {
        return;
    }
    let dir = std::env::temp_dir().join(format!("cite-fuzz-detect-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(dir.join("package.json"), data);
    let _ = cite_core::detect_site(&dir);
    let _ = std::fs::remove_dir_all(&dir);
});
