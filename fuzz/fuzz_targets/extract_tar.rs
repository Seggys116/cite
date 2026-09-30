#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let dir = std::env::temp_dir().join(format!("cite-fuzz-extract-{}", std::process::id()));
    let dest = dir.join("out");
    let _ = std::fs::remove_dir_all(&dir);
    let limits = cite_core::ExtractLimits {
        max_compressed_bytes: 64 * 1024,
        max_extracted_bytes: 128 * 1024,
        max_entries: 32,
        max_file_bytes: 32 * 1024,
    };
    let _ = cite_core::extract_archive(Cursor::new(data), &dest, &limits, 0);
    let _ = std::fs::remove_dir_all(&dir);
});
