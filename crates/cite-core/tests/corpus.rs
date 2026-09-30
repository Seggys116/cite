#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;
use std::time::Duration;

#[test]
fn seed_corpus_does_not_panic() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus");
    let feed = |dir: &str, f: &dyn Fn(&[u8])| {
        let path = root.join(dir);
        if !path.is_dir() {
            return;
        }
        for entry in fs::read_dir(path).unwrap() {
            let bytes = fs::read(entry.unwrap().path()).unwrap();
            f(&bytes);
        }
    };
    feed("extract_tar", &|bytes| {
        let dest = std::env::temp_dir().join(format!("cite-corpus-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dest);
        let _ = cite_core::extract_archive(
            std::io::Cursor::new(bytes),
            &dest.join("out"),
            &cite_core::ExtractLimits {
                max_compressed_bytes: 1024 * 1024,
                max_extracted_bytes: 1024 * 1024,
                max_entries: 100,
                max_file_bytes: 1024 * 1024,
            },
            0,
        );
        let _ = std::fs::remove_dir_all(&dest);
    });
    feed("start_command", &|bytes| {
        if let Ok(text) = std::str::from_utf8(bytes) {
            let _ = cite_core::split_command(text);
        }
    });
    feed("duration_parser", &|bytes| {
        if let Ok(text) = std::str::from_utf8(bytes) {
            let _ = cite_core::parse_duration(text);
            let _ = cite_core::parse_poll_interval(text, Duration::from_secs(60));
        }
    });
    feed("request_path", &|bytes| {
        if let Ok(text) = std::str::from_utf8(bytes) {
            let _ = cite_core::request_path(text);
        }
    });
    feed("release_json", &|bytes| {
        let _ = cite_core::decode_release(bytes);
    });
    feed("desired_json", &|bytes| {
        let _ = cite_core::decode_desired(bytes);
    });
    feed("status_json", &|bytes| {
        let _ = cite_core::decode_status(bytes);
    });
    feed("redact_line", &|bytes| {
        if let Ok(text) = std::str::from_utf8(bytes) {
            let mut redactor = cite_core::Redactor::new();
            redactor.push_secret("super-secret-value");
            let _ = redactor.redact_line(text);
        }
    });
    feed("pack_tree", &|bytes| {
        let dir = std::env::temp_dir().join(format!("cite-corpus-pack-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(dir.join("file"), bytes);
        let mut buf = Vec::new();
        let _ = cite_core::pack_dir(
            &dir,
            &mut buf,
            &cite_core::PackLimits {
                max_bytes: 64 * 1024,
                max_files: 16,
            },
        );
        let _ = cite_core::hash_tree(&dir);
        let _ = std::fs::remove_dir_all(&dir);
    });
    feed("detect_package", &|bytes| {
        let dir = std::env::temp_dir().join(format!("cite-corpus-detect-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(dir.join("package.json"), bytes);
        let _ = cite_core::detect_site(&dir);
        let _ = std::fs::remove_dir_all(&dir);
    });
    feed("host_header", &|bytes| {
        if let Ok(text) = std::str::from_utf8(bytes) {
            let allowed = [String::from("app.example")];
            let _ = cite_core::host_allowed(&allowed, text);
        }
    });
}
