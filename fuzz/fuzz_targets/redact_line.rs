#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let mut redactor = cite_core::Redactor::new();
        redactor.push_secret("super-secret-value");
        let _ = redactor.redact_line(text);
    }
});
