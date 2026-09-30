#![no_main]

use std::time::Duration;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = cite_core::parse_duration(text);
        let _ = cite_core::parse_poll_interval(text, Duration::from_secs(60));
        let _ = cite_core::parse_byte_size(text);
    }
});
