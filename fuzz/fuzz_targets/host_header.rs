#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let allowed = [String::from("app.example"), String::from("localhost")];
    let _ = cite_core::host_allowed(&allowed, text);
    let _ = cite_core::host_allowed(&[], text);
    let _ = cite_core::request_path(text);
});
