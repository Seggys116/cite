#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(argv) = cite_core::split_command(text) {
            let _ = cite_core::validate_start_argv(&argv);
            let rendered = cite_core::render_argv(&argv);
            let _ = cite_core::split_command(&rendered);
        }
    }
});
