#![no_main]
use libfuzzer_sys::fuzz_target;
use rustbox::config::types::DirectoryBinding;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        let _ = DirectoryBinding::parse_secure(input);
    }
});
