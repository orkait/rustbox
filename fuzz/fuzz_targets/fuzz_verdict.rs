#![no_main]
use libfuzzer_sys::fuzz_target;
use rustbox::config::types::{EvidenceBundle, LimitSnapshot};
use rustbox::verdict::classifier::VerdictClassifier;

fuzz_target!(|data: &[u8]| {
    if let Ok(json_str) = std::str::from_utf8(data) {
        if let Ok(evidence) = serde_json::from_str::<EvidenceBundle>(json_str) {
            let limits = LimitSnapshot {
                cpu_limit_ms: Some(4000),
                wall_limit_ms: Some(7000),
                memory_limit_bytes: Some(128 * 1024 * 1024),
                process_limit: Some(10),
                output_limit_bytes: Some(64 * 1024),
            };
            let _ = VerdictClassifier::classify(&evidence, &limits);
        }
    }
});
