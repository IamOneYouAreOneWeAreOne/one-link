#![no_main]
//! Fuzz the `is_cover_payload` sentinel-check against arbitrary
//! byte slices. Must never panic; output is a bool but each call
//! exercises the prefix-comparison and the underlying slice indexing.

use libfuzzer_sys::fuzz_target;
use ol_onion::sphinx::cover::{is_cover_payload, COVER_SENTINEL};

fuzz_target!(|data: &[u8]| {
    let r = is_cover_payload(data);
    // Crash-coverage check: short bytes never cover; sentinel-prefix
    // always cover. These are cheap to assert inline.
    if data.len() < COVER_SENTINEL.len() {
        assert!(!r);
    } else if &data[..COVER_SENTINEL.len()] == COVER_SENTINEL {
        assert!(r);
    } else {
        assert!(!r);
    }
});
