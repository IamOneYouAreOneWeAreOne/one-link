#![no_main]
//! Fuzz the discovery wire decoder against arbitrary input.
//!
//! The wire decoder is the FIRST CODE that runs on bytes received
//! from an untrusted UDP socket. Any panic / OOB read here is
//! exploitable. Must NEVER panic — every malformed input must
//! return a clean WireError.

use libfuzzer_sys::fuzz_target;
use ol_discovery::wire::decode;

fuzz_target!(|data: &[u8]| {
    // Decoder MUST handle arbitrary input gracefully.
    let _ = decode(data);
});
