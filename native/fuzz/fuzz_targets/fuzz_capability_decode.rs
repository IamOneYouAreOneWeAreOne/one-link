#![no_main]
//! Fuzz `Capability::decode` against arbitrary wire bytes. Must never
//! panic; must always return a structured error on malformed input.

use libfuzzer_sys::fuzz_target;
use ol_capability::Capability;

fuzz_target!(|data: &[u8]| {
    let _ = Capability::decode(data);
});
