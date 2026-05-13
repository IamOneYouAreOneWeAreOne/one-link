#![no_main]
//! Fuzz ol_onion canon Reader. Walk a sequence of primitive reads
//! against arbitrary input; must never panic.

use libfuzzer_sys::fuzz_target;
use ol_onion::canon::Reader;

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    let _ = r.read_u8();
    let _ = r.read_u16();
    let _ = r.read_fixed(32);
    let _ = r.read_fixed(12);
    let _ = r.read_u16();
    let _ = r.read_u8();
});
