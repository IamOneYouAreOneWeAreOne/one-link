#![no_main]
//! Fuzz ol_onion OnionPacket::decode with arbitrary bytes.
//! Must never panic.

use libfuzzer_sys::fuzz_target;
use ol_onion::OnionPacket;

fuzz_target!(|data: &[u8]| {
    let _ = OnionPacket::decode(data);
});
