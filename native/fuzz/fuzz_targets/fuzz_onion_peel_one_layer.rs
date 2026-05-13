#![no_main]
//! Fuzz ol_onion peel_one_layer with arbitrary bytes interpreted as
//! both relay key + packet. Must never panic; AEAD must reject any
//! frame not produced by a corresponding build_onion call.

use libfuzzer_sys::fuzz_target;
use ol_onion::{peel_one_layer, OnionPacket};
use x25519_dalek::StaticSecret;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&data[..32]);
    let sk = StaticSecret::from(sk_bytes);
    let rest = &data[32..];
    if let Ok(packet) = OnionPacket::decode(rest) {
        let _ = peel_one_layer(&sk, &packet);
    }
});
