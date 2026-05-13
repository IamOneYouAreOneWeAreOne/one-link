#![no_main]
//! Fuzz `ServerHandshake::accept` with arbitrary bytes. Must never
//! panic; arbitrary input either succeeds (vanishingly rare) or
//! returns a typed error.

use libfuzzer_sys::fuzz_target;
use ol_onion::transport_obfs::handshake::{BridgeKeypair, ServerHandshake};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fuzz_target!(|data: &[u8]| {
    // Deterministic bridge so fuzz runs are reproducible.
    let mut bridge_rng = ChaCha20Rng::from_seed([0xA1u8; 32]);
    let bridge = BridgeKeypair::generate(&mut bridge_rng);
    let mut rng = ChaCha20Rng::from_seed([0xB2u8; 32]);
    let _ = ServerHandshake::accept(&mut rng, &bridge, data, 1_700_000_000);
});
