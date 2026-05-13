#![no_main]
//! Fuzz ol_pqsig verify with arbitrary signature bytes against a
//! fixed verifying key. Must never panic; arbitrary bytes that
//! happen to be valid → expected; everything else returns a typed
//! error.

use libfuzzer_sys::fuzz_target;
use ol_pqsig::{HybridSigningKey, HYBRID_SIG_LEN};

fuzz_target!(|data: &[u8]| {
    use rand::SeedableRng;
    // Generate a deterministic keypair so fuzz runs are reproducible.
    let seed = [0xA1u8; 32];
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
    let (_sk, vk) = HybridSigningKey::generate(&mut rng);

    // Try to interpret data as (message_len_u16 | message | sig).
    if data.len() < 2 + HYBRID_SIG_LEN {
        // Just try verify with arbitrary sig length.
        let _ = vk.verify(data, &[0u8; HYBRID_SIG_LEN]);
        return;
    }
    let msg_len = (data[0] as usize) << 8 | (data[1] as usize);
    let msg_len = msg_len.min(data.len() - 2 - HYBRID_SIG_LEN);
    let msg = &data[2..2 + msg_len];
    let sig_start = 2 + msg_len;
    let sig = &data[sig_start..sig_start + HYBRID_SIG_LEN];
    let _ = vk.verify(msg, sig);
});
