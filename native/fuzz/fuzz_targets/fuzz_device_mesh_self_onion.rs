#![no_main]
//! Fuzz the Layer 7 self-onion surface.

use libfuzzer_sys::fuzz_target;
use ol_device_mesh::self_onion::{
    build_self_onion_circuit, derive_onion_identity, peel_self_onion_layer,
    sign_onion_attestation, OnionKeyRegistry,
};
use ol_device_mesh::self_routing::Route;
use ol_device_mesh::{MasterIdentity, DEVICE_ID_LEN};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fuzz_target!(|data: &[u8]| {
    let mut rng = ChaCha20Rng::from_seed([0xA7u8; 32]);
    let master = MasterIdentity::generate(&mut rng);
    // Two devices in the registry.
    let src = [0x11u8; DEVICE_ID_LEN];
    let dst = [0x22u8; DEVICE_ID_LEN];
    let src_ident = derive_onion_identity(&master, &src);
    let dst_ident = derive_onion_identity(&master, &dst);
    let mut reg = OnionKeyRegistry::empty();
    for (id, ident) in [(&src, &src_ident), (&dst, &dst_ident)] {
        let att = sign_onion_attestation(
            &master, *id, ident.public_bytes(), 0, 365,
        )
        .unwrap();
        reg.ingest(att, &master.verifying_key()).unwrap();
    }

    // 1. Build + peel round-trip with fuzz-derived payload.
    let max_payload = 256;
    let payload_len = (data.first().copied().unwrap_or(0) as usize) % max_payload;
    let payload: Vec<u8> = (0..payload_len)
        .map(|i| data.get(i + 1).copied().unwrap_or(0))
        .collect();
    let route = Route {
        hops: vec![src, dst],
        bottleneck_tau: 1,
        min_last_seen_unix: 1,
    };
    if let Ok(packet) = build_self_onion_circuit(&route, &reg, 0, &payload, &mut rng) {
        let _ = peel_self_onion_layer(&dst_ident, &packet);
        let _ = peel_self_onion_layer(&src_ident, &packet);
    }

    // 2. Mutate a signed attestation and re-verify.
    let att = sign_onion_attestation(
        &master, src, src_ident.public_bytes(), 0, 365,
    )
    .unwrap();
    let mut tampered = att.clone();
    if let Some(&b) = data.first() {
        if !tampered.master_sig.is_empty() {
            tampered.master_sig[0] ^= b;
        }
    }
    let _ = tampered.verify(&master.verifying_key());
});
