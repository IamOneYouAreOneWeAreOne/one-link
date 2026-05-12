//! Phase C acceptance gate for ADR-0017:
//!
//!   > ML-KEM-768 + X25519 hybrid completes handshake at PQ-conservative
//!   > parameters.
//!
//! Stronger interpretation we hold ourselves to:
//!
//! 1. **10K-seed round trip**: `encap(pk)` and `decap(sk, ct)` produce
//!    byte-equivalent shared secrets across 10,000 random `(pk, sk)`
//!    pairs.
//! 2. **Wire-format determinism**: a fixed `(sk_bytes, ct_bytes)` always
//!    decapsulates to the same shared secret bytes — required for the
//!    hybrid combiner to be safe to use as an AEAD key directly.

use ol_pqkem::{decapsulate, encapsulate, keypair, HybridSecretKey};
use rand::rngs::StdRng;
use rand::SeedableRng;

const SEEDS: u64 = 10_000;

#[test]
fn adr0017_hybrid_round_trip_10k_seeds() {
    let mut failures = 0usize;
    for seed in 0..SEEDS {
        let mut rng = StdRng::seed_from_u64(seed);
        let (pk, sk) = keypair(&mut rng);
        let (ct, ss_initiator) = encapsulate(&pk, &mut rng).expect("encap");
        let ss_responder = decapsulate(&sk, &ct).expect("decap");
        if *ss_initiator != *ss_responder {
            failures += 1;
            eprintln!("seed {seed}: shared secrets diverged");
        }
    }
    assert_eq!(
        failures, 0,
        "Phase C gate: ADR-0017 hybrid KEM failed {failures}/{SEEDS} round trips"
    );
    eprintln!("ADR-0017 acceptance: PASSED {SEEDS}/{SEEDS} hybrid KEM encap/decap round trips");
}

#[test]
fn adr0017_wire_round_trip_keys_survive_serialization() {
    // sk + pk + ct serialized then re-parsed must still decapsulate
    // to the same shared secret. Confirms the on-wire form is the
    // engine's source of truth.
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF);
    let (pk, sk) = keypair(&mut rng);
    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();

    let pk_again = ol_pqkem::HybridPublicKey::from_bytes(&pk_bytes).unwrap();
    let (ct, ss_a) = encapsulate(&pk_again, &mut rng).unwrap();
    let ct_bytes = ct.to_bytes();
    let ct_again = ol_pqkem::HybridCiphertext::from_bytes(&ct_bytes).unwrap();

    let sk_again = HybridSecretKey::from_bytes(&sk_bytes[..]).unwrap();
    let ss_b = decapsulate(&sk_again, &ct_again).unwrap();
    assert_eq!(*ss_a, *ss_b, "sk round-trip changed the derived secret");
}

#[test]
fn adr0017_shared_secret_is_32_bytes() {
    let mut rng = StdRng::seed_from_u64(0xCAFE);
    let (pk, _sk) = keypair(&mut rng);
    let (_ct, ss) = encapsulate(&pk, &mut rng).unwrap();
    assert_eq!(ss.len(), 32, "Shared secret must be AEAD-key sized (32 B)");
}

#[test]
fn adr0017_distinct_sessions_yield_distinct_secrets() {
    let mut rng = StdRng::seed_from_u64(0xBABE);
    let (pk, _sk) = keypair(&mut rng);
    let (_, ss_a) = encapsulate(&pk, &mut rng).unwrap();
    let (_, ss_b) = encapsulate(&pk, &mut rng).unwrap();
    assert_ne!(
        *ss_a, *ss_b,
        "encap with fresh randomness must produce distinct shared secrets"
    );
}
