//! Deterministic test vector for the hybrid KEM.
//!
//! ml-kem 0.2 doesn't expose its FIPS 203 `generate_deterministic` API
//! (it's `pub(crate)`), so we can't run a NIST KAT directly. Instead we
//! pin the `(pk, sk, ct, ss)` quadruple produced by a **fixed seed**
//! through `StdRng`. Any divergence — ml-kem version bump, x25519
//! change, BLAKE3 combiner mod, RNG behaviour shift — flags loudly.
//!
//! Verifies the same property a NIST KAT would: deterministic input
//! → deterministic output. The values are platform-independent because
//! `StdRng` (ChaCha12-based) is byte-stable across architectures.

use ol_pqkem::{decapsulate, encapsulate, keypair};
use rand::rngs::StdRng;
use rand::SeedableRng;

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

#[test]
fn deterministic_seed_round_trip_pinned() {
    // Use a fixed seed and feed the same RNG into BOTH keypair and
    // encapsulate. The resulting (pk, sk, ct, ss) is fully
    // deterministic.
    let mut rng = StdRng::seed_from_u64(0x9E37_79B9_7F4A_7C15);
    let (pk, sk) = keypair(&mut rng);
    let (ct, ss) = encapsulate(&pk, &mut rng).unwrap();

    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();
    let ct_bytes = ct.to_bytes();
    let ss_bytes: [u8; 32] = *ss;

    // Sanity: decapsulate to make sure the test isn't broken.
    let ss_recovered = decapsulate(&sk, &ct).unwrap();
    assert_eq!(*ss, *ss_recovered);

    // Print on divergence so the new vector is easy to paste in.
    let pk_first16 = hex_lower(&pk_bytes[..16]);
    let sk_first16 = hex_lower(&sk_bytes[..16]);
    let ct_first16 = hex_lower(&ct_bytes[..16]);
    let ss_hex = hex_lower(&ss_bytes);

    if pk_first16 != PINNED_PK_FIRST16
        || sk_first16 != PINNED_SK_FIRST16
        || ct_first16 != PINNED_CT_FIRST16
        || ss_hex != PINNED_SS_HEX
    {
        eprintln!("=== ol_pqkem deterministic vector ===");
        eprintln!("PINNED_PK_FIRST16 = \"{pk_first16}\"");
        eprintln!("PINNED_SK_FIRST16 = \"{sk_first16}\"");
        eprintln!("PINNED_CT_FIRST16 = \"{ct_first16}\"");
        eprintln!("PINNED_SS_HEX     = \"{ss_hex}\"");
    }

    assert_eq!(pk_first16, PINNED_PK_FIRST16, "PK first 16 bytes diverged");
    assert_eq!(sk_first16, PINNED_SK_FIRST16, "SK first 16 bytes diverged");
    assert_eq!(ct_first16, PINNED_CT_FIRST16, "CT first 16 bytes diverged");
    assert_eq!(ss_hex, PINNED_SS_HEX, "shared secret diverged");
}

// Pinned values from the reference platform with ml-kem 0.2.3 +
// x25519-dalek 2.0 + rand 0.8 + BLAKE3 1.5. Any drift here means
// a dependency version bumped without an ADR + wire-format update.
const PINNED_PK_FIRST16: &str = "d1055e4d2c1ab8c21baf6452455103a1";
const PINNED_SK_FIRST16: &str = "40ea7584222c1d56ca37a81042e981af";
const PINNED_CT_FIRST16: &str = "37df38d5f4761421dfb40fdb07aa43d2";
const PINNED_SS_HEX: &str =
    "430df9f1f29dd3879a34af9aa5956466264fcc9d3d9586967c0889673b4942d1";
