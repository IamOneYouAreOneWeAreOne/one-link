//! Cross-platform determinism vector for `ol_erasure`.
//!
//! The StripeId is BLAKE3-derived and the shard bytes are RS(k, m)
//! encoded — both must be deterministic across platforms.

use ol_erasure::{encode_stripe, stripe::stripe_id_of, ShardRole, StripeParams};

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
fn cross_platform_stripe_id_pinned() {
    // Fixed plaintext: 200 bytes of `(i * 31) as u8`.
    let plaintext: Vec<u8> = (0..200u32).map(|i| (i.wrapping_mul(31)) as u8).collect();
    let id_standard = stripe_id_of(&plaintext, StripeParams::STANDARD);
    let id_archival = stripe_id_of(&plaintext, StripeParams::ARCHIVAL);

    let std_hex = hex_lower(&id_standard);
    let arc_hex = hex_lower(&id_archival);

    if std_hex != PINNED_STRIPE_ID_STANDARD {
        eprintln!("PINNED_STRIPE_ID_STANDARD = \"{std_hex}\"");
        eprintln!("(divergence vs {PINNED_STRIPE_ID_STANDARD})");
    }
    if arc_hex != PINNED_STRIPE_ID_ARCHIVAL {
        eprintln!("PINNED_STRIPE_ID_ARCHIVAL = \"{arc_hex}\"");
        eprintln!("(divergence vs {PINNED_STRIPE_ID_ARCHIVAL})");
    }

    assert_eq!(std_hex, PINNED_STRIPE_ID_STANDARD, "STANDARD StripeId diverged");
    assert_eq!(arc_hex, PINNED_STRIPE_ID_ARCHIVAL, "ARCHIVAL StripeId diverged");
    // Distinct params → distinct IDs.
    assert_ne!(id_standard, id_archival);
}

#[test]
fn cross_platform_data_shard_0_pinned() {
    // Encode a fixed plaintext with STANDARD(10,4); pin the bytes of
    // data shard 0. (Since the encoding is systematic, data shard 0
    // is just the first chunk of the padded plaintext.)
    let plaintext: Vec<u8> = (0..200u32).map(|i| (i.wrapping_mul(31)) as u8).collect();
    let shards = encode_stripe(&plaintext, StripeParams::STANDARD).unwrap();
    assert_eq!(shards.len(), 14);
    assert_eq!(shards[0].role, ShardRole::Data);
    assert_eq!(shards[0].index, 0);
    // shard_len = ceil(200/10) = 20 bytes.
    assert_eq!(shards[0].bytes.len(), 20);

    let hex0 = hex_lower(&shards[0].bytes);
    assert_eq!(shards[10].role, ShardRole::Parity);
    let hex_p0 = hex_lower(&shards[10].bytes);

    // Print both before any assert so divergence shows full vector set.
    if hex0 != PINNED_DATA_SHARD_0 || hex_p0 != PINNED_PARITY_SHARD_0 {
        eprintln!("PINNED_DATA_SHARD_0   = \"{hex0}\"");
        eprintln!("PINNED_PARITY_SHARD_0 = \"{hex_p0}\"");
    }
    assert_eq!(hex0, PINNED_DATA_SHARD_0, "data shard 0 diverged");
    assert_eq!(hex_p0, PINNED_PARITY_SHARD_0, "parity shard 0 diverged");
}

// Pinned on Windows x86_64 with SSSE3 path. Linux/macOS arm64 builds
// must match or these tests fail loudly — drift = wire-format break.
const PINNED_STRIPE_ID_STANDARD: &str =
    "b0471f2170da648b76ffe84f156853ea4b50c93ff2e522878738ee998b291994";
const PINNED_STRIPE_ID_ARCHIVAL: &str =
    "5e4025ff7a26414946c607c7aecf1429808e8ab7115fd2f3b219ddd2bef7a649";
const PINNED_DATA_SHARD_0: &str = "001f3e5d7c9bbad9f81736557493b2d1f00f2e4d";
const PINNED_PARITY_SHARD_0: &str = "44b0d8933d309213fb9dc6be461238e6311f5021";
