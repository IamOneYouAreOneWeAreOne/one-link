//! Pinned KAT vectors for the sovereign-discovery layer.
//!
//! These vectors guarantee cross-build reproducibility for the three
//! canonical primitives a peer's identity depends on:
//!
//!   1. `NodeId::from_pubkey(pk)` — BLAKE3(pk) is byte-stable.
//!   2. `PeerRecord::canonical_bytes()` — the byte string a peer signs.
//!   3. `SignedRecord::sign` round-trips through `verify` with a
//!      ChaCha20-seeded deterministic signing key.
//!
//! If any of these drift across releases, every existing peer record
//! on the network silently breaks. Pinning them here forces a deliberate
//! version-bump on the wire format.
//!
//! ## Regenerating
//!
//! ```text
//! OL_DISCOVERY_KAT_REGEN=1 cargo test -p ol_discovery --release \
//!     --test known_answer_vectors -- --nocapture
//! ```
//!
//! Copy the printed hex back into the constants below.

use ed25519_dalek::SigningKey;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use ol_discovery::node_id::NodeId;
use ol_discovery::record::{PeerRecord, SignedRecord, RECORD_DEFAULT_TTL_SECS};

const PUBKEY_FIXED: [u8; 32] = [
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
];

/// BLAKE3([0x42; 32]) — pinned for cross-build identity.
const EXPECTED_NODE_ID_HEX: &str =
    "bcff11daf7dbb8c789b7bcc4e45298041666f92fa8454b1c3fa86e174fd611e4";

/// canonical_bytes() of the seed PeerRecord — pinned to detect wire
/// format drift. Encodes magic / pubkey / pub_time / ttl / endpoint
/// count / endpoint length-prefixed string in a deterministic layout.
const EXPECTED_CANONICAL_HEX: &str = concat!(
    "4f4c5231",                                                         // OLR1 magic
    "4242424242424242424242424242424242424242424242424242424242424242", // pubkey
    "0000000000000001",                     // publish_time_unix = 1 (BE u64)
    "0000000000015180",                     // ttl_secs = 86400 = 0x15180 (BE u64)
    "0001",                                 // n_endpoints = 1
    "0012",                                 // endpoint[0] length = 18 (0x12)
    "7564703a2f2f312e322e332e343a35363738", // "udp://1.2.3.4:5678" (18 bytes)
);

/// Verify the SignedRecord round-trips through verify with a
/// ChaCha20-seeded signing key. We pin the first 32 bytes of the
/// 64-byte Ed25519 signature for cross-build reproducibility.
///
/// The full 64-byte signature includes a nonce derived from the
/// (deterministic) Ed25519 procedure, so pinning is meaningful.
const SEED_FOR_SIGNING: [u8; 32] = [0xC0; 32];
const EXPECTED_SIG_FIRST_32_HEX: &str =
    "c4a8bf4cfa1ca469878df7d6338516e843204f744424e1ef13e484ba5112c320";

fn check_regen<F: FnOnce()>(label: &str, dump: F) {
    if std::env::var("OL_DISCOVERY_KAT_REGEN").as_deref() == Ok("1") {
        eprintln!("[KAT REGEN] {label}");
        dump();
    }
}

#[test]
fn kat_node_id_blake3_pinned() {
    let actual = NodeId::from_pubkey(&PUBKEY_FIXED);
    let actual_hex: String = actual
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    check_regen("NodeId from [0x42; 32]", || {
        eprintln!("    EXPECTED_NODE_ID_HEX = \"{actual_hex}\"");
    });
    assert_eq!(actual_hex, EXPECTED_NODE_ID_HEX, "BLAKE3 NodeId drift");
}

fn fixed_record() -> PeerRecord {
    PeerRecord {
        publisher_pubkey: PUBKEY_FIXED,
        endpoints: vec!["udp://1.2.3.4:5678".to_string()],
        publish_time_unix: 1,
        ttl_secs: RECORD_DEFAULT_TTL_SECS,
    }
}

#[test]
fn kat_record_canonical_bytes_pinned() {
    let rec = fixed_record();
    let bytes = rec.canonical_bytes();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let expected: String = EXPECTED_CANONICAL_HEX
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    check_regen("Record canonical_bytes() of fixed_record", || {
        eprintln!("    EXPECTED_CANONICAL_HEX = \"{hex}\"");
    });
    assert_eq!(hex, expected, "Record wire-format drift");
}

#[test]
fn kat_record_canonical_byte_count_pinned() {
    // 4 magic + 32 pk + 8 pub_time + 8 ttl + 2 n_eps + 2 ep_len + 18 ep_str = 74
    let rec = fixed_record();
    let bytes = rec.canonical_bytes();
    assert_eq!(bytes.len(), 74, "canonical-bytes size drift");
}

#[test]
fn kat_signed_record_seeded_verify_roundtrip() {
    let mut rng = ChaCha20Rng::from_seed(SEED_FOR_SIGNING);
    let sk = SigningKey::generate(&mut rng);
    let pk = sk.verifying_key().to_bytes();
    let rec = PeerRecord {
        publisher_pubkey: pk,
        endpoints: vec!["udp://10.0.0.1:9000".into()],
        publish_time_unix: 1_700_000_000,
        ttl_secs: RECORD_DEFAULT_TTL_SECS,
    };
    let signed = SignedRecord::sign(rec, &sk).unwrap();
    // First 32 bytes of the Ed25519 signature (the "R" point) pinned.
    let sig_first_hex: String = signed.signature[..32]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    check_regen("Sig[0..32] of seeded record", || {
        eprintln!("    EXPECTED_SIG_FIRST_32_HEX = \"{sig_first_hex}\"");
    });
    assert_eq!(
        sig_first_hex, EXPECTED_SIG_FIRST_32_HEX,
        "Ed25519 sig R-point drift"
    );
    // Round-trips through verify.
    signed.verify().unwrap();
}

#[test]
fn kat_constants_match_wire_spec() {
    // Document the constants the rest of the system relies on.
    assert_eq!(ol_discovery::NODE_ID_BYTES, 32, "NodeId byte size pinned");
    assert_eq!(ol_discovery::NODE_ID_BITS, 256, "NodeId bit size pinned");
    assert_eq!(
        RECORD_DEFAULT_TTL_SECS, 86_400,
        "Default record TTL pinned at 24h"
    );
}
