//! Pinned KAT vectors for the Row 7 transport_obfs layer.
//!
//! Pins:
//!   1. `derive_nonce(conn_id, counter)` byte-format.
//!   2. `obfuscate(key, nonce, plaintext)` keystream output.
//!   3. Handshake message length constants (BridgeKeypair, MAC, total).
//!   4. Round-trip seal_outbound + open_inbound with seeded keys.
//!
//! ## Regenerating
//!
//! ```text
//! OL_OBFS_KAT_REGEN=1 cargo test -p ol_onion --release \
//!     --test known_answer_vectors_obfs -- --nocapture
//! ```

use ol_onion::transport_obfs::handshake::{
    BRIDGE_ID_LEN, BRIDGE_PUBKEY_LEN, BRIDGE_SECRET_LEN, HANDSHAKE_EPOCH_SECS,
    HANDSHAKE_LEN, HANDSHAKE_MAC_LEN,
};
use ol_onion::transport_obfs::primitive::{
    derive_nonce, obfuscate, OBFS_KEY_LEN, OBFS_NONCE_LEN,
};
use ol_onion::transport_obfs::session::{Session, SESSION_KEY_LEN};

const KEY_FIXED: [u8; OBFS_KEY_LEN] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a,
    0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
    0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
];

const NONCE_FIXED: [u8; OBFS_NONCE_LEN] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
];

/// `derive_nonce(0xDEADBEEF, 0x123456789ABCDEF0)` — pinned.
const EXPECTED_DERIVED_NONCE_HEX: &str = "deadbeef123456789abcdef0";

/// `obfuscate(KEY_FIXED, NONCE_FIXED, [0; 32])` — i.e. raw ChaCha20
/// keystream first 32 bytes under the fixed key/nonce. Drift here
/// means ChaCha20 swapped impl or our wrapping changed.
const EXPECTED_KEYSTREAM_HEX: &str = "e7a333c2a548179fbc60220459847aa60fb23c46ec527bcb3091b4e088ae900e";

fn check_regen<F: FnOnce()>(label: &str, dump: F) {
    if std::env::var("OL_OBFS_KAT_REGEN").as_deref() == Ok("1") {
        eprintln!("[KAT REGEN] {label}");
        dump();
    }
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn kat_derive_nonce_byte_format_pinned() {
    let n = derive_nonce(0xDEADBEEF, 0x123456789ABCDEF0);
    let hex = to_hex(&n);
    check_regen("derive_nonce(0xDEADBEEF, 0x123456789ABCDEF0)", || {
        eprintln!("    EXPECTED_DERIVED_NONCE_HEX = \"{hex}\"");
    });
    assert_eq!(hex, EXPECTED_DERIVED_NONCE_HEX, "derive_nonce drift");
}

#[test]
fn kat_chacha20_keystream_pinned() {
    let zero = [0u8; 32];
    let out = obfuscate(&KEY_FIXED, &NONCE_FIXED, &zero);
    let hex = to_hex(&out);
    check_regen("ChaCha20 keystream(KEY_FIXED, NONCE_FIXED)[:32]", || {
        eprintln!("    EXPECTED_KEYSTREAM_HEX = \"{hex}\"");
    });
    assert_eq!(hex, EXPECTED_KEYSTREAM_HEX, "ChaCha20 keystream drift");
}

#[test]
fn kat_constants_pinned() {
    assert_eq!(OBFS_KEY_LEN, 32, "ChaCha20 key length pinned");
    assert_eq!(OBFS_NONCE_LEN, 12, "ChaCha20 nonce length pinned");
    assert_eq!(SESSION_KEY_LEN, OBFS_KEY_LEN, "Session key = obfs key length");
    assert_eq!(BRIDGE_ID_LEN, 32, "Bridge id length pinned");
    assert_eq!(BRIDGE_PUBKEY_LEN, 32, "Bridge pubkey length pinned");
    assert_eq!(BRIDGE_SECRET_LEN, 32, "Bridge secret length pinned");
    assert_eq!(HANDSHAKE_MAC_LEN, 16, "Handshake MAC length pinned");
    assert_eq!(HANDSHAKE_LEN, 48, "Handshake message length (32 pk + 16 mac)");
    assert_eq!(
        HANDSHAKE_EPOCH_SECS, 3600,
        "Handshake epoch window pinned at 1 hour"
    );
}

#[test]
fn kat_session_round_trip_pinned() {
    // Two fixed keys → both sides build symmetric sessions → message
    // round-trips byte-for-byte.
    let k1 = [0xA1u8; SESSION_KEY_LEN];
    let k2 = [0xB2u8; SESSION_KEY_LEN];
    let client = Session::new(k1, k2);
    let server = Session::for_server(k1, k2);
    let plaintext = b"obfs session known-answer round trip";

    let on_wire = client.seal_outbound(plaintext, 1);
    assert_eq!(on_wire.len(), plaintext.len());
    let recovered = server.open_inbound(&on_wire, 1).unwrap();
    assert_eq!(&recovered, plaintext);

    // First 16 bytes of the on-wire bytes are pinned for cross-build
    // reproducibility.
    let first16_hex = to_hex(&on_wire[..16]);
    check_regen("client.seal_outbound([0xA1*],[0xB2*], plaintext, 1)[:16]", || {
        eprintln!("    EXPECTED_SESSION_CIPHER_FIRST16_HEX = \"{first16_hex}\"");
    });
    const EXPECTED_SESSION_CIPHER_FIRST16_HEX: &str = "be394f65b06edcb69ea94f0b902a806c";
    assert_eq!(
        first16_hex, EXPECTED_SESSION_CIPHER_FIRST16_HEX,
        "Session.seal_outbound byte format drift"
    );
}
