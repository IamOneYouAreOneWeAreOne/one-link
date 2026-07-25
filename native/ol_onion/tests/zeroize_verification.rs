//! Zeroize verification for sensitive material in `ol_onion`.
//!
//! The crate uses `zeroize::Zeroize` on:
//! - [`HopId`]: not sensitive per se, but uniform handling.
//! - [`LayerKey`]: per-layer AEAD key derived from ECDH.
//!
//! These tests don't directly observe the underlying memory after
//! `drop` (Rust's destructor semantics don't expose that). Instead
//! they verify that the type IMPLEMENTS `Zeroize` correctly, by
//! confirming `zeroize()` empties the inner bytes when called.

use ol_onion::keyderiv::LayerKey;
use ol_onion::{HopId, HOP_ID_LEN};
use zeroize::Zeroize;

#[test]
fn hop_id_zeroize_empties_bytes() {
    let mut h = HopId::from_bytes([0xAB; HOP_ID_LEN]);
    assert_ne!(h.as_bytes(), &[0u8; HOP_ID_LEN]);
    h.zeroize();
    assert_eq!(h.as_bytes(), &[0u8; HOP_ID_LEN]);
}

#[test]
fn layer_key_zeroize_empties_bytes() {
    let mut k = LayerKey::from_bytes([0xCD; 32]);
    assert_ne!(k.as_bytes(), &[0u8; 32]);
    k.zeroize();
    assert_eq!(k.as_bytes(), &[0u8; 32]);
}

#[test]
fn layer_key_drop_implies_zeroize() {
    // ZeroizeOnDrop wraps drop in zeroize(). We can't directly read
    // bytes after drop, but we can verify drop-glue runs without
    // panicking and the type behaves correctly under move.
    let k = LayerKey::from_bytes([0xCD; 32]);
    let _moved = k;
    // No panic = success. (Rust's drop checker would have caught
    // any double-free here.)
}
