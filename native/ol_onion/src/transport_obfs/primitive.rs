//! Row 7 — pluggable transport obfuscation primitive.
//!
//! Wraps wire bytes with a ChaCha20 keystream derived from a pre-
//! shared key + per-packet nonce. A DPI box / passive observer that
//! doesn't hold the pre-shared key sees uniformly-random bytes,
//! making One Link traffic statistically indistinguishable from
//! e.g. encrypted-but-padded HTTPS payloads, random VPN traffic, or
//! WireGuard packet bodies.
//!
//! ## What this is
//!
//! A FOUNDATION. Real pluggable transports (obfs4, Cloak, Snowflake)
//! build a TLS-shaped or browser-fronting handshake on top of an
//! obfuscation primitive like this one. The handshake is where the
//! key exchange + protocol fingerprint live; this layer is purely
//! the bulk-byte XOR after the key is established.
//!
//! ## What this is NOT
//!
//! - Not a full TLS-mimicry. Real DPI defeats need to mimic the
//!   TLS handshake bit-for-bit + JA3 fingerprint matching.
//! - Not a key-exchange protocol. The pre-shared key arrives via
//!   F2 pair-by-QR or F3-onion-routed channel.
//! - Not steganographic. Random-looking is the goal, not "looks like
//!   YouTube traffic specifically." For deeper traffic-analysis
//!   resistance, layer cover-traffic (row 6) + onion routing
//!   (row 5).
//!
//! ## API
//!
//! `obfuscate(key, packet_bytes, packet_id) -> Vec<u8>` XORs the
//! input with a deterministic ChaCha20 keystream. `deobfuscate(...)`
//! is the same operation (XOR is symmetric).
//!
//! Length is preserved byte-for-byte. There is NO authentication at
//! this layer — apply it BENEATH an authenticated transport (QUIC's
//! TLS handshake, the Sphinx layer's MAC, the noise of Double
//! Ratchet) so a flipped byte by the censor causes the upper layer
//! to drop the packet.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use thiserror::Error;

/// Length of the pre-shared obfuscation key.
pub const OBFS_KEY_LEN: usize = 32;

/// Length of the per-packet nonce. ChaCha20 standard 96-bit nonce.
pub const OBFS_NONCE_LEN: usize = 12;

/// Typed error surface.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ObfsError {
    /// Wrong key or nonce length.
    #[error("wrong byte length: expected {expected}, got {got}")]
    BadLength {
        /// Required length.
        expected: usize,
        /// Actual length.
        got: usize,
    },
}

/// Obfuscate `bytes` with the key + nonce. Returns a fresh Vec of
/// the same length. Symmetric: pass the same key + nonce to
/// `deobfuscate` (or `obfuscate` again) to recover the input.
///
/// Nonces MUST NOT repeat under the same key — pick a fresh nonce
/// per packet (e.g., a per-connection counter + random per-conn
/// salt). Reusing a (key, nonce) pair leaks the XOR of two
/// plaintexts.
pub fn obfuscate(
    key: &[u8; OBFS_KEY_LEN],
    nonce: &[u8; OBFS_NONCE_LEN],
    bytes: &[u8],
) -> Vec<u8> {
    let mut out = bytes.to_vec();
    let mut cipher = ChaCha20::new(key.into(), nonce.into());
    cipher.apply_keystream(&mut out);
    out
}

/// In-place version of [`obfuscate`]. Useful for hot-path callers
/// that pre-allocate buffers.
pub fn obfuscate_in_place(
    key: &[u8; OBFS_KEY_LEN],
    nonce: &[u8; OBFS_NONCE_LEN],
    bytes: &mut [u8],
) {
    let mut cipher = ChaCha20::new(key.into(), nonce.into());
    cipher.apply_keystream(bytes);
}

/// Deobfuscate `bytes`. Pure-alias for [`obfuscate`] — ChaCha20
/// XOR is symmetric. Provided as a separate name so call sites
/// document direction.
pub fn deobfuscate(
    key: &[u8; OBFS_KEY_LEN],
    nonce: &[u8; OBFS_NONCE_LEN],
    bytes: &[u8],
) -> Vec<u8> {
    obfuscate(key, nonce, bytes)
}

/// In-place deobfuscate. Symmetric alias for `obfuscate_in_place`.
pub fn deobfuscate_in_place(
    key: &[u8; OBFS_KEY_LEN],
    nonce: &[u8; OBFS_NONCE_LEN],
    bytes: &mut [u8],
) {
    obfuscate_in_place(key, nonce, bytes);
}

/// Derive a per-packet nonce from a connection ID + monotonic
/// packet counter. The connection ID provides per-connection
/// uniqueness; the counter provides per-packet uniqueness.
///
/// Format: 4-byte conn_id || 8-byte counter (big-endian) = 12 bytes.
///
/// Daemons SHOULD use this rather than rolling their own nonce
/// scheme — repeating a (key, nonce) pair is catastrophic.
pub fn derive_nonce(conn_id: u32, packet_counter: u64) -> [u8; OBFS_NONCE_LEN] {
    let mut out = [0u8; OBFS_NONCE_LEN];
    out[..4].copy_from_slice(&conn_id.to_be_bytes());
    out[4..].copy_from_slice(&packet_counter.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obfuscate_deobfuscate_round_trip() {
        let key = [0x42u8; OBFS_KEY_LEN];
        let nonce = [0x99u8; OBFS_NONCE_LEN];
        let plain = b"hello world, this is a packet";
        let obf = obfuscate(&key, &nonce, plain);
        // Output differs from input (probabilistically near-certain).
        assert_ne!(obf, plain);
        let recovered = deobfuscate(&key, &nonce, &obf);
        assert_eq!(recovered, plain);
    }

    #[test]
    fn obfuscation_preserves_length() {
        let key = [0u8; OBFS_KEY_LEN];
        let nonce = [0u8; OBFS_NONCE_LEN];
        for len in [0usize, 1, 16, 64, 256, 1024, 1280, 2400] {
            let plain = vec![0xAAu8; len];
            let obf = obfuscate(&key, &nonce, &plain);
            assert_eq!(obf.len(), len);
        }
    }

    #[test]
    fn different_keys_produce_different_output() {
        let nonce = [0x99u8; OBFS_NONCE_LEN];
        let plain = b"x" as &[u8];
        let o1 = obfuscate(&[0x11u8; OBFS_KEY_LEN], &nonce, plain);
        let o2 = obfuscate(&[0x22u8; OBFS_KEY_LEN], &nonce, plain);
        assert_ne!(o1, o2);
    }

    #[test]
    fn different_nonces_produce_different_output() {
        let key = [0x77u8; OBFS_KEY_LEN];
        let plain = b"same input bytes";
        let o1 = obfuscate(&key, &[0x01u8; OBFS_NONCE_LEN], plain);
        let o2 = obfuscate(&key, &[0x02u8; OBFS_NONCE_LEN], plain);
        assert_ne!(o1, o2);
    }

    #[test]
    fn output_looks_uniform_for_zero_plaintext() {
        // Pure keystream output (XOR with all-zero plaintext).
        let key = [0xAB; OBFS_KEY_LEN];
        let nonce = [0xCD; OBFS_NONCE_LEN];
        let plain = vec![0u8; 4096];
        let obf = obfuscate(&key, &nonce, &plain);
        // Chi-squared: byte distribution should look uniform.
        let mut counts = [0u32; 256];
        for &b in &obf {
            counts[b as usize] += 1;
        }
        let expected = obf.len() as f64 / 256.0;
        let chi: f64 = counts
            .iter()
            .map(|&c| {
                let d = c as f64 - expected;
                d * d / expected
            })
            .sum();
        // df=255 critical value at p=0.001 is ~340. ChaCha20 output
        // sits comfortably under this.
        eprintln!("obfuscation byte-dist chi-sq = {chi:.1}");
        assert!(chi < 400.0);
    }

    #[test]
    fn in_place_matches_alloc_version() {
        let key = [0x55u8; OBFS_KEY_LEN];
        let nonce = [0x66u8; OBFS_NONCE_LEN];
        let plain = b"in-place test buffer".to_vec();
        let alloc_obf = obfuscate(&key, &nonce, &plain);
        let mut in_place = plain.clone();
        obfuscate_in_place(&key, &nonce, &mut in_place);
        assert_eq!(alloc_obf, in_place);
    }

    #[test]
    fn derive_nonce_distinct_per_counter() {
        let n1 = derive_nonce(0x42, 1);
        let n2 = derive_nonce(0x42, 2);
        let n3 = derive_nonce(0x43, 1);
        assert_ne!(n1, n2);
        assert_ne!(n1, n3);
        assert_ne!(n2, n3);
    }

    #[test]
    fn derive_nonce_deterministic() {
        let n1 = derive_nonce(0xDEADBEEF, 0x123456789ABCDEF0);
        let n2 = derive_nonce(0xDEADBEEF, 0x123456789ABCDEF0);
        assert_eq!(n1, n2);
    }

    #[test]
    fn obfuscation_then_tamper_then_deobfuscate_changes_output() {
        // Confirms the layer has NO integrity — a censor flipping
        // bytes propagates to the deobfuscated output. This is the
        // intentional property: integrity comes from the upper layer
        // (Sphinx MAC, AEAD, Double Ratchet, QUIC TLS).
        let key = [0x88; OBFS_KEY_LEN];
        let nonce = [0x77; OBFS_NONCE_LEN];
        let plain = b"original message bytes";
        let mut obf = obfuscate(&key, &nonce, plain);
        obf[3] ^= 0x01;
        let recovered = deobfuscate(&key, &nonce, &obf);
        assert_ne!(recovered, plain);
        // The flipped bit propagates directly (stream cipher).
        let mut expected = plain.to_vec();
        expected[3] ^= 0x01;
        assert_eq!(recovered, expected);
    }
}
