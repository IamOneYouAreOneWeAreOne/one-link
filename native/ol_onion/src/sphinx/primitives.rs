//! Sphinx primitives: constants, key derivation, MAC, stream
//! cipher, and the filler-byte construction.
//!
//! Everything in this module is pure-byte math — no elliptic curve
//! operations. This makes the filler-byte algorithm directly
//! testable in isolation, which is the part the previous F3 attempt
//! got wrong.

use blake3::Hasher;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use subtle::ConstantTimeEq;

use crate::PROTOCOL_DOMAIN;

// ── Constants ────────────────────────────────────────────────────

/// Length of a routing-information slot: 32-byte hop_id +
/// 16-byte MAC = 48 bytes per relay slot.
pub const SLOT_LEN: usize = 48;

/// Bytes for the hop_id portion of a slot.
pub const SLOT_ID_LEN: usize = 32;

/// Bytes for the MAC portion of a slot.
pub const SLOT_MAC_LEN: usize = 16;

/// Maximum supported circuit length (relays + destination).
pub const MAX_HOPS: usize = 5;

/// Total fixed header length: one slot per hop.
pub const HEADER_LEN: usize = MAX_HOPS * SLOT_LEN;

/// Fixed payload length.
pub const PAYLOAD_LEN: usize = 1024;

/// Length of the per-layer ChaCha20 keystream we generate. We need
/// HEADER_LEN bytes for the visible header XOR + SLOT_LEN bytes
/// past the end for the trailing-slot padding after shift.
pub const HEADER_KEYSTREAM_LEN: usize = HEADER_LEN + SLOT_LEN;

/// Length of the BLAKE3-derived per-hop AEAD key.
pub const LAYER_KEY_LEN: usize = 32;

// ── Per-hop derived keys ─────────────────────────────────────────

/// Key material derived for one hop in the circuit.
///
/// The sender derives this from `(shared_secret, alpha_i)` at build
/// time. The relay derives the same value from
/// `(my_shared_secret, alpha_received)` at peel time.
#[derive(Clone)]
pub struct HopKeys {
    /// 32-byte ChaCha20 key for the header stream cipher.
    pub header_stream: [u8; 32],
    /// 32-byte ChaCha20 key for the payload stream cipher.
    pub payload_stream: [u8; 32],
    /// 32-byte BLAKE3-keyed-MAC key for the per-hop header MAC.
    pub mac_key: [u8; 32],
    /// 32-byte raw bytes used (clamped) as the per-hop blinding
    /// scalar for the next alpha derivation. The Ristretto255 layer
    /// converts these bytes into a scalar.
    pub blinding_seed: [u8; 32],
}

impl std::fmt::Debug for HopKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never leak key bytes in debug formatting.
        f.debug_struct("HopKeys").finish_non_exhaustive()
    }
}

/// Derive the 4 per-hop sub-keys from a shared secret + alpha pair.
///
/// `shared` is the X25519 / Ristretto255 ECDH output (32 bytes).
/// `alpha` is the per-hop ephemeral pubkey carried in the packet.
pub fn derive_hop_keys(shared: &[u8; 32], alpha: &[u8; 32]) -> HopKeys {
    HopKeys {
        header_stream: derive_subkey(shared, alpha, b"sphinx-header-stream-v1"),
        payload_stream: derive_subkey(shared, alpha, b"sphinx-payload-stream-v1"),
        mac_key: derive_subkey(shared, alpha, b"sphinx-mac-v1"),
        blinding_seed: derive_subkey(shared, alpha, b"sphinx-blind-v1"),
    }
}

fn derive_subkey(shared: &[u8; 32], alpha: &[u8; 32], tag: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(PROTOCOL_DOMAIN);
    h.update(b"-");
    h.update(tag);
    h.update(shared);
    h.update(alpha);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_bytes());
    out
}

// ── BLAKE3-keyed MAC over the header ─────────────────────────────

/// Compute the per-hop header MAC. Truncates BLAKE3-keyed output to
/// [`SLOT_MAC_LEN`].
pub fn header_mac(key: &[u8; 32], header: &[u8]) -> [u8; SLOT_MAC_LEN] {
    let mut h = Hasher::new_keyed(key);
    h.update(header);
    let d = h.finalize();
    let mut out = [0u8; SLOT_MAC_LEN];
    out.copy_from_slice(&d.as_bytes()[..SLOT_MAC_LEN]);
    out
}

/// Constant-time MAC comparison.
pub fn verify_header_mac(
    key: &[u8; 32],
    header: &[u8],
    expected: &[u8; SLOT_MAC_LEN],
) -> bool {
    let actual = header_mac(key, header);
    bool::from(actual.ct_eq(expected))
}

// ── ChaCha20 stream cipher helpers ───────────────────────────────

/// Generate `len` bytes of ChaCha20 keystream with the given key.
/// Uses an all-zero nonce — safe because each hop has a unique
/// stream key per circuit.
///
/// Prefer [`chacha20_keystream_into`] on hot paths to avoid the
/// per-call Vec allocation; this function is kept for callers that
/// can't pre-size their buffer (and tests).
pub fn chacha20_keystream(key: &[u8; 32], len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    chacha20_keystream_into(key, &mut buf);
    buf
}

/// Generate ChaCha20 keystream directly into a caller-provided
/// buffer. The buffer MUST start at all zeros — `apply_keystream`
/// XORs into the buffer, so a zero buffer yields pure keystream.
/// Hot-path helper used by [`build_filler`] and
/// [`crate::sphinx::core::build_sphinx_onion`].
#[inline]
pub fn chacha20_keystream_into(key: &[u8; 32], out: &mut [u8]) {
    let nonce = [0u8; 12];
    let mut cipher = ChaCha20::new(key.into(), (&nonce).into());
    cipher.apply_keystream(out);
}

/// ChaCha20 XOR-decrypt / encrypt into the buffer in place (no
/// pre-zero step). Same key + zero nonce semantics as
/// [`chacha20_keystream`].
#[inline]
pub fn chacha20_xor_in_place(key: &[u8; 32], buf: &mut [u8]) {
    let nonce = [0u8; 12];
    let mut cipher = ChaCha20::new(key.into(), (&nonce).into());
    cipher.apply_keystream(buf);
}

/// XOR `keystream` into `buf` in place. Lengths must match.
pub fn xor_in_place(buf: &mut [u8], keystream: &[u8]) {
    debug_assert_eq!(buf.len(), keystream.len());
    for (b, k) in buf.iter_mut().zip(keystream.iter()) {
        *b ^= *k;
    }
}

// ── Filler-byte construction (the load-bearing algorithm) ────────
//
// The filler `phi` has length `n_relays * SLOT_LEN` where
// `n_relays = circuit.len() - 1` (the relays that come BEFORE the
// destination — destination doesn't contribute to filler).
//
// Iterative construction:
//
//     phi[0] = empty
//     for i in 0..n_relays:
//         # Generate hop_i's extended keystream (HEADER_KEYSTREAM_LEN bytes).
//         # Extend filler by SLOT_LEN zero bytes.
//         # XOR the new (i+1)*SLOT_LEN-byte filler with the LAST
//         # (i+1)*SLOT_LEN bytes of the keystream.
//
// The filler ends up at the trailing portion of the destination's
// pre-encryption header. When upstream relays peel + shift, their
// keystream tails reconstruct the destination's expected trailing
// bytes byte-for-byte, so the MAC verifies all the way through.

/// Build the cumulative filler for `n_relays` upstream hops.
///
/// `relay_header_streams[i]` is the header-stream ChaCha20 key for
/// the `i`-th relay in the circuit (the relays *before* the
/// destination).
pub fn build_filler(relay_header_streams: &[[u8; 32]]) -> Vec<u8> {
    let n = relay_header_streams.len();
    if n == 0 {
        return Vec::new();
    }
    // Allocate ONCE at max final size. We XOR-shift in place rather
    // than allocating per-iteration. Stack-allocate the keystream
    // buffer (HEADER_KEYSTREAM_LEN = 288 bytes for SLOT_LEN=48,
    // MAX_HOPS=5; well under 1 KiB).
    let final_len = n * SLOT_LEN;
    let mut filler = vec![0u8; final_len];
    let mut keystream = [0u8; HEADER_KEYSTREAM_LEN];
    let mut current_len = 0;
    for (i, key) in relay_header_streams.iter().enumerate() {
        let new_len = (i + 1) * SLOT_LEN;
        // Zero keystream buffer (apply_keystream XORs into existing
        // bytes, so a zero buffer is needed for pure keystream).
        for b in keystream.iter_mut() {
            *b = 0;
        }
        chacha20_keystream_into(key, &mut keystream);
        let tail_start = HEADER_KEYSTREAM_LEN - new_len;
        for j in 0..new_len {
            filler[j] ^= keystream[tail_start + j];
        }
        current_len = new_len;
    }
    debug_assert_eq!(current_len, final_len);
    filler
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Key derivation ───────────────────────────────────────────

    #[test]
    fn derive_hop_keys_deterministic() {
        let shared = [0x11u8; 32];
        let alpha = [0x22u8; 32];
        let k1 = derive_hop_keys(&shared, &alpha);
        let k2 = derive_hop_keys(&shared, &alpha);
        assert_eq!(k1.header_stream, k2.header_stream);
        assert_eq!(k1.payload_stream, k2.payload_stream);
        assert_eq!(k1.mac_key, k2.mac_key);
        assert_eq!(k1.blinding_seed, k2.blinding_seed);
    }

    #[test]
    fn derive_hop_keys_all_four_subkeys_distinct() {
        let shared = [0x33u8; 32];
        let alpha = [0x44u8; 32];
        let k = derive_hop_keys(&shared, &alpha);
        assert_ne!(k.header_stream, k.payload_stream);
        assert_ne!(k.header_stream, k.mac_key);
        assert_ne!(k.header_stream, k.blinding_seed);
        assert_ne!(k.payload_stream, k.mac_key);
        assert_ne!(k.payload_stream, k.blinding_seed);
        assert_ne!(k.mac_key, k.blinding_seed);
    }

    #[test]
    fn derive_hop_keys_different_shared_different_keys() {
        let alpha = [0xAAu8; 32];
        let k1 = derive_hop_keys(&[0x11; 32], &alpha);
        let k2 = derive_hop_keys(&[0x12; 32], &alpha);
        assert_ne!(k1.header_stream, k2.header_stream);
    }

    // ── MAC ──────────────────────────────────────────────────────

    #[test]
    fn header_mac_deterministic() {
        let key = [0x55u8; 32];
        let data = vec![0u8; HEADER_LEN];
        let m1 = header_mac(&key, &data);
        let m2 = header_mac(&key, &data);
        assert_eq!(m1, m2);
    }

    #[test]
    fn header_mac_changes_on_one_bit_flip() {
        let key = [0x55u8; 32];
        let mut data = vec![0u8; HEADER_LEN];
        let m1 = header_mac(&key, &data);
        data[0] ^= 0x01;
        let m2 = header_mac(&key, &data);
        assert_ne!(m1, m2);
    }

    #[test]
    fn verify_header_mac_constant_time_correctness() {
        let key = [0x55u8; 32];
        let data = vec![0u8; HEADER_LEN];
        let real = header_mac(&key, &data);
        assert!(verify_header_mac(&key, &data, &real));
        let mut wrong = real;
        wrong[0] ^= 0x80;
        assert!(!verify_header_mac(&key, &data, &wrong));
    }

    // ── Filler ───────────────────────────────────────────────────

    #[test]
    fn filler_empty_for_zero_relays() {
        let filler = build_filler(&[]);
        assert!(filler.is_empty());
    }

    #[test]
    fn filler_length_n_times_slot_len() {
        for n in 1..=4 {
            let keys: Vec<[u8; 32]> = (0..n).map(|i| [i as u8 + 1; 32]).collect();
            let filler = build_filler(&keys);
            assert_eq!(filler.len(), n * SLOT_LEN, "n={n}");
        }
    }

    #[test]
    fn filler_deterministic() {
        let keys = vec![[0x11u8; 32], [0x22u8; 32]];
        let f1 = build_filler(&keys);
        let f2 = build_filler(&keys);
        assert_eq!(f1, f2);
    }

    #[test]
    fn filler_one_relay_matches_keystream_tail() {
        // For 1 relay, filler should equal the last SLOT_LEN bytes
        // of relay_0's HEADER_KEYSTREAM_LEN keystream.
        let key = [0xAAu8; 32];
        let filler = build_filler(&[key]);
        let keystream = chacha20_keystream(&key, HEADER_KEYSTREAM_LEN);
        let expected = &keystream[HEADER_KEYSTREAM_LEN - SLOT_LEN..];
        assert_eq!(filler.as_slice(), expected);
    }

    #[test]
    fn filler_two_relays_first_slot_xor() {
        // For 2 relays, filler is 2*SLOT_LEN bytes long.
        // - First SLOT_LEN: keystream_0_tail XOR keystream_1_at(HEADER_LEN-SLOT_LEN..HEADER_LEN)
        // - Last SLOT_LEN: keystream_1_at(HEADER_LEN..HEADER_LEN+SLOT_LEN)
        let k0 = [0xAAu8; 32];
        let k1 = [0xBBu8; 32];
        let filler = build_filler(&[k0, k1]);
        let ks0 = chacha20_keystream(&k0, HEADER_KEYSTREAM_LEN);
        let ks1 = chacha20_keystream(&k1, HEADER_KEYSTREAM_LEN);

        let expected_first_slot: Vec<u8> = (0..SLOT_LEN)
            .map(|j| ks0[HEADER_KEYSTREAM_LEN - SLOT_LEN + j] ^ ks1[HEADER_LEN - SLOT_LEN + j])
            .collect();
        let expected_last_slot: Vec<u8> = (0..SLOT_LEN).map(|j| ks1[HEADER_LEN + j]).collect();

        assert_eq!(&filler[..SLOT_LEN], expected_first_slot.as_slice());
        assert_eq!(&filler[SLOT_LEN..], expected_last_slot.as_slice());
    }

    // ── ChaCha20 sanity ──────────────────────────────────────────

    #[test]
    fn chacha20_keystream_deterministic() {
        let key = [0x77u8; 32];
        let a = chacha20_keystream(&key, 256);
        let b = chacha20_keystream(&key, 256);
        assert_eq!(a, b);
    }

    #[test]
    fn chacha20_keystream_different_keys_different_output() {
        let a = chacha20_keystream(&[0x11; 32], 64);
        let b = chacha20_keystream(&[0x22; 32], 64);
        assert_ne!(a, b);
    }

    #[test]
    fn xor_in_place_round_trip() {
        let mut buf = vec![0x42u8; 64];
        let keystream = chacha20_keystream(&[0x99; 32], 64);
        let original = buf.clone();
        xor_in_place(&mut buf, &keystream);
        assert_ne!(buf, original);
        // XOR-ing again restores.
        xor_in_place(&mut buf, &keystream);
        assert_eq!(buf, original);
    }
}
