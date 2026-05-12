//! Stage 4: privacy amplification via BLAKE3-keyed hash.
//!
//! After reconciliation both sides agree on a bit string, but an
//! eavesdropper learned `syndrome_len` bits of it from the public
//! syndrome exchange. To remove that leakage, hash the entire string
//! down to a smaller fixed-size key. The result is information-
//! theoretically secret as long as the input has more remaining
//! entropy than the output size.
//!
//! BLAKE3 in keyed mode is the universal-hash family. Both sides
//! use the SAME salt (typically a transcript hash of the Factor-1
//! QR scan / bootstrap handshake), guaranteeing they produce the
//! SAME output from the same reconciled input.

/// Final key size in bytes (256 bits — matches Ed25519 master seed,
/// AES-256 key, ChaCha20 key, BLAKE3 output).
pub const AMPLIFIED_KEY_BYTES: usize = 32;

/// Privacy amplification: BLAKE3-keyed-hash `reconciled_bits` with `salt`
/// to produce a 32-byte key.
///
/// `reconciled_bits` is a packed bit string (one bit per byte, LSB).
/// `salt` is a 32-byte universal-hash key — must be identical on
/// both sides for the output to match.
#[must_use]
pub fn privacy_amplify(reconciled_bits: &[u8], salt: &[u8; 32]) -> [u8; AMPLIFIED_KEY_BYTES] {
    // Pack the bit string into bytes (8 bits per byte) so BLAKE3
    // sees less input + the hash is faster. Order-preserving:
    // bit i ends up at byte i/8, bit position 7-(i%8).
    let n_bits = reconciled_bits.len();
    let n_bytes = n_bits.div_ceil(8);
    let mut packed = vec![0u8; n_bytes];
    for (i, &b) in reconciled_bits.iter().enumerate() {
        if b & 1 != 0 {
            packed[i / 8] |= 1 << (7 - (i % 8));
        }
    }
    // BLAKE3 keyed mode with salt as key. Same input + same salt =>
    // same output on both sides.
    let h = blake3::keyed_hash(salt, &packed);
    *h.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_input_same_salt_yields_same_key() {
        let bits = vec![1u8, 0, 1, 1, 0, 0, 1, 0, 0, 1];
        let salt = [0x42u8; 32];
        let k1 = privacy_amplify(&bits, &salt);
        let k2 = privacy_amplify(&bits, &salt);
        assert_eq!(k1, k2);
    }

    #[test]
    fn different_salt_yields_different_key() {
        let bits = vec![1u8, 0, 1, 1, 0, 0, 1, 0];
        let salt_a = [0x42u8; 32];
        let salt_b = [0x99u8; 32];
        let k_a = privacy_amplify(&bits, &salt_a);
        let k_b = privacy_amplify(&bits, &salt_b);
        assert_ne!(k_a, k_b);
    }

    #[test]
    fn different_input_yields_different_key() {
        let bits1 = vec![1u8, 0, 1, 1, 0, 0, 1, 0];
        let mut bits2 = bits1.clone();
        bits2[0] ^= 1;
        let salt = [0x42u8; 32];
        let k1 = privacy_amplify(&bits1, &salt);
        let k2 = privacy_amplify(&bits2, &salt);
        assert_ne!(k1, k2);
    }

    #[test]
    fn empty_input_still_produces_key() {
        // Defensive: zero-length input shouldn't panic. The output
        // is the BLAKE3-keyed hash of an empty string with the salt
        // as key — deterministic but useless (caller's bug).
        let k = privacy_amplify(&[], &[0u8; 32]);
        assert_eq!(k.len(), AMPLIFIED_KEY_BYTES);
    }

    #[test]
    fn output_is_exactly_32_bytes() {
        let bits = vec![1u8; 128];
        let salt = [0u8; 32];
        let k = privacy_amplify(&bits, &salt);
        assert_eq!(k.len(), 32);
    }
}
