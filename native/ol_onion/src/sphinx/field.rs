//! T1.3 — field-bound blinding for Sphinx Coherence.
//!
//! Each hop's blinding factor derivation takes an additional 32-byte
//! `field_witness` input. The witness is the digest of the relay's
//! coherence-field PDE state (Phase E `ol_coherence_field`) at the
//! tick the sender observed.
//!
//! ```text
//!   key_input = BLAKE3("field-bound" || shared || alpha || witness)
//! ```
//!
//! Daemon-side responsibility:
//! - At build time: fetch each relay's most recently published
//!   field witness via the discovery layer (`ol_discovery`).
//! - At peel time: provide the relay's CURRENT (or recent-window)
//!   witness. If it doesn't match the sender's bake, MAC fails.
//!
//! This Sphinx layer only plumbs the bytes through. The actual field
//! sampling + freshness window are the daemon's concern.
//!
//! ## Security scope
//!
//! This function domain-separates and mixes 32 caller-supplied bytes.
//! It proves no physical provenance, entropy, secrecy, or
//! non-reconstructability. In the design where relays publish the
//! witness, a recorder can record it as public context. A public or
//! low-entropy field digest therefore does not add cryptographic secrecy
//! or survive a break of the underlying key agreement. Any future design
//! that needs an independent security factor must supply separately
//! managed CSPRNG-grade secret material and specify its lifecycle.

use crate::sphinx::primitives::{derive_hop_keys, HopKeys};

/// Length of a field witness in bytes (matches BLAKE3 output).
pub const FIELD_WITNESS_LEN: usize = 32;

/// Sentinel for "no field witness" — when a hop opts out of field-
/// binding, pass this value. Both sides must agree to use it.
pub const NO_WITNESS: [u8; FIELD_WITNESS_LEN] = [0u8; FIELD_WITNESS_LEN];

/// Derive per-hop keys with a field witness mixed in.
///
/// When `witness == NO_WITNESS`, this is bytewise-equivalent to
/// [`derive_hop_keys`] (the BLAKE3 input space is partitioned by
/// the domain-separation tag, so a zero-witness still produces a
/// distinct key from the non-field-bound version).
pub fn derive_hop_keys_with_witness(
    shared: &[u8; 32],
    alpha: &[u8; 32],
    witness: &[u8; FIELD_WITNESS_LEN],
) -> HopKeys {
    use blake3::Hasher;
    let mut h = Hasher::new();
    h.update(crate::PROTOCOL_DOMAIN);
    h.update(b"-sphinx-field-bound-v1");
    h.update(shared);
    h.update(alpha);
    h.update(witness);
    let d = h.finalize();
    let mut combined_shared = [0u8; 32];
    combined_shared.copy_from_slice(d.as_bytes());
    derive_hop_keys(&combined_shared, alpha)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_witness_is_distinct_from_non_field_bound() {
        // The field-bound path with NO_WITNESS should differ from
        // plain derive_hop_keys (different domain tag).
        let shared = [0x11; 32];
        let alpha = [0x22; 32];
        let k_plain = derive_hop_keys(&shared, &alpha);
        let k_field = derive_hop_keys_with_witness(&shared, &alpha, &NO_WITNESS);
        assert_ne!(k_plain.header_stream, k_field.header_stream);
    }

    #[test]
    fn same_witness_yields_same_keys() {
        let shared = [0x11; 32];
        let alpha = [0x22; 32];
        let witness = [0x77; 32];
        let k1 = derive_hop_keys_with_witness(&shared, &alpha, &witness);
        let k2 = derive_hop_keys_with_witness(&shared, &alpha, &witness);
        assert_eq!(k1.header_stream, k2.header_stream);
    }

    #[test]
    fn different_witnesses_yield_different_keys() {
        let shared = [0x11; 32];
        let alpha = [0x22; 32];
        let k1 = derive_hop_keys_with_witness(&shared, &alpha, &[0x77; 32]);
        let k2 = derive_hop_keys_with_witness(&shared, &alpha, &[0x78; 32]);
        assert_ne!(k1.header_stream, k2.header_stream);
        assert_ne!(k1.mac_key, k2.mac_key);
        assert_ne!(k1.payload_stream, k2.payload_stream);
        assert_ne!(k1.blinding_seed, k2.blinding_seed);
    }

    #[test]
    fn one_bit_flip_in_witness_avalanche() {
        let shared = [0x11; 32];
        let alpha = [0x22; 32];
        let w1 = [0x77; 32];
        let mut w2 = w1;
        w2[0] ^= 0x01;
        let k1 = derive_hop_keys_with_witness(&shared, &alpha, &w1);
        let k2 = derive_hop_keys_with_witness(&shared, &alpha, &w2);
        // All four sub-keys must differ.
        assert_ne!(k1.header_stream, k2.header_stream);
        assert_ne!(k1.payload_stream, k2.payload_stream);
        assert_ne!(k1.mac_key, k2.mac_key);
        assert_ne!(k1.blinding_seed, k2.blinding_seed);
    }
}
