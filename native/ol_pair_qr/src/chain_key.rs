//! Final shared chain-key derivation.
//!
//! After both sides verify the transcript hash + the SAS check
//! passes, the chain key is derived deterministically from:
//!
//! - The transcript hash (binds the entire conversation).
//! - The X25519 ECDH shared secret between the two ephemeral keys.
//! - A domain-separation tag.
//!
//! ```text
//!   chain_key = BLAKE3.derive_key("OL-pair-qr-v1-chain-key", transcript || x25519_ss)
//! ```
//!
//! Optional Factor-2: externally supplied 32-byte candidate material can be
//! mixed in via [`mix_factor2_recip`]. The stateful pairing API performs
//! explicit key confirmation before releasing the mixed key. This low-level
//! transform alone does not prove candidate entropy, provenance, physical
//! co-presence, or resistance to relay attacks.

use blake3::Hasher;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::transcript::TranscriptHash;
use crate::PROTOCOL_DOMAIN;

/// Length of the chain key in bytes.
pub const CHAIN_KEY_LEN: usize = 32;

/// Byte length of each Factor-2 key-confirmation tag.
pub const FACTOR2_CONFIRMATION_TAG_LEN: usize = 32;

/// Protocol role bound into a Factor-2 key-confirmation tag.
#[derive(Clone, Copy)]
pub(crate) enum Factor2ConfirmationRole {
    Inviter,
    Scanner,
}

impl Factor2ConfirmationRole {
    fn domain(self) -> &'static [u8] {
        match self {
            Self::Inviter => b"inviter",
            Self::Scanner => b"scanner",
        }
    }
}

/// Strongly-typed chain key. Zeroized on drop.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct ChainKey {
    inner: [u8; CHAIN_KEY_LEN],
}

impl ChainKey {
    /// Wrap raw bytes.
    pub fn from_bytes(b: [u8; CHAIN_KEY_LEN]) -> Self {
        Self { inner: b }
    }

    /// View the raw 32 bytes. Callers MUST keep this short-lived;
    /// the chain key is the seed material for the Double Ratchet
    /// session and zeroizes itself on drop.
    pub fn as_bytes(&self) -> &[u8; CHAIN_KEY_LEN] {
        &self.inner
    }
}

impl PartialEq for ChainKey {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.inner.ct_eq(&other.inner).into()
    }
}
impl Eq for ChainKey {}

/// Derive the chain key from the transcript and the 32-byte X25519
/// ECDH shared secret. Both sides compute the same value.
pub fn derive_chain_key(transcript: &TranscriptHash, x25519_ss: &[u8; 32]) -> ChainKey {
    let mut h = Hasher::new();
    h.update(PROTOCOL_DOMAIN);
    h.update(b"-chain-key-v1");
    h.update(transcript.as_bytes());
    h.update(x25519_ss);
    let digest = h.finalize();
    let mut k = [0u8; CHAIN_KEY_LEN];
    k.copy_from_slice(digest.as_bytes());
    ChainKey { inner: k }
}

/// Mix externally supplied Factor-2 candidate material into the chain key.
/// The output requires both the base chain key and candidate to reproduce.
///
/// This is a low-level deterministic transform, not an agreement protocol.
/// Applications must use [`crate::Inviter::confirm_with_factor2`],
/// [`crate::Scanner::receive_confirm_with_factor2`], and
/// [`crate::Inviter::receive_factor2_ack`] so mismatched candidates fail
/// closed before ratchet state is created.
pub fn mix_factor2_recip(chain_key: &ChainKey, factor2_key: &[u8; 32]) -> ChainKey {
    let mut h = Hasher::new();
    h.update(PROTOCOL_DOMAIN);
    h.update(b"-chain-key-f2-mix-v1");
    h.update(chain_key.as_bytes());
    h.update(factor2_key);
    let digest = h.finalize();
    let mut k = [0u8; CHAIN_KEY_LEN];
    k.copy_from_slice(digest.as_bytes());
    ChainKey { inner: k }
}

/// Produce a transcript- and role-bound proof of possession of the final
/// Factor-2-mixed chain key.
///
/// This is intentionally crate-private: applications must use the stateful
/// [`crate::Inviter`] / [`crate::Scanner`] confirmation exchange instead of
/// treating a standalone tag as authentication.
pub(crate) fn factor2_confirmation_tag(
    chain_key: &ChainKey,
    transcript: &TranscriptHash,
    role: Factor2ConfirmationRole,
) -> [u8; FACTOR2_CONFIRMATION_TAG_LEN] {
    let mut h = Hasher::new_keyed(chain_key.as_bytes());
    h.update(PROTOCOL_DOMAIN);
    h.update(b"-factor2-key-confirm-v1");
    h.update(role.domain());
    h.update(transcript.as_bytes());
    *h.finalize().as_bytes()
}

/// Constant-time verification for a Factor-2 key-confirmation tag.
pub(crate) fn factor2_confirmation_matches(
    expected: &[u8; FACTOR2_CONFIRMATION_TAG_LEN],
    supplied: &[u8; FACTOR2_CONFIRMATION_TAG_LEN],
) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(expected.ct_eq(supplied))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript::TRANSCRIPT_LEN;

    #[test]
    fn derive_deterministic() {
        let t = TranscriptHash::from_bytes([0x42; TRANSCRIPT_LEN]);
        let ss = [0x55u8; 32];
        let k1 = derive_chain_key(&t, &ss);
        let k2 = derive_chain_key(&t, &ss);
        assert_eq!(k1, k2);
        assert_eq!(k1.as_bytes().len(), CHAIN_KEY_LEN);
    }

    #[test]
    fn different_transcript_different_chain_key() {
        let ss = [0xAAu8; 32];
        let t1 = TranscriptHash::from_bytes([0x01; TRANSCRIPT_LEN]);
        let t2 = TranscriptHash::from_bytes([0x02; TRANSCRIPT_LEN]);
        assert_ne!(derive_chain_key(&t1, &ss), derive_chain_key(&t2, &ss));
    }

    #[test]
    fn different_ss_different_chain_key() {
        let t = TranscriptHash::from_bytes([0x42; TRANSCRIPT_LEN]);
        let ss1 = [0x55u8; 32];
        let ss2 = [0x56u8; 32];
        assert_ne!(derive_chain_key(&t, &ss1), derive_chain_key(&t, &ss2));
    }

    #[test]
    fn factor2_mix_deterministic() {
        let t = TranscriptHash::from_bytes([0x42; TRANSCRIPT_LEN]);
        let ss = [0x55u8; 32];
        let f2 = [0x11u8; 32];
        let k = derive_chain_key(&t, &ss);
        let m1 = mix_factor2_recip(&k, &f2);
        let m2 = mix_factor2_recip(&k, &f2);
        assert_eq!(m1, m2);
    }

    #[test]
    fn factor2_mix_differs_from_unmixed() {
        let t = TranscriptHash::from_bytes([0x42; TRANSCRIPT_LEN]);
        let ss = [0x55u8; 32];
        let f2 = [0x11u8; 32];
        let k = derive_chain_key(&t, &ss);
        let m = mix_factor2_recip(&k, &f2);
        assert_ne!(k, m);
    }

    #[test]
    fn factor2_mix_avalanches_on_one_bit_flip() {
        let t = TranscriptHash::from_bytes([0x42; TRANSCRIPT_LEN]);
        let ss = [0x55u8; 32];
        let k = derive_chain_key(&t, &ss);
        let mut f2a = [0x11u8; 32];
        let mut f2b = [0x11u8; 32];
        f2b[0] ^= 0x01;
        let m1 = mix_factor2_recip(&k, &f2a);
        let m2 = mix_factor2_recip(&k, &f2b);
        f2a.zeroize();
        assert_ne!(m1, m2);
    }

    #[test]
    fn factor2_confirmation_is_key_transcript_and_role_bound() {
        let t1 = TranscriptHash::from_bytes([0x42; TRANSCRIPT_LEN]);
        let t2 = TranscriptHash::from_bytes([0x43; TRANSCRIPT_LEN]);
        let k1 = ChainKey::from_bytes([0x11; CHAIN_KEY_LEN]);
        let k2 = ChainKey::from_bytes([0x12; CHAIN_KEY_LEN]);
        let inviter = factor2_confirmation_tag(&k1, &t1, Factor2ConfirmationRole::Inviter);
        let same = factor2_confirmation_tag(&k1, &t1, Factor2ConfirmationRole::Inviter);
        let other_key = factor2_confirmation_tag(&k2, &t1, Factor2ConfirmationRole::Inviter);
        let other_transcript = factor2_confirmation_tag(&k1, &t2, Factor2ConfirmationRole::Inviter);
        let other_role = factor2_confirmation_tag(&k1, &t1, Factor2ConfirmationRole::Scanner);

        assert!(factor2_confirmation_matches(&inviter, &same));
        assert!(!factor2_confirmation_matches(&inviter, &other_key));
        assert!(!factor2_confirmation_matches(&inviter, &other_transcript));
        assert!(!factor2_confirmation_matches(&inviter, &other_role));
    }

    #[test]
    fn ct_eq_via_partial_eq_constant_time_path() {
        let k1 = ChainKey::from_bytes([7u8; CHAIN_KEY_LEN]);
        let k2 = ChainKey::from_bytes([7u8; CHAIN_KEY_LEN]);
        assert_eq!(k1, k2);
        let k3 = ChainKey::from_bytes([7u8; CHAIN_KEY_LEN].map(|b| if b == 7 { 7 } else { 0 }));
        assert_eq!(k1, k3);
    }
}
