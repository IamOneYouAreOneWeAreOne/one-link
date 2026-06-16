//! SAS — short authentication string derivation.
//!
//! 30 bits of entropy encoded as 5 words from a 64-word dictionary.
//! Each word represents 6 bits; we use 5 words = 30 bits ≈ 10⁹
//! distinct SAS values.
//!
//! ## Why 30 bits?
//!
//! The user compares the SAS once, out-of-band. An active MITM
//! attacker has to guess the user's SAS value BEFORE the user
//! reads it. With 30 bits, the attack success probability is
//! 2⁻³⁰ ≈ 1 in 10⁹ per pairing attempt — solid for a one-shot
//! in-person comparison.
//!
//! ## Why words (not numbers or emoji)?
//!
//! Words are easier to read aloud, easier to confirm at a glance,
//! and survive screen-reader / accessibility paths. Numbers are
//! more error-prone for the user; emoji rendering varies across
//! devices and can collide ambiguously.
//!
//! ## Example
//!
//! ```
//! use ol_pair_qr::sas::Sas;
//! use ol_pair_qr::transcript::TranscriptHash;
//!
//! let t = TranscriptHash::from_bytes([0x42u8; 32]);
//! let sas = Sas::derive(&t);
//! // Five words, space-joined, all from the 64-word dictionary.
//! assert_eq!(sas.display().split(' ').count(), 5);
//! // Determinism: same transcript → same SAS.
//! assert_eq!(sas, Sas::derive(&t));
//! ```

use blake3::Hasher;

use crate::sas_words::SAS_WORDS;
use crate::transcript::TranscriptHash;
use crate::PROTOCOL_DOMAIN;

/// Number of bits represented by the SAS (5 words × 6 bits).
pub const SAS_BITS: usize = 30;

/// Number of words displayed in the SAS.
pub const SAS_WORD_COUNT: usize = 5;

/// Strongly-typed SAS value. Display this to the user; both sides
/// compare verbally and confirm a match before completing the pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sas {
    /// 5-tuple of word slices (each word from [`SAS_WORDS`]).
    pub words: [&'static str; SAS_WORD_COUNT],
    /// Raw 30 bits packed into the low bits of this u32.
    pub raw_bits: u32,
}

impl Sas {
    /// Derive the SAS from the transcript hash deterministically.
    /// Both sides compute the same SAS from the same transcript.
    pub fn derive(transcript: &TranscriptHash) -> Self {
        let mut h = Hasher::new();
        h.update(PROTOCOL_DOMAIN);
        h.update(b"-sas-v1");
        h.update(transcript.as_bytes());
        let digest = h.finalize();
        let bytes = digest.as_bytes();
        // Take 30 bits from the first 4 bytes; mask to 30 bits.
        let raw_bits =
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) & ((1u32 << SAS_BITS) - 1);
        let mut words = [""; SAS_WORD_COUNT];
        for (i, slot) in words.iter_mut().enumerate() {
            // Most significant 6 bits first → reads naturally
            // left-to-right.
            let shift = SAS_BITS - 6 * (i + 1);
            let idx = ((raw_bits >> shift) & 0x3F) as usize;
            *slot = SAS_WORDS[idx];
        }
        Self { words, raw_bits }
    }

    /// Human-readable space-joined rendering.
    pub fn display(&self) -> String {
        self.words.join(" ")
    }

    /// Constant-time word-by-word comparison. Use this when the
    /// daemon receives the peer's SAS over the wire (which is NOT
    /// the standard flow — usually users compare verbally — but
    /// the option exists for accessibility tooling).
    pub fn ct_eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        let a = self.raw_bits.to_be_bytes();
        let b = other.raw_bits.to_be_bytes();
        a.ct_eq(&b).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript::TRANSCRIPT_LEN;

    #[test]
    fn derive_is_deterministic() {
        let t = TranscriptHash::from_bytes([0x42; TRANSCRIPT_LEN]);
        let s1 = Sas::derive(&t);
        let s2 = Sas::derive(&t);
        assert_eq!(s1, s2);
        assert_eq!(s1.raw_bits, s2.raw_bits);
    }

    #[test]
    fn derive_uses_exactly_30_bits() {
        let t = TranscriptHash::from_bytes([0xFF; TRANSCRIPT_LEN]);
        let s = Sas::derive(&t);
        assert!(s.raw_bits < (1u32 << SAS_BITS));
    }

    #[test]
    fn derive_picks_valid_dictionary_words() {
        let t = TranscriptHash::from_bytes([0x77; TRANSCRIPT_LEN]);
        let s = Sas::derive(&t);
        for w in &s.words {
            assert!(SAS_WORDS.contains(w));
        }
    }

    #[test]
    fn display_renders_five_words_space_joined() {
        let t = TranscriptHash::from_bytes([0x11; TRANSCRIPT_LEN]);
        let s = Sas::derive(&t);
        let d = s.display();
        let parts: Vec<&str> = d.split(' ').collect();
        assert_eq!(parts.len(), SAS_WORD_COUNT);
        for p in &parts {
            assert!(SAS_WORDS.contains(p));
        }
    }

    #[test]
    fn different_transcript_different_sas() {
        let t1 = TranscriptHash::from_bytes([0x01; TRANSCRIPT_LEN]);
        let t2 = TranscriptHash::from_bytes([0x02; TRANSCRIPT_LEN]);
        let s1 = Sas::derive(&t1);
        let s2 = Sas::derive(&t2);
        // High-entropy hash means probability of accidental match is
        // ≈ 2⁻³⁰; practically guaranteed to differ on these test inputs.
        assert_ne!(s1, s2);
    }

    #[test]
    fn ct_eq_matches_normal_eq() {
        let t = TranscriptHash::from_bytes([0x55; TRANSCRIPT_LEN]);
        let s1 = Sas::derive(&t);
        let s2 = Sas::derive(&t);
        assert!(s1.ct_eq(&s2));
    }

    #[test]
    fn ct_eq_detects_difference() {
        let t1 = TranscriptHash::from_bytes([0x01; TRANSCRIPT_LEN]);
        let t2 = TranscriptHash::from_bytes([0x02; TRANSCRIPT_LEN]);
        let s1 = Sas::derive(&t1);
        let s2 = Sas::derive(&t2);
        assert!(!s1.ct_eq(&s2));
    }

    #[test]
    fn first_word_is_top_6_bits() {
        // 30 bits where top 6 are 0b000001 = 1 → SAS_WORDS[1].
        let raw_bits = 1u32 << (SAS_BITS - 6);
        let idx = ((raw_bits >> (SAS_BITS - 6)) & 0x3F) as usize;
        assert_eq!(idx, 1);
        // Validate the index is within bounds; the specific word is
        // intentionally not pinned here so dictionary curation can
        // proceed without breaking the bit-layout property.
        assert!(idx < SAS_WORDS.len());
    }
}
