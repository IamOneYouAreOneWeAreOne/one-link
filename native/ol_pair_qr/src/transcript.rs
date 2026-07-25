//! Transcript hash — the single trust anchor for the pair flow.
//!
//! The transcript is the BLAKE3 hash of the canon-encoded
//! concatenation of every message both parties have committed to so
//! far, prefixed with a domain-separator. Both sides compute it
//! independently from their own observed bytes; if they diverge by
//! a single bit, the SAS derived from the transcript will differ
//! and the user-visible compare step fails.

use blake3::Hasher;

use crate::canon::Writer;
use crate::invite::Invite;
use crate::response::PairResponse;
use crate::PROTOCOL_DOMAIN;

/// Length of the transcript hash in bytes.
pub const TRANSCRIPT_LEN: usize = 32;

/// Strongly-typed 32-byte transcript hash. Implements
/// constant-time equality via `subtle::ConstantTimeEq`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TranscriptHash(pub [u8; TRANSCRIPT_LEN]);

impl TranscriptHash {
    /// Wrap raw bytes.
    pub fn from_bytes(b: [u8; TRANSCRIPT_LEN]) -> Self {
        Self(b)
    }

    /// View the raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; TRANSCRIPT_LEN] {
        &self.0
    }

    /// Constant-time equality. Use this instead of `==` when
    /// comparing against attacker-controlled values.
    pub fn ct_eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.0.ct_eq(&other.0).into()
    }
}

/// Build the transcript hash from the invite and response.
///
/// The `PairConfirm` message commits to this exact value; if anything
/// in either party's view of the invite/response diverges, the
/// confirmation's signature fails to verify locally.
pub fn transcript_hash(invite: &Invite, response: &PairResponse) -> TranscriptHash {
    let mut h = Hasher::new();
    h.update(PROTOCOL_DOMAIN);
    h.update(b"-transcript");
    // Length-prefix each frame so they can never be ambiguously
    // re-grouped. Frame lengths are well below `u32::MAX`.
    let invite_bytes = invite.encode();
    let response_bytes = response.encode();
    let mut w = Writer::with_capacity(8 + invite_bytes.len() + response_bytes.len());
    let invite_len = match u32::try_from(invite_bytes.len()) {
        Ok(len) => len,
        Err(error) => panic!("encoded invite length must fit its u32 transcript prefix: {error}"),
    };
    w.write_u32(invite_len);
    w.write_fixed(&invite_bytes);
    let response_len = match u32::try_from(response_bytes.len()) {
        Ok(len) => len,
        Err(error) => {
            panic!("encoded response length must fit its u32 transcript prefix: {error}")
        }
    };
    w.write_u32(response_len);
    w.write_fixed(&response_bytes);
    h.update(w.as_bytes());
    let digest = h.finalize();
    let mut out = [0u8; TRANSCRIPT_LEN];
    out.copy_from_slice(digest.as_bytes());
    TranscriptHash(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invite::CapabilityScope;
    use crate::response::PairResponse;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn fresh_invite(scope: &[u8]) -> (SigningKey, StaticSecret, Invite) {
        let sk = SigningKey::generate(&mut OsRng);
        let esk = StaticSecret::random_from_rng(OsRng);
        let epk = PublicKey::from(&esk).to_bytes();
        let mut nonce = [0u8; crate::invite::INVITE_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let invite = Invite::sign(
            &sk,
            epk,
            nonce,
            1_900_000_000,
            CapabilityScope::from_bytes(scope).unwrap(),
        );
        (sk, esk, invite)
    }

    fn fresh_response(transcript_bind: &[u8]) -> (SigningKey, StaticSecret, PairResponse) {
        let sk = SigningKey::generate(&mut OsRng);
        let esk = StaticSecret::random_from_rng(OsRng);
        let epk = PublicKey::from(&esk).to_bytes();
        let mut nonce = [0u8; crate::response::RESPONSE_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let resp = PairResponse::sign_for_transcript(&sk, epk, nonce, transcript_bind);
        (sk, esk, resp)
    }

    #[test]
    fn same_inputs_same_transcript() {
        let (_, _, invite) = fresh_invite(b"contact");
        let (_, _, resp) = fresh_response(b"x");
        let t1 = transcript_hash(&invite, &resp);
        let t2 = transcript_hash(&invite, &resp);
        assert_eq!(t1, t2);
    }

    #[test]
    fn different_invite_different_transcript() {
        let (_, _, invite1) = fresh_invite(b"a");
        let (_, _, invite2) = fresh_invite(b"b");
        let (_, _, resp) = fresh_response(b"x");
        let t1 = transcript_hash(&invite1, &resp);
        let t2 = transcript_hash(&invite2, &resp);
        assert_ne!(t1, t2);
    }

    #[test]
    fn different_response_different_transcript() {
        let (_, _, invite) = fresh_invite(b"a");
        let (_, _, r1) = fresh_response(b"x");
        let (_, _, r2) = fresh_response(b"y");
        let t1 = transcript_hash(&invite, &r1);
        let t2 = transcript_hash(&invite, &r2);
        assert_ne!(t1, t2);
    }

    #[test]
    fn ct_eq_matches_eq_for_equal_hashes() {
        let h = TranscriptHash([7u8; TRANSCRIPT_LEN]);
        let g = TranscriptHash([7u8; TRANSCRIPT_LEN]);
        assert!(h.ct_eq(&g));
        assert_eq!(h, g);
    }

    #[test]
    fn ct_eq_detects_one_bit_diff() {
        let a = [7u8; TRANSCRIPT_LEN];
        let mut b = [7u8; TRANSCRIPT_LEN];
        b[31] ^= 0x01;
        let ha = TranscriptHash(a);
        let hb = TranscriptHash(b);
        assert!(!ha.ct_eq(&hb));
        assert_ne!(ha, hb);
    }
}
