//! Inviter state machine.
//!
//! The inviter is the device generating the QR code. Lifecycle:
//!
//! 1. [`Inviter::new`] — generate ephemeral X25519 keypair, build
//!    + sign the [`Invite`], emit the bytes that go into the QR.
//! 2. [`Inviter::receive_response`] — accept the scanner's
//!    [`PairResponse`], verify the signature, compute the
//!    transcript hash + SAS for the user to compare.
//! 3. [`Inviter::confirm`] — after the user confirms the SAS
//!    matches, sign the [`PairConfirm`] and derive the final
//!    [`ChainKey`].

use ed25519_dalek::SigningKey;
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::chain_key::{derive_chain_key, ChainKey};
use crate::confirm::PairConfirm;
use crate::errors::{PairError, PairResult};
use crate::invite::{CapabilityScope, Invite, INVITE_NONCE_LEN};
use crate::response::PairResponse;
use crate::sas::Sas;
use crate::transcript::{transcript_hash, TranscriptHash};

/// State enum for the inviter machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviterState {
    /// Invite generated; waiting for scanner's response.
    AwaitingResponse,
    /// Response received + verified; waiting for user to confirm SAS.
    AwaitingUserConfirm,
    /// User confirmed; chain key derived; pairing complete.
    Done,
    /// Pairing was aborted (e.g. user said SAS mismatch).
    Aborted,
}

/// Inviter side of the pair-by-QR protocol.
///
/// The state machine refuses out-of-order transitions and returns
/// [`PairError::WrongState`] when a call doesn't match the current
/// stage.
pub struct Inviter {
    id_signing: SigningKey,
    ephemeral_secret: Option<StaticSecret>,
    invite: Invite,
    state: InviterState,

    // Populated after receive_response:
    response: Option<PairResponse>,
    transcript: Option<TranscriptHash>,
    sas: Option<Sas>,
    pending_chain_key: Option<ChainKey>,
}

impl Inviter {
    /// Construct a new inviter and produce the QR-encodable invite
    /// bytes. The caller passes their identity signing key + an RNG
    /// for the ephemeral material.
    pub fn new<R: RngCore + CryptoRng>(
        id_signing: SigningKey,
        rng: &mut R,
        expiry_unix: u64,
        scope: CapabilityScope,
    ) -> Self {
        let ephemeral_secret = StaticSecret::random_from_rng(&mut *rng);
        let ephemeral_pk = PublicKey::from(&ephemeral_secret).to_bytes();
        let mut nonce = [0u8; INVITE_NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let invite = Invite::sign(&id_signing, ephemeral_pk, nonce, expiry_unix, scope);
        Self {
            id_signing,
            ephemeral_secret: Some(ephemeral_secret),
            invite,
            state: InviterState::AwaitingResponse,
            response: None,
            transcript: None,
            sas: None,
            pending_chain_key: None,
        }
    }

    /// Read-only view of the invite the QR layer should encode.
    pub fn invite(&self) -> &Invite {
        &self.invite
    }

    /// Encoded invite bytes ready for QR encoding.
    pub fn invite_bytes(&self) -> Vec<u8> {
        self.invite.encode()
    }

    /// Current state.
    pub fn state(&self) -> InviterState {
        self.state
    }

    /// Accept the scanner's response. Verifies the signature,
    /// computes the transcript hash + SAS, and advances state.
    pub fn receive_response(&mut self, response_bytes: &[u8]) -> PairResult<&Sas> {
        if self.state != InviterState::AwaitingResponse {
            return Err(PairError::WrongState);
        }
        let bind = self.invite.body_bytes();
        let response = PairResponse::decode_and_verify(response_bytes, &bind)?;

        let esk = self
            .ephemeral_secret
            .as_ref()
            .ok_or(PairError::Internal("ephemeral_secret missing"))?;
        let peer_pk = PublicKey::from(response.ephemeral_x25519_pk);
        let ss = esk.diffie_hellman(&peer_pk);
        let ss_bytes: [u8; 32] = ss.to_bytes();

        // Reject all-zero / small-order shared secret. x25519-dalek
        // already returns an all-zero SS for small-order pubkeys.
        if ss_bytes.iter().all(|&b| b == 0) {
            return Err(PairError::SmallOrderPubkey);
        }

        let t = transcript_hash(&self.invite, &response);
        let sas = Sas::derive(&t);
        let chain_key = derive_chain_key(&t, &ss_bytes);

        self.response = Some(response);
        self.transcript = Some(t);
        self.sas = Some(sas);
        self.pending_chain_key = Some(chain_key);
        self.state = InviterState::AwaitingUserConfirm;
        Ok(self.sas.as_ref().expect("just set"))
    }

    /// View the SAS without advancing state (e.g. for re-displaying
    /// in the UI). Returns `None` until [`Inviter::receive_response`]
    /// has been called.
    pub fn sas(&self) -> Option<&Sas> {
        self.sas.as_ref()
    }

    /// User confirmed the SAS matches. Sign the [`PairConfirm`] and
    /// finalize the chain key. Returns `(confirm_bytes, chain_key)`.
    pub fn confirm(&mut self) -> PairResult<(Vec<u8>, ChainKey)> {
        self.confirm_inner(None)
    }

    /// Like [`Inviter::confirm`] but mixes in a Factor-2
    /// channel-reciprocity key (output of `ol_proximity_pair::privacy_amplify`).
    /// Both peers MUST supply the same factor-2 key; otherwise the
    /// chain keys diverge and the first ciphertext fails to decrypt.
    pub fn confirm_with_factor2(
        &mut self,
        factor2_key: &[u8; 32],
    ) -> PairResult<(Vec<u8>, ChainKey)> {
        self.confirm_inner(Some(factor2_key))
    }

    fn confirm_inner(&mut self, factor2_key: Option<&[u8; 32]>) -> PairResult<(Vec<u8>, ChainKey)> {
        if self.state != InviterState::AwaitingUserConfirm {
            return Err(PairError::WrongState);
        }
        let t = self
            .transcript
            .ok_or(PairError::Internal("transcript missing"))?;
        let chain_key = self
            .pending_chain_key
            .take()
            .ok_or(PairError::Internal("chain_key missing"))?;
        let final_chain_key = match factor2_key {
            Some(f2) => crate::chain_key::mix_factor2_recip(&chain_key, f2),
            None => chain_key,
        };
        let confirm = PairConfirm::sign(&self.id_signing, t);
        let bytes = confirm.encode();
        self.state = InviterState::Done;
        // Zeroize ephemeral material now that pairing is done.
        if let Some(esk) = self.ephemeral_secret.take() {
            drop(esk);
        }
        Ok((bytes, final_chain_key))
    }

    /// User rejected the SAS comparison. Mark the machine aborted
    /// and zeroize secret material.
    pub fn abort(&mut self) {
        self.state = InviterState::Aborted;
        self.ephemeral_secret = None;
        self.pending_chain_key = None;
    }
}

impl Drop for Inviter {
    fn drop(&mut self) {
        if let Some(esk) = self.ephemeral_secret.take() {
            drop(esk);
        }
        let mut sig_bytes = self.invite.signature;
        sig_bytes.zeroize();
    }
}

impl std::fmt::Debug for Inviter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inviter")
            .field("state", &self.state)
            .field("invite_id_pubkey_prefix", &&self.invite.id_pubkey[..4])
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn invite_bytes_round_trip() {
        let sk = SigningKey::generate(&mut OsRng);
        let inv = Inviter::new(
            sk,
            &mut OsRng,
            1_900_000_000,
            CapabilityScope::from_bytes(b"test").unwrap(),
        );
        let bytes = inv.invite_bytes();
        let decoded = Invite::decode_and_verify(&bytes).unwrap();
        assert_eq!(decoded, *inv.invite());
    }

    #[test]
    fn receive_response_before_init_state_check() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut inv = Inviter::new(sk, &mut OsRng, 1_900_000_000, CapabilityScope::empty());
        // Call confirm before receive_response → WrongState
        let err = inv.confirm().unwrap_err();
        assert_eq!(err, PairError::WrongState);
    }

    #[test]
    fn abort_zeroizes_state() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut inv = Inviter::new(sk, &mut OsRng, 1_900_000_000, CapabilityScope::empty());
        inv.abort();
        assert_eq!(inv.state(), InviterState::Aborted);
        assert!(inv.ephemeral_secret.is_none());
    }
}
