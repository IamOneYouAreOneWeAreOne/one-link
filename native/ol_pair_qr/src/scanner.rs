//! Scanner state machine.
//!
//! The scanner is the device reading the QR code. Lifecycle:
//!
//! 1. [`Scanner::scan`] — decode + verify the [`Invite`], check
//!    expiry, generate the [`PairResponse`].
//! 2. The scanner displays the SAS derived from the transcript
//!    (built from the verified Invite + the scanner's own
//!    response).
//! 3. [`Scanner::receive_confirm`] — accept the inviter's
//!    [`PairConfirm`], verify it commits to the same transcript
//!    the scanner saw, and emit the final [`ChainKey`].

use ed25519_dalek::SigningKey;
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::chain_key::{
    derive_chain_key, factor2_confirmation_matches, factor2_confirmation_tag, mix_factor2_recip,
    ChainKey, Factor2ConfirmationRole, FACTOR2_CONFIRMATION_TAG_LEN,
};
use crate::confirm::{PairConfirm, CONFIRM_ENCODED_BYTES};
use crate::errors::{PairError, PairResult};
use crate::invite::Invite;
use crate::response::{PairResponse, RESPONSE_NONCE_LEN};
use crate::sas::Sas;
use crate::transcript::{transcript_hash, TranscriptHash};

/// State enum for the scanner machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScannerState {
    /// Invite scanned + verified; response generated; waiting for
    /// inviter's confirm.
    AwaitingConfirm,
    /// User confirmed SAS + inviter's confirm verified; chain key
    /// derived; pairing complete.
    Done,
    /// Pairing was aborted (user said SAS mismatch, or confirm
    /// signature invalid).
    Aborted,
}

/// Scanner side of the pair-by-QR protocol.
pub struct Scanner {
    #[allow(dead_code)] // retained so future revisions can re-sign confirm-acks
    id_signing: SigningKey,
    ephemeral_secret: Option<StaticSecret>,
    invite: Invite,
    response: PairResponse,
    transcript: TranscriptHash,
    sas: Sas,
    pending_chain_key: Option<ChainKey>,
    state: ScannerState,
}

impl Scanner {
    /// Scan + verify an invite, generate the response, and compute
    /// the transcript + SAS for the user to compare.
    ///
    /// Returns the constructed scanner and the wire bytes of the
    /// response that should be sent back to the inviter.
    pub fn scan<R: RngCore + CryptoRng>(
        id_signing: SigningKey,
        invite_bytes: &[u8],
        now_unix: u64,
        rng: &mut R,
    ) -> PairResult<(Self, Vec<u8>)> {
        let invite = Invite::decode_and_verify(invite_bytes)?;
        invite.check_not_expired(now_unix)?;

        let ephemeral_secret = StaticSecret::random_from_rng(&mut *rng);
        let ephemeral_pk = PublicKey::from(&ephemeral_secret).to_bytes();
        let mut nonce = [0u8; RESPONSE_NONCE_LEN];
        rng.fill_bytes(&mut nonce);

        let response = PairResponse::sign_for_transcript(
            &id_signing,
            ephemeral_pk,
            nonce,
            &invite.body_bytes(),
        );
        let response_bytes = response.encode();

        // Compute transcript + SAS + ECDH for the chain key.
        let t = transcript_hash(&invite, &response);
        let sas = Sas::derive(&t);

        let inviter_pk = PublicKey::from(invite.ephemeral_x25519_pk);
        let ss = ephemeral_secret.diffie_hellman(&inviter_pk);
        let ss_bytes: [u8; 32] = ss.to_bytes();
        if ss_bytes.iter().all(|&b| b == 0) {
            return Err(PairError::SmallOrderPubkey);
        }
        let chain_key = derive_chain_key(&t, &ss_bytes);

        Ok((
            Self {
                id_signing,
                ephemeral_secret: Some(ephemeral_secret),
                invite,
                response,
                transcript: t,
                sas,
                pending_chain_key: Some(chain_key),
                state: ScannerState::AwaitingConfirm,
            },
            response_bytes,
        ))
    }

    /// Read the SAS to display to the user.
    pub fn sas(&self) -> &Sas {
        &self.sas
    }

    /// Read the inviter's identity pubkey for UI display
    /// ("you are pairing with: <pubkey-fingerprint>").
    pub fn inviter_pubkey(&self) -> &[u8; 32] {
        &self.invite.id_pubkey
    }

    /// Current state.
    pub fn state(&self) -> ScannerState {
        self.state
    }

    /// Accept the inviter's confirm. Verifies the signature + that
    /// the transcript hash matches what we saw, then advances to
    /// Done and returns the final chain key.
    pub fn receive_confirm(&mut self, confirm_bytes: &[u8]) -> PairResult<ChainKey> {
        self.receive_confirm_inner(confirm_bytes)
    }

    /// Verify the inviter's Factor-2 key-confirmation proof, then return a
    /// scanner acknowledgement and the confirmed mixed chain key.
    ///
    /// A different Factor-2 candidate fails closed with
    /// [`PairError::Factor2KeyConfirmationFailed`]; no chain key is released
    /// and the state machine remains pending so a valid frame may be retried.
    pub fn receive_confirm_with_factor2(
        &mut self,
        confirm_bytes: &[u8],
        factor2_key: &[u8; 32],
    ) -> PairResult<(Vec<u8>, ChainKey)> {
        let expected_len = CONFIRM_ENCODED_BYTES + FACTOR2_CONFIRMATION_TAG_LEN;
        if confirm_bytes.len() != expected_len {
            return Err(PairError::BadFactor2ConfirmationLen {
                expected: expected_len,
                got: confirm_bytes.len(),
            });
        }
        if self.state != ScannerState::AwaitingConfirm {
            return Err(PairError::WrongState);
        }
        let (signed_confirm, supplied_tag_bytes) = confirm_bytes.split_at(CONFIRM_ENCODED_BYTES);
        let _ = PairConfirm::decode_and_verify(
            signed_confirm,
            &self.invite.id_pubkey,
            &self.transcript,
        )?;
        let base_chain_key = self
            .pending_chain_key
            .as_ref()
            .ok_or(PairError::Internal("chain_key missing"))?;
        let final_chain_key = mix_factor2_recip(base_chain_key, factor2_key);
        let expected_tag = factor2_confirmation_tag(
            &final_chain_key,
            &self.transcript,
            Factor2ConfirmationRole::Inviter,
        );
        let mut supplied_tag = [0u8; FACTOR2_CONFIRMATION_TAG_LEN];
        supplied_tag.copy_from_slice(supplied_tag_bytes);
        if !factor2_confirmation_matches(&expected_tag, &supplied_tag) {
            return Err(PairError::Factor2KeyConfirmationFailed);
        }

        let ack = factor2_confirmation_tag(
            &final_chain_key,
            &self.transcript,
            Factor2ConfirmationRole::Scanner,
        );
        self.pending_chain_key = None;
        self.state = ScannerState::Done;
        self.ephemeral_secret = None;
        Ok((ack.to_vec(), final_chain_key))
    }

    fn receive_confirm_inner(&mut self, confirm_bytes: &[u8]) -> PairResult<ChainKey> {
        if self.state != ScannerState::AwaitingConfirm {
            return Err(PairError::WrongState);
        }
        let _ = PairConfirm::decode_and_verify(
            confirm_bytes,
            &self.invite.id_pubkey,
            &self.transcript,
        )?;
        let chain_key = self
            .pending_chain_key
            .take()
            .ok_or(PairError::Internal("chain_key missing"))?;
        self.state = ScannerState::Done;
        // Zeroize ephemeral material now that pairing is done.
        if let Some(esk) = self.ephemeral_secret.take() {
            drop(esk);
        }
        Ok(chain_key)
    }

    /// User said the SAS doesn't match. Abort + zeroize secrets.
    pub fn abort(&mut self) {
        self.state = ScannerState::Aborted;
        self.ephemeral_secret = None;
        self.pending_chain_key = None;
    }

    /// Read-only view of the scanned invite (for UI / audit).
    pub fn invite(&self) -> &Invite {
        &self.invite
    }

    /// Read-only view of the response the scanner sent (for audit).
    pub fn response(&self) -> &PairResponse {
        &self.response
    }
}

impl Drop for Scanner {
    fn drop(&mut self) {
        if let Some(esk) = self.ephemeral_secret.take() {
            drop(esk);
        }
    }
}

impl std::fmt::Debug for Scanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scanner")
            .field("state", &self.state)
            .field("inviter_pubkey_prefix", &&self.invite.id_pubkey[..4])
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invite::CapabilityScope;
    use rand::rngs::OsRng;

    #[test]
    fn scan_then_confirm_succeeds() {
        // Inviter side
        let mut inviter = crate::inviter::Inviter::new(
            SigningKey::generate(&mut OsRng),
            &mut OsRng,
            1_900_000_000,
            CapabilityScope::from_bytes(b"contact").unwrap(),
        );
        let invite_bytes = inviter.invite_bytes();

        // Scanner side
        let scanner_sk = SigningKey::generate(&mut OsRng);
        let (mut scanner, response_bytes) =
            Scanner::scan(scanner_sk, &invite_bytes, 100, &mut OsRng).unwrap();

        // SAS displayed on both sides → user confirms equal.
        let sas_inviter = inviter.receive_response(&response_bytes).unwrap();
        assert_eq!(sas_inviter, scanner.sas());

        // Inviter signs confirm
        let (confirm_bytes, k_inviter) = inviter.confirm().unwrap();

        // Scanner accepts confirm
        let k_scanner = scanner.receive_confirm(&confirm_bytes).unwrap();
        assert_eq!(k_inviter, k_scanner);
        assert_eq!(scanner.state(), ScannerState::Done);
    }

    #[test]
    fn scan_expired_invite_rejected() {
        let inviter = crate::inviter::Inviter::new(
            SigningKey::generate(&mut OsRng),
            &mut OsRng,
            100,
            CapabilityScope::empty(),
        );
        let invite_bytes = inviter.invite_bytes();
        let err = Scanner::scan(
            SigningKey::generate(&mut OsRng),
            &invite_bytes,
            200, // past expiry
            &mut OsRng,
        )
        .unwrap_err();
        assert!(matches!(err, PairError::Expired { .. }));
    }

    #[test]
    fn confirm_wrong_pubkey_rejected() {
        let mut inviter = crate::inviter::Inviter::new(
            SigningKey::generate(&mut OsRng),
            &mut OsRng,
            1_900_000_000,
            CapabilityScope::empty(),
        );
        let invite_bytes = inviter.invite_bytes();
        let (mut scanner, response_bytes) = Scanner::scan(
            SigningKey::generate(&mut OsRng),
            &invite_bytes,
            100,
            &mut OsRng,
        )
        .unwrap();
        let _ = inviter.receive_response(&response_bytes).unwrap();

        // Sign a confirm with a DIFFERENT key — same transcript bytes.
        let attacker_sk = SigningKey::generate(&mut OsRng);
        let bogus = PairConfirm::sign(&attacker_sk, scanner.transcript);
        let err = scanner.receive_confirm(&bogus.encode()).unwrap_err();
        assert_eq!(err, PairError::BadSignature);
    }

    #[test]
    fn abort_zeroizes_state() {
        let inviter = crate::inviter::Inviter::new(
            SigningKey::generate(&mut OsRng),
            &mut OsRng,
            1_900_000_000,
            CapabilityScope::empty(),
        );
        let invite_bytes = inviter.invite_bytes();
        let (mut scanner, _) = Scanner::scan(
            SigningKey::generate(&mut OsRng),
            &invite_bytes,
            100,
            &mut OsRng,
        )
        .unwrap();
        scanner.abort();
        assert_eq!(scanner.state(), ScannerState::Aborted);
        assert!(scanner.ephemeral_secret.is_none());
    }
}
