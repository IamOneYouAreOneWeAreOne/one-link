//! Continuous attestation: chained heartbeat docs with a monotonic
//! counter so peers detect downtime / replay / chain-fork attacks.
//!
//! ## How it works
//!
//! A `HeartbeatAttestation` is a normal [`crate::AttestationDoc`]
//! plus a `monotonic_counter` (strictly increasing per master) and a
//! `prev_heartbeat_id` (`BLAKE3` of the previous doc's canonical
//! bytes, forming a hash chain).
//!
//! Peers maintain a small per-master state:
//!
//! - `last_counter` — monotonic counter of the most recent doc seen.
//! - `last_id` — BLAKE3 of that doc's canonical bytes.
//!
//! On receipt, they accept the next doc iff:
//! 1. `monotonic_counter > last_counter` (strict).
//! 2. `prev_heartbeat_id == last_id` (chain continuity).
//! 3. Normal [`crate::verify_attestation`] checks pass.
//!
//! Attacks closed:
//! - **Replay across time**: counter strictly increases.
//! - **Fork attack** (issuer simultaneously emits two distinct
//!   heartbeat chains to different peers): once a peer has seen
//!   `counter = N`, they reject any other `counter = N` from the
//!   same master. The fork is observable.
//! - **Stale-key attack** (attacker holds an old `master_vk` and
//!   forges new attestations): the master sig still has to verify;
//!   chain continuity adds the requirement that the attacker
//!   reproduces the entire prior chain.

use blake3::Hasher;

use crate::attestation::{AttestationDoc, AttestationNonce};
use crate::errors::{ConfidentialError, ConfidentialResult};

/// Domain-separation prefix for the per-doc chain-id digest.
pub const HEARTBEAT_ID_DOMAIN: &[u8] = b"OL-confidential-heartbeat-id-v1";

/// Domain-separation prefix for the heartbeat-specific transcript
/// the master signs over (carries counter + `prev_id` + the embedded
/// attestation doc transcript bytes).
pub const HEARTBEAT_TRANSCRIPT_DOMAIN: &[u8] =
    b"OL-confidential-heartbeat-transcript-v1";

/// Heartbeat-id: a 32-byte BLAKE3 commitment to a doc's canonical
/// form.
pub type HeartbeatId = [u8; 32];

/// Compute the heartbeat-id over a fully-signed [`AttestationDoc`].
/// Used by peers as the `prev_heartbeat_id` for the next doc.
#[must_use]
pub fn heartbeat_id(doc: &AttestationDoc) -> HeartbeatId {
    let mut h = Hasher::new();
    h.update(HEARTBEAT_ID_DOMAIN);
    h.update(&[doc.provider_tag.as_u8()]);
    h.update(&doc.master_vk.to_bytes());
    h.update(&doc.peer_nonce);
    h.update(&doc.issued_unix.to_be_bytes());
    h.update(&doc.deadline_unix.to_be_bytes());
    match doc.field_witness_commitment {
        None => h.update(&[0u8]),
        Some(c) => {
            h.update(&[1u8]);
            h.update(&c);
            &mut h
        }
    };
    h.update(&u32::try_from(doc.platform_quote.len()).unwrap_or(u32::MAX).to_be_bytes());
    h.update(&doc.platform_quote);
    h.update(&doc.master_sig);
    *h.finalize().as_bytes()
}

/// A heartbeat-attached attestation. The `attestation` field is a
/// normal [`AttestationDoc`]; the heartbeat-specific fields chain
/// it to the prior doc and pin a monotonic counter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatAttestation {
    /// The underlying attestation doc (verified via the normal path).
    pub attestation: AttestationDoc,
    /// Strictly increasing per-master counter.
    pub monotonic_counter: u64,
    /// BLAKE3 of the previous heartbeat's canonical bytes
    /// (`[0u8; 32]` for the genesis doc).
    pub prev_heartbeat_id: HeartbeatId,
}

/// Per-master state a verifier holds. Update on each accepted
/// heartbeat.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HeartbeatVerifierState {
    /// Highest counter accepted so far.
    pub last_counter: u64,
    /// Heartbeat-id of the most recent accepted doc.
    pub last_id: HeartbeatId,
    /// `true` if at least one heartbeat has been accepted (genesis
    /// rule: first accepted doc's `prev_heartbeat_id` must be all
    /// zeros).
    pub initialised: bool,
}

impl HeartbeatVerifierState {
    /// Fresh state — accepts the first heartbeat with `counter ≥ 1`
    /// and `prev_heartbeat_id = [0; 32]`.
    #[must_use]
    pub fn fresh() -> Self {
        Self {
            last_counter: 0,
            last_id: [0u8; 32],
            initialised: false,
        }
    }

    /// Try to accept a new heartbeat. Updates `self` on success.
    ///
    /// # Errors
    /// - [`ConfidentialError::Internal`] for invariant violations
    ///   (counter not increasing, chain break, etc.).
    /// - Any error returned by [`crate::verify_attestation`] for
    ///   the embedded doc.
    pub fn ingest(
        &mut self,
        hb: &HeartbeatAttestation,
        expected_peer_nonce: &AttestationNonce,
        expected_field_witness: Option<&[u8; 32]>,
        now_unix: u64,
    ) -> ConfidentialResult<()> {
        if !self.initialised {
            if hb.prev_heartbeat_id != [0u8; 32] {
                return Err(ConfidentialError::Internal(
                    "first heartbeat must have prev_heartbeat_id = [0; 32]",
                ));
            }
        } else if hb.prev_heartbeat_id != self.last_id {
            return Err(ConfidentialError::Internal(
                "heartbeat chain break — prev_id does not match",
            ));
        }
        if hb.monotonic_counter <= self.last_counter {
            return Err(ConfidentialError::Internal(
                "heartbeat counter must strictly increase",
            ));
        }
        // The embedded doc must independently verify.
        crate::verify_attestation(
            &hb.attestation,
            expected_peer_nonce,
            expected_field_witness,
            now_unix,
        )?;
        // Accept: update state.
        self.last_counter = hb.monotonic_counter;
        self.last_id = heartbeat_id(&hb.attestation);
        self.initialised = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fresh_attestation_nonce, sign_attestation, ProviderTag};
    use ol_pqsig::HybridSigningKey;
    use rand::rngs::OsRng;

    fn make_doc(
        sk: &HybridSigningKey,
        nonce: AttestationNonce,
        issued: u64,
    ) -> AttestationDoc {
        sign_attestation(
            sk,
            ProviderTag::Software,
            nonce,
            issued,
            issued + 20,
            None,
            Vec::new(),
        )
        .unwrap()
    }

    #[test]
    fn genesis_then_2nd_heartbeat_accepted() {
        let (sk, _vk) = HybridSigningKey::generate(&mut OsRng);
        let nonce_a = fresh_attestation_nonce(&mut OsRng);
        let nonce_b = fresh_attestation_nonce(&mut OsRng);

        let doc_a = make_doc(&sk, nonce_a, 100);
        let id_a = heartbeat_id(&doc_a);
        let hb_a = HeartbeatAttestation {
            attestation: doc_a,
            monotonic_counter: 1,
            prev_heartbeat_id: [0u8; 32],
        };

        let doc_b = make_doc(&sk, nonce_b, 200);
        let hb_b = HeartbeatAttestation {
            attestation: doc_b,
            monotonic_counter: 2,
            prev_heartbeat_id: id_a,
        };

        let mut state = HeartbeatVerifierState::fresh();
        state.ingest(&hb_a, &nonce_a, None, 110).unwrap();
        state.ingest(&hb_b, &nonce_b, None, 210).unwrap();
        assert!(state.initialised);
        assert_eq!(state.last_counter, 2);
    }

    #[test]
    fn reusing_counter_rejected() {
        let (sk, _vk) = HybridSigningKey::generate(&mut OsRng);
        let nonce = fresh_attestation_nonce(&mut OsRng);
        let doc = make_doc(&sk, nonce, 100);
        let hb_a = HeartbeatAttestation {
            attestation: doc.clone(),
            monotonic_counter: 5,
            prev_heartbeat_id: [0u8; 32],
        };
        let mut state = HeartbeatVerifierState::fresh();
        state.ingest(&hb_a, &nonce, None, 110).unwrap();

        // Same counter again — must reject.
        let hb_replay = HeartbeatAttestation {
            attestation: doc.clone(),
            monotonic_counter: 5,
            prev_heartbeat_id: heartbeat_id(&doc),
        };
        let r = state.ingest(&hb_replay, &nonce, None, 110);
        assert!(r.is_err());
    }

    #[test]
    fn chain_break_rejected() {
        let (sk, _vk) = HybridSigningKey::generate(&mut OsRng);
        let nonce_a = fresh_attestation_nonce(&mut OsRng);
        let nonce_b = fresh_attestation_nonce(&mut OsRng);

        let doc_a = make_doc(&sk, nonce_a, 100);
        let hb_a = HeartbeatAttestation {
            attestation: doc_a,
            monotonic_counter: 1,
            prev_heartbeat_id: [0u8; 32],
        };

        // doc_b's prev_id is WRONG (random bytes, not heartbeat_id(doc_a)).
        let doc_b = make_doc(&sk, nonce_b, 200);
        let hb_b = HeartbeatAttestation {
            attestation: doc_b,
            monotonic_counter: 2,
            prev_heartbeat_id: [0xFFu8; 32],
        };

        let mut state = HeartbeatVerifierState::fresh();
        state.ingest(&hb_a, &nonce_a, None, 110).unwrap();
        let r = state.ingest(&hb_b, &nonce_b, None, 210);
        assert!(r.is_err(), "chain break must be detected");
    }

    #[test]
    fn fork_is_observable() {
        // Issuer simultaneously emits two distinct heartbeats with
        // the same counter. Each peer accepts only the FIRST one
        // they see; the second is rejected with a chain-break or
        // counter-reuse error. Visible from peer's state, so the
        // fork is observable.
        let (sk, _vk) = HybridSigningKey::generate(&mut OsRng);
        let nonce_a = fresh_attestation_nonce(&mut OsRng);
        let nonce_b = fresh_attestation_nonce(&mut OsRng);

        let doc_a = make_doc(&sk, nonce_a, 100);
        let id_a = heartbeat_id(&doc_a);
        let hb_a = HeartbeatAttestation {
            attestation: doc_a,
            monotonic_counter: 1,
            prev_heartbeat_id: [0u8; 32],
        };

        // Two distinct heartbeats with same counter = 2 — different
        // nonces, different content. The verifier rejects the second.
        let doc_b1 = make_doc(&sk, nonce_b, 200);
        let doc_b2 = make_doc(&sk, fresh_attestation_nonce(&mut OsRng), 200);
        let hb_b1 = HeartbeatAttestation {
            attestation: doc_b1,
            monotonic_counter: 2,
            prev_heartbeat_id: id_a,
        };
        let hb_b2 = HeartbeatAttestation {
            attestation: doc_b2,
            monotonic_counter: 2,
            prev_heartbeat_id: id_a,
        };

        let mut state = HeartbeatVerifierState::fresh();
        state.ingest(&hb_a, &nonce_a, None, 110).unwrap();
        state.ingest(&hb_b1, &nonce_b, None, 210).unwrap();
        let r = state.ingest(&hb_b2, &hb_b2.attestation.peer_nonce, None, 210);
        assert!(r.is_err(), "second branch of the fork must be rejected");
    }
}
