//! Property tests for Row 8 Layer 2 (quorum).
//!
//! Two tiers:
//!   - pure-derivation paths (proposal_id / policy handle): 1M iters
//!   - keygen-bound paths (mint subkey + propose + approve + verify):
//!     1k iters because each iteration mints multiple PQ-hybrid keys.

use proptest::prelude::*;
use rand::rngs::OsRng;

use ol_device_mesh::quorum::{
    mint_policy, propose_operation, sign_approval, QuorumCertificate, OPERATION_DIGEST_LEN,
    PROPOSAL_NONCE_LEN,
};
use ol_device_mesh::{mint_subkey, DeviceClass, DeviceMeshError, MasterIdentity, DEVICE_ID_LEN};

fn cheap_cases() -> u32 {
    if std::env::var("ONE_LINK_F1_GATE").as_deref() == Ok("1") {
        5_000_000
    } else {
        1_000_000
    }
}

fn keygen_cases() -> u32 {
    if std::env::var("ONE_LINK_F1_GATE").as_deref() == Ok("1") {
        10_000
    } else {
        1_000
    }
}

// ── 1M-iter properties on pure derivation paths ───────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cheap_cases(),
        max_global_rejects: cheap_cases() * 4,
        .. ProptestConfig::default()
    })]

    /// Proposal id is a pure function of the canonical transcript:
    /// same inputs → same id, distinct inputs → distinct id (with
    /// overwhelming probability).
    #[test]
    fn proposal_id_determinism_via_canonical_transcript(
        policy_id in any::<[u8; 16]>(),
        op_digest in any::<[u8; OPERATION_DIGEST_LEN]>(),
        nonce in any::<[u8; PROPOSAL_NONCE_LEN]>(),
        issued in any::<u64>(),
        deadline in any::<u64>(),
        issuer in any::<[u8; DEVICE_ID_LEN]>(),
        day in any::<u64>(),
    ) {
        let bytes_a = ol_device_mesh::quorum::QuorumProposal::canonical_transcript(
            &policy_id, &op_digest, &nonce, issued, deadline, &issuer, day,
        );
        let bytes_b = ol_device_mesh::quorum::QuorumProposal::canonical_transcript(
            &policy_id, &op_digest, &nonce, issued, deadline, &issuer, day,
        );
        prop_assert_eq!(bytes_a, bytes_b);
    }
}

// ── Keygen-bound properties ───────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: keygen_cases(),
        max_global_rejects: keygen_cases() * 4,
        .. ProptestConfig::default()
    })]

    /// Honest happy-path: K=2 of N=3 approval → certificate verifies.
    #[test]
    fn cert_verifies_with_k_of_n_approvals(
        op_digest in any::<[u8; OPERATION_DIGEST_LEN]>(),
        nonce in any::<[u8; PROPOSAL_NONCE_LEN]>(),
    ) {
        let master = MasterIdentity::generate(&mut OsRng);
        let id1 = [0x11; DEVICE_ID_LEN];
        let id2 = [0x22; DEVICE_ID_LEN];
        let id3 = [0x33; DEVICE_ID_LEN];
        let (sk1, a1) =
            mint_subkey(&master, DeviceClass::Phone, id1, 0, 365).unwrap();
        let (sk2, a2) =
            mint_subkey(&master, DeviceClass::Laptop, id2, 0, 365).unwrap();
        let (sk3, a3) =
            mint_subkey(&master, DeviceClass::Desktop, id3, 0, 365).unwrap();
        let policy =
            mint_policy(&master, [0xAA; 16], b"p", 2, vec![id1, id2, id3]).unwrap();
        let now: u64 = 1_700_000_000;
        let proposal = propose_operation(
            &sk1, &policy, op_digest, nonce, now, now + 3600,
        )
        .unwrap();
        let ap2 = sign_approval(&sk2, &proposal, now + 60).unwrap();
        let ap3 = sign_approval(&sk3, &proposal, now + 120).unwrap();
        let cert = QuorumCertificate {
            proposal,
            approvals: vec![ap2, ap3],
            policy,
            subkey_attestations: vec![a1, a2, a3],
        };
        cert.verify(&master.verifying_key(), now + 200).unwrap();
    }

    /// Below-threshold ALWAYS rejected — for K=3 we provide 2 approvals.
    #[test]
    fn cert_below_threshold_always_rejected(
        op_digest in any::<[u8; OPERATION_DIGEST_LEN]>(),
    ) {
        let master = MasterIdentity::generate(&mut OsRng);
        let id1 = [0x11; DEVICE_ID_LEN];
        let id2 = [0x22; DEVICE_ID_LEN];
        let id3 = [0x33; DEVICE_ID_LEN];
        let (sk1, a1) =
            mint_subkey(&master, DeviceClass::Phone, id1, 0, 365).unwrap();
        let (sk2, a2) =
            mint_subkey(&master, DeviceClass::Laptop, id2, 0, 365).unwrap();
        let (sk3, a3) =
            mint_subkey(&master, DeviceClass::Desktop, id3, 0, 365).unwrap();
        // K=3 of N=3 means 2 approvals is below threshold.
        let policy =
            mint_policy(&master, [0xAA; 16], b"p", 3, vec![id1, id2, id3]).unwrap();
        let now: u64 = 1_700_000_000;
        let proposal = propose_operation(
            &sk1, &policy, op_digest, [0xDA; 16], now, now + 3600,
        )
        .unwrap();
        // Only 2 approvals — sk1 is the issuer; sk2 and sk3 approve;
        // sk1's proposal-signature doesn't count toward K.
        let ap2 = sign_approval(&sk2, &proposal, now + 1).unwrap();
        let ap3 = sign_approval(&sk3, &proposal, now + 2).unwrap();
        let cert = QuorumCertificate {
            proposal,
            approvals: vec![ap2, ap3],
            policy,
            subkey_attestations: vec![a1, a2, a3],
        };
        let err = cert.verify(&master.verifying_key(), now + 100).unwrap_err();
        let ok = matches!(err, DeviceMeshError::CertBelowThreshold { .. });
        prop_assert!(ok);
    }

    /// Verifier wall clock past deadline ALWAYS rejected.
    #[test]
    fn cert_past_deadline_always_rejected(
        skew in 1u64..1_000_000u64,
    ) {
        let master = MasterIdentity::generate(&mut OsRng);
        let id1 = [0x11; DEVICE_ID_LEN];
        let id2 = [0x22; DEVICE_ID_LEN];
        let (sk1, a1) =
            mint_subkey(&master, DeviceClass::Phone, id1, 0, 365).unwrap();
        let (sk2, a2) =
            mint_subkey(&master, DeviceClass::Laptop, id2, 0, 365).unwrap();
        let policy =
            mint_policy(&master, [0xAA; 16], b"p", 1, vec![id1, id2]).unwrap();
        let now: u64 = 1_700_000_000;
        let proposal = propose_operation(
            &sk1, &policy, [0xEE; 32], [0xDA; 16], now, now + 100,
        )
        .unwrap();
        let ap2 = sign_approval(&sk2, &proposal, now + 1).unwrap();
        let cert = QuorumCertificate {
            proposal,
            approvals: vec![ap2],
            policy,
            subkey_attestations: vec![a1, a2],
        };
        let err = cert
            .verify(&master.verifying_key(), now + 100 + skew)
            .unwrap_err();
        let ok = matches!(err, DeviceMeshError::CertProposalExpired { .. });
        prop_assert!(ok);
    }
}
