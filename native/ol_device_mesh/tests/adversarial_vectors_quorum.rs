//! Adversarial vectors for Row 8 Layer 2 (quorum).

use ol_device_mesh::quorum::{mint_policy, propose_operation, sign_approval, QuorumCertificate};
use ol_device_mesh::{mint_subkey, DeviceClass, DeviceMeshError, MasterIdentity};
use rand::rngs::OsRng;

fn make_master() -> MasterIdentity {
    MasterIdentity::generate(&mut OsRng)
}

// ── Forge attempts ─────────────────────────────────────────────────

#[test]
fn adversarial_forged_master_policy_rejected() {
    let real_master = make_master();
    let attacker = make_master();
    let id1 = [0x11; 16];
    let id2 = [0x22; 16];
    // Attacker mints a policy under THEIR master, presents it to a
    // verifier that pinned the REAL master.
    let bad_policy = mint_policy(&attacker, [0xAA; 16], b"p", 1, vec![id1, id2]).unwrap();
    let err = bad_policy.verify(&real_master.verifying_key()).unwrap_err();
    assert!(matches!(err, DeviceMeshError::PolicyVerifyFail));
}

#[test]
fn adversarial_replay_old_proposal_with_new_deadline_rejected() {
    let master = make_master();
    let id1 = [0x11; 16];
    let id2 = [0x22; 16];
    let id3 = [0x33; 16];
    let (sk1, a1) = mint_subkey(&master, DeviceClass::Phone, id1, 0, 365).unwrap();
    let (sk2, a2) = mint_subkey(&master, DeviceClass::Laptop, id2, 0, 365).unwrap();
    let (_sk3, a3) = mint_subkey(&master, DeviceClass::Desktop, id3, 0, 365).unwrap();
    let policy = mint_policy(&master, [0xAA; 16], b"p", 1, vec![id1, id2, id3]).unwrap();
    let now: u64 = 1_700_000_000;
    let mut proposal =
        propose_operation(&sk1, &policy, [0xEE; 32], [0xDA; 16], now, now + 100).unwrap();
    // Tamper: extend the deadline beyond what was signed.
    proposal.deadline_unix = now + 36000;
    let ap2 = sign_approval(&sk2, &proposal, now + 1).unwrap();
    let cert = QuorumCertificate {
        proposal,
        approvals: vec![ap2],
        policy,
        subkey_attestations: vec![a1, a2, a3],
    };
    let err = cert.verify(&master.verifying_key(), now + 200).unwrap_err();
    assert!(matches!(err, DeviceMeshError::ProposalIssuerVerifyFail));
}

#[test]
fn adversarial_replay_approval_for_different_op_rejected() {
    let master = make_master();
    let id1 = [0x11; 16];
    let id2 = [0x22; 16];
    let id3 = [0x33; 16];
    let (sk1, a1) = mint_subkey(&master, DeviceClass::Phone, id1, 0, 365).unwrap();
    let (sk2, a2) = mint_subkey(&master, DeviceClass::Laptop, id2, 0, 365).unwrap();
    let (sk3, a3) = mint_subkey(&master, DeviceClass::Desktop, id3, 0, 365).unwrap();
    let policy = mint_policy(&master, [0xAA; 16], b"p", 2, vec![id1, id2, id3]).unwrap();
    let now: u64 = 1_700_000_000;
    let benign = propose_operation(&sk1, &policy, [0xCC; 32], [0xDB; 16], now, now + 100).unwrap();
    let bad = propose_operation(&sk1, &policy, [0xEE; 32], [0xDA; 16], now, now + 100).unwrap();
    // Attacker collects sk2 + sk3's approvals on BENIGN, then tries
    // to staple them into a certificate that authorises BAD.
    let ap2 = sign_approval(&sk2, &benign, now + 1).unwrap();
    let ap3 = sign_approval(&sk3, &benign, now + 2).unwrap();
    let cert = QuorumCertificate {
        proposal: bad,
        approvals: vec![ap2, ap3],
        policy,
        subkey_attestations: vec![a1, a2, a3],
    };
    let err = cert.verify(&master.verifying_key(), now + 50).unwrap_err();
    assert!(matches!(err, DeviceMeshError::ApprovalForOtherProposal));
}

#[test]
fn adversarial_outside_eligible_roster_rejected() {
    let master = make_master();
    let id1 = [0x11; 16];
    let id2 = [0x22; 16];
    let outsider = [0x99; 16];
    let (sk1, a1) = mint_subkey(&master, DeviceClass::Phone, id1, 0, 365).unwrap();
    let (sk2, a2) = mint_subkey(&master, DeviceClass::Laptop, id2, 0, 365).unwrap();
    let (sk_outsider, a_outsider) =
        mint_subkey(&master, DeviceClass::Desktop, outsider, 0, 365).unwrap();
    // Roster excludes the outsider.
    let policy = mint_policy(&master, [0xAA; 16], b"p", 2, vec![id1, id2]).unwrap();
    let now: u64 = 1_700_000_000;
    let proposal =
        propose_operation(&sk1, &policy, [0xEE; 32], [0xDA; 16], now, now + 3600).unwrap();
    // Outsider approves.
    let ap_outsider = sign_approval(&sk_outsider, &proposal, now + 1).unwrap();
    let ap2 = sign_approval(&sk2, &proposal, now + 2).unwrap();
    let cert = QuorumCertificate {
        proposal,
        approvals: vec![ap_outsider, ap2],
        policy,
        subkey_attestations: vec![a1, a2, a_outsider],
    };
    let err = cert.verify(&master.verifying_key(), now + 100).unwrap_err();
    assert!(matches!(err, DeviceMeshError::ApproverNotEligible { .. }));
}

#[test]
fn adversarial_two_approvals_from_same_device_count_once() {
    let master = make_master();
    let id1 = [0x11; 16];
    let id2 = [0x22; 16];
    let id3 = [0x33; 16];
    let (sk1, a1) = mint_subkey(&master, DeviceClass::Phone, id1, 0, 365).unwrap();
    let (sk2, a2) = mint_subkey(&master, DeviceClass::Laptop, id2, 0, 365).unwrap();
    let (_sk3, a3) = mint_subkey(&master, DeviceClass::Desktop, id3, 0, 365).unwrap();
    let policy = mint_policy(&master, [0xAA; 16], b"p", 2, vec![id1, id2, id3]).unwrap();
    let now: u64 = 1_700_000_000;
    let proposal =
        propose_operation(&sk1, &policy, [0xEE; 32], [0xDA; 16], now, now + 3600).unwrap();
    let ap_a = sign_approval(&sk2, &proposal, now + 1).unwrap();
    let ap_b = sign_approval(&sk2, &proposal, now + 2).unwrap();
    let cert = QuorumCertificate {
        proposal,
        approvals: vec![ap_a, ap_b],
        policy,
        subkey_attestations: vec![a1, a2, a3],
    };
    let err = cert.verify(&master.verifying_key(), now + 100).unwrap_err();
    assert!(matches!(err, DeviceMeshError::DuplicateApprover { .. }));
}

#[test]
fn adversarial_attestation_substitution_rejected() {
    // Two masters mint subkeys for the same device_id; attacker
    // substitutes their master's attestation into a certificate
    // signed under the real master's policy.
    let real_master = make_master();
    let fake_master = make_master();
    let id1 = [0x11; 16];
    let id2 = [0x22; 16];
    let id3 = [0x33; 16];
    let (sk1, _a1_real) = mint_subkey(&real_master, DeviceClass::Phone, id1, 0, 365).unwrap();
    let (_sk1_fake, a1_fake) = mint_subkey(&fake_master, DeviceClass::Phone, id1, 0, 365).unwrap();
    let (sk2, a2) = mint_subkey(&real_master, DeviceClass::Laptop, id2, 0, 365).unwrap();
    let (sk3, a3) = mint_subkey(&real_master, DeviceClass::Desktop, id3, 0, 365).unwrap();
    let policy = mint_policy(&real_master, [0xAA; 16], b"p", 2, vec![id1, id2, id3]).unwrap();
    let now: u64 = 1_700_000_000;
    let proposal =
        propose_operation(&sk1, &policy, [0xEE; 32], [0xDA; 16], now, now + 3600).unwrap();
    let ap2 = sign_approval(&sk2, &proposal, now + 1).unwrap();
    let ap3 = sign_approval(&sk3, &proposal, now + 2).unwrap();
    let cert = QuorumCertificate {
        proposal,
        approvals: vec![ap2, ap3],
        policy,
        // Use the FAKE master's attestation for device id1.
        subkey_attestations: vec![a1_fake, a2, a3],
    };
    let err = cert
        .verify(&real_master.verifying_key(), now + 100)
        .unwrap_err();
    // Fake attestation fails master verification first.
    assert!(matches!(err, DeviceMeshError::AttestationVerifyFail));
}

#[test]
fn adversarial_oversized_certificate_rejected() {
    let master = make_master();
    let id1 = [0x11; 16];
    let id2 = [0x22; 16];
    let (sk1, a1) = mint_subkey(&master, DeviceClass::Phone, id1, 0, 365).unwrap();
    let (sk2, a2) = mint_subkey(&master, DeviceClass::Laptop, id2, 0, 365).unwrap();
    let policy = mint_policy(&master, [0xAA; 16], b"p", 1, vec![id1, id2]).unwrap();
    let now: u64 = 1_700_000_000;
    let proposal =
        propose_operation(&sk1, &policy, [0xEE; 32], [0xDA; 16], now, now + 3600).unwrap();
    let real = sign_approval(&sk2, &proposal, now + 1).unwrap();
    // Stuff with 100 fake approvals to exceed MAX_APPROVALS=64.
    let mut approvals = vec![real];
    for _ in 0..100 {
        approvals.push(approvals[0].clone());
    }
    let cert = QuorumCertificate {
        proposal,
        approvals,
        policy,
        subkey_attestations: vec![a1, a2],
    };
    let err = cert.verify(&master.verifying_key(), now + 100).unwrap_err();
    assert!(matches!(err, DeviceMeshError::CertTooManyApprovals { .. }));
}

#[test]
fn adversarial_cross_policy_certificate_rejected() {
    // Build TWO policies under the same master; attacker stuffs the
    // wrong policy into the certificate.
    let master = make_master();
    let id1 = [0x11; 16];
    let id2 = [0x22; 16];
    let id3 = [0x33; 16];
    let (sk1, a1) = mint_subkey(&master, DeviceClass::Phone, id1, 0, 365).unwrap();
    let (sk2, a2) = mint_subkey(&master, DeviceClass::Laptop, id2, 0, 365).unwrap();
    let (_sk3, a3) = mint_subkey(&master, DeviceClass::Desktop, id3, 0, 365).unwrap();
    let policy_a = mint_policy(&master, [0xAA; 16], b"a", 1, vec![id1, id2, id3]).unwrap();
    let policy_b = mint_policy(&master, [0xBB; 16], b"b", 1, vec![id1, id2, id3]).unwrap();
    let now: u64 = 1_700_000_000;
    // Proposal is under policy_a; certificate carries policy_b.
    let proposal =
        propose_operation(&sk1, &policy_a, [0xEE; 32], [0xDA; 16], now, now + 3600).unwrap();
    let ap2 = sign_approval(&sk2, &proposal, now + 1).unwrap();
    let cert = QuorumCertificate {
        proposal,
        approvals: vec![ap2],
        policy: policy_b,
        subkey_attestations: vec![a1, a2, a3],
    };
    let err = cert.verify(&master.verifying_key(), now + 100).unwrap_err();
    assert!(matches!(err, DeviceMeshError::CertProposalPolicyMismatch));
}

#[test]
fn adversarial_revoked_device_rotated_attestation_still_required() {
    // Sibling key gets rotated. An OLD attestation for a previous
    // day shouldn't cover an approval the device signed at a NEW
    // day index.
    let master = make_master();
    let id1 = [0x11; 16];
    let id2 = [0x22; 16];
    let (sk1, a1) = mint_subkey(&master, DeviceClass::Phone, id1, 0, 365).unwrap();
    let (mut sk2, a2_initial) = mint_subkey(&master, DeviceClass::Laptop, id2, 0, 0).unwrap();
    // Day-0 attestation only covers day 0. sk2 advances to day 1.
    sk2.step_one_day();
    assert_eq!(sk2.day_index(), 1);
    let policy = mint_policy(&master, [0xAA; 16], b"p", 1, vec![id1, id2]).unwrap();
    let now: u64 = 1_700_000_000;
    let proposal =
        propose_operation(&sk1, &policy, [0xEE; 32], [0xDA; 16], now, now + 3600).unwrap();
    let approval = sign_approval(&sk2, &proposal, now + 1).unwrap();
    let cert = QuorumCertificate {
        proposal,
        approvals: vec![approval],
        policy,
        subkey_attestations: vec![a1, a2_initial], // only covers day 0
    };
    let err = cert.verify(&master.verifying_key(), now + 100).unwrap_err();
    assert!(matches!(err, DeviceMeshError::AttestationMissing { .. }));
}
