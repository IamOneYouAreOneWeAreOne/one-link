//! Pinned KAT vectors for the Row 8 Layer 2 quorum primitives.
//!
//! Pins:
//!   1. The canonical wire-format prefixes (domain tags).
//!   2. Bounded sizes (MAX_APPROVALS / MAX_ELIGIBLE_DEVICES / POLICY_LABEL_MAX).
//!   3. Policy canonical-transcript bytes for a fixed input.
//!   4. Proposal canonical-transcript bytes for a fixed input.
//!   5. Approval canonical-transcript bytes for a fixed input.
//!
//! Regen path:
//!
//! ```text
//! OL_QUORUM_KAT_REGEN=1 cargo test -p ol_device_mesh --release \
//!     --test known_answer_vectors_quorum -- --nocapture
//! ```

use ol_device_mesh::quorum::{
    QuorumApproval, QuorumPolicy, QuorumProposal, APPROVAL_DOMAIN, MAX_APPROVALS,
    MAX_ELIGIBLE_DEVICES, OPERATION_DIGEST_LEN, POLICY_DOMAIN, POLICY_ID_LEN, POLICY_LABEL_MAX,
    PROPOSAL_DOMAIN, PROPOSAL_NONCE_LEN,
};
use ol_device_mesh::DEVICE_ID_LEN;

fn check_regen<F: FnOnce()>(label: &str, dump: F) {
    if std::env::var("OL_QUORUM_KAT_REGEN").as_deref() == Ok("1") {
        eprintln!("[KAT REGEN] {label}");
        dump();
    }
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ── 1. Domain tags pinned ─────────────────────────────────────────

#[test]
fn kat_domain_tags_pinned() {
    assert_eq!(POLICY_DOMAIN, b"OL-device-mesh-policy-v1");
    assert_eq!(PROPOSAL_DOMAIN, b"OL-device-mesh-proposal-v1");
    assert_eq!(APPROVAL_DOMAIN, b"OL-device-mesh-approval-v1");
}

// ── 2. Bound constants pinned ─────────────────────────────────────

#[test]
fn kat_bound_constants_pinned() {
    assert_eq!(MAX_APPROVALS, 64);
    assert_eq!(MAX_ELIGIBLE_DEVICES, 64);
    assert_eq!(POLICY_LABEL_MAX, 64);
    assert_eq!(POLICY_ID_LEN, 16);
    assert_eq!(PROPOSAL_NONCE_LEN, 16);
    assert_eq!(OPERATION_DIGEST_LEN, 32);
    assert_eq!(DEVICE_ID_LEN, 16);
}

// ── 3. Policy canonical transcript ─────────────────────────────────

#[test]
fn kat_policy_canonical_transcript_pinned() {
    let policy_id = [0x42; POLICY_ID_LEN];
    let label = b"layer2-test-policy";
    let k = 2u8;
    let devices = vec![
        [0x11u8; DEVICE_ID_LEN],
        [0x22u8; DEVICE_ID_LEN],
        [0x33u8; DEVICE_ID_LEN],
    ];
    let bytes = QuorumPolicy::canonical_transcript(&policy_id, label, k, &devices);
    let hex = to_hex(&bytes);

    // The hex should start with the domain tag, then the policy id,
    // then the label length prefix.
    let domain_hex = to_hex(POLICY_DOMAIN);
    assert!(
        hex.starts_with(&domain_hex),
        "transcript must start with domain"
    );

    check_regen("policy canonical_transcript", || {
        eprintln!("    EXPECTED_POLICY_TRANSCRIPT_HEX = \"{hex}\"");
    });

    const EXPECTED_POLICY_TRANSCRIPT_HEX: &str = concat!(
        "4f4c2d6465766963652d6d6573682d706f6c6963792d7631", // "OL-device-mesh-policy-v1"
        "42424242424242424242424242424242",                 // policy_id
        "0012",                                             // label length = 18 (BE)
        "6c6179657232",                                     // "layer2"
        "2d746573742d706f6c696379",                         // "-test-policy"
        "02",                                               // k = 2
        "0003",                                             // n = 3 (BE)
        "11111111111111111111111111111111",                 // device id 1
        "22222222222222222222222222222222",                 // device id 2
        "33333333333333333333333333333333",                 // device id 3
    );
    assert_eq!(
        hex, EXPECTED_POLICY_TRANSCRIPT_HEX,
        "policy transcript drift"
    );
}

// ── 4. Proposal canonical transcript ───────────────────────────────

#[test]
fn kat_proposal_canonical_transcript_pinned() {
    let policy_id = [0x42; POLICY_ID_LEN];
    let op_digest = [0xEE; OPERATION_DIGEST_LEN];
    let nonce = [0xDA; PROPOSAL_NONCE_LEN];
    let issued_unix: u64 = 1_700_000_000;
    let deadline_unix: u64 = 1_700_003_600;
    let issuer = [0x11; DEVICE_ID_LEN];
    let day: u64 = 7;
    let bytes = QuorumProposal::canonical_transcript(
        &policy_id,
        &op_digest,
        &nonce,
        issued_unix,
        deadline_unix,
        &issuer,
        day,
    );
    let hex = to_hex(&bytes);
    let domain_hex = to_hex(PROPOSAL_DOMAIN);
    assert!(hex.starts_with(&domain_hex));

    check_regen("proposal canonical_transcript", || {
        eprintln!("    EXPECTED_PROPOSAL_TRANSCRIPT_HEX = \"{hex}\"");
    });

    const EXPECTED_PROPOSAL_TRANSCRIPT_HEX: &str = concat!(
        "4f4c2d6465766963652d6d6573682d70726f706f73616c2d7631", // "OL-device-mesh-proposal-v1"
        "42424242424242424242424242424242",                     // policy_id
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", // op_digest
        "dadadadadadadadadadadadadadadada",                     // nonce
        "000000006553f100",                                     // issued_unix BE
        "000000006553ff10",                                     // deadline_unix BE
        "11111111111111111111111111111111",                     // issuer id
        "0000000000000007",                                     // day BE
    );
    assert_eq!(
        hex, EXPECTED_PROPOSAL_TRANSCRIPT_HEX,
        "proposal transcript drift"
    );
}

// ── 5. Approval canonical transcript ───────────────────────────────

#[test]
fn kat_approval_canonical_transcript_pinned() {
    let pid = [0xBE; 32];
    let approver = [0x22; DEVICE_ID_LEN];
    let day: u64 = 3;
    let approved_unix: u64 = 1_700_001_000;
    let bytes = QuorumApproval::canonical_transcript(&pid, &approver, day, approved_unix);
    let hex = to_hex(&bytes);
    let domain_hex = to_hex(APPROVAL_DOMAIN);
    assert!(hex.starts_with(&domain_hex));

    check_regen("approval canonical_transcript", || {
        eprintln!("    EXPECTED_APPROVAL_TRANSCRIPT_HEX = \"{hex}\"");
    });

    const EXPECTED_APPROVAL_TRANSCRIPT_HEX: &str = concat!(
        "4f4c2d6465766963652d6d6573682d617070726f76616c2d7631", // "OL-device-mesh-approval-v1"
        "bebebebebebebebebebebebebebebebebebebebebebebebebebebebebebebebe", // proposal id
        "22222222222222222222222222222222",                     // approver id
        "0000000000000003",                                     // day BE
        "000000006553f4e8",                                     // approved_unix BE
    );
    assert_eq!(
        hex, EXPECTED_APPROVAL_TRANSCRIPT_HEX,
        "approval transcript drift"
    );
}
