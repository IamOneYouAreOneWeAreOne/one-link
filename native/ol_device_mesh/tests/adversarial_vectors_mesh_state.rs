//! Adversarial vectors for Row 8 Layer 3 mesh-state.

use ol_device_mesh::mesh_state::{
    AuthenticatedOp, Delta, MeshState, SubtreePolicyKind, SyncState, MAX_DELTA_VALUE_LEN, MAX_SUBTREE_LABEL_LEN,
};
use ol_device_mesh::{
    mint_subkey, DeviceClass, DeviceMeshError, MasterIdentity, DEVICE_ID_LEN,
};
use ol_pqsig::HybridVerifyingKey;
use rand::rngs::OsRng;

fn setup() -> (MasterIdentity, ol_device_mesh::DeviceSubkey, HybridVerifyingKey) {
    let master = MasterIdentity::generate(&mut OsRng);
    let id = [0x42; DEVICE_ID_LEN];
    let (sk, att) =
        mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
    let vk = HybridVerifyingKey::from_bytes(&att.subkey_vk_bytes).unwrap();
    (master, sk, vk)
}

// ── Forgery + tampering ─────────────────────────────────────────────

#[test]
fn adversarial_cross_subtree_replay_rejected() {
    // Attacker captures an op signed for subtree "a" and tries to
    // re-deliver it as if it targeted "b". Re-signing isn't possible
    // (no subkey); the tampered op fails verify.
    let (_m, sk, vk) = setup();
    let mut op = AuthenticatedOp::sign(
        &sk,
        b"a".to_vec(),
        Delta::LwwSet { value: b"v".to_vec(), ts: 1 },
        1,
        1,
    )
    .unwrap();
    op.subtree = b"b".to_vec();
    let err = op.verify(&vk).unwrap_err();
    assert!(matches!(err, DeviceMeshError::AuthOpVerifyFail));
}

#[test]
fn adversarial_seq_regression_rejected_at_record() {
    let (_m, sk, _vk) = setup();
    let mut sync = SyncState::empty();
    let op_a = AuthenticatedOp::sign(
        &sk,
        b"x".to_vec(),
        Delta::LwwSet { value: b"a".to_vec(), ts: 1 },
        5,
        1,
    )
    .unwrap();
    sync.record_local_emit(op_a).unwrap();
    let op_b = AuthenticatedOp::sign(
        &sk,
        b"x".to_vec(),
        Delta::LwwSet { value: b"b".to_vec(), ts: 2 },
        3, // regression
        2,
    )
    .unwrap();
    let err = sync.record_local_emit(op_b).unwrap_err();
    assert!(matches!(err, DeviceMeshError::OpSeqNotMonotonic { .. }));
}

#[test]
fn adversarial_truncated_signature_rejected() {
    let (_m, sk, vk) = setup();
    let mut op = AuthenticatedOp::sign(
        &sk,
        b"x".to_vec(),
        Delta::LwwSet { value: b"v".to_vec(), ts: 1 },
        1,
        1,
    )
    .unwrap();
    op.subkey_sig.truncate(8);
    let err = op.verify(&vk).unwrap_err();
    assert!(matches!(err, DeviceMeshError::BadLength { .. }));
}

#[test]
fn adversarial_oversize_subtree_label_rejected_at_sign() {
    let (_m, sk, _vk) = setup();
    let big = vec![b'L'; MAX_SUBTREE_LABEL_LEN + 1];
    let err = AuthenticatedOp::sign(
        &sk,
        big,
        Delta::LwwSet { value: b"v".to_vec(), ts: 1 },
        1,
        1,
    )
    .unwrap_err();
    assert!(matches!(err, DeviceMeshError::SubtreeLabelTooLong { .. }));
}

#[test]
fn adversarial_oversize_value_rejected_at_sign() {
    let (_m, sk, _vk) = setup();
    let big = vec![0u8; MAX_DELTA_VALUE_LEN + 1];
    let err = AuthenticatedOp::sign(
        &sk,
        b"x".to_vec(),
        Delta::LwwSet { value: big, ts: 1 },
        1,
        1,
    )
    .unwrap_err();
    assert!(matches!(err, DeviceMeshError::DeltaValueTooLong { .. }));
}

// ── Apply / kind-mismatch ───────────────────────────────────────────

#[test]
fn adversarial_delta_kind_mismatch_rejected_at_apply() {
    let (_m, _sk, _vk) = setup();
    let mut state = MeshState::empty();
    state.ensure_subtree(b"x".to_vec(), SubtreePolicyKind::LwwRegister).unwrap();
    // Wrong delta kind for an LWW-Register subtree.
    let err = state
        .apply_delta(b"x", &Delta::Counter { device_id: [0; 16], delta: 1 }, &[0; 16])
        .unwrap_err();
    assert!(matches!(err, DeviceMeshError::DeltaKindMismatch));
}

#[test]
fn adversarial_apply_to_missing_subtree_rejected() {
    let mut state = MeshState::empty();
    let err = state
        .apply_delta(
            b"missing",
            &Delta::LwwSet { value: b"v".to_vec(), ts: 1 },
            &[0; 16],
        )
        .unwrap_err();
    assert!(matches!(err, DeviceMeshError::SubtreeMissing));
}

// ── Convergence under adversarial reorder ───────────────────────────

#[test]
fn adversarial_reverse_op_order_still_converges() {
    let (_m, sk, vk) = setup();
    let lookup = |_: &[u8; 16], _: u64| Ok(vk.clone());
    let mut state_a = MeshState::empty();
    let mut state_b = MeshState::empty();
    state_a.ensure_subtree(b"x".to_vec(), SubtreePolicyKind::LwwMap).unwrap();
    state_b.ensure_subtree(b"x".to_vec(), SubtreePolicyKind::LwwMap).unwrap();
    let mut sa = SyncState::empty();
    let mut sb = SyncState::empty();
    let ops: Vec<AuthenticatedOp> = (1u64..=10)
        .map(|i| {
            AuthenticatedOp::sign(
                &sk,
                b"x".to_vec(),
                Delta::MapPut { key: vec![i as u8], value: vec![i as u8], ts: i },
                i,
                i,
            )
            .unwrap()
        })
        .collect();
    for op in &ops {
        sa.ingest(op.clone(), &mut state_a, &lookup).unwrap();
    }
    for op in ops.iter().rev() {
        sb.ingest(op.clone(), &mut state_b, &lookup).unwrap();
    }
    assert_eq!(state_a.root(), state_b.root());
}
