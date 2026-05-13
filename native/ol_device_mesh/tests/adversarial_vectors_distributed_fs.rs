//! Adversarial vectors for Row 8 Layer 4 distributed FS.

use std::collections::BTreeSet;

use ol_device_mesh::distributed_fs::{
    repair_plan, sign_storage_attestation, under_replicated, ChunkHash,
    ChunkPlacement, ErasurePolicy, FileManifest, MAX_CHUNKS_PER_FILE,
};
use ol_device_mesh::{
    mint_subkey, DeviceClass, DeviceMeshError, MasterIdentity, DEVICE_ID_LEN,
};
use rand::rngs::OsRng;

// ── Manifest forgery + tampering ───────────────────────────────────

#[test]
fn adversarial_manifest_zero_chunk_count_rejected() {
    let policy = ErasurePolicy::new(2, 1, 1).unwrap();
    let m = FileManifest {
        file_size: 1,
        chunk_size: 1,
        chunks: vec![],
        mime: b"x".to_vec(),
        created_unix: 0,
        policy,
    };
    let err = m.shape_check().unwrap_err();
    assert!(matches!(err, DeviceMeshError::FileManifestEmpty));
}

#[test]
fn adversarial_manifest_non_stripe_count_rejected() {
    let policy = ErasurePolicy::new(2, 1, 1).unwrap();
    let m = FileManifest {
        file_size: 1,
        chunk_size: 1,
        chunks: vec![[0; 32]; 5], // not a multiple of 3
        mime: b"x".to_vec(),
        created_unix: 0,
        policy,
    };
    let err = m.shape_check().unwrap_err();
    assert!(matches!(
        err,
        DeviceMeshError::FileManifestChunkCountNotStripe { .. }
    ));
}

#[test]
fn adversarial_manifest_oversize_rejected() {
    let policy = ErasurePolicy::new(2, 1, 1).unwrap();
    let chunks = vec![[0; 32]; MAX_CHUNKS_PER_FILE + 3];
    let m = FileManifest {
        file_size: 1,
        chunk_size: 1,
        chunks,
        mime: b"x".to_vec(),
        created_unix: 0,
        policy,
    };
    let err = m.shape_check().unwrap_err();
    assert!(matches!(
        err,
        DeviceMeshError::FileManifestTooManyChunks { .. }
    ));
}

#[test]
fn adversarial_manifest_chunk_flip_changes_file_id() {
    let policy = ErasurePolicy::new(2, 1, 1).unwrap();
    let chunks: Vec<ChunkHash> = vec![[0x11; 32], [0x22; 32], [0x33; 32]];
    let base = FileManifest {
        file_size: 1,
        chunk_size: 256,
        chunks: chunks.clone(),
        mime: b"x".to_vec(),
        created_unix: 1,
        policy,
    };
    let mut tampered = base.clone();
    tampered.chunks[1][7] ^= 0x01;
    assert_ne!(base.file_id(), tampered.file_id());
}

// ── Storage-attestation forgery + tampering ────────────────────────

#[test]
fn adversarial_attestation_wrong_subkey_rejected() {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk_a, _) =
        mint_subkey(&master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365).unwrap();
    let (sk_b, _) =
        mint_subkey(&master, DeviceClass::Laptop, [0xBB; DEVICE_ID_LEN], 0, 365).unwrap();
    let att = sign_storage_attestation(&sk_a, 1, vec![[0xCC; 32]]).unwrap();
    let err = att.verify(&sk_b.verifying_key()).unwrap_err();
    assert!(matches!(err, DeviceMeshError::StorageAttestVerifyFail));
}

#[test]
fn adversarial_attestation_tampered_chunks_rejected() {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk, _) =
        mint_subkey(&master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365).unwrap();
    let mut att =
        sign_storage_attestation(&sk, 1, vec![[0x01; 32], [0x02; 32]]).unwrap();
    // Flip a byte in a chunk hash (preserve sort order so shape_check passes).
    att.chunk_hashes[1][31] ^= 0x01;
    let err = att.verify(&sk.verifying_key()).unwrap_err();
    assert!(matches!(err, DeviceMeshError::StorageAttestVerifyFail));
}

#[test]
fn adversarial_attestation_manual_unsort_rejected() {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk, _) =
        mint_subkey(&master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365).unwrap();
    let mut att =
        sign_storage_attestation(&sk, 1, vec![[0x01; 32], [0x02; 32], [0x03; 32]]).unwrap();
    att.chunk_hashes.swap(0, 2); // not sorted anymore
    let err = att.verify(&sk.verifying_key()).unwrap_err();
    assert!(matches!(err, DeviceMeshError::AttestationChunksNotSorted));
}

// ── Placement / repair adversaries ─────────────────────────────────

#[test]
fn adversarial_under_replicated_catches_all_failing_chunks() {
    let policy = ErasurePolicy::new(2, 1, 3).unwrap();
    let mut good = ChunkPlacement::empty([0x01; 32]);
    good.add_holder([1u8; DEVICE_ID_LEN], 1);
    good.add_holder([2u8; DEVICE_ID_LEN], 1);
    good.add_holder([3u8; DEVICE_ID_LEN], 1);
    let mut bad = ChunkPlacement::empty([0x02; 32]);
    bad.add_holder([1u8; DEVICE_ID_LEN], 1);
    let under = under_replicated([&good, &bad], &policy);
    assert_eq!(under, vec![[0x02; 32]]);
}

#[test]
fn adversarial_repair_plan_with_too_few_devices_emits_partial() {
    // Need 5 holders; mesh has only 3 → planner emits the 3 it can.
    let policy = ErasurePolicy::new(2, 1, 5).unwrap();
    let mesh: BTreeSet<[u8; DEVICE_ID_LEN]> =
        (1u8..=3).map(|i| [i; DEVICE_ID_LEN]).collect();
    let p = ChunkPlacement::empty([0x01; 32]);
    let plan = repair_plan([&p], &mesh, &policy);
    assert_eq!(plan.len(), 3); // exhausted the mesh
}

#[test]
fn adversarial_repair_plan_load_balanced() {
    // 4 chunks needing 2 new holders each across a 4-device mesh.
    // Total assignments = 8 across 4 devices = 2 each (load-balanced).
    let policy = ErasurePolicy::new(2, 1, 2).unwrap();
    let mesh: BTreeSet<[u8; DEVICE_ID_LEN]> =
        (1u8..=4).map(|i| [i; DEVICE_ID_LEN]).collect();
    let placements: Vec<ChunkPlacement> = (0u8..4)
        .map(|i| ChunkPlacement::empty([i; 32]))
        .collect();
    let plan = repair_plan(placements.iter(), &mesh, &policy);
    assert_eq!(plan.len(), 8);
    let mut device_counts = std::collections::BTreeMap::<[u8; 16], usize>::new();
    for a in &plan {
        *device_counts.entry(a.assigned_to).or_default() += 1;
    }
    // Each of the 4 mesh devices got 2 assignments.
    for d in &mesh {
        assert_eq!(*device_counts.get(d).unwrap_or(&0), 2);
    }
}

// ── Erasure-policy edge cases ──────────────────────────────────────

#[test]
fn adversarial_erasure_policy_k_zero_rejected() {
    let err = ErasurePolicy::new(0, 4, 2).unwrap_err();
    assert!(matches!(err, DeviceMeshError::ErasurePolicyZeroData));
}

#[test]
fn adversarial_erasure_policy_oversize_rejected() {
    let err = ErasurePolicy::new(30, 30, 2).unwrap_err();
    assert!(matches!(err, DeviceMeshError::ErasurePolicyOversize { .. }));
}

#[test]
fn adversarial_erasure_policy_min_devices_zero_rejected() {
    let err = ErasurePolicy::new(2, 1, 0).unwrap_err();
    assert!(matches!(err, DeviceMeshError::ErasurePolicyZeroMinDevices));
}
