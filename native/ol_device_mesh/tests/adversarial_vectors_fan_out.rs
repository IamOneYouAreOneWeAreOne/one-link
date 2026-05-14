//! Adversarial vectors for Row 8 Layer 5 fan-out.

use ol_device_mesh::distributed_fs::{
    ChunkHash, ErasurePolicy, FileManifest, FILE_ID_LEN,
};
use ol_device_mesh::fan_out::{
    fan_out_plan, replan_after_source_failure, sign_chunk_ack, sign_fetch_request,
    SourceCapacity, TransferProgress, FETCH_NONCE_LEN, MAX_CHUNKS_PER_FETCH,
};
use ol_device_mesh::{
    mint_subkey, DeviceClass, DeviceMeshError, MasterIdentity, DEVICE_ID_LEN,
};
use rand::rngs::OsRng;

fn manifest_for(chunks: Vec<ChunkHash>) -> FileManifest {
    let policy = ErasurePolicy::new(2, 1, 1).unwrap();
    FileManifest {
        file_size: 1,
        chunk_size: 256,
        chunks,
        mime: b"x".to_vec(),
        created_unix: 0,
        policy,
    }
}

// ── FetchRequest forgery + tampering ───────────────────────────────

#[test]
fn adversarial_fetch_request_wrong_subkey_rejected() {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk_a, _) = mint_subkey(
        &master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365,
    )
    .unwrap();
    let (sk_b, _) = mint_subkey(
        &master, DeviceClass::Laptop, [0xBB; DEVICE_ID_LEN], 0, 365,
    )
    .unwrap();
    let req = sign_fetch_request(
        &sk_a,
        [0xCC; DEVICE_ID_LEN],
        [0xDD; FILE_ID_LEN],
        vec![[0x01; 32]],
        1,
        1,
        10,
        [0xDA; FETCH_NONCE_LEN],
    )
    .unwrap();
    let err = req.verify(&sk_b.verifying_key()).unwrap_err();
    assert!(matches!(err, DeviceMeshError::FetchRequestVerifyFail));
}

#[test]
fn adversarial_fetch_request_oversize_rejected() {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk, _) = mint_subkey(
        &master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365,
    )
    .unwrap();
    let chunks: Vec<ChunkHash> = (0..(MAX_CHUNKS_PER_FETCH as u32 + 1))
        .map(|i| {
            let mut h = [0u8; 32];
            h[..4].copy_from_slice(&i.to_be_bytes());
            h
        })
        .collect();
    let err = sign_fetch_request(
        &sk,
        [0xBB; DEVICE_ID_LEN],
        [0xCC; FILE_ID_LEN],
        chunks,
        1,
        1,
        10,
        [0xDA; FETCH_NONCE_LEN],
    )
    .unwrap_err();
    assert!(matches!(
        err,
        DeviceMeshError::FetchRequestTooManyChunks { .. }
    ));
}

#[test]
fn adversarial_fetch_request_tampered_budget_rejected() {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk, _) = mint_subkey(
        &master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365,
    )
    .unwrap();
    let mut req = sign_fetch_request(
        &sk,
        [0xBB; DEVICE_ID_LEN],
        [0xCC; FILE_ID_LEN],
        vec![[0x01; 32]],
        1,
        1,
        10,
        [0xDA; FETCH_NONCE_LEN],
    )
    .unwrap();
    req.max_byte_budget = u64::MAX;
    let err = req.verify(&sk.verifying_key()).unwrap_err();
    assert!(matches!(err, DeviceMeshError::FetchRequestVerifyFail));
}

#[test]
fn adversarial_fetch_request_unsort_after_sign_rejected() {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk, _) = mint_subkey(
        &master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365,
    )
    .unwrap();
    let mut req = sign_fetch_request(
        &sk,
        [0xBB; DEVICE_ID_LEN],
        [0xCC; FILE_ID_LEN],
        vec![[0x01; 32], [0x02; 32], [0x03; 32]],
        1,
        1,
        10,
        [0xDA; FETCH_NONCE_LEN],
    )
    .unwrap();
    req.chunk_hashes.swap(0, 2);
    let err = req.verify(&sk.verifying_key()).unwrap_err();
    assert!(matches!(
        err,
        DeviceMeshError::FetchRequestChunksNotSorted
    ));
}

// ── ChunkAck forgery + tampering ───────────────────────────────────

#[test]
fn adversarial_chunk_ack_wrong_source_rejected() {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk_a, _) = mint_subkey(
        &master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365,
    )
    .unwrap();
    let (sk_b, _) = mint_subkey(
        &master, DeviceClass::Laptop, [0xBB; DEVICE_ID_LEN], 0, 365,
    )
    .unwrap();
    let ack = sign_chunk_ack(
        &sk_a,
        [0xCC; FILE_ID_LEN],
        [0xDD; 32],
        [0xEE; DEVICE_ID_LEN],
        1,
        128,
    )
    .unwrap();
    let err = ack.verify(&sk_b.verifying_key()).unwrap_err();
    assert!(matches!(err, DeviceMeshError::ChunkAckVerifyFail));
}

#[test]
fn adversarial_chunk_ack_replay_to_other_receiver_rejected() {
    // Attacker captures A→C ack and tries to re-present it as A→D
    // by mutating the receiver field. Signature won't validate.
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk, _) = mint_subkey(
        &master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365,
    )
    .unwrap();
    let mut ack = sign_chunk_ack(
        &sk,
        [0xCC; FILE_ID_LEN],
        [0xDD; 32],
        [0xEE; DEVICE_ID_LEN],
        1,
        128,
    )
    .unwrap();
    ack.receiver_device_id = [0xFF; DEVICE_ID_LEN];
    let err = ack.verify(&sk.verifying_key()).unwrap_err();
    assert!(matches!(err, DeviceMeshError::ChunkAckVerifyFail));
}

// ── Planner adversarial ───────────────────────────────────────────

#[test]
fn adversarial_planner_no_sources_rejected() {
    let chunks: Vec<ChunkHash> = (1u8..=3).map(|i| [i; 32]).collect();
    let m = manifest_for(chunks);
    let err = fan_out_plan(&m, &[], &[], 1.0).unwrap_err();
    assert!(matches!(err, DeviceMeshError::FanOutNoSources));
}

#[test]
fn adversarial_planner_overrequest_below_one_rejected() {
    let chunks: Vec<ChunkHash> = (1u8..=3).map(|i| [i; 32]).collect();
    let m = manifest_for(chunks);
    let sources = vec![SourceCapacity {
        device_id: [1; 16],
        estimated_bps: 1,
        current_load_bytes: 0,
    }];
    let err = fan_out_plan(&m, &[], &sources, 0.5).unwrap_err();
    assert!(matches!(
        err,
        DeviceMeshError::FanOutBadOverrequestFactor { .. }
    ));
}

#[test]
fn adversarial_planner_nan_overrequest_rejected() {
    let chunks: Vec<ChunkHash> = (1u8..=3).map(|i| [i; 32]).collect();
    let m = manifest_for(chunks);
    let sources = vec![SourceCapacity {
        device_id: [1; 16],
        estimated_bps: 1,
        current_load_bytes: 0,
    }];
    let err = fan_out_plan(&m, &[], &sources, f64::NAN).unwrap_err();
    assert!(matches!(
        err,
        DeviceMeshError::FanOutBadOverrequestFactor { .. }
    ));
}

#[test]
fn adversarial_replan_with_no_chunks_rejected() {
    let chunks: Vec<ChunkHash> = (1u8..=3).map(|i| [i; 32]).collect();
    let m = manifest_for(chunks);
    let sources = vec![
        SourceCapacity { device_id: [1; 16], estimated_bps: 1, current_load_bytes: 0 },
        SourceCapacity { device_id: [2; 16], estimated_bps: 1, current_load_bytes: 0 },
    ];
    let err = replan_after_source_failure(
        &m, &[], &sources, [2; 16], &[], 1.0,
    )
    .unwrap_err();
    assert!(matches!(err, DeviceMeshError::FanOutNothingToReplan));
}

#[test]
fn adversarial_replan_all_sources_failed_rejected() {
    let chunks: Vec<ChunkHash> = (1u8..=3).map(|i| [i; 32]).collect();
    let m = manifest_for(chunks.clone());
    let sources = vec![SourceCapacity {
        device_id: [1; 16],
        estimated_bps: 1,
        current_load_bytes: 0,
    }];
    let err = replan_after_source_failure(
        &m, &[], &sources, [1; 16], &chunks, 1.0,
    )
    .unwrap_err();
    assert!(matches!(err, DeviceMeshError::FanOutNoSources));
}

// ── TransferProgress adversarial ──────────────────────────────────

#[test]
fn adversarial_progress_source_failure_releases_in_flight() {
    use ol_device_mesh::fan_out::plan::{FanOutAssignment, FanOutPlan};
    let chunks: Vec<ChunkHash> = (1u8..=6).map(|i| [i; 32]).collect();
    let m = manifest_for(chunks);
    let plan = FanOutPlan {
        file_id: [0xAA; FILE_ID_LEN],
        assignments: vec![
            FanOutAssignment {
                source_device_id: [1; 16],
                chunk_hashes: vec![[1; 32], [2; 32], [3; 32]],
                estimated_bytes: 3,
            },
            FanOutAssignment {
                source_device_id: [2; 16],
                chunk_hashes: vec![[4; 32], [5; 32], [6; 32]],
                estimated_bytes: 3,
            },
        ],
        total_chunks: 6,
    };
    let mut prog = TransferProgress::new(plan, &m);
    prog.mark_in_flight([1; 32], [1; 16]);
    prog.mark_in_flight([2; 32], [1; 16]);
    prog.mark_in_flight([4; 32], [2; 16]);
    let released = prog.mark_source_failed([1; 16]);
    assert_eq!(released.len(), 2);
    // Chunks from source 2 remain in flight.
    assert!(prog.in_flight_chunks.contains_key(&[4; 32]));
    // After failure, source 1's chunks count as pending again (but
    // they were already removed from in_flight). pending() excludes
    // the failed-source assignments entirely.
    let pending = prog.pending();
    for c in &pending {
        assert!(c[0] >= 4);
    }
}
