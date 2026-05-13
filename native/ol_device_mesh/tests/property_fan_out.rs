//! Property tests for Row 8 Layer 5 multi-device fan-out.

use proptest::prelude::*;
use rand::rngs::OsRng;

use ol_device_mesh::distributed_fs::{
    ChunkHash, ChunkPlacement, ErasurePolicy, FileManifest, FILE_ID_LEN,
};
use ol_device_mesh::fan_out::{
    fan_out_plan, replan_after_source_failure, sign_chunk_ack, sign_fetch_request,
    FanOutPlan, SourceCapacity, TransferProgress, FETCH_NONCE_LEN,
};
use ol_device_mesh::{
    mint_subkey, DeviceClass, DeviceMeshError, MasterIdentity, DEVICE_ID_LEN,
};

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

fn manifest_for(chunks: Vec<ChunkHash>) -> FileManifest {
    let policy = ErasurePolicy::new(2, 1, 1).unwrap();
    FileManifest {
        file_size: 1024,
        chunk_size: 256,
        chunks,
        mime: b"x".to_vec(),
        created_unix: 0,
        policy,
    }
}

// ── 1M-iter properties on the planner ─────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cheap_cases() / 100, // planner allocates; reduce
        max_global_rejects: cheap_cases(),
        .. ProptestConfig::default()
    })]

    /// fan_out_plan is deterministic.
    #[test]
    fn fan_out_plan_deterministic(
        n_chunks_stripes in 1u8..6u8,
        n_sources in 1u8..6u8,
        seed in any::<[u8; 32]>(),
    ) {
        let chunks: Vec<ChunkHash> = (0..(n_chunks_stripes as usize * 3))
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i as u8;
                h
            })
            .collect();
        let m = manifest_for(chunks.clone());
        let placements: Vec<ChunkPlacement> = chunks
            .iter()
            .map(|c| {
                let mut p = ChunkPlacement::empty(*c);
                for i in 0..n_sources {
                    p.add_holder([i; DEVICE_ID_LEN], 1);
                }
                p
            })
            .collect();
        let sources: Vec<SourceCapacity> = (0..n_sources)
            .map(|i| SourceCapacity {
                device_id: [i; DEVICE_ID_LEN],
                estimated_bps: u64::from(seed[i as usize]).max(1) * 1_000_000,
                current_load_bytes: 0,
            })
            .collect();
        let p1 = fan_out_plan(&m, &placements, &sources, 1.0).unwrap();
        let p2 = fan_out_plan(&m, &placements, &sources, 1.0).unwrap();
        prop_assert_eq!(p1, p2);
    }

    /// No assignment names a chunk a source doesn't hold.
    #[test]
    fn no_assignment_to_non_holder(
        n_chunks_stripes in 1u8..6u8,
        holder_byte in 0u8..6u8,
    ) {
        let chunks: Vec<ChunkHash> = (0..(n_chunks_stripes as usize * 3))
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i as u8;
                h
            })
            .collect();
        let m = manifest_for(chunks.clone());
        // Only one device holds every chunk.
        let placements: Vec<ChunkPlacement> = chunks
            .iter()
            .map(|c| {
                let mut p = ChunkPlacement::empty(*c);
                p.add_holder([holder_byte; DEVICE_ID_LEN], 1);
                p
            })
            .collect();
        // But our source list has multiple devices, only one of which
        // is the actual holder.
        let sources: Vec<SourceCapacity> = (0u8..6).map(|i| SourceCapacity {
            device_id: [i; DEVICE_ID_LEN],
            estimated_bps: 1_000_000,
            current_load_bytes: 0,
        }).collect();
        let plan = fan_out_plan(&m, &placements, &sources, 1.0).unwrap();
        for a in &plan.assignments {
            prop_assert_eq!(a.source_device_id, [holder_byte; DEVICE_ID_LEN]);
        }
    }

    /// Every chunk-hash assigned by the planner is present in some
    /// placement.
    #[test]
    fn assigned_chunks_are_in_some_placement(
        n_stripes in 1u8..6u8,
    ) {
        let chunks: Vec<ChunkHash> = (0..(n_stripes as usize * 3))
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i as u8;
                h
            })
            .collect();
        let m = manifest_for(chunks.clone());
        let placements: Vec<ChunkPlacement> = chunks
            .iter()
            .map(|c| {
                let mut p = ChunkPlacement::empty(*c);
                p.add_holder([1; DEVICE_ID_LEN], 1);
                p
            })
            .collect();
        let sources = vec![SourceCapacity {
            device_id: [1; DEVICE_ID_LEN],
            estimated_bps: 1_000_000,
            current_load_bytes: 0,
        }];
        let plan = fan_out_plan(&m, &placements, &sources, 1.0).unwrap();
        let known: std::collections::BTreeSet<ChunkHash> =
            placements.iter().map(|p| p.chunk_hash).collect();
        for a in &plan.assignments {
            for c in &a.chunk_hashes {
                prop_assert!(known.contains(c));
            }
        }
    }
}

// ── Keygen-bound properties ───────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: keygen_cases(),
        max_global_rejects: keygen_cases() * 4,
        .. ProptestConfig::default()
    })]

    /// FetchRequest sign+verify round-trips.
    #[test]
    fn fetch_request_sign_verify_round_trip(
        budget in any::<u64>(),
        issued in 0u64..1_000_000_000u64,
        ttl in 1u64..1_000u64,
    ) {
        let master = MasterIdentity::generate(&mut OsRng);
        let (sk, _) = mint_subkey(
            &master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365,
        ).unwrap();
        let req = sign_fetch_request(
            &sk,
            [0xBB; DEVICE_ID_LEN],
            [0xCC; FILE_ID_LEN],
            vec![[0x01; 32], [0x02; 32]],
            budget,
            issued,
            issued.saturating_add(ttl),
            [0xDA; FETCH_NONCE_LEN],
        ).unwrap();
        req.verify(&sk.verifying_key()).unwrap();
    }

    /// ChunkAck sign+verify round-trips.
    #[test]
    fn chunk_ack_sign_verify_round_trip(
        delivered in any::<u64>(),
        byte_size in 1u32..1_000_000u32,
    ) {
        let master = MasterIdentity::generate(&mut OsRng);
        let (sk, _) = mint_subkey(
            &master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365,
        ).unwrap();
        let ack = sign_chunk_ack(
            &sk,
            [0xCC; FILE_ID_LEN],
            [0xDD; 32],
            [0xBB; DEVICE_ID_LEN],
            delivered,
            byte_size,
        ).unwrap();
        ack.verify(&sk.verifying_key()).unwrap();
    }

    /// Replan after source failure never includes the failed source.
    #[test]
    fn replan_excludes_failed_source(
        n_chunks_stripes in 1u8..4u8,
        failed in 1u8..4u8,
    ) {
        let chunks: Vec<ChunkHash> = (0..(n_chunks_stripes as usize * 3))
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i as u8;
                h
            })
            .collect();
        let m = manifest_for(chunks.clone());
        let placements: Vec<ChunkPlacement> = chunks
            .iter()
            .map(|c| {
                let mut p = ChunkPlacement::empty(*c);
                for i in 1u8..=4 {
                    p.add_holder([i; DEVICE_ID_LEN], 1);
                }
                p
            })
            .collect();
        let sources: Vec<SourceCapacity> = (1u8..=4).map(|i| SourceCapacity {
            device_id: [i; DEVICE_ID_LEN],
            estimated_bps: 1_000_000,
            current_load_bytes: 0,
        }).collect();
        let failed_id = [failed; DEVICE_ID_LEN];
        let plan = replan_after_source_failure(
            &m, &placements, &sources, failed_id, &chunks, 1.0,
        ).unwrap();
        for a in &plan.assignments {
            prop_assert_ne!(a.source_device_id, failed_id);
        }
    }
}

// ── TransferProgress sanity ───────────────────────────────────────

#[test]
fn progress_completion_at_threshold() {
    let chunks: Vec<ChunkHash> = (1u8..=6).map(|i| [i; 32]).collect();
    let m = manifest_for(chunks.clone());
    let placements: Vec<ChunkPlacement> = chunks
        .iter()
        .map(|c| {
            let mut p = ChunkPlacement::empty(*c);
            p.add_holder([1; DEVICE_ID_LEN], 1);
            p
        })
        .collect();
    let sources = vec![SourceCapacity {
        device_id: [1; DEVICE_ID_LEN],
        estimated_bps: 1_000_000,
        current_load_bytes: 0,
    }];
    let plan: FanOutPlan = fan_out_plan(&m, &placements, &sources, 1.0).unwrap();
    let mut prog = TransferProgress::new(plan, &m);
    // 6 chunks at (k=2, m=1) ⇒ 2 stripes × 2 = 4 needed.
    assert_eq!(prog.completion_threshold, 4);
    for c in chunks.iter().take(3) {
        prog.complete_chunk(*c);
    }
    assert!(!prog.is_complete());
    prog.complete_chunk(chunks[3]);
    assert!(prog.is_complete());
}
