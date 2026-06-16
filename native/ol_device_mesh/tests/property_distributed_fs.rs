//! Property tests for Row 8 Layer 4 distributed FS.
//!
//! Two tiers:
//!   - Pure derivation (file_id, manifest canonical bytes,
//!     placement / repair planning): 1M iters CI default.
//!   - Keygen-bound storage-attestation round-trips: 1k iters.

use proptest::prelude::*;
use rand::rngs::OsRng;

use std::collections::BTreeSet;

use ol_device_mesh::distributed_fs::{
    repair_plan, sign_storage_attestation, under_replicated, ChunkHash, ChunkPlacement,
    ErasurePolicy, FileManifest,
};
use ol_device_mesh::{mint_subkey, DeviceClass, MasterIdentity, DEVICE_ID_LEN};

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

fn policy_strategy() -> impl Strategy<Value = ErasurePolicy> {
    (1u8..=8u8, 0u8..=8u8, 1u8..=8u8)
        .prop_filter("k+m within MAX_K_PLUS_M", |(k, m, _)| {
            (*k as u16) + (*m as u16) <= 32
        })
        .prop_map(|(k, m, min)| ErasurePolicy::new(k, m, min).unwrap())
}

// ── 1M-iter properties on pure derivation paths ───────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cheap_cases(),
        max_global_rejects: cheap_cases() * 4,
        .. ProptestConfig::default()
    })]

    /// FileId of a manifest is a pure function of its canonical bytes.
    #[test]
    fn file_id_deterministic_under_clone(
        file_size in any::<u64>(),
        chunk_size in 1u32..1_048_576,
        chunk_count in 1u32..32u32,
        mime in prop::collection::vec(any::<u8>(), 0..32),
        created in any::<u64>(),
        policy in policy_strategy(),
    ) {
        let stripe = policy.total_shards() as u32;
        let count = ((chunk_count / stripe.max(1)) * stripe.max(1)).max(stripe);
        let chunks: Vec<ChunkHash> = (0..count)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..4].copy_from_slice(&i.to_be_bytes());
                h
            })
            .collect();
        let m = FileManifest {
            file_size,
            chunk_size,
            chunks,
            mime,
            created_unix: created,
            policy,
        };
        prop_assert!(m.shape_check().is_ok());
        prop_assert_eq!(m.file_id(), m.file_id());
    }

    /// Distinct chunk-hash lists ⇒ distinct FileIds (with overwhelming
    /// probability over BLAKE3).
    #[test]
    fn file_id_changes_on_chunk_flip(
        flip_idx in 0usize..32usize,
        policy in policy_strategy(),
    ) {
        let stripe = policy.total_shards() as usize;
        let chunks: Vec<ChunkHash> = (0..stripe)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i as u8;
                h
            })
            .collect();
        let base = FileManifest {
            file_size: 1,
            chunk_size: 1,
            chunks: chunks.clone(),
            mime: b"x".to_vec(),
            created_unix: 0,
            policy,
        };
        let mut tampered = base.clone();
        let idx = flip_idx % tampered.chunks[0].len();
        tampered.chunks[0][idx] ^= 0x01;
        prop_assert_ne!(base.file_id(), tampered.file_id());
    }

    /// under_replicated is a pure filter — same input → same output.
    #[test]
    fn under_replicated_pure(
        n_chunks in 0usize..32,
        threshold in 1u8..=8u8,
    ) {
        let policy = ErasurePolicy::new(2, 1, threshold).unwrap();
        let placements: Vec<ChunkPlacement> = (0..n_chunks)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i as u8;
                ChunkPlacement::empty(h)
            })
            .collect();
        let r1 = under_replicated(placements.iter(), &policy);
        let r2 = under_replicated(placements.iter(), &policy);
        prop_assert_eq!(r1, r2);
    }

    /// repair_plan: no assignment ever pairs (chunk, device) where
    /// the device already holds the chunk.
    #[test]
    fn repair_plan_never_assigns_existing_holder(
        n_devices in 2u8..8u8,
        n_chunks in 1u8..6u8,
        existing_holder in 0u8..8u8,
    ) {
        let policy = ErasurePolicy::new(2, 1, 3).unwrap();
        let mesh: BTreeSet<[u8; DEVICE_ID_LEN]> =
            (1..=n_devices).map(|i| [i; DEVICE_ID_LEN]).collect();
        let placements: Vec<ChunkPlacement> = (0..n_chunks)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i;
                let mut p = ChunkPlacement::empty(h);
                let holder_byte = (existing_holder % n_devices) + 1;
                p.add_holder([holder_byte; DEVICE_ID_LEN], 1);
                p
            })
            .collect();
        let plan = repair_plan(placements.iter(), &mesh, &policy);
        for a in &plan {
            let p = placements.iter().find(|p| p.chunk_hash == a.chunk_hash).unwrap();
            prop_assert!(!p.device_ids.contains(&a.assigned_to));
        }
    }

    /// repair_plan: distinct devices per chunk.
    #[test]
    fn repair_plan_distinct_devices_per_chunk(
        n_devices in 2u8..8u8,
        n_chunks in 1u8..6u8,
    ) {
        let policy = ErasurePolicy::new(2, 1, 4).unwrap();
        let mesh: BTreeSet<[u8; DEVICE_ID_LEN]> =
            (1..=n_devices).map(|i| [i; DEVICE_ID_LEN]).collect();
        let placements: Vec<ChunkPlacement> = (0..n_chunks)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i;
                ChunkPlacement::empty(h)
            })
            .collect();
        let plan = repair_plan(placements.iter(), &mesh, &policy);
        // For each chunk, the set of assigned devices must be unique.
        for c in &placements {
            let assignees: Vec<_> = plan
                .iter()
                .filter(|a| a.chunk_hash == c.chunk_hash)
                .map(|a| a.assigned_to)
                .collect();
            let unique: BTreeSet<_> = assignees.iter().copied().collect();
            prop_assert_eq!(unique.len(), assignees.len());
        }
    }
}

// ── Keygen-bound properties on storage attestation ─────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: keygen_cases(),
        max_global_rejects: keygen_cases() * 4,
        .. ProptestConfig::default()
    })]

    /// Storage-attestation sign+verify round-trips.
    #[test]
    fn storage_attestation_sign_verify_round_trip(
        n_chunks in 0usize..16,
        attest_unix in any::<u64>(),
    ) {
        let master = MasterIdentity::generate(&mut OsRng);
        let (sk, _att) =
            mint_subkey(&master, DeviceClass::Phone, [0x55; DEVICE_ID_LEN], 0, 365).unwrap();
        let chunks: Vec<ChunkHash> = (0..n_chunks)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..4].copy_from_slice(&(i as u32).to_be_bytes());
                h
            })
            .collect();
        let att = sign_storage_attestation(&sk, attest_unix, chunks).unwrap();
        att.verify(&sk.verifying_key()).unwrap();
    }

    /// Storage-attestation under a different subkey rejected.
    #[test]
    fn storage_attestation_cross_subkey_rejected(
        attest_unix in any::<u64>(),
    ) {
        let master = MasterIdentity::generate(&mut OsRng);
        let (sk_a, _) =
            mint_subkey(&master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365).unwrap();
        let (sk_b, _) =
            mint_subkey(&master, DeviceClass::Laptop, [0xBB; DEVICE_ID_LEN], 0, 365).unwrap();
        let att = sign_storage_attestation(&sk_a, attest_unix, vec![[0x01; 32]]).unwrap();
        let r = att.verify(&sk_b.verifying_key());
        prop_assert!(r.is_err());
    }
}
