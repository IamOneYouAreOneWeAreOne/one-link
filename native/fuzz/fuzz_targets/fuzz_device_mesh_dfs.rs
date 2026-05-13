#![no_main]
//! Fuzz the Layer 4 distributed-FS surface. Must never panic for
//! any input shape.

use libfuzzer_sys::fuzz_target;
use ol_device_mesh::distributed_fs::{
    repair_plan, sign_storage_attestation, under_replicated, ChunkHash,
    ChunkPlacement, ErasurePolicy, FileManifest,
};
use ol_device_mesh::{
    mint_subkey, DeviceClass, MasterIdentity, DEVICE_ID_LEN,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeSet;

fuzz_target!(|data: &[u8]| {
    let mut rng = ChaCha20Rng::from_seed([0xA4u8; 32]);
    let master = MasterIdentity::generate(&mut rng);
    let (sk, att_l1) =
        mint_subkey(&master, DeviceClass::Phone, [0x55; DEVICE_ID_LEN], 0, 365).unwrap();
    let vk = ol_pqsig::HybridVerifyingKey::from_bytes(&att_l1.subkey_vk_bytes).unwrap();

    // 1. Storage-attestation sign + verify on arbitrary chunk count.
    let n = (data.first().copied().unwrap_or(0) as usize) % 64;
    let chunks: Vec<ChunkHash> = (0..n)
        .map(|i| {
            let mut h = [0u8; 32];
            h[0] = i as u8;
            h[1] = data.get(i + 1).copied().unwrap_or(0);
            h
        })
        .collect();
    if let Ok(att) = sign_storage_attestation(&sk, 1, chunks) {
        let _ = att.verify(&vk);
    }

    // 2. Manifest shape-check on arbitrary parameters.
    let policy_k = (data.get(0).copied().unwrap_or(2) % 8).max(1);
    let policy_m = data.get(1).copied().unwrap_or(1) % 8;
    let min_devices = (data.get(2).copied().unwrap_or(1) % 8).max(1);
    if let Ok(policy) = ErasurePolicy::new(policy_k, policy_m, min_devices) {
        let chunk_count = ((data.get(3).copied().unwrap_or(0) as usize)
            % 16)
            .max(1)
            * policy.total_shards() as usize;
        let chunks: Vec<ChunkHash> =
            (0..chunk_count).map(|i| [(i as u8); 32]).collect();
        let m = FileManifest {
            file_size: u64::from(data.get(4).copied().unwrap_or(1)),
            chunk_size: u32::from(data.get(5).copied().unwrap_or(1)).max(1),
            chunks,
            mime: data.get(6..6 + 8).unwrap_or(&[]).to_vec(),
            created_unix: 1,
            policy,
        };
        if m.shape_check().is_ok() {
            let _ = m.canonical_bytes();
            let _ = m.file_id();
        }
    }

    // 3. repair_plan on arbitrary placement sets.
    let policy = ErasurePolicy::new(2, 1, 3).unwrap();
    let mesh: BTreeSet<[u8; DEVICE_ID_LEN]> = (1u8..=4)
        .map(|i| [i; DEVICE_ID_LEN])
        .collect();
    let placements: Vec<ChunkPlacement> = (0u8..4)
        .map(|i| {
            let mut p = ChunkPlacement::empty([i; 32]);
            if let Some(d) = data.get(usize::from(i)) {
                p.add_holder([*d; DEVICE_ID_LEN], 1);
            }
            p
        })
        .collect();
    let _ = repair_plan(placements.iter(), &mesh, &policy);
    let _ = under_replicated(placements.iter(), &policy);
});
