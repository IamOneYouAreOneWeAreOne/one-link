#![no_main]
//! Fuzz the Layer 5 fan-out surface. Must never panic.

use libfuzzer_sys::fuzz_target;
use ol_device_mesh::distributed_fs::{
    ChunkHash, ChunkPlacement, ErasurePolicy, FileManifest, FILE_ID_LEN,
};
use ol_device_mesh::fan_out::{
    fan_out_plan, sign_fetch_request, FetchRequest, SourceCapacity, FETCH_NONCE_LEN,
};
use ol_device_mesh::{
    mint_subkey, DeviceClass, MasterIdentity, DEVICE_ID_LEN,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fuzz_target!(|data: &[u8]| {
    let mut rng = ChaCha20Rng::from_seed([0xA5u8; 32]);
    let master = MasterIdentity::generate(&mut rng);
    let (sk, att_l1) = mint_subkey(
        &master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365,
    )
    .unwrap();
    let vk = ol_pqsig::HybridVerifyingKey::from_bytes(&att_l1.subkey_vk_bytes).unwrap();

    // 1. Sign-then-verify a fetch request derived from fuzz bytes.
    let n_chunks = ((data.first().copied().unwrap_or(0) as usize) % 16) + 1;
    let chunks: Vec<ChunkHash> = (0..n_chunks)
        .map(|i| {
            let mut h = [0u8; 32];
            h[0] = i as u8;
            h[1] = data.get(i + 1).copied().unwrap_or(0);
            h
        })
        .collect();
    if let Ok(req) = sign_fetch_request(
        &sk,
        [0xBB; DEVICE_ID_LEN],
        [0xCC; FILE_ID_LEN],
        chunks.clone(),
        u64::from(data.get(0).copied().unwrap_or(0)) * 1000,
        1,
        100,
        [0xDA; FETCH_NONCE_LEN],
    ) {
        let _ = req.verify(&vk);
    }

    // 2. Build a manifest + placements from fuzz bytes and run the
    //    planner.
    let k = (data.get(0).copied().unwrap_or(2) % 8).max(1);
    let m = data.get(1).copied().unwrap_or(1) % 8;
    if let Ok(policy) = ErasurePolicy::new(k, m, 1) {
        let stripe = policy.total_shards() as usize;
        let chunk_count =
            ((data.get(2).copied().unwrap_or(1) as usize) % 4 + 1) * stripe;
        let manifest_chunks: Vec<ChunkHash> = (0..chunk_count)
            .map(|i| [(i as u8); 32])
            .collect();
        let manifest = FileManifest {
            file_size: 1,
            chunk_size: 256,
            chunks: manifest_chunks.clone(),
            mime: b"x".to_vec(),
            created_unix: 0,
            policy,
        };
        let placements: Vec<ChunkPlacement> = manifest_chunks
            .iter()
            .map(|c| {
                let mut p = ChunkPlacement::empty(*c);
                for i in 1u8..=4 {
                    if let Some(&b) = data.get(i as usize) {
                        if (b & 1) == 1 {
                            p.add_holder([i; DEVICE_ID_LEN], 1);
                        }
                    }
                }
                p
            })
            .collect();
        let sources: Vec<SourceCapacity> = (1u8..=4)
            .map(|i| SourceCapacity {
                device_id: [i; DEVICE_ID_LEN],
                estimated_bps: u64::from(data.get(i as usize).copied().unwrap_or(1))
                    .max(1) * 1_000_000,
                current_load_bytes: 0,
            })
            .collect();
        let _ = fan_out_plan(&manifest, &placements, &sources, 1.0);
    }

    // 3. Mutate a signed fetch request and re-verify.
    if let Ok(mut req) = sign_fetch_request(
        &sk,
        [0xBB; DEVICE_ID_LEN],
        [0xCC; FILE_ID_LEN],
        vec![[0x01; 32]],
        1,
        1,
        10,
        [0xDA; FETCH_NONCE_LEN],
    ) {
        if let Some(&b) = data.first() {
            req.max_byte_budget = u64::from(b);
        }
        let _ = req.verify(&vk);
    }
});
