#![no_main]
//! Fuzz the Layer 8 compute surface.

use libfuzzer_sys::fuzz_target;
use ol_device_mesh::compute::{
    pick_executor, sign_capability_attestation, sign_task_request, sign_task_result,
    CapabilityRegistry, DeviceCapability, TaskClass,
};
use ol_device_mesh::distributed_fs::FILE_ID_LEN;
use ol_device_mesh::fan_out::SourceCapacity;
use ol_device_mesh::{
    mint_subkey, DeviceClass, MasterIdentity, DEVICE_ID_LEN,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fuzz_target!(|data: &[u8]| {
    let mut rng = ChaCha20Rng::from_seed([0xACu8; 32]);
    let master = MasterIdentity::generate(&mut rng);

    // 1. CapabilityAttestation sign + verify on fuzz-derived caps.
    let pool = DeviceCapability::all();
    let n = (data.first().copied().unwrap_or(0) as usize) % pool.len().max(1);
    let mut caps_vec: Vec<DeviceCapability> = (0..n)
        .filter_map(|i| pool.get(i).copied())
        .collect();
    if let Ok(att) = sign_capability_attestation(
        &master, [0xAA; DEVICE_ID_LEN], caps_vec.clone(), 0, 365,
    ) {
        let _ = att.verify(&master.verifying_key());
    }
    caps_vec.sort();
    caps_vec.dedup();

    // 2. Task request sign + verify.
    let (sk, _) = mint_subkey(
        &master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365,
    )
    .unwrap();
    let class_bytes: Vec<u8> = data.iter().take(16).copied().collect();
    if let Ok(class) = TaskClass::new(&class_bytes) {
        let mut file_id = [0u8; FILE_ID_LEN];
        for (i, b) in data.iter().take(FILE_ID_LEN).enumerate() {
            file_id[i] = *b;
        }
        let mut nonce = [0u8; 16];
        for (i, b) in data.iter().rev().take(16).enumerate() {
            nonce[i] = *b;
        }
        if let Ok(mut req) = sign_task_request(
            &sk, class, file_id, caps_vec.clone(), 1, 1, 1, 10, nonce,
        ) {
            let _ = req.verify(&sk.verifying_key());
            if let Some(&b) = data.first() {
                req.max_wall_secs = u32::from(b);
            }
            let _ = req.verify(&sk.verifying_key());
            let _ = req.request_id();
        }
    }

    // 3. Task result.
    let mut request_id = [0u8; 32];
    for (i, b) in data.iter().take(32).enumerate() {
        request_id[i] = *b;
    }
    if let Ok(mut result) = sign_task_result(
        &sk, request_id, [0xFF; FILE_ID_LEN], 1024, 1,
    ) {
        let _ = result.verify(&sk.verifying_key());
        if let Some(&b) = data.first() {
            result.output_byte_size = u64::from(b);
        }
        let _ = result.verify(&sk.verifying_key());
    }

    // 4. Picker.
    let mut reg = CapabilityRegistry::empty();
    let _ = reg.ingest(
        sign_capability_attestation(
            &master, [0xBB; DEVICE_ID_LEN], caps_vec.clone(), 0, 365,
        )
        .unwrap(),
        &master.verifying_key(),
    );
    let caps = vec![SourceCapacity {
        device_id: [0xBB; DEVICE_ID_LEN],
        estimated_bps: u64::from(data.first().copied().unwrap_or(1)) + 1,
        current_load_bytes: 0,
    }];
    let _ = pick_executor(&caps_vec, &reg, &caps, 100);
});
