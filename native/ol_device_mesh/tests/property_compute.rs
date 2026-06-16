//! Property tests for Row 8 Layer 8 distributed compute.

use proptest::prelude::*;
use rand::rngs::OsRng;

use ol_device_mesh::compute::{
    pick_executor, sign_capability_attestation, sign_task_request, sign_task_result,
    CapabilityAttestation, CapabilityRegistry, DeviceCapability, TaskClass, TaskRequest,
};
use ol_device_mesh::distributed_fs::FILE_ID_LEN;
use ol_device_mesh::fan_out::SourceCapacity;
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

// ── 1M-iter properties on canonical transcripts ────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cheap_cases(),
        max_global_rejects: cheap_cases() * 4,
        .. ProptestConfig::default()
    })]

    /// Capability-attestation transcript is a pure function.
    #[test]
    fn capability_attestation_transcript_deterministic(
        device_id in any::<[u8; DEVICE_ID_LEN]>(),
        mint in any::<u64>(),
        expiry in any::<u64>(),
    ) {
        let caps = vec![DeviceCapability::Gpu, DeviceCapability::CpuHeavy];
        let a = CapabilityAttestation::canonical_transcript(
            &device_id, &caps, mint, expiry,
        );
        let b = CapabilityAttestation::canonical_transcript(
            &device_id, &caps, mint, expiry,
        );
        prop_assert_eq!(a, b);
    }

    /// Task-request transcript is deterministic.
    #[test]
    fn task_request_transcript_deterministic(
        requester in any::<[u8; DEVICE_ID_LEN]>(),
        day in any::<u64>(),
        file_id in any::<[u8; FILE_ID_LEN]>(),
        wall in any::<u32>(),
        out in any::<u64>(),
        issued in 0u64..1_000_000_000,
        ttl in 1u64..1_000,
        nonce in any::<[u8; 16]>(),
    ) {
        let class = TaskClass::new(b"transcribe").unwrap();
        let caps = vec![DeviceCapability::Microphone];
        let a = TaskRequest::canonical_transcript(
            &class, &requester, day, &file_id, &caps, wall, out, issued,
            issued.saturating_add(ttl), &nonce,
        );
        let b = TaskRequest::canonical_transcript(
            &class, &requester, day, &file_id, &caps, wall, out, issued,
            issued.saturating_add(ttl), &nonce,
        );
        prop_assert_eq!(a, b);
    }
}

// ── Keygen-bound properties ────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: keygen_cases(),
        max_global_rejects: keygen_cases() * 4,
        .. ProptestConfig::default()
    })]

    /// Capability-attestation sign + verify round-trip.
    #[test]
    fn capability_attestation_sign_verify(
        device_id in any::<[u8; DEVICE_ID_LEN]>(),
        mint in 0u64..1_000_000,
        ttl in 1u64..1_000,
    ) {
        let master = MasterIdentity::generate(&mut OsRng);
        let att = sign_capability_attestation(
            &master,
            device_id,
            vec![DeviceCapability::Gpu, DeviceCapability::CpuHeavy],
            mint,
            mint + ttl,
        )
        .unwrap();
        att.verify(&master.verifying_key()).unwrap();
    }

    /// Task request sign + verify round-trip.
    #[test]
    fn task_request_sign_verify(
        wall in 1u32..3600,
        out in 1u64..1_000_000,
        issued in 0u64..1_000_000,
        ttl in 1u64..1_000,
    ) {
        let master = MasterIdentity::generate(&mut OsRng);
        let (sk, _) = mint_subkey(
            &master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365,
        )
        .unwrap();
        let req = sign_task_request(
            &sk,
            TaskClass::new(b"transcribe-audio").unwrap(),
            [0xCC; FILE_ID_LEN],
            vec![DeviceCapability::Microphone],
            wall,
            out,
            issued,
            issued + ttl,
            [0xDA; 16],
        )
        .unwrap();
        req.verify(&sk.verifying_key()).unwrap();
    }

    /// Task result sign + verify round-trip.
    #[test]
    fn task_result_sign_verify(
        size in 1u64..1_000_000,
        completed in 0u64..1_000_000,
    ) {
        let master = MasterIdentity::generate(&mut OsRng);
        let (sk, _) = mint_subkey(
            &master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365,
        )
        .unwrap();
        let result = sign_task_result(
            &sk,
            [0xEE; 32],
            [0xFF; FILE_ID_LEN],
            size,
            completed,
        )
        .unwrap();
        result.verify(&sk.verifying_key()).unwrap();
    }
}

// ── pick_executor invariants ──────────────────────────────────────

#[test]
fn pick_executor_never_returns_ineligible_device() {
    let master = MasterIdentity::generate(&mut OsRng);
    let mut reg = CapabilityRegistry::empty();
    reg.ingest(
        sign_capability_attestation(
            &master,
            [0x11; DEVICE_ID_LEN],
            vec![DeviceCapability::Microphone],
            0,
            365,
        )
        .unwrap(),
        &master.verifying_key(),
    )
    .unwrap();
    let caps = vec![SourceCapacity {
        device_id: [0x11; DEVICE_ID_LEN],
        estimated_bps: 1_000_000,
        current_load_bytes: 0,
    }];
    // Request needs GPU; phone doesn't have it.
    let pick = pick_executor(&[DeviceCapability::Gpu], &reg, &caps, 100);
    assert!(pick.is_none());
}
