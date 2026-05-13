//! Adversarial vectors for Row 8 Layer 8 distributed compute.

use ol_device_mesh::compute::{
    pick_executor, sign_capability_attestation, sign_task_request,
    sign_task_result, CapabilityRegistry, DeviceCapability, TaskClass,
    MAX_TASK_CLASS_LEN,
};
use ol_device_mesh::distributed_fs::FILE_ID_LEN;
use ol_device_mesh::fan_out::SourceCapacity;
use ol_device_mesh::{
    mint_subkey, DeviceClass, DeviceMeshError, MasterIdentity, DEVICE_ID_LEN,
};
use rand::rngs::OsRng;

fn make_subkey() -> ol_device_mesh::DeviceSubkey {
    let master = MasterIdentity::generate(&mut OsRng);
    let id = [0xAA; DEVICE_ID_LEN];
    let (sk, _) = mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
    sk
}

// ── Capability-attestation adversarial ────────────────────────────

#[test]
fn adversarial_capability_attestation_wrong_master_rejected() {
    let master_a = MasterIdentity::generate(&mut OsRng);
    let master_b = MasterIdentity::generate(&mut OsRng);
    let att = sign_capability_attestation(
        &master_a,
        [0xAA; DEVICE_ID_LEN],
        vec![DeviceCapability::Gpu],
        0,
        365,
    )
    .unwrap();
    let err = att.verify(&master_b.verifying_key()).unwrap_err();
    assert!(matches!(
        err,
        DeviceMeshError::CapabilityAttestationVerifyFail
    ));
}

#[test]
fn adversarial_capability_attestation_tampered_capability_rejected() {
    let master = MasterIdentity::generate(&mut OsRng);
    let mut att = sign_capability_attestation(
        &master,
        [0xAA; DEVICE_ID_LEN],
        vec![DeviceCapability::Microphone, DeviceCapability::Camera],
        0,
        365,
    )
    .unwrap();
    // Add a fake GPU capability to a pre-signed attestation —
    // captor's attempt to "upgrade" the device's cap list.
    att.capabilities.push(DeviceCapability::Gpu);
    let err = att.verify(&master.verifying_key()).unwrap_err();
    // Either VerifyFail or NotSorted depending on the insertion
    // order; both indicate rejection.
    assert!(
        matches!(err, DeviceMeshError::CapabilityAttestationVerifyFail)
            || matches!(err, DeviceMeshError::CapabilityAttestationNotSorted)
    );
}

#[test]
fn adversarial_capability_attestation_bad_validity_window_rejected() {
    let master = MasterIdentity::generate(&mut OsRng);
    let err = sign_capability_attestation(
        &master,
        [0xAA; DEVICE_ID_LEN],
        vec![DeviceCapability::Gpu],
        100,
        50,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        DeviceMeshError::CapabilityAttestationBadValidityWindow { .. }
    ));
}

// ── TaskClass adversarial ─────────────────────────────────────────

#[test]
fn adversarial_task_class_empty_rejected() {
    let err = TaskClass::new(b"").unwrap_err();
    assert!(matches!(err, DeviceMeshError::TaskClassEmpty));
}

#[test]
fn adversarial_task_class_oversize_rejected() {
    let big = vec![b'x'; MAX_TASK_CLASS_LEN + 1];
    let err = TaskClass::new(&big).unwrap_err();
    assert!(matches!(err, DeviceMeshError::TaskClassTooLong { .. }));
}

// ── TaskRequest adversarial ───────────────────────────────────────

#[test]
fn adversarial_task_request_cross_subkey_rejected() {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk_a, _) = mint_subkey(
        &master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365,
    )
    .unwrap();
    let (sk_b, _) = mint_subkey(
        &master, DeviceClass::Laptop, [0xBB; DEVICE_ID_LEN], 0, 365,
    )
    .unwrap();
    let req = sign_task_request(
        &sk_a,
        TaskClass::new(b"x").unwrap(),
        [0xCC; FILE_ID_LEN],
        vec![DeviceCapability::Gpu],
        1,
        1,
        1,
        10,
        [0xDA; 16],
    )
    .unwrap();
    let err = req.verify(&sk_b.verifying_key()).unwrap_err();
    assert!(matches!(err, DeviceMeshError::TaskRequestVerifyFail));
}

#[test]
fn adversarial_task_request_deadline_before_issue_rejected() {
    let sk = make_subkey();
    let err = sign_task_request(
        &sk,
        TaskClass::new(b"x").unwrap(),
        [0xCC; FILE_ID_LEN],
        vec![],
        1,
        1,
        10,
        5,
        [0xDA; 16],
    )
    .unwrap_err();
    assert!(matches!(
        err,
        DeviceMeshError::TaskDeadlineNotAfterIssue { .. }
    ));
}

#[test]
fn adversarial_task_request_tampered_input_file_id_rejected() {
    let sk = make_subkey();
    let mut req = sign_task_request(
        &sk,
        TaskClass::new(b"x").unwrap(),
        [0xCC; FILE_ID_LEN],
        vec![DeviceCapability::Gpu],
        1,
        1,
        1,
        10,
        [0xDA; 16],
    )
    .unwrap();
    req.input_file_id[0] ^= 0x01;
    let err = req.verify(&sk.verifying_key()).unwrap_err();
    assert!(matches!(err, DeviceMeshError::TaskRequestVerifyFail));
}

#[test]
fn adversarial_task_request_capabilities_post_sign_unsort_rejected() {
    let sk = make_subkey();
    let mut req = sign_task_request(
        &sk,
        TaskClass::new(b"x").unwrap(),
        [0xCC; FILE_ID_LEN],
        vec![
            DeviceCapability::Gpu,
            DeviceCapability::CpuHeavy,
            DeviceCapability::Camera,
        ],
        1,
        1,
        1,
        10,
        [0xDA; 16],
    )
    .unwrap();
    req.required_capabilities.swap(0, 2);
    let err = req.verify(&sk.verifying_key()).unwrap_err();
    assert!(matches!(
        err,
        DeviceMeshError::TaskCapabilitiesNotSorted
    ));
}

// ── TaskResult adversarial ────────────────────────────────────────

#[test]
fn adversarial_task_result_cross_executor_rejected() {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk_a, _) = mint_subkey(
        &master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365,
    )
    .unwrap();
    let (sk_b, _) = mint_subkey(
        &master, DeviceClass::Laptop, [0xBB; DEVICE_ID_LEN], 0, 365,
    )
    .unwrap();
    let result = sign_task_result(
        &sk_a,
        [0xEE; 32],
        [0xFF; FILE_ID_LEN],
        8192,
        1,
    )
    .unwrap();
    let err = result.verify(&sk_b.verifying_key()).unwrap_err();
    assert!(matches!(err, DeviceMeshError::TaskResultVerifyFail));
}

#[test]
fn adversarial_task_result_tampered_output_size_rejected() {
    let sk = make_subkey();
    let mut result = sign_task_result(
        &sk,
        [0xEE; 32],
        [0xFF; FILE_ID_LEN],
        8192,
        1,
    )
    .unwrap();
    result.output_byte_size = 9_999_999;
    let err = result.verify(&sk.verifying_key()).unwrap_err();
    assert!(matches!(err, DeviceMeshError::TaskResultVerifyFail));
}

#[test]
fn adversarial_task_result_substitute_executor_id_rejected() {
    let sk = make_subkey();
    let mut result = sign_task_result(
        &sk,
        [0xEE; 32],
        [0xFF; FILE_ID_LEN],
        8192,
        1,
    )
    .unwrap();
    result.executor_device_id = [0xCD; DEVICE_ID_LEN];
    let err = result.verify(&sk.verifying_key()).unwrap_err();
    assert!(matches!(err, DeviceMeshError::TaskResultVerifyFail));
}

// ── pick_executor adversarial ─────────────────────────────────────

#[test]
fn adversarial_picker_no_match_returns_none() {
    let master = MasterIdentity::generate(&mut OsRng);
    let mut reg = CapabilityRegistry::empty();
    reg.ingest(
        sign_capability_attestation(
            &master,
            [0xAA; DEVICE_ID_LEN],
            vec![DeviceCapability::Microphone],
            0,
            365,
        )
        .unwrap(),
        &master.verifying_key(),
    )
    .unwrap();
    let caps = vec![SourceCapacity {
        device_id: [0xAA; DEVICE_ID_LEN],
        estimated_bps: 1_000,
        current_load_bytes: 0,
    }];
    let pick = pick_executor(&[DeviceCapability::Tee], &reg, &caps, 100);
    assert!(pick.is_none());
}

#[test]
fn adversarial_picker_unattested_device_not_picked() {
    // Capacity profile mentions device X but registry has no
    // attestation for X → X is ineligible.
    let master = MasterIdentity::generate(&mut OsRng);
    let reg = CapabilityRegistry::empty();
    let caps = vec![SourceCapacity {
        device_id: [0xAA; DEVICE_ID_LEN],
        estimated_bps: 1_000_000_000,
        current_load_bytes: 0,
    }];
    let pick = pick_executor(&[DeviceCapability::Gpu], &reg, &caps, 100);
    assert!(pick.is_none());
    let _ = master;
}
