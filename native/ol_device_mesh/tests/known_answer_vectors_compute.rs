//! Pinned KAT vectors for Row 8 Layer 8 distributed compute.

use ol_device_mesh::compute::{
    CapabilityAttestation, DeviceCapability, TaskRequest, TaskResult,
    CAPABILITY_ATTESTATION_DOMAIN, MAX_CAPABILITIES_PER_DEVICE, MAX_TASK_CLASS_LEN,
    TASK_REQUEST_DOMAIN, TASK_RESULT_DOMAIN,
};
use ol_device_mesh::distributed_fs::FILE_ID_LEN;
use ol_device_mesh::DEVICE_ID_LEN;
use std::fmt::Write as _;

fn check_regen<F: FnOnce()>(label: &str, dump: F) {
    if std::env::var("OL_COMPUTE_KAT_REGEN").as_deref() == Ok("1") {
        eprintln!("[KAT REGEN] {label}");
        dump();
    }
}

fn to_hex(b: &[u8]) -> String {
    let mut hex = String::with_capacity(b.len() * 2);
    for byte in b {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hex
}

#[test]
fn kat_domain_tags_pinned() {
    assert_eq!(
        CAPABILITY_ATTESTATION_DOMAIN,
        b"OL-mesh-capability-attestation-v1"
    );
    assert_eq!(TASK_REQUEST_DOMAIN, b"OL-mesh-task-request-v1");
    assert_eq!(TASK_RESULT_DOMAIN, b"OL-mesh-task-result-v1");
}

#[test]
fn kat_bound_constants_pinned() {
    assert_eq!(MAX_CAPABILITIES_PER_DEVICE, 32);
    assert_eq!(MAX_TASK_CLASS_LEN, 32);
}

#[test]
fn kat_capability_tags_pinned() {
    assert_eq!(&DeviceCapability::Gpu.tag(), b"OL-CP-GP");
    assert_eq!(&DeviceCapability::CpuHeavy.tag(), b"OL-CP-CH");
    assert_eq!(&DeviceCapability::Microphone.tag(), b"OL-CP-MC");
    assert_eq!(&DeviceCapability::Camera.tag(), b"OL-CP-CA");
    assert_eq!(&DeviceCapability::LargeDisk.tag(), b"OL-CP-LD");
    assert_eq!(&DeviceCapability::LowLatencyNet.tag(), b"OL-CP-LN");
    assert_eq!(&DeviceCapability::AlwaysOn.tag(), b"OL-CP-AO");
    assert_eq!(&DeviceCapability::Display.tag(), b"OL-CP-DP");
    assert_eq!(&DeviceCapability::GpsLocation.tag(), b"OL-CP-GS");
    assert_eq!(&DeviceCapability::HardwareSecurity.tag(), b"OL-CP-HS");
    assert_eq!(&DeviceCapability::Tee.tag(), b"OL-CP-TE");
}

#[test]
fn kat_capability_attestation_canonical_transcript_pinned() {
    const EXPECTED_HEX: &str = concat!(
        "4f4c2d6d6573682d6361706162696c6974792d6174746573746174696f6e2d7631", // domain
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",                                   // device_id
        "0002",                                                               // count = 2
        "4f4c2d43502d4750",                                                   // OL-CP-GP
        "4f4c2d43502d4348",                                                   // OL-CP-CH
        "0000000000000007",                                                   // mint_day = 7
        "000000000000016d",                                                   // expiry_day = 365
    );
    let bytes = CapabilityAttestation::canonical_transcript(
        &[0xAA; DEVICE_ID_LEN],
        &[DeviceCapability::Gpu, DeviceCapability::CpuHeavy],
        7,
        365,
    );
    let hex = to_hex(&bytes);
    let domain_hex = to_hex(CAPABILITY_ATTESTATION_DOMAIN);
    assert!(hex.starts_with(&domain_hex));
    check_regen("capability-attestation canonical_transcript", || {
        eprintln!("    EXPECTED_HEX = \"{hex}\"");
    });
    assert_eq!(hex, EXPECTED_HEX, "capability-attestation transcript drift");
}

#[test]
fn kat_task_result_canonical_transcript_pinned() {
    const EXPECTED_HEX: &str = concat!(
        "4f4c2d6d6573682d7461736b2d726573756c742d7631", // domain
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", // task_request_id
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",             // executor
        "0000000000000003",                             // day = 3
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // output_file_id
        "0000000000002000",                             // output_byte_size = 8192
        "000000006553f100",                             // completed_unix = 1_700_000_000
    );
    let bytes = TaskResult::canonical_transcript(
        &[0xEE; 32],
        &[0xAA; DEVICE_ID_LEN],
        3,
        &[0xFF; FILE_ID_LEN],
        8192,
        1_700_000_000,
    );
    let hex = to_hex(&bytes);
    let domain_hex = to_hex(TASK_RESULT_DOMAIN);
    assert!(hex.starts_with(&domain_hex));
    check_regen("task-result canonical_transcript", || {
        eprintln!("    EXPECTED_HEX = \"{hex}\"");
    });
    assert_eq!(hex, EXPECTED_HEX, "task-result transcript drift");
}

#[test]
fn kat_task_request_transcript_known_byte_layout() {
    use ol_device_mesh::compute::TaskClass;
    let class = TaskClass::new(b"x").unwrap();
    let bytes = TaskRequest::canonical_transcript(
        &class,
        &[0; DEVICE_ID_LEN],
        0,
        &[0; FILE_ID_LEN],
        &[],
        0,
        0,
        0,
        1,
        &[0; 16],
    );
    // domain(23) + class_len(2) + class(1) + device(16) + day(8)
    //  + file_id(32) + n_caps(2) + max_wall(4) + max_out(8)
    //  + issued(8) + deadline(8) + nonce(16) = 128 bytes
    assert_eq!(bytes.len(), 128);
}
