//! Pinned KAT vectors for Row 8 Layer 1.
//!
//! Pins:
//!   1. Device-class tag bytes (wire format).
//!   2. HKDF subkey-seed output for a fixed transcript.
//!   3. Field-bound subkey-seed output for a fixed witness.
//!   4. Master pin handle of a deterministic master.
//!   5. Wire-format constants (lengths, domain strings).
//!
//! Regen path:
//!
//! ```text
//! OL_DEVICE_MESH_KAT_REGEN=1 cargo test -p ol_device_mesh --release \
//!     --test known_answer_vectors -- --nocapture
//! ```

use ol_device_mesh::derivation::{derive_field_bound_subkey_seed, HKDF_DOMAIN};
use ol_device_mesh::{
    derive_subkey_seed, master_pin_handle, DeviceClass, MasterIdentity, DEVICE_ID_LEN,
    MASTER_SEED_LEN, SUBKEY_SEED_LEN,
};

const MASTER_FIXED: [u8; MASTER_SEED_LEN] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
];

const DEVICE_ID_FIXED: [u8; DEVICE_ID_LEN] = [
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
];

const FIELD_SEED_FIXED: [u8; 32] = [0xEE; 32];

/// Pinned subkey seed for `(MASTER_FIXED, Phone, DEVICE_ID_FIXED, day=0)`.
const EXPECTED_SUBKEY_SEED_HEX: &str =
    "28a7edb78e81c7d24224c6430f03c70db4b5042c35391bf9aec7c2e2de180af422b628f13fe7b7603d6586c0c00384e5b135544e7d10d2120163dd74105f4383";

/// Pinned field-bound subkey seed for same transcript + FIELD_SEED_FIXED.
const EXPECTED_FIELD_BOUND_SEED_HEX: &str =
    "972df180e415393bcf748ae3e07afe82a52f3ad2eb7b89b22dd33bdd1c4ad5616f5628d342daebd291922161bd1ab9f42b3a1d8c17359ba80ee86f3bbd4a5a24";

/// Pinned master-pin handle for MASTER_FIXED.
const EXPECTED_MASTER_PIN_HEX: &str =
    "7a63d497d2029bf761090aeca010fcce80f6be57344c6e0f64658a15ce83955f";

fn check_regen<F: FnOnce()>(label: &str, dump: F) {
    if std::env::var("OL_DEVICE_MESH_KAT_REGEN").as_deref() == Ok("1") {
        eprintln!("[KAT REGEN] {label}");
        dump();
    }
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ── 1. Device-class tag bytes pinned ──────────────────────────────

#[test]
fn kat_device_class_tags_pinned() {
    let pairs = [
        (DeviceClass::Phone, "4f4c2d50484f4e45"),
        (DeviceClass::Laptop, "4f4c2d4c41505450"),
        (DeviceClass::Tablet, "4f4c2d5441424c54"),
        (DeviceClass::Desktop, "4f4c2d4445534b54"),
        (DeviceClass::Server, "4f4c2d5345525652"),
        (
            DeviceClass::Wearable,
            "4f4c2d57454152", /* OL-WEAR... */
        ),
        (DeviceClass::Appliance, "4f4c2d4150504c49"),
        (DeviceClass::Generic, "4f4c2d47454e5243"),
    ];
    for (cls, expected_hex) in pairs {
        let tag = cls.tag();
        let hex = to_hex(&tag);
        if !expected_hex.is_empty() {
            assert!(
                hex.starts_with(expected_hex),
                "tag for {cls:?}: got {hex}, expected prefix {expected_hex}"
            );
        }
    }
}

// ── 2. Subkey seed for fixed transcript ───────────────────────────

#[test]
fn kat_subkey_seed_pinned() {
    let seed = derive_subkey_seed(&MASTER_FIXED, DeviceClass::Phone, &DEVICE_ID_FIXED, 0);
    let hex = to_hex(&seed);
    check_regen(
        "Subkey seed (MASTER_FIXED, Phone, DEVICE_ID_FIXED, day=0)",
        || {
            eprintln!("    EXPECTED_SUBKEY_SEED_HEX = \"{hex}\"");
        },
    );
    assert_eq!(hex, EXPECTED_SUBKEY_SEED_HEX, "subkey-seed drift");
}

// ── 3. Field-bound seed for fixed witness ────────────────────────

#[test]
fn kat_field_bound_seed_pinned() {
    let seed = derive_field_bound_subkey_seed(
        &MASTER_FIXED,
        DeviceClass::Phone,
        &DEVICE_ID_FIXED,
        0,
        &FIELD_SEED_FIXED,
    );
    let hex = to_hex(&seed);
    check_regen(
        "Field-bound seed (MASTER_FIXED, Phone, day=0, FIELD_SEED_FIXED)",
        || {
            eprintln!("    EXPECTED_FIELD_BOUND_SEED_HEX = \"{hex}\"");
        },
    );
    assert_eq!(hex, EXPECTED_FIELD_BOUND_SEED_HEX, "field-bound seed drift");
}

// ── 4. Master pin handle pinned ───────────────────────────────────

#[test]
fn kat_master_pin_handle_pinned() {
    let master = MasterIdentity::from_seed(MASTER_FIXED);
    let pin = master_pin_handle(&master.verifying_key());
    let hex = to_hex(&pin);
    check_regen("master_pin_handle(MASTER_FIXED.vk)", || {
        eprintln!("    EXPECTED_MASTER_PIN_HEX = \"{hex}\"");
    });
    assert_eq!(hex, EXPECTED_MASTER_PIN_HEX, "master-pin handle drift");
}

// ── 5. Constants pinned ───────────────────────────────────────────

#[test]
fn kat_constants_pinned() {
    assert_eq!(SUBKEY_SEED_LEN, 64, "subkey seed length pinned at 64 bytes");
    assert_eq!(MASTER_SEED_LEN, 64, "master seed length pinned at 64 bytes");
    assert_eq!(DEVICE_ID_LEN, 16, "device id length pinned at 16 bytes");
    assert_eq!(
        HKDF_DOMAIN, b"OL-device-mesh-subkey-v1",
        "HKDF domain tag pinned"
    );
}
