//! Pinned KAT vectors for the Row 6 cover-traffic primitives.
//!
//! Pins:
//!   1. COVER_SENTINEL byte-equality.
//!   2. COVER_PAYLOAD_MIN.
//!   3. CoverScheduler at (rate=1.0, seed=[0x42; 32]) produces a
//!      known wait-sequence for the first 8 emissions.
//!
//! If any of these drift across releases, cover-packet receivers can
//! silently misidentify cover traffic and the scheduler's audit
//! property (deterministic-per-seed) breaks.
//!
//! ## Regenerating
//!
//! ```text
//! OL_COVER_KAT_REGEN=1 cargo test -p ol_onion --release \
//!     --test known_answer_vectors_cover -- --nocapture
//! ```

use ol_onion::sphinx::cover::{
    CoverScheduler, COVER_DEFAULT_RATE_HZ, COVER_PAYLOAD_MIN, COVER_SENTINEL,
};

/// COVER_SENTINEL is the byte string "OL-COVER".
const EXPECTED_SENTINEL_HEX: &str = "4f4c2d434f564552"; // "OL-COVER"

const SCHED_SEED: [u8; 32] = [0x42; 32];
const SCHED_RATE_HZ: f64 = 1.0;

/// First 8 emissions from `CoverScheduler::new(1.0, [0x42; 32])`.
/// Generated via the BLAKE3 keystream over (seed || counter); pinning
/// these prevents an accidental swap of the keystream-derivation
/// algorithm from silently changing every daemon's emission pattern.
const EXPECTED_FIRST_8_WAITS_MS: [u64; 8] = [
    1906, 1970, 2078, 1167, 3119, 1609, 1013, 1204,
];

fn check_regen<F: FnOnce()>(label: &str, dump: F) {
    if std::env::var("OL_COVER_KAT_REGEN").as_deref() == Ok("1") {
        eprintln!("[KAT REGEN] {label}");
        dump();
    }
}

#[test]
fn kat_cover_sentinel_pinned() {
    let actual_hex: String = COVER_SENTINEL.iter().map(|b| format!("{b:02x}")).collect();
    check_regen("COVER_SENTINEL bytes", || {
        eprintln!("    EXPECTED_SENTINEL_HEX = \"{actual_hex}\"");
    });
    assert_eq!(actual_hex, EXPECTED_SENTINEL_HEX, "COVER_SENTINEL byte drift");
    assert_eq!(COVER_SENTINEL.len(), 8, "Sentinel size pinned at 8 bytes");
    assert_eq!(COVER_SENTINEL, b"OL-COVER", "Sentinel meaning pinned");
}

#[test]
fn kat_cover_payload_min_pinned() {
    assert_eq!(COVER_PAYLOAD_MIN, 64, "COVER_PAYLOAD_MIN drift");
}

#[test]
fn kat_default_rate_pinned() {
    assert!(
        (COVER_DEFAULT_RATE_HZ - 1.0).abs() < f64::EPSILON,
        "Default rate drift: {COVER_DEFAULT_RATE_HZ}"
    );
}

#[test]
fn kat_scheduler_deterministic_sequence_pinned() {
    let mut s = CoverScheduler::new(SCHED_RATE_HZ, SCHED_SEED);
    let actual: Vec<u64> = (0..8).map(|_| s.next_wait_ms()).collect();
    check_regen("First 8 waits (rate=1.0, seed=[0x42; 32])", || {
        eprintln!(
            "    EXPECTED_FIRST_8_WAITS_MS = {:?}",
            actual
        );
    });
    assert_eq!(
        actual,
        EXPECTED_FIRST_8_WAITS_MS,
        "Scheduler keystream drift — every daemon's emission pattern would change!"
    );
}

#[test]
fn kat_scheduler_second_call_advances_counter() {
    // Repeated construction at same seed yields same first value;
    // but reuse of one instance must advance — pin that property.
    let mut s = CoverScheduler::new(SCHED_RATE_HZ, SCHED_SEED);
    let w1 = s.next_wait_ms();
    let w2 = s.next_wait_ms();
    // Different counter → different BLAKE3 output → almost-certainly
    // different wait.
    assert_ne!(w1, w2, "counter must advance keystream");
    assert_eq!(w1, EXPECTED_FIRST_8_WAITS_MS[0]);
    assert_eq!(w2, EXPECTED_FIRST_8_WAITS_MS[1]);
}

// ── Audit M4: authenticated cover-trailer KAT ──────────────────────

use ol_onion::sphinx::cover::{
    is_cover_payload_authenticated, COVER_TRAILER_LEN,
};

/// Pin the audit-M4 cover-trailer derivation.
///
/// Verifies that for a known (shared_key, body) pair, the
/// `is_cover_payload_authenticated` check accepts a payload whose
/// trailing 16 bytes are produced by the same compute-trailer
/// routine, and rejects any single-bit perturbation of either body
/// or trailer. This pins both the derivation function AND the
/// constant-time-equality wiring.
#[test]
fn kat_m4_authenticated_trailer_round_trip() {
    let shared_key = [0xA5u8; 32];
    // Build a synthetic cover payload: sentinel || body || trailer.
    let mut payload = COVER_SENTINEL.to_vec();
    let body_bytes: Vec<u8> = (0u8..128).collect();
    payload.extend_from_slice(&body_bytes);
    // Compute trailer over (sentinel || body).
    let trailer_input = payload.clone();
    let derived =
        blake3::derive_key("ol-sphinx-cover-trailer-v1", &shared_key);
    let mut h = blake3::Hasher::new_keyed(&derived);
    h.update(&trailer_input);
    let mut tag = [0u8; COVER_TRAILER_LEN];
    tag.copy_from_slice(&h.finalize().as_bytes()[..COVER_TRAILER_LEN]);
    payload.extend_from_slice(&tag);

    assert!(
        is_cover_payload_authenticated(&shared_key, &payload),
        "valid trailer rejected — derivation drift?"
    );
    // Bit-flip in body invalidates.
    let mut tampered = payload.clone();
    tampered[COVER_SENTINEL.len() + 1] ^= 0x01;
    assert!(
        !is_cover_payload_authenticated(&shared_key, &tampered),
        "body bit-flip accepted as cover — MAC binding broken!"
    );
    // Bit-flip in trailer invalidates.
    let last = payload.len() - 1;
    let mut bad_tag = payload.clone();
    bad_tag[last] ^= 0x01;
    assert!(
        !is_cover_payload_authenticated(&shared_key, &bad_tag),
        "trailer bit-flip accepted — equality not constant-time-correct?"
    );
    // Different shared_key rejects.
    let other_key = [0x5Au8; 32];
    assert!(
        !is_cover_payload_authenticated(&other_key, &payload),
        "wrong shared_key accepted — MAC key derivation broken!"
    );
}
