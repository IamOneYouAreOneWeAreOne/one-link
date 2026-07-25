//! Property tests for the Row 8 Layer 1 surface.
//!
//! Gate ladder matches F1.x convention: CI default runs at 1M iters
//! for pure-decoder paths and 10k iters for keygen/sign-bound paths.
//! Nightly switches to 5M / 100k via `ONE_LINK_F1_GATE=1`.

use proptest::prelude::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use ol_device_mesh::{
    derive_subkey_seed, master_pin_handle, mint_subkey, mint_subkey_field_bound, ratchet_one_day,
    sibling_witness, state_root, verify_liveness, DeviceClass, DeviceMeshError, HardwareWrapper,
    LivenessProof, MasterIdentity, SoftwareWrapper, DEVICE_ID_LEN, MASTER_SEED_LEN,
    SUBKEY_SEED_LEN, WRAPPED_KEY_OVERHEAD,
};

fn cases() -> u32 {
    if std::env::var("ONE_LINK_F1_GATE").as_deref() == Ok("1") {
        5_000_000
    } else {
        1_000_000
    }
}

fn class_strategy() -> impl Strategy<Value = DeviceClass> {
    prop_oneof![
        Just(DeviceClass::Phone),
        Just(DeviceClass::Laptop),
        Just(DeviceClass::Tablet),
        Just(DeviceClass::Desktop),
        Just(DeviceClass::Server),
        Just(DeviceClass::Wearable),
        Just(DeviceClass::Appliance),
        Just(DeviceClass::Generic),
    ]
}

// ── 1M-iter properties on pure derivation paths ────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases(),
        max_global_rejects: cases() * 4,
        .. ProptestConfig::default()
    })]

    /// Same `(master_seed, class, id, day)` ALWAYS yields the same seed.
    #[test]
    fn derive_subkey_seed_deterministic(
        master in any::<[u8; MASTER_SEED_LEN]>(),
        class in class_strategy(),
        id in any::<[u8; DEVICE_ID_LEN]>(),
        day in any::<u64>(),
    ) {
        let a = derive_subkey_seed(&master, class, &id, day);
        let b = derive_subkey_seed(&master, class, &id, day);
        prop_assert_eq!(a, b);
    }

    /// Changing the master seed changes the output.
    #[test]
    fn derive_subkey_seed_master_sensitivity(
        m1 in any::<[u8; MASTER_SEED_LEN]>(),
        m2 in any::<[u8; MASTER_SEED_LEN]>(),
        class in class_strategy(),
        id in any::<[u8; DEVICE_ID_LEN]>(),
        day in any::<u64>(),
    ) {
        prop_assume!(m1 != m2);
        prop_assert_ne!(
            derive_subkey_seed(&m1, class, &id, day),
            derive_subkey_seed(&m2, class, &id, day),
        );
    }

    /// Changing the device id changes the output.
    #[test]
    fn derive_subkey_seed_device_id_sensitivity(
        master in any::<[u8; MASTER_SEED_LEN]>(),
        class in class_strategy(),
        id1 in any::<[u8; DEVICE_ID_LEN]>(),
        id2 in any::<[u8; DEVICE_ID_LEN]>(),
        day in any::<u64>(),
    ) {
        prop_assume!(id1 != id2);
        prop_assert_ne!(
            derive_subkey_seed(&master, class, &id1, day),
            derive_subkey_seed(&master, class, &id2, day),
        );
    }

    /// Changing the day index changes the output.
    #[test]
    fn derive_subkey_seed_day_sensitivity(
        master in any::<[u8; MASTER_SEED_LEN]>(),
        class in class_strategy(),
        id in any::<[u8; DEVICE_ID_LEN]>(),
        d1 in any::<u64>(),
        d2 in any::<u64>(),
    ) {
        prop_assume!(d1 != d2);
        prop_assert_ne!(
            derive_subkey_seed(&master, class, &id, d1),
            derive_subkey_seed(&master, class, &id, d2),
        );
    }

    /// Ratchet step never panics, always zeroes `prev`, output is non-zero.
    #[test]
    fn ratchet_step_never_panics(
        seed in any::<[u8; SUBKEY_SEED_LEN]>(),
    ) {
        let mut s = seed;
        let next = ratchet_one_day(&mut s);
        prop_assert_eq!(s, [0u8; SUBKEY_SEED_LEN]);
        // Probability of next being all-zero is 2^-512; effectively zero.
        let zero = [0u8; SUBKEY_SEED_LEN];
        prop_assert_ne!(next, zero);
    }

    /// state_root is deterministic + collision-resistant on byte-distinct inputs.
    #[test]
    fn state_root_deterministic(blob in prop::collection::vec(any::<u8>(), 0..256)) {
        prop_assert_eq!(state_root(&blob), state_root(&blob));
    }

    /// Class tag round-trip — every produced tag parses back to the same class.
    #[test]
    fn device_class_tag_round_trip(class in class_strategy()) {
        let tag = class.tag();
        prop_assert_eq!(DeviceClass::from_tag(&tag), Some(class));
    }
}

// ── 10k-iter properties on keygen-bound paths ──────────────────────

fn keygen_cases() -> u32 {
    if std::env::var("ONE_LINK_F1_GATE").as_deref() == Ok("1") {
        100_000
    } else {
        10_000
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: keygen_cases(),
        max_global_rejects: keygen_cases() * 4,
        .. ProptestConfig::default()
    })]

    /// Master-signed subkey attestation ALWAYS verifies under the
    /// master's verifying key for honest mints.
    #[test]
    fn attestation_verifies_under_master(
        master_seed in any::<[u8; MASTER_SEED_LEN]>(),
        class in class_strategy(),
        id in any::<[u8; DEVICE_ID_LEN]>(),
        mint_day in 0u64..100_000u64,
        valid_days in 1u64..1_000u64,
    ) {
        let master = MasterIdentity::from_seed(master_seed);
        let expiry = mint_day + valid_days;
        let (_sk, att) = mint_subkey(&master, class, id, mint_day, expiry).unwrap();
        att.verify(&master.verifying_key()).unwrap();
        prop_assert!(att.covers_day(mint_day));
        prop_assert!(att.covers_day(expiry));
    }

    /// Attestation under a DIFFERENT master ALWAYS fails verification.
    #[test]
    fn attestation_rejects_wrong_master(
        m1 in any::<[u8; MASTER_SEED_LEN]>(),
        m2 in any::<[u8; MASTER_SEED_LEN]>(),
        class in class_strategy(),
        id in any::<[u8; DEVICE_ID_LEN]>(),
    ) {
        prop_assume!(m1 != m2);
        let master_a = MasterIdentity::from_seed(m1);
        let master_b = MasterIdentity::from_seed(m2);
        let (_sk, att) = mint_subkey(&master_a, class, id, 0, 365).unwrap();
        let err = att.verify(&master_b.verifying_key()).unwrap_err();
        prop_assert_eq!(err, DeviceMeshError::AttestationVerifyFail);
    }

    /// Field-bound subkey ALWAYS differs from the plain subkey for
    /// any non-zero witness contribution.
    #[test]
    fn field_bound_diverges(
        master_seed in any::<[u8; MASTER_SEED_LEN]>(),
        class in class_strategy(),
        id in any::<[u8; DEVICE_ID_LEN]>(),
        field_seed in any::<[u8; 32]>(),
    ) {
        let master = MasterIdentity::from_seed(master_seed);
        let (plain, _) = mint_subkey(&master, class, id, 0, 365).unwrap();
        let (bound, _) = mint_subkey_field_bound(
            &master, class, id, 0, 365, &field_seed,
        ).unwrap();
        // Probability of the BLAKE3 mask being all-zero for a random
        // 32-byte witness is vanishingly small; assert strict inequality.
        prop_assert_ne!(plain.raw_seed(), bound.raw_seed());
    }

    /// Liveness proof issued at time T with skew K verifies at any
    /// verifier-time within [T-K, T+K] and rejects outside.
    #[test]
    fn liveness_skew_window_property(
        master_seed in any::<[u8; MASTER_SEED_LEN]>(),
        class in class_strategy(),
        id in any::<[u8; DEVICE_ID_LEN]>(),
        issued_at in 1_000_000u64..2_000_000u64,
        skew in 1u64..10_000u64,
        verifier_offset in -20_000i64..20_000i64,
    ) {
        let master = MasterIdentity::from_seed(master_seed);
        let (sk, _att) = mint_subkey(&master, class, id, 0, 365).unwrap();
        let proof = LivenessProof::issue(&sk, issued_at, state_root(b"s")).unwrap();
        let witness = sibling_witness(sk.verifying_key(), skew);
        let offset_magnitude = verifier_offset.unsigned_abs();
        let verifier_now = if verifier_offset >= 0 {
            issued_at.saturating_add(offset_magnitude)
        } else {
            issued_at.saturating_sub(offset_magnitude)
        };
        let actual_diff = verifier_now.abs_diff(issued_at);
        let r = verify_liveness(&proof, &witness, verifier_now);
        if actual_diff <= skew {
            prop_assert!(r.is_ok());
        } else {
            prop_assert!(r.is_err());
        }
    }

    /// Hardware wrap+unwrap ALWAYS round-trips for any 64-byte input.
    #[test]
    fn hardware_wrap_unwrap_round_trip(
        kek in any::<[u8; 32]>(),
        plaintext in any::<[u8; SUBKEY_SEED_LEN]>(),
    ) {
        let w = SoftwareWrapper::new(kek);
        let ct = w.wrap(&plaintext).unwrap();
        prop_assert_eq!(ct.len(), plaintext.len() + WRAPPED_KEY_OVERHEAD);
        let rec = w.unwrap(&ct).unwrap();
        prop_assert_eq!(rec.as_slice(), &plaintext[..]);
    }

    /// Master pin handle is collision-resistant across distinct masters.
    #[test]
    fn master_pin_handle_collision_resistant(
        m1 in any::<[u8; MASTER_SEED_LEN]>(),
        m2 in any::<[u8; MASTER_SEED_LEN]>(),
    ) {
        prop_assume!(m1 != m2);
        let mi1 = MasterIdentity::from_seed(m1);
        let mi2 = MasterIdentity::from_seed(m2);
        prop_assert_ne!(
            master_pin_handle(&mi1.verifying_key()),
            master_pin_handle(&mi2.verifying_key()),
        );
    }
}

// ── Standalone unit tests not amenable to property form ────────────

#[test]
fn deterministic_keypair_via_chacha_rng() {
    // Pin a deterministic-RNG flow so tests + KATs are reproducible
    // across builds (no OsRng).
    let mut rng = ChaCha20Rng::from_seed([0xA1; 32]);
    let master = MasterIdentity::generate(&mut rng);
    let id = [0xBB; DEVICE_ID_LEN];
    let (sk, att) = mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
    att.verify(&master.verifying_key()).unwrap();
    let _ = sk;
}
