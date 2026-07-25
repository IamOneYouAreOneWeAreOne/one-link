//! Property-based tests for `ol_duress`.

use ol_duress::{DuressGate, DuressOutcome, GateError};
use proptest::prelude::*;

proptest! {
    /// Wrong passphrase (one that doesn't match either expected check)
    /// always returns Rejected — never silently unlocks.
    #[test]
    fn wrong_passphrase_always_rejected(
        real_root in any::<[u8; 32]>(),
        duress_root in any::<[u8; 32]>(),
        pair_secret in any::<[u8; 32]>(),
        wrong_pw in proptest::collection::vec(any::<u8>(), 1..64),
        garbage_check_a in any::<[u8; 32]>(),
        garbage_check_b in any::<[u8; 32]>(),
    ) {
        let gate = DuressGate::new(real_root, duress_root, pair_secret);
        // Garbage check hashes are extremely unlikely to match any
        // derive_key output from a random passphrase. (Birthday-bound
        // collision probability ~1 / 2^128 per byte.)
        match gate.open(&wrong_pw, &garbage_check_a, &garbage_check_b) {
            Err(GateError::Rejected) => {} // expected
            Ok(_) => prop_assert!(false, "garbage check matched a random passphrase"),
            Err(GateError::InvalidInput) => prop_assert!(false, "non-empty pw rejected as invalid"),
        }
    }

    /// Empty passphrase always returns InvalidInput.
    #[test]
    fn empty_passphrase_rejected_as_invalid(
        real_root in any::<[u8; 32]>(),
        duress_root in any::<[u8; 32]>(),
        pair_secret in any::<[u8; 32]>(),
        check_a in any::<[u8; 32]>(),
        check_b in any::<[u8; 32]>(),
    ) {
        let gate = DuressGate::new(real_root, duress_root, pair_secret);
        match gate.open(&[], &check_a, &check_b) {
            Err(GateError::InvalidInput) => {} // expected
            other => prop_assert!(false, "empty passphrase produced {:?}", other),
        }
    }

    /// signal_in_ratchet_header is deterministic per gate.
    #[test]
    fn covert_signal_deterministic(
        real_root in any::<[u8; 32]>(),
        duress_root in any::<[u8; 32]>(),
        pair_secret in any::<[u8; 32]>(),
    ) {
        let gate = DuressGate::new(real_root, duress_root, pair_secret);
        let s1 = gate.signal_in_ratchet_header();
        let s2 = gate.signal_in_ratchet_header();
        prop_assert_eq!(s1, s2);
    }
}

/// Sanity: a constructed valid passphrase round-trips through Real path.
#[test]
fn real_passphrase_reaches_real_path() {
    let gate = DuressGate::new([0x42u8; 32], [0xAAu8; 32], [0x77u8; 32]);
    let pw = b"my-real-passphrase";
    let real_check =
        blake3::derive_key("ol-duress-real-check-v1", &[&[0x42u8; 32][..], pw].concat());
    let duress_check = blake3::derive_key(
        "ol-duress-decoy-check-v1",
        &[&[0xAAu8; 32][..], b"some-other-pw".as_slice()].concat(),
    );
    match gate.open(pw, &real_check, &duress_check).unwrap() {
        DuressOutcome::Real(_) => {}
        other @ DuressOutcome::Duress { .. } => panic!("expected real path, got {other:?}"),
    }
}
