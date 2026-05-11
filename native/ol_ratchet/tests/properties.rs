//! Proptest properties for `ol_ratchet`.

use ol_ratchet::{Chain, SkippedKeyStore};
use proptest::prelude::*;
use zeroize::Zeroizing;

proptest! {
    /// Two independent chains seeded from the same secret produce
    /// byte-equivalent message keys at every step.
    #[test]
    fn chain_determinism_from_shared_secret(
        secret in prop::array::uniform32(any::<u8>()),
        steps in 1usize..50,
    ) {
        let mut a = Chain::from_shared_secret(&secret);
        let mut b = Chain::from_shared_secret(&secret);
        for _ in 0..steps {
            let mk_a = a.next_message_key();
            let mk_b = b.next_message_key();
            prop_assert_eq!(*mk_a, *mk_b);
        }
    }

    /// `fast_forward(n)` followed by `next_message_key` equals
    /// `next_message_key` called n+1 times from the same chain.
    #[test]
    fn fast_forward_equivalent_to_iteration(
        secret in prop::array::uniform32(any::<u8>()),
        target in 0u64..30,
    ) {
        let mut a = Chain::from_shared_secret(&secret);
        let mut b = Chain::from_shared_secret(&secret);
        a.fast_forward(target).unwrap();
        for _ in 0..target {
            let _ = b.next_message_key();
        }
        prop_assert_eq!(a.step(), b.step());
        prop_assert_eq!(*a.next_message_key(), *b.next_message_key());
    }

    /// `peek_message_key(step)` doesn't mutate state and matches the
    /// key from iterating to `step`.
    #[test]
    fn peek_matches_iteration(
        secret in prop::array::uniform32(any::<u8>()),
        target in 0u64..30,
    ) {
        let a = Chain::from_shared_secret(&secret);
        let mk_peek = a.peek_message_key(target).unwrap();
        // a is unchanged.
        prop_assert_eq!(a.step(), 0);

        let mut b = Chain::from_shared_secret(&secret);
        for _ in 0..target {
            let _ = b.next_message_key();
        }
        let mk_iter = b.next_message_key();
        prop_assert_eq!(*mk_peek, *mk_iter);
    }

    /// Distinct secrets produce distinct message keys at step 0.
    #[test]
    fn distinct_secrets_distinct_first_key(
        sa in prop::array::uniform32(any::<u8>()),
        sb in prop::array::uniform32(any::<u8>()),
    ) {
        prop_assume!(sa != sb);
        let mut a = Chain::from_shared_secret(&sa);
        let mut b = Chain::from_shared_secret(&sb);
        prop_assert_ne!(*a.next_message_key(), *b.next_message_key());
    }

    /// `SkippedKeyStore::insert + take` is a round trip.
    #[test]
    fn skipped_store_insert_take_round_trip(
        step in 0u64..u64::MAX,
        seed in 0u8..255,
    ) {
        let mut store = SkippedKeyStore::with_capacity(8);
        let key: ol_ratchet::MessageKey = Zeroizing::new([seed; 32]);
        store.insert(step, key).unwrap();
        let taken = store.take(step).unwrap();
        prop_assert_eq!(*taken, [seed; 32]);
        // Re-take must fail.
        prop_assert!(store.take(step).is_err());
    }
}
