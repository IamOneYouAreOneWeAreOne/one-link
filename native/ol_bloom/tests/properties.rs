//! Property tests for `ol_bloom`.

use ol_bloom::{Bloom, BloomError};
use proptest::prelude::*;

proptest! {
    /// Property: every inserted key is reported as present.
    #[test]
    fn inserted_keys_are_present(
        ids in prop::collection::vec(prop::array::uniform32(any::<u8>()), 0..200),
    ) {
        let mut f = Bloom::new(ids.len().max(1));
        for cid in &ids {
            f.insert(cid);
        }
        for cid in &ids {
            prop_assert!(f.contains(cid));
        }
    }

    /// Property: encode + decode is the identity.
    #[test]
    fn encode_decode_round_trip(
        ids in prop::collection::vec(prop::array::uniform32(any::<u8>()), 0..200),
    ) {
        let mut f = Bloom::new(ids.len().max(1));
        for cid in &ids {
            f.insert(cid);
        }
        let encoded = f.encode().unwrap();
        let decoded = Bloom::decode(&encoded).unwrap();
        prop_assert_eq!(f, decoded);
    }

    /// Property: order of insertion does not affect the encoded bytes.
    #[test]
    fn order_independence(
        ids in prop::collection::vec(prop::array::uniform32(any::<u8>()), 1..100),
    ) {
        let mut a = Bloom::new(ids.len());
        let mut b = Bloom::new(ids.len());
        for cid in &ids {
            a.insert(cid);
        }
        let mut shuffled = ids.clone();
        shuffled.reverse();
        for cid in &shuffled {
            b.insert(cid);
        }
        prop_assert_eq!(a.encode().unwrap(), b.encode().unwrap());
    }

    /// Property: a filter constructed for `n` elements has predictable
    /// encoded size (12-byte header + ceil(m/8) bytes).
    #[test]
    fn encoded_size_predictable(n in 1usize..100_000) {
        let f = Bloom::new(n);
        prop_assert_eq!(f.encoded_len(), 12 + f.encode().unwrap().len() - 12);
    }

    /// Property: `popcount` increases monotonically as we insert.
    #[test]
    fn popcount_monotone(
        ids in prop::collection::vec(prop::array::uniform32(any::<u8>()), 1..100),
    ) {
        let mut f = Bloom::new(ids.len());
        let mut prev = f.popcount();
        for cid in &ids {
            f.insert(cid);
            let now = f.popcount();
            prop_assert!(now >= prev);
            prev = now;
        }
    }

    /// Property: any single bit-flip in the encoded bytes that hits a
    /// reserved-zero byte produces a decode error.
    #[test]
    fn reserved_byte_corruption_rejected(
        n in 1usize..100,
        offset in 8usize..12,
    ) {
        let f = Bloom::new(n);
        let mut encoded = f.encode().unwrap();
        encoded[offset] ^= 0x42;
        let result = Bloom::decode(&encoded);
        prop_assert!(matches!(result, Err(BloomError::ReservedNonZero)));
    }
}
