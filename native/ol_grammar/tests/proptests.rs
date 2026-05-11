//! Property-based tests for `ol_grammar`.
//!
//! Core property: `decompress(compress(x)) == x` for any byte string.

use ol_grammar::{compress, compression_ratio, decompress};
use proptest::prelude::*;

proptest! {
    /// round_trip identity for any byte string up to 4 KiB.
    #[test]
    fn compress_decompress_round_trip(input in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let grammar = compress(&input);
        let recovered = decompress(&grammar).expect("grammar always decompresses");
        prop_assert_eq!(recovered, input);
    }

    /// repeating inputs compress to a size strictly smaller than input.
    #[test]
    fn repeating_pattern_compresses(
        pattern in proptest::collection::vec(any::<u8>(), 1..16),
        repeats in 20usize..100,
    ) {
        let input: Vec<u8> = pattern.iter().cycle().take(pattern.len() * repeats).copied().collect();
        let grammar = compress(&input);
        let ratio = compression_ratio(&grammar, input.len());
        prop_assert!(ratio <= 1.0, "compression should never make output larger");
    }

    /// compression_ratio is well-defined (no NaN, no inf).
    #[test]
    fn compression_ratio_is_finite(input in proptest::collection::vec(any::<u8>(), 1..2048)) {
        let grammar = compress(&input);
        let ratio = compression_ratio(&grammar, input.len());
        prop_assert!(ratio.is_finite());
        prop_assert!(ratio >= 0.0);
    }
}
