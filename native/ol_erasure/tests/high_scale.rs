//! High-scale integration: 1000 random plaintexts each striped under
//! `STANDARD` (RS(10,4)), with random 4-shard erasure patterns, all
//! recover to byte-exact plaintexts.

use ol_erasure::{decode_stripe, encode_stripe, Shard, StripeParams};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};

const TRIALS: u32 = 1_000;

#[test]
fn standard_stripe_round_trip_with_random_erasures_1000_trials() {
    let mut failures = 0usize;
    for seed in 0..TRIALS {
        let mut rng = StdRng::seed_from_u64(0xCAFE_F00D + u64::from(seed));
        let len = 1 + rng.random_range(0..32_768);
        let plaintext: Vec<u8> = (0..len).map(|_| rng.random::<u8>()).collect();
        let shards = encode_stripe(&plaintext, StripeParams::STANDARD).unwrap();
        assert_eq!(shards.len(), 14);

        // Random 4-of-14 erasure pattern.
        let mut indices: Vec<usize> = (0..14).collect();
        indices.shuffle(&mut rng);
        let to_drop: Vec<usize> = indices.into_iter().take(4).collect();
        let mut present: Vec<Option<&Shard>> = shards.iter().map(Some).collect();
        for &drop in &to_drop {
            present[drop] = None;
        }

        let decoded = decode_stripe(StripeParams::STANDARD, &present).unwrap();
        if decoded != plaintext {
            failures += 1;
        }
    }
    assert_eq!(
        failures, 0,
        "high-scale stripe failures: {failures}/{TRIALS}"
    );
}
