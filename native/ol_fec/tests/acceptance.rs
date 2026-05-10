//! Phase C acceptance gate for ADR-0016:
//!
//!   > Reed-Solomon (10,4) survives any 4-shard erasure with 100%
//!   > recovery across ≥10,000 seeds.
//!
//! For each seed:
//! 1. Build 10 random 1 KiB data shards.
//! 2. Encode → 4 parity shards (14 total).
//! 3. Pick 4 random shard indices (out of 14) to drop. Per Cauchy
//!    submatrix theory, ANY 4-erasure pattern is decodable.
//! 4. Decode from the remaining 10 shards.
//! 5. Assert byte-exact recovery of the original 10 data shards.
//!
//! Anything less than 100% across 10K seeds = ADR-0016 doesn't ship.

use ol_fec::Codec;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};

const K: usize = 10;
const M: usize = 4;
const N: usize = K + M; // 14
const SHARD_LEN: usize = 1024;
const SEEDS: u64 = 10_000;

#[test]
fn adr0016_rs_10_4_survives_any_4_erasure_across_10k_seeds() {
    let codec = Codec::new(K, M).expect("RS(10,4) constructs");
    let mut failures = 0usize;
    for seed in 0..SEEDS {
        let mut rng = StdRng::seed_from_u64(seed);
        let data: Vec<Vec<u8>> = (0..K)
            .map(|_| (0..SHARD_LEN).map(|_| rng.r#gen::<u8>()).collect())
            .collect();
        let data_refs: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
        let parity = codec.encode(&data_refs).expect("encode");

        // Pick 4 of 14 indices to drop, uniformly at random.
        let mut indices: Vec<usize> = (0..N).collect();
        indices.shuffle(&mut rng);
        let dropped: Vec<usize> = indices.into_iter().take(M).collect();

        // Assemble the `present` vector.
        let mut present: Vec<Option<&[u8]>> = Vec::with_capacity(N);
        for i in 0..K {
            if dropped.contains(&i) {
                present.push(None);
            } else {
                present.push(Some(data[i].as_slice()));
            }
        }
        for i in 0..M {
            let shard_index = K + i;
            if dropped.contains(&shard_index) {
                present.push(None);
            } else {
                present.push(Some(parity[i].as_slice()));
            }
        }
        let present_count = present.iter().filter(|o| o.is_some()).count();
        assert_eq!(
            present_count, K,
            "exactly K shards must be present after dropping M"
        );

        let decoded = codec.decode(&present).expect("decode");
        if decoded != data {
            failures += 1;
            eprintln!(
                "seed {seed}: dropped={:?}, decoded mismatch",
                dropped
            );
        }
    }
    assert_eq!(failures, 0, "Phase C gate: failed {failures}/{SEEDS}");
    eprintln!(
        "ADR-0016 acceptance: PASSED {SEEDS}/{SEEDS} RS(10,4) decodes with random 4-erasure patterns"
    );
}

/// Additional gate: 100% recovery when ANY combination of `m` shards is
/// dropped — not just random sampling. We enumerate enough seeds to
/// cover every (K+M choose M) = (14 choose 4) = 1001 erasure pattern at
/// least once with high probability.
#[test]
fn adr0016_rs_10_4_recovers_from_every_4_erasure_pattern() {
    let codec = Codec::new(K, M).expect("RS(10,4) constructs");
    let mut rng = StdRng::seed_from_u64(0xCAFE_BABE);
    let data: Vec<Vec<u8>> = (0..K)
        .map(|_| (0..SHARD_LEN).map(|_| rng.r#gen::<u8>()).collect())
        .collect();
    let data_refs: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
    let parity = codec.encode(&data_refs).expect("encode");

    // Enumerate all C(14, 4) = 1001 ways to drop 4 shards.
    let mut tested = 0usize;
    for a in 0..N {
        for b in (a + 1)..N {
            for c in (b + 1)..N {
                for d in (c + 1)..N {
                    let dropped = [a, b, c, d];
                    let mut present: Vec<Option<&[u8]>> = Vec::with_capacity(N);
                    for i in 0..K {
                        if dropped.contains(&i) {
                            present.push(None);
                        } else {
                            present.push(Some(data[i].as_slice()));
                        }
                    }
                    for i in 0..M {
                        let shard_index = K + i;
                        if dropped.contains(&shard_index) {
                            present.push(None);
                        } else {
                            present.push(Some(parity[i].as_slice()));
                        }
                    }
                    let decoded = codec.decode(&present).expect("decode");
                    assert_eq!(decoded, data, "erasure pattern {dropped:?} failed");
                    tested += 1;
                }
            }
        }
    }
    assert_eq!(tested, 1001, "expected to enumerate 1001 patterns");
}
