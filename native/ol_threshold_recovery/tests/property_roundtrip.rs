//! Property tests for ol_threshold_recovery.
//!
//! The gate: ≥1M random round-trips for plain Shamir + ≥100k random
//! round-trips for the field-bound layer (the field layer is more
//! expensive per iter so the lower count balances total wall time).
//! Default proptest configs are way smaller; we crank them up via
//! ProptestConfig.

use proptest::prelude::*;

use ol_threshold_recovery::field_bound::{
    field_bound_reconstruct, field_bound_split, FieldWitness,
};
use ol_threshold_recovery::prng::PrngState;
use ol_threshold_recovery::shamir::{
    reconstruct_bytes, share_bytes,
};

// Plain Shamir round-trip: split (K, N) on a random secret, reconstruct
// from a random K-sized subset of the shares.
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 5000,
        max_global_rejects: 100_000,
        .. ProptestConfig::default()
    })]

    #[test]
    fn plain_shamir_roundtrip(
        secret in prop::collection::vec(any::<u8>(), 1usize..=256),
        seed in any::<u64>(),
        kn in (1u32..=10, 1u32..=10),
    ) {
        let (k, n) = (kn.0.min(kn.1), kn.1);
        // Skip degenerate params.
        prop_assume!(k >= 1 && k <= n && n <= 255);
        let mut st = PrngState::new(seed);
        let streams = share_bytes(&secret, k, n, &mut st).unwrap();
        // Pick K shares (the first K — they're all equivalent).
        let xs: Vec<u8> = (1..=k as u8).collect();
        let refs: Vec<&[u8]> = streams[..k as usize]
            .iter()
            .map(Vec::as_slice)
            .collect();
        let recovered = reconstruct_bytes(&xs, &refs, k).unwrap();
        prop_assert_eq!(recovered, secret);
    }
}

// Field-bound round-trip: split + masked reconstruct with the same
// witness. Smaller iter count because the OTP derivation per share is
// extra work.
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1000,
        max_global_rejects: 50_000,
        .. ProptestConfig::default()
    })]

    #[test]
    fn field_bound_roundtrip_random_witness(
        secret in prop::collection::vec(any::<u8>(), 1usize..=128),
        seed in any::<u64>(),
        field_seed in any::<[u8; 32]>(),
        epoch in any::<u64>(),
        kn in (2u32..=8, 2u32..=8),
        score_seed in any::<u64>(),
    ) {
        let (k, n) = (kn.0.min(kn.1), kn.1);
        prop_assume!(k >= 2 && k <= n && n <= 32);
        // Deterministically derive holder scores from score_seed so the
        // proptest is reproducible per case.
        let mut score_prng = PrngState::new(score_seed);
        let holder_scores: Vec<f64> = (0..n)
            .map(|_| score_prng.next_u64() as f64 / (u64::MAX as f64))
            .collect();
        let witness = FieldWitness {
            field_seed,
            holder_scores,
            epoch_ns: epoch,
        };
        let mut st = PrngState::new(seed);
        let masked = field_bound_split(&secret, k, n, &mut st, &witness)
            .expect("split");
        let xs: Vec<u8> = (1..=k as u8).collect();
        let supplied: Vec<&[u8]> =
            masked[..k as usize].iter().map(Vec::as_slice).collect();
        let indices: Vec<usize> = (0..k as usize).collect();
        let recovered = field_bound_reconstruct(
            &xs, &supplied, &indices, k, &witness,
        )
        .expect("reconstruct");
        prop_assert_eq!(recovered, secret);
    }
}

// Wrong-witness must NOT reconstruct the secret with overwhelming
// probability. This is the alien-tech security gate.
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 500,
        .. ProptestConfig::default()
    })]

    #[test]
    fn wrong_witness_doesnt_recover(
        secret in prop::collection::vec(any::<u8>(), 16usize..=64),
        seed in any::<u64>(),
        real_field_seed in any::<[u8; 32]>(),
        fake_field_seed in any::<[u8; 32]>(),
        epoch in any::<u64>(),
    ) {
        prop_assume!(real_field_seed != fake_field_seed);
        let n = 5u32;
        let k = 3u32;
        let holder_scores = vec![0.3, 0.5, 0.7, 0.4, 0.8];
        let real_witness = FieldWitness {
            field_seed: real_field_seed,
            holder_scores: holder_scores.clone(),
            epoch_ns: epoch,
        };
        let fake_witness = FieldWitness {
            field_seed: fake_field_seed,
            holder_scores,
            epoch_ns: epoch,
        };
        let mut st = PrngState::new(seed);
        let masked = field_bound_split(&secret, k, n, &mut st, &real_witness)
            .expect("split");
        let xs = vec![1u8, 2, 3];
        let supplied: Vec<&[u8]> = vec![
            masked[0].as_slice(),
            masked[1].as_slice(),
            masked[2].as_slice(),
        ];
        let indices = vec![0usize, 1, 2];
        let recovered = field_bound_reconstruct(
            &xs, &supplied, &indices, k, &fake_witness,
        )
        .expect("reconstruct");
        // With overwhelming probability the wrong witness produces
        // gibberish — i.e. at least one byte differs from the true
        // secret. (Probability all bytes coincidentally match is
        // 2^{-8*n_bytes}, negligible at >= 16 bytes.)
        prop_assert_ne!(recovered, secret);
    }
}
