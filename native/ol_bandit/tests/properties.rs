//! Proptest properties for `ol_bandit`.

use ol_bandit::{Bandit, BanditRng, BanditSeed};
use proptest::prelude::*;

proptest! {
    /// `update` never panics for valid `(arm, reward)` pairs and
    /// always errors for invalid ones.
    #[test]
    fn update_total_over_valid_and_invalid(
        n_arms in 1usize..32,
        arm in 0usize..64,
        reward in -1.0f64..2.0,
    ) {
        let mut bandit = Bandit::new(n_arms).unwrap();
        let r = bandit.update(arm, reward);
        if arm >= n_arms || !reward.is_finite() || !(0.0..=1.0).contains(&reward) {
            prop_assert!(r.is_err());
        } else {
            prop_assert!(r.is_ok());
            // Posterior advanced: arm's alpha + beta strictly above
            // the starting (1.0 + 1.0) sum.
            prop_assert!(bandit.arms()[arm].observations() > 2.0);
        }
    }

    /// `select` always returns a valid arm index for any prior state.
    #[test]
    fn select_total_over_reasonable_priors(
        n_arms in 1usize..32,
        seed in any::<u64>(),
    ) {
        let bandit = Bandit::new(n_arms).unwrap();
        let mut rng = BanditSeed::new(seed);
        for _ in 0..50 {
            let idx = bandit.select(&mut rng);
            prop_assert!(idx < n_arms);
        }
    }

    /// `select` after many `update`s prefers the highest-reward arm
    /// (greedy under perfect prior).
    #[test]
    fn select_eventually_finds_best_arm(
        n_arms in 2usize..6,
        best_arm in 0usize..6,
        seed in any::<u64>(),
    ) {
        prop_assume!(best_arm < n_arms);
        let mut bandit = Bandit::new(n_arms).unwrap();
        // Train: best arm always rewarded, others never.
        for _ in 0..100 {
            for arm in 0..n_arms {
                let reward = if arm == best_arm { 1.0 } else { 0.0 };
                bandit.update(arm, reward).unwrap();
            }
        }
        // After 100 rounds of perfect signal, best_arm is unambiguously
        // the winner: alpha = 101, beta = 1 vs others: alpha = 1, beta = 101.
        prop_assert_eq!(bandit.best_arm(), best_arm);

        // Now sample 100x and verify the bandit overwhelmingly picks best_arm.
        let mut rng = BanditSeed::new(seed);
        let mut hits = 0;
        for _ in 0..100 {
            if bandit.select(&mut rng) == best_arm {
                hits += 1;
            }
        }
        prop_assert!(hits >= 80, "best arm hit rate {hits}/100 too low");
    }
}
