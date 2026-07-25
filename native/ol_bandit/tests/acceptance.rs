//! Phase C primitive acceptance gate for ADR-0019:
//!
//!   > Bandit converges on a known-optimum synthetic arm within ≤200
//!   > interactions in simulation.
//!
//! Simulation: 5-arm bandit where arm probabilities are
//! `{0.20, 0.40, 0.55, 0.70, 0.85}`. Arm 4 (p = 0.85) is the optimum.
//! We "interact" by selecting an arm and observing a Bernoulli(p)
//! reward. After 200 interactions, the bandit's `best_arm()` MUST be
//! arm 4. Repeat across 100 random seeds; require ≥95% convergence
//! (some unlucky seeds may need a few more rounds). This verifies the
//! policy-neutral sampler, not any deferred non-route control loop.

use ol_bandit::{Bandit, BanditRng, BanditSeed};

fn bounded_ratio(numerator: u64, denominator: u64) -> f64 {
    assert!(denominator > 0, "ratio denominator must be non-zero");
    let numerator = u32::try_from(numerator).expect("acceptance-test count fits u32");
    let denominator = u32::try_from(denominator).expect("acceptance-test count fits u32");
    f64::from(numerator) / f64::from(denominator)
}

#[test]
fn adr0019_bandit_converges_within_200_interactions() {
    const N_SEEDS: u64 = 100;
    const HORIZON: usize = 200;
    const ARM_PROBABILITIES: [f64; 5] = [0.20, 0.40, 0.55, 0.70, 0.85];
    const OPTIMAL_ARM: usize = 4;

    let mut converged = 0usize;
    let mut total_optimal_pulls_in_last_half = 0u64;
    let mut total_pulls_in_last_half = 0u64;

    for seed in 0..N_SEEDS {
        let mut rng = BanditSeed::new(0xCAFE_BABE_u64.wrapping_add(seed));
        let mut bandit = Bandit::new(ARM_PROBABILITIES.len()).unwrap();
        let half = HORIZON / 2;

        for t in 0..HORIZON {
            let idx = bandit.select(&mut rng);
            // Simulate Bernoulli reward.
            let p = ARM_PROBABILITIES[idx];
            let u = rng.next_f64();
            let reward = if u < p { 1.0 } else { 0.0 };
            bandit.update(idx, reward).expect("valid update");

            if t >= half {
                total_pulls_in_last_half += 1;
                if idx == OPTIMAL_ARM {
                    total_optimal_pulls_in_last_half += 1;
                }
            }
        }

        if bandit.best_arm() == OPTIMAL_ARM {
            converged += 1;
        }
    }

    let convergence_rate = bounded_ratio(
        u64::try_from(converged).expect("seed count fits u64"),
        N_SEEDS,
    );
    let optimal_pull_fraction =
        bounded_ratio(total_optimal_pulls_in_last_half, total_pulls_in_last_half);

    eprintln!(
        "ADR-0019 bandit convergence: {converged}/{N_SEEDS} = {:.1}% of seeds picked the optimal arm by step {HORIZON}",
        convergence_rate * 100.0,
    );
    eprintln!(
        "  In the last half of the horizon, {:.1}% of pulls went to the optimal arm.",
        optimal_pull_fraction * 100.0,
    );

    // Phase C gate: ≥95% of seeds converge on the optimal arm by step 200.
    assert!(
        convergence_rate >= 0.95,
        "Phase C gate: bandit converged on only {:.1}% of seeds (need ≥95%)",
        convergence_rate * 100.0,
    );
    // Sanity: the bandit should be EXPLOITING by the second half — at
    // least 60% of pulls in the last half on the optimal arm.
    assert!(
        optimal_pull_fraction >= 0.60,
        "bandit isn't exploiting; only {:.1}% optimal pulls in last half (need ≥60%)",
        optimal_pull_fraction * 100.0,
    );
}

/// Tighter gate: even with a small gap between best and second-best,
/// the bandit converges within the bound.
#[test]
fn bandit_handles_small_arm_gap() {
    const N_SEEDS: u64 = 100;
    const HORIZON: usize = 500; // Tighter gap → larger horizon allowed
    const ARM_PROBABILITIES: [f64; 4] = [0.55, 0.60, 0.65, 0.70];
    const OPTIMAL_ARM: usize = 3;

    let mut converged = 0usize;
    for seed in 0..N_SEEDS {
        let mut rng = BanditSeed::new(0xDEAD_BEEF_u64.wrapping_add(seed));
        let mut bandit = Bandit::new(ARM_PROBABILITIES.len()).unwrap();
        for _ in 0..HORIZON {
            let idx = bandit.select(&mut rng);
            let p = ARM_PROBABILITIES[idx];
            let u = rng.next_f64();
            let reward = if u < p { 1.0 } else { 0.0 };
            bandit.update(idx, reward).unwrap();
        }
        if bandit.best_arm() == OPTIMAL_ARM {
            converged += 1;
        }
    }
    let rate = bounded_ratio(
        u64::try_from(converged).expect("seed count fits u64"),
        N_SEEDS,
    );
    eprintln!(
        "small-gap bandit convergence at HORIZON={HORIZON}: {converged}/{N_SEEDS} = {:.1}%",
        rate * 100.0,
    );
    assert!(rate >= 0.75, "small-gap bandit only {rate:.2} convergence");
}
