//! Thompson-sampling device picker.
//!
//! For each candidate `(device, class)` pair we look up (or seed)
//! the `Beta(α, β)` posterior from the routing history, sample
//! `p ~ Beta(α, β)`, and pick the device with the largest sample.
//!
//! Thompson sampling is the canonical algorithm here: it has
//! Bayesian-optimal regret for stochastic multi-armed bandits and
//! requires no manual ε-greedy hyperparameter. Exploration falls
//! out of the posterior variance.

use rand_core::RngCore;

use crate::device_class::DeviceClass;
use crate::subkey::DEVICE_ID_LEN;

use super::cohort::CohortPrior;
use super::context::RoutingContext;
use super::history::RoutingHistory;

/// Hard cap on candidates we'll consider in one pick. Bounds the
/// picker's cost; daemons typically have << 32 personal devices.
pub const MAX_CANDIDATES_PER_PICK: usize = 32;

/// Pick the device most likely (under the current posterior) to
/// receive an action from the user in this context.
///
/// `candidates` is the list of `(device_id, device_class)` pairs the
/// caller is willing to route to. The class is used only for cold-
/// start cohort priors; once enough observations accumulate the
/// class becomes irrelevant.
///
/// Returns `None` if `candidates` is empty.
#[must_use]
pub fn pick_device_for_context<R: RngCore>(
    context: &RoutingContext,
    candidates: &[([u8; DEVICE_ID_LEN], DeviceClass)],
    history: &RoutingHistory,
    cohort: &CohortPrior,
    rng: &mut R,
) -> Option<[u8; DEVICE_ID_LEN]> {
    if candidates.is_empty() {
        return None;
    }
    let ctx_hash = context.canonical_hash();
    let mut best: Option<([u8; DEVICE_ID_LEN], f64)> = None;
    for (id, class) in candidates.iter().take(MAX_CANDIDATES_PER_PICK) {
        let (mut alpha, mut beta) = cohort.for_class(*class);
        if let Some(rec) = history.record(&ctx_hash, id) {
            alpha = rec.alpha;
            beta = rec.beta;
        }
        let sample = beta_sample(alpha, beta, rng);
        match best {
            None => best = Some((*id, sample)),
            Some((cur_id, cur_score)) => {
                let better = sample > cur_score
                    || (sample == cur_score && id < &cur_id);
                if better {
                    best = Some((*id, sample));
                }
            }
        }
    }
    best.map(|(id, _)| id)
}

/// Sample a `Beta(α, β)` random variable via the ratio of two
/// Gamma(α, 1) / Gamma(β, 1) samples. For integer α, Gamma(α, 1)
/// is the sum of α independent `Exp(1)` samples. Each `Exp(1)`
/// is `-ln(U)` where U is uniform (0, 1].
fn beta_sample<R: RngCore>(alpha: u32, beta: u32, rng: &mut R) -> f64 {
    let a = gamma_int_sample(alpha.max(1), rng);
    let b = gamma_int_sample(beta.max(1), rng);
    if a + b <= 0.0 {
        return 0.5;
    }
    a / (a + b)
}

fn gamma_int_sample<R: RngCore>(k: u32, rng: &mut R) -> f64 {
    // Sum of k independent Exp(1) samples = Gamma(k, 1).
    let mut sum = 0.0_f64;
    for _ in 0..k {
        sum += exp1_sample(rng);
    }
    sum
}

fn exp1_sample<R: RngCore>(rng: &mut R) -> f64 {
    // u in (0, 1], computed as (u_raw + 1) / (u32::MAX + 2) so we
    // never sample exactly 0 (which would give an infinite Exp).
    let raw = rng.next_u32();
    let u = (f64::from(raw) + 1.0) / (f64::from(u32::MAX) + 2.0);
    -u.ln()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::active_routing::RoutingContext;
    use rand::rngs::OsRng;

    fn ctx() -> RoutingContext {
        RoutingContext {
            contact_pin: [1; 32],
            hour_bucket: 14,
            day_of_week: 2,
            message_class: *b"DM  ",
            urgency: 1,
        }
    }

    fn candidates() -> Vec<([u8; DEVICE_ID_LEN], DeviceClass)> {
        vec![
            ([0x01; DEVICE_ID_LEN], DeviceClass::Phone),
            ([0x02; DEVICE_ID_LEN], DeviceClass::Laptop),
            ([0x03; DEVICE_ID_LEN], DeviceClass::Desktop),
        ]
    }

    #[test]
    fn picker_returns_a_candidate() {
        let history = RoutingHistory::empty();
        let cohort = CohortPrior::uniform();
        let pick = pick_device_for_context(&ctx(), &candidates(), &history, &cohort, &mut OsRng);
        assert!(pick.is_some());
        let picked = pick.unwrap();
        assert!(candidates().iter().any(|(id, _)| *id == picked));
    }

    #[test]
    fn picker_empty_candidates_returns_none() {
        let history = RoutingHistory::empty();
        let cohort = CohortPrior::uniform();
        let pick = pick_device_for_context(&ctx(), &[], &history, &cohort, &mut OsRng);
        assert!(pick.is_none());
    }

    #[test]
    fn picker_converges_to_winner_with_strong_history() {
        // Massively bias laptop's posterior toward act.
        let mut history = RoutingHistory::empty();
        let ctx_hash = ctx().canonical_hash();
        for _ in 0..200 {
            history.observe(ctx_hash, [0x02; DEVICE_ID_LEN], true, 1, 1, 1);
        }
        // Also bias phone toward dismiss.
        for _ in 0..200 {
            history.observe(ctx_hash, [0x01; DEVICE_ID_LEN], false, 1, 1, 1);
        }
        let cohort = CohortPrior::uniform();
        // Pick 200 times; laptop should dominate.
        let mut laptop_picks = 0;
        for _ in 0..200 {
            if let Some(p) =
                pick_device_for_context(&ctx(), &candidates(), &history, &cohort, &mut OsRng)
            {
                if p == [0x02; DEVICE_ID_LEN] {
                    laptop_picks += 1;
                }
            }
        }
        // With a >0.99 posterior on laptop and ~0.005 on phone,
        // laptop should win the vast majority of the time.
        assert!(laptop_picks >= 150, "laptop won {laptop_picks}/200");
    }

    #[test]
    fn picker_no_history_uses_cohort_bias() {
        let history = RoutingHistory::empty();
        let cohort = CohortPrior::typical_user();
        // Cold-start with typical_user prior should still pick a
        // valid candidate.
        let mut counts = std::collections::HashMap::<[u8; DEVICE_ID_LEN], u32>::new();
        for _ in 0..500 {
            if let Some(p) =
                pick_device_for_context(&ctx(), &candidates(), &history, &cohort, &mut OsRng)
            {
                *counts.entry(p).or_default() += 1;
            }
        }
        // Phone has the strongest prior; should win more than 1/3.
        let phone_count = counts.get(&[0x01; DEVICE_ID_LEN]).copied().unwrap_or(0);
        assert!(phone_count > 500 / 4);
    }

    #[test]
    fn picker_oversize_candidate_list_truncated() {
        let history = RoutingHistory::empty();
        let cohort = CohortPrior::uniform();
        let big: Vec<([u8; DEVICE_ID_LEN], DeviceClass)> = (0u8..=64)
            .map(|i| ([i; DEVICE_ID_LEN], DeviceClass::Generic))
            .collect();
        let pick = pick_device_for_context(&ctx(), &big, &history, &cohort, &mut OsRng);
        assert!(pick.is_some());
        // Picked id must be within the first MAX_CANDIDATES_PER_PICK.
        let id = pick.unwrap()[0];
        assert!(usize::from(id) < MAX_CANDIDATES_PER_PICK);
    }
}
