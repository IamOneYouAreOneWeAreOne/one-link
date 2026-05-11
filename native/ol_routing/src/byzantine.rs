//! Byzantine-tolerant tau measurement (Phase D #2, ADR-0029).
//!
//! Harvested from `OneField/onefield/mesh/byzantine.cl`. The BFT
//! threshold math is identical; on top we add a tau-corroboration
//! predicate that catches malicious peers reporting fake high τ_c.
//!
//! Per `FILE_ENGINE_V2_PLAN.md` Phase D item #2:
//!
//! > Byzantine-tolerant tau measurement. A malicious peer reporting
//! > fake high τ gets cross-validated against observed delivery;
//! > ignored if no corroboration.

/// Maximum number of Byzantine nodes the protocol tolerates:
/// `floor((N-1)/3)`. Returns 0 for `n_total < 1`.
#[must_use]
pub fn max_byzantine_count(n_total: i64) -> i64 {
    if n_total < 1 {
        0
    } else {
        (n_total - 1) / 3
    }
}

/// True iff `f_faulty` is within the BFT-tolerable bound for a network
/// of `n_total` nodes.
#[must_use]
pub fn quorum_safe(n_total: i64, f_faulty: i64) -> bool {
    f_faulty <= max_byzantine_count(n_total)
}

/// Expected mean degree of a random-geometric graph with `n_nodes`
/// uniformly in the unit square and connection radius `r`:
///
/// ```text
/// E[deg] ~ (N - 1) * pi * r^2     (for r much smaller than 1)
/// ```
#[must_use]
pub fn rgg_mean_degree(n_nodes: i64, radius: f64) -> f64 {
    let pi = std::f64::consts::PI;
    let nf = n_nodes as f64;
    let safe = if nf > 1.0 { nf - 1.0 } else { 0.0 };
    safe * pi * radius * radius
}

/// Conservative connectivity threshold for a random-geometric graph
/// in the unit square: `r >= sqrt(log(N) / (pi * N))` gives a single
/// component with high probability (Penrose 1999).
#[must_use]
pub fn rgg_connectivity_radius(n_nodes: i64) -> f64 {
    let pi = std::f64::consts::PI;
    let nf = n_nodes as f64;
    let safe = if nf > 1.0001 { nf } else { 2.0 };
    (safe.ln() / (pi * safe)).sqrt()
}

/// Tau-corroboration check: a peer reports `claimed_tau_c_s` for a
/// link, but we observed `actual_success_rate` of chunks succeeding
/// over that link in the recent window. If the claim is wildly out
/// of line with observed reality, ignore it.
///
/// Concretely: a peer claiming τ_c=10s on a link where we've watched
/// 50% of chunks drop is lying. We expect roughly
/// `observed_success_rate ≈ 1 - 1/(c * τ_c_s)` (RF heuristic), but
/// the daemon-level check just looks for "claimed-high-but-observed-
/// low" mismatches.
///
/// Returns true iff the claim is consistent (peer can be trusted for
/// this metric); false iff the daemon should ignore the report.
///
/// `tolerance` is the fraction of observed success rate the claim
/// must clear. Default 0.5 means: if the peer claims very-high τ_c
/// (>1s) but the link's observed success rate is less than half of
/// what such a τ_c would predict, reject the claim.
#[must_use]
pub fn tau_claim_corroborated(
    claimed_tau_c_s: f64,
    observed_success_rate: f64,
    tolerance: f64,
) -> bool {
    if claimed_tau_c_s <= 0.0 {
        // Negative or zero claim — trivially "doesn't claim anything
        // meaningful," accept.
        return true;
    }
    let observed = observed_success_rate.clamp(0.0, 1.0);
    let tol = tolerance.clamp(0.0, 1.0);
    // Heuristic: a claimed high τ_c (say >0.1s) should correlate with
    // a high observed success rate. Specifically, we expect
    // observed ≥ 0.5 for any honest "high-stability" claim. For very
    // small claimed τ_c, we don't enforce this.
    if claimed_tau_c_s < 0.001 {
        // Peer claims very-fragile link — no consistency to enforce.
        return true;
    }
    // Map claimed τ_c to an "expected minimum success rate" via a
    // simple monotonic function. For τ_c ≥ 0.1s we expect ≥0.9; for
    // τ_c=0.001s we expect anything.
    let expected_min = 1.0 - (-claimed_tau_c_s.ln() / 6.0).max(0.0);
    let expected = expected_min.clamp(0.0, 0.99);
    observed >= expected * tol
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_byz_for_4_is_one() {
        assert_eq!(max_byzantine_count(4), 1);
    }
    #[test]
    fn max_byz_for_7_is_two() {
        assert_eq!(max_byzantine_count(7), 2);
    }
    #[test]
    fn max_byz_for_100_is_33() {
        assert_eq!(max_byzantine_count(100), 33);
    }
    #[test]
    fn max_byz_for_zero_or_negative_is_zero() {
        assert_eq!(max_byzantine_count(0), 0);
        assert_eq!(max_byzantine_count(-5), 0);
    }
    #[test]
    fn quorum_safe_under_bound() {
        assert!(quorum_safe(10, 3));
    }
    #[test]
    fn quorum_unsafe_above_bound() {
        let bound = max_byzantine_count(10);
        assert!(!quorum_safe(10, bound + 1));
    }
    #[test]
    fn rgg_mean_degree_grows_with_radius() {
        assert!(rgg_mean_degree(200, 0.20) > rgg_mean_degree(200, 0.05));
    }
    #[test]
    fn rgg_connectivity_radius_shrinks_with_n() {
        assert!(rgg_connectivity_radius(10) > rgg_connectivity_radius(1000));
    }

    #[test]
    fn tau_corroboration_rejects_lying_high_claim_with_low_observed_success() {
        // Peer claims τ_c = 1.0s (very stable) but only 10% of chunks
        // get through. Reject.
        assert!(!tau_claim_corroborated(1.0, 0.10, 0.5));
    }

    #[test]
    fn tau_corroboration_accepts_high_claim_with_high_observed_success() {
        // Peer claims τ_c = 1.0s and 95% of chunks get through. OK.
        assert!(tau_claim_corroborated(1.0, 0.95, 0.5));
    }

    #[test]
    fn tau_corroboration_accepts_small_tau_c_claims_without_enforcement() {
        // Peer claims very-fragile link (τ_c < 1ms) — no consistency
        // check enforced (peer is just admitting their link is bad).
        assert!(tau_claim_corroborated(0.0005, 0.05, 0.5));
    }

    #[test]
    fn tau_corroboration_accepts_zero_or_negative_claims() {
        assert!(tau_claim_corroborated(0.0, 0.0, 0.5));
        assert!(tau_claim_corroborated(-1.0, 0.0, 0.5));
    }
}
