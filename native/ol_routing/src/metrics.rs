//! Pure cost math harvested from `OneField/onefield/mesh/routing.cl`.

/// Edge weight for a link with stability proxy `tau_c_s` (seconds) and
/// logical distance `dist_m` (meters or network-equivalent units).
/// Higher `τ_c` lowers cost — stable links are cheaper than fragile ones.
///
/// ```text
/// weight = dist_m / (c * tau_c_s)
/// ```
///
/// `c` is the speed of light (299,792,458 m/s). In network contexts
/// the constant is arbitrary — what matters is monotonicity in
/// (`dist_m` / `tau_c_s`). Keeping the physical constant lets RF + network
/// graphs share a single cost surface when the daemon is meshed with
/// `OneField` RF nodes.
///
/// Units: dimensionless. Closer + more-stable → smaller weight.
#[must_use]
pub fn edge_weight(tau_c_s: f64, dist_m: f64) -> f64 {
    const C: f64 = 299_792_458.0;
    let denom = C * tau_c_s;
    let safe = if denom > 1.0e-30 { denom } else { 1.0e-30 };
    dist_m / safe
}

/// Penalty multiplier when a link's recent loss rate exceeds zero.
/// `loss_rate` is clamped to `[0, 0.99]`. At 0.0 the multiplier is 1.0;
/// at 0.5 it's 4×; at 0.9 it's 100×; at 0.95 it's 400×.
///
/// ```text
/// penalty = 1 / (1 - loss)^2
/// ```
///
/// Quadratic so a small loss bump translates into a strong route
/// preference change — links with sustained loss get aggressively
/// avoided.
#[must_use]
pub fn loss_penalty(loss_rate: f64) -> f64 {
    let safe = loss_rate.clamp(0.0, 0.99);
    1.0 / ((1.0 - safe) * (1.0 - safe))
}

/// Combined edge cost: τ_c-weighted distance scaled by loss penalty.
/// This is what the Dijkstra solver uses as the per-edge weight.
#[must_use]
pub fn edge_cost(tau_c_s: f64, dist_m: f64, loss_rate: f64) -> f64 {
    edge_weight(tau_c_s, dist_m) * loss_penalty(loss_rate)
}

/// True if `cost_a` is strictly preferable to `cost_b` (smaller).
#[must_use]
pub fn prefer_first(cost_a: f64, cost_b: f64) -> bool {
    cost_a < cost_b
}

/// Hysteresis-gated next-hop swap predicate. Returns true only when
/// the candidate cost is at least `hysteresis_factor` smaller than the
/// current cost. Avoids flapping when costs jitter around the same
/// midpoint. Typical `hysteresis_factor` is 0.9 (require 10%
/// improvement to swap).
#[must_use]
pub fn should_swap_hop(current_cost: f64, candidate_cost: f64, hysteresis_factor: f64) -> bool {
    candidate_cost < current_cost * hysteresis_factor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edge_weight_smaller_for_higher_tau_c() {
        let w_short = edge_weight(0.001, 100.0);
        let w_long = edge_weight(0.010, 100.0);
        assert!(w_long < w_short);
    }

    #[test]
    fn edge_weight_grows_with_distance() {
        let w_close = edge_weight(0.001, 10.0);
        let w_far = edge_weight(0.001, 1000.0);
        assert!(w_far > w_close);
    }

    #[test]
    fn edge_weight_clamps_tiny_tau_c() {
        // tau_c_s = 0 must not produce inf or NaN.
        let w = edge_weight(0.0, 100.0);
        assert!(w.is_finite());
    }

    #[test]
    fn loss_penalty_one_at_zero_loss() {
        let p = loss_penalty(0.0);
        assert!((p - 1.0).abs() < 1e-9);
    }

    #[test]
    fn loss_penalty_four_at_half_loss() {
        let p = loss_penalty(0.5);
        assert!((p - 4.0).abs() < 1e-9);
    }

    #[test]
    fn loss_penalty_huge_near_full_loss() {
        let p = loss_penalty(0.95);
        assert!(p > 100.0);
        assert!(p.is_finite());
    }

    #[test]
    fn loss_penalty_clamps_out_of_range() {
        // Negative loss must clamp to 0 (penalty 1).
        assert!((loss_penalty(-0.5) - 1.0).abs() < 1e-9);
        // Loss >= 0.99 must clamp to 0.99 (penalty 10_000).
        let p = loss_penalty(1.5);
        assert!(p.is_finite());
        assert!(p > 100.0);
    }

    #[test]
    fn edge_cost_combines_factors_multiplicatively() {
        let raw = edge_weight(0.001, 100.0);
        let lossy = edge_cost(0.001, 100.0, 0.5);
        // 4x penalty for 50% loss
        assert!((lossy - 4.0 * raw).abs() < raw * 0.01);
    }

    #[test]
    fn prefer_first_strict() {
        assert!(prefer_first(1.0, 2.0));
        assert!(!prefer_first(2.0, 1.0));
        assert!(!prefer_first(1.0, 1.0)); // equal => not strictly preferred
    }

    #[test]
    fn should_swap_hop_respects_hysteresis() {
        // 5% better — does NOT swap with 10% threshold (factor 0.9).
        assert!(!should_swap_hop(1.0, 0.95, 0.9));
        // 20% better — swaps.
        assert!(should_swap_hop(1.0, 0.80, 0.9));
        // No improvement — never swaps.
        assert!(!should_swap_hop(1.0, 1.0, 0.9));
    }
}
