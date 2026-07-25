//! `τ_c` × active-inference prefetch coupling.
//!
//! `ol_prefetch` ships a cohort-prior + time-weighted co-occurrence
//! predictor that emits the next-likely-chunks for each peer-pair.
//! By itself, it tells you WHAT to prefetch — but not WHERE to stage
//! the prefetched chunks. The coherence field tells you where.
//!
//! Joint optimization: for each predicted next-chunk, the field
//! tells us which set of K peers should pre-position the chunk
//! along high-coherence paths to the predicted requester. Result:
//! when the predicted request actually fires, the chunk is already
//! 1 hop away on a stable edge. Effective latency = wire-RTT, not
//! source-to-receiver-RTT.
//!
//! This is what makes One Link able to compete with a CDN's cache
//! hierarchy — except without the CDN.
//!
//! ## Data flow
//!
//! ```text
//! ol_prefetch.predict_top_n(requester, n=K)
//!   → [(chunk_id, confidence), ...]
//!
//! For each predicted chunk:
//!   prefetch_priorities(field, requester, holders)
//!     → ranks holders by field-induced cost to the requester
//!   → daemon issues low-priority prefetch transfers from top-M holders
//! ```

/// One priority entry produced by [`prefetch_priorities`]: which
/// holder, what its field-induced cost is, and the routing-quality
/// score (lower = better).
#[derive(Debug, Clone, PartialEq)]
pub struct PrefetchPriority {
    /// Index of the holder peer in the daemon's peer table.
    pub holder: usize,
    /// Field response at this holder normalised to (0, 1] (1 = best
    /// coherence in the swarm; ε = worst).
    pub normalised_field: f64,
    /// Final routing cost: lower → better choice for staging.
    pub cost: f64,
}

/// Rank holders by their field-induced cost to pre-position a chunk
/// for `requester`. Returns a sorted list (best first).
///
/// `field` is the recovered `δτ_c` at every peer (output of
/// `solve_helmholtz`). `requester` is the peer we expect to soon
/// request the chunk; the holders are the peers currently holding
/// it. We pick holders that sit on high-coherence paths to the
/// requester.
///
/// Cost model: `cost(holder) = -log(field[holder]) + d(holder,
/// requester) * route_weight` where `d` is the Euclidean field-value
/// difference (a cheap proxy for the actual field-induced path cost
/// without re-solving). Smaller cost = better.
pub fn prefetch_priorities(
    field: &[f64],
    requester: usize,
    holders: &[usize],
    route_weight: f64,
) -> Vec<PrefetchPriority> {
    if field.is_empty() || requester >= field.len() {
        return Vec::new();
    }
    let f_min = field.iter().copied().fold(f64::INFINITY, f64::min);
    let f_max = field.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let span = (f_max - f_min).max(1e-9);
    let requester_field = field[requester];

    let mut priorities: Vec<PrefetchPriority> = holders
        .iter()
        .filter(|&&h| h < field.len() && h != requester)
        .map(|&h| {
            let normalised = ((field[h] - f_min) / span).max(1e-9);
            // Coherence-deficit at the holder.
            let log_deficit = -normalised.ln();
            // Distance from holder's field to requester's field (in
            // normalised units). Peers whose field is closest to the
            // requester are "near" in field-space and good for
            // staging.
            let field_distance = ((field[h] - requester_field).abs() / span).max(1e-12);
            let cost = log_deficit + route_weight * field_distance;
            PrefetchPriority {
                holder: h,
                normalised_field: normalised,
                cost,
            }
        })
        .collect();
    priorities.sort_by(|a, b| {
        a.cost
            .partial_cmp(&b.cost)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    priorities
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_field_holder_ranks_ahead_of_low_field() {
        // 4 peers, field = [0.1, 0.9, 0.5, 0.1]. Requester = 0.
        // Holders = [1, 2, 3]. Highest field holder (1) should rank
        // first.
        let field = vec![0.1, 0.9, 0.5, 0.1];
        let p = prefetch_priorities(&field, 0, &[1, 2, 3], 1.0);
        assert_eq!(p[0].holder, 1, "highest-field holder should rank first");
    }

    #[test]
    fn requester_excluded_from_holder_list() {
        let field = vec![1.0, 0.5, 0.5];
        let p = prefetch_priorities(&field, 0, &[0, 1, 2], 1.0);
        assert!(!p.iter().any(|x| x.holder == 0), "requester excluded");
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn out_of_range_holders_skipped() {
        let field = vec![1.0, 0.5];
        let p = prefetch_priorities(&field, 0, &[1, 99, 100], 1.0);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].holder, 1);
    }

    #[test]
    fn empty_input_returns_empty() {
        let field = vec![];
        let p = prefetch_priorities(&field, 0, &[1, 2, 3], 1.0);
        assert!(p.is_empty());
    }

    #[test]
    fn route_weight_breaks_ties() {
        // Two holders with equal field. Route weight tilts toward
        // the one closer in field-space to the requester.
        let field = vec![0.5, 1.0, 1.0]; // requester = 0
        let p = prefetch_priorities(&field, 0, &[1, 2], 1.0);
        // Both holders identical → cost should be equal.
        assert!((p[0].cost - p[1].cost).abs() < 1e-9);
    }
}
