//! τ_c × persistent-homology coupling.
//!
//! When `ol_homology` detects a closing-loop fragility event in the
//! chunk-co-hold graph, that's a *predictive* signal: the topology
//! is about to lose redundancy in a localized region. Without the
//! field, the daemon would react by re-replicating after the
//! partition opens. With the field, the homology event sources a
//! *negative spike* into the coherence-source term — the field then
//! computes a new equilibrium where the affected region's
//! neighborhood already routes around the fragility BEFORE the
//! partition completes.
//!
//! This is the difference between reaction and anticipation.
//!
//! ## Data flow
//!
//! ```text
//! ol_homology detects fragility cycle in [peer_a, peer_b, peer_c]
//!   → emit FragilityEvent { affected_nodes, severity }
//!   → inject_fragility_events() modifies the source vector S
//!   → next solve_helmholtz() re-equilibrates the field
//!   → Dijkstra over the new nu-score landscape avoids the region
//! ```
//!
//! The injection is *additive* (not destructive): events accumulate
//! per node, with severity weighting. A peer that's been flagged for
//! 3 separate fragility cycles in the same round gets 3× the
//! source-side penalty.

/// One fragility event from `ol_homology`. Carries the affected
/// peer indices + a severity ∈ (0, 1] describing how closing the
/// loop would degrade swarm-wide redundancy.
#[derive(Debug, Clone)]
pub struct FragilityEvent {
    /// Indices of peers participating in the closing loop. Each gets
    /// a source-term spike of strength proportional to `severity`.
    pub affected_nodes: Vec<usize>,
    /// Severity ∈ (0, 1]. 1.0 = imminent partition, 0.1 = mild loop.
    pub severity: f64,
}

/// Modify the source vector `S` to encode the fragility events. The
/// events are applied as *negative* contributions to the source —
/// reducing `S[node]` proportionally to severity. Lower S means lower
/// field response means higher nu-cost means routes avoid the node.
///
/// The clamp at zero prevents pathological inputs from driving S
/// strongly negative; a node that was already a weak source becomes
/// a sink, not a repellor.
///
/// Returns the per-node penalty applied (sum of severity * weight
/// across all events involving the node), for diagnostics.
pub fn inject_fragility_events(
    source: &mut [f64],
    events: &[FragilityEvent],
    coupling_strength: f64,
) -> Vec<f64> {
    let n = source.len();
    let mut applied = vec![0.0; n];
    for ev in events {
        // Clamp severity to a sane range — homology might emit
        // numerically-out-of-band severities under degenerate
        // graphs, so we don't trust it blindly.
        let sev = ev.severity.clamp(0.0, 1.0);
        for &node in &ev.affected_nodes {
            if node < n {
                let penalty = coupling_strength * sev;
                source[node] = (source[node] - penalty).max(0.0);
                applied[node] += penalty;
            }
        }
    }
    applied
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragility_reduces_source_at_affected_nodes() {
        let mut s = vec![1.0; 10];
        let events = vec![FragilityEvent {
            affected_nodes: vec![2, 5, 7],
            severity: 0.5,
        }];
        let applied = inject_fragility_events(&mut s, &events, 1.0);
        // Affected nodes: source drops by 0.5.
        assert!((s[2] - 0.5).abs() < 1e-12);
        assert!((s[5] - 0.5).abs() < 1e-12);
        assert!((s[7] - 0.5).abs() < 1e-12);
        // Unaffected nodes: untouched.
        assert!((s[0] - 1.0).abs() < 1e-12);
        // Applied vector matches.
        assert!((applied[2] - 0.5).abs() < 1e-12);
        assert!((applied[0] - 0.0).abs() < 1e-12);
    }

    #[test]
    fn fragility_clamps_at_zero() {
        // A single very-strong event must not drive S negative.
        let mut s = vec![0.1; 5];
        let events = vec![FragilityEvent {
            affected_nodes: vec![0],
            severity: 1.0,
        }];
        inject_fragility_events(&mut s, &events, 10.0); // would normally subtract 10
        assert!(s[0] >= 0.0, "source clamped: got {}", s[0]);
        assert!(s[0] < 1e-12, "source should saturate to 0");
    }

    #[test]
    fn multiple_events_at_same_node_accumulate() {
        let mut s = vec![5.0; 3];
        let events = vec![
            FragilityEvent {
                affected_nodes: vec![1],
                severity: 1.0,
            },
            FragilityEvent {
                affected_nodes: vec![1],
                severity: 0.5,
            },
            FragilityEvent {
                affected_nodes: vec![1],
                severity: 0.5,
            },
        ];
        inject_fragility_events(&mut s, &events, 1.0);
        // 5.0 - (1.0 + 0.5 + 0.5) = 3.0
        assert!((s[1] - 3.0).abs() < 1e-12);
    }

    #[test]
    fn out_of_range_node_ignored() {
        let mut s = vec![1.0; 3];
        let events = vec![FragilityEvent {
            affected_nodes: vec![99],
            severity: 1.0,
        }];
        // Should not panic.
        let applied = inject_fragility_events(&mut s, &events, 1.0);
        assert_eq!(applied.len(), 3);
        assert!(s.iter().all(|&v| (v - 1.0).abs() < 1e-12));
    }

    #[test]
    fn severity_clamped_to_unit_interval() {
        let mut s = vec![10.0; 3];
        let events = vec![
            FragilityEvent {
                affected_nodes: vec![0],
                severity: 5.0, // out of range, should clamp to 1.0
            },
            FragilityEvent {
                affected_nodes: vec![1],
                severity: -1.0, // out of range, should clamp to 0.0
            },
        ];
        inject_fragility_events(&mut s, &events, 1.0);
        assert!((s[0] - 9.0).abs() < 1e-12); // clamped to severity 1
        assert!((s[1] - 10.0).abs() < 1e-12); // clamped to severity 0, no change
    }
}
