//! Fragility scoring: how badly would losing a chunk hurt the swarm?

use std::collections::{HashMap, HashSet};

use crate::components::components_of;

/// Per-chunk fragility — higher means MORE fragile (greater priority
/// for preemptive replication).
#[derive(Debug, Clone, PartialEq)]
pub struct FragilityScore {
    pub chunk_id: String,
    pub n_peers_holding: usize,
    /// True iff removing this chunk increases the connected-component
    /// count. Bridge chunks lose the swarm if they fail without
    /// replication.
    pub is_bridge: bool,
    /// Composite score in [0, 1] suitable for replication-priority sort.
    pub score: f64,
}

#[derive(Debug, Clone)]
pub struct FragilityReport {
    pub scores: Vec<FragilityScore>,
    /// Chunks the operator should replicate FIRST (sorted score desc).
    pub replication_priority: Vec<String>,
}

/// Score every chunk on a co-hold graph.
///
/// - `nodes` — chunk ids.
/// - `edges` — `(chunk_a, chunk_b)` co-hold pairs.
/// - `holders` — per-chunk peer-count (how many distinct peers
///   currently hold each chunk).
///
/// Score formula:
///
/// ```text
/// score = max(
///     (3 - n_peers_holding) / 3       // peer-redundancy axis
///     + 0.5 * is_bridge as 0/1,        // bridge bonus
///     0.0,
/// ).min(1.0)
/// ```
///
/// A chunk held by ≤3 peers AND that's a bridge gets the highest
/// score. A chunk held by ≥3 peers and not a bridge gets a score
/// near zero.
pub fn fragility_score(
    nodes: &[String],
    edges: &[(String, String)],
    holders: &HashMap<String, usize>,
) -> FragilityReport {
    // Reference baseline: how many components does the full graph
    // have? Any chunk whose removal raises this is a bridge.
    let baseline = components_of(nodes, edges);
    let baseline_components = baseline.n_components;

    let mut scores: Vec<FragilityScore> = Vec::with_capacity(nodes.len());

    for chunk in nodes {
        let nodes_without: Vec<String> = nodes.iter().filter(|n| n != &chunk).cloned().collect();
        let edges_without: Vec<(String, String)> = edges
            .iter()
            .filter(|(a, b)| a != chunk && b != chunk)
            .cloned()
            .collect();
        let without = components_of(&nodes_without, &edges_without);
        let is_bridge = without.n_components > baseline_components;

        let n_peers = *holders.get(chunk).unwrap_or(&0);
        let peer_axis = ((3_i64 - n_peers as i64).max(0) as f64) / 3.0;
        let bridge_bonus = if is_bridge { 0.5 } else { 0.0 };
        let score = (peer_axis + bridge_bonus).clamp(0.0, 1.0);

        scores.push(FragilityScore {
            chunk_id: chunk.clone(),
            n_peers_holding: n_peers,
            is_bridge,
            score,
        });
    }

    // Sort by descending score; tiebreak by ascending peer count.
    scores.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.n_peers_holding.cmp(&b.n_peers_holding))
    });

    let replication_priority: Vec<String> = scores
        .iter()
        .filter(|s| s.score > 0.0)
        .map(|s| s.chunk_id.clone())
        .collect();

    FragilityReport {
        scores,
        replication_priority,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> String {
        x.to_string()
    }

    fn holders_for(items: &[(&str, usize)]) -> HashMap<String, usize> {
        items.iter().map(|(k, v)| (s(k), *v)).collect()
    }

    #[test]
    fn singleton_with_one_holder_is_maximally_fragile() {
        let r = fragility_score(&[s("a")], &[], &holders_for(&[("a", 1)]));
        assert_eq!(r.scores.len(), 1);
        let a = &r.scores[0];
        assert_eq!(a.chunk_id, s("a"));
        assert_eq!(a.n_peers_holding, 1);
        // is_bridge requires raising component count; removing the
        // only node DROPS to 0 components, which is NOT > 1, so
        // not a "bridge" per our defn. The peer axis alone gives
        // (3-1)/3 ≈ 0.67.
        assert!(a.score > 0.6);
    }

    #[test]
    fn well_replicated_chunk_low_fragility() {
        let r = fragility_score(
            &[s("a"), s("b")],
            &[(s("a"), s("b"))],
            &holders_for(&[("a", 5), ("b", 5)]),
        );
        for s in &r.scores {
            assert!(s.score < 0.3, "chunk {} score={}", s.chunk_id, s.score);
        }
    }

    #[test]
    fn bridge_chunk_gets_bridge_bonus() {
        //   a — b — c  (b is a bridge: removing it splits {a} | {c}).
        let r = fragility_score(
            &[s("a"), s("b"), s("c")],
            &[(s("a"), s("b")), (s("b"), s("c"))],
            &holders_for(&[("a", 5), ("b", 5), ("c", 5)]),
        );
        let b = r.scores.iter().find(|s| s.chunk_id == "b").unwrap();
        assert!(b.is_bridge, "b should be a bridge");
        let a = r.scores.iter().find(|s| s.chunk_id == "a").unwrap();
        assert!(!a.is_bridge);
        // b's score > a's score (bridge bonus pushes it up).
        assert!(b.score > a.score);
    }

    #[test]
    fn replication_priority_sorts_fragile_first() {
        let r = fragility_score(
            &[s("a"), s("b")],
            &[(s("a"), s("b"))],
            &holders_for(&[("a", 1), ("b", 10)]),
        );
        assert_eq!(r.replication_priority.first().map(|x| x.as_str()), Some("a"));
    }

    #[test]
    fn fully_meshed_clique_no_bridges() {
        // 4-node clique — no single node is a bridge.
        let r = fragility_score(
            &[s("a"), s("b"), s("c"), s("d")],
            &[
                (s("a"), s("b")),
                (s("a"), s("c")),
                (s("a"), s("d")),
                (s("b"), s("c")),
                (s("b"), s("d")),
                (s("c"), s("d")),
            ],
            &holders_for(&[("a", 3), ("b", 3), ("c", 3), ("d", 3)]),
        );
        for s in &r.scores {
            assert!(!s.is_bridge, "{} should not be a bridge", s.chunk_id);
        }
    }
}
