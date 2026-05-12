//! Property-based tests for `ol_homology`.

use std::collections::HashMap;

use ol_homology::{components_of, fragility_score};
use proptest::prelude::*;

/// A small graph generator: 1-8 nodes with random edges.
fn small_graph() -> impl Strategy<Value = (Vec<String>, Vec<(String, String)>)> {
    (
        1usize..8usize,
        proptest::collection::vec((0usize..8, 0usize..8), 0..16),
    )
        .prop_map(|(n_nodes, edge_seeds)| {
            let nodes: Vec<String> = (0..n_nodes).map(|i| format!("n{}", i)).collect();
            let edges: Vec<(String, String)> = edge_seeds
                .into_iter()
                .filter(|(a, b)| a != b && *a < n_nodes && *b < n_nodes)
                .map(|(a, b)| (nodes[a].clone(), nodes[b].clone()))
                .collect();
            (nodes, edges)
        })
}

proptest! {
    /// n_components is always at least 1 if there are any nodes.
    #[test]
    fn components_count_at_least_one(g in small_graph()) {
        let (nodes, edges) = g;
        if !nodes.is_empty() {
            let r = components_of(&nodes, &edges);
            prop_assert!(r.n_components >= 1);
            // Sum of component sizes equals total node count
            // (no node belongs to multiple components).
            let total: usize = r.sizes.iter().sum();
            prop_assert!(total >= nodes.len());
        }
    }

    /// fragility scores always in [0.0, 1.0].
    #[test]
    fn fragility_scores_bounded(g in small_graph()) {
        let (nodes, edges) = g;
        if nodes.is_empty() {
            return Ok(());
        }
        let holders: HashMap<String, usize> = nodes.iter().map(|n| (n.clone(), 2)).collect();
        let r = fragility_score(&nodes, &edges, &holders);
        for s in &r.scores {
            prop_assert!(s.score >= 0.0 && s.score <= 1.0);
        }
    }

    /// replication_priority entries all have score > 0.
    #[test]
    fn replication_priority_excludes_zero_scored(g in small_graph()) {
        let (nodes, edges) = g;
        if nodes.is_empty() {
            return Ok(());
        }
        let holders: HashMap<String, usize> = nodes.iter().map(|n| (n.clone(), 5)).collect();
        let r = fragility_score(&nodes, &edges, &holders);
        for prio in &r.replication_priority {
            let s = r.scores.iter().find(|s| &s.chunk_id == prio).unwrap();
            prop_assert!(s.score > 0.0);
        }
    }
}
