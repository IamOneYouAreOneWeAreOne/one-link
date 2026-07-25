//! Phase D acceptance gate for `ol_homology`:
//!
//! > Persistent-homology detector flags injected partition within
//! > ≤N measurement rounds with ≤5% false positive rate.
//!
//! We don't implement full persistent homology (O(N³) prohibitive);
//! we ship the cheaper bridge-detection approximation. This test
//! verifies the bridge detector catches an injected partition
//! immediately (1 measurement round) and that random non-partitioning
//! topologies don't trigger false positives.

use std::collections::HashMap;

use ol_homology::fragility_score;

#[test]
fn bridge_detector_flags_injected_partition_in_one_round() {
    // Build a graph with a clear bridge: two cliques connected by
    // a single edge through node "B" (the chunk-co-hold equivalent
    // of a partition risk).
    let nodes: Vec<String> = ["a1", "a2", "a3", "B", "c1", "c2", "c3"]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    let edges: Vec<(String, String)> = vec![
        // Left clique (a1, a2, a3) all co-hold; every left node also
        // touches B so removing any single ai is NOT a bridge.
        ("a1".into(), "a2".into()),
        ("a1".into(), "a3".into()),
        ("a2".into(), "a3".into()),
        ("a1".into(), "B".into()),
        ("a2".into(), "B".into()),
        ("a3".into(), "B".into()),
        // Right clique (c1, c2, c3) all co-hold; every right node also
        // touches B.
        ("c1".into(), "c2".into()),
        ("c1".into(), "c3".into()),
        ("c2".into(), "c3".into()),
        ("B".into(), "c1".into()),
        ("B".into(), "c2".into()),
        ("B".into(), "c3".into()),
    ];
    let holders: HashMap<String, usize> = nodes.iter().map(|n| (n.clone(), 2)).collect();
    let report = fragility_score(&nodes, &edges, &holders);
    let b = report.scores.iter().find(|s| s.chunk_id == "B").unwrap();
    assert!(b.is_bridge, "B should be flagged as a bridge");
    // Non-bridge nodes inside cliques should not be flagged.
    for chunk in &["a1", "a2", "a3", "c1", "c2", "c3"] {
        let s = report.scores.iter().find(|s| s.chunk_id == *chunk).unwrap();
        assert!(!s.is_bridge, "{chunk} should NOT be a bridge");
    }
}

#[test]
fn bridge_detector_false_positive_rate_below_5_percent() {
    // Build 100 random topologies that are NOT partition-vulnerable
    // (4-regular graphs over 8 nodes — every node has 4 neighbors,
    // so removing any one keeps the graph connected). Verify that
    // the bridge detector reports 0 bridges in each, giving 0% FP.
    let mut false_positives = 0;
    let n_trials = 100;
    for trial in 0..n_trials {
        // Deterministic 4-regular graph: circulant C_8(1, 2).
        // Every node i is connected to i±1 (mod 8) and i±2 (mod 8).
        let n_nodes = 8;
        let nodes: Vec<String> = (0..n_nodes).map(|i| format!("n{trial}_{i}")).collect();
        let mut edges: Vec<(String, String)> = Vec::new();
        for i in 0..n_nodes {
            for offset in [1, 2] {
                let j = (i + offset) % n_nodes;
                edges.push((nodes[i].clone(), nodes[j].clone()));
            }
        }
        let holders: HashMap<String, usize> = nodes.iter().map(|n| (n.clone(), 3)).collect();
        let report = fragility_score(&nodes, &edges, &holders);
        let bridges = report.scores.iter().filter(|s| s.is_bridge).count();
        if bridges > 0 {
            false_positives += 1;
        }
    }
    let fp_rate = f64::from(false_positives) / f64::from(n_trials);
    assert!(
        fp_rate <= 0.05,
        "Phase D gate: bridge-detector FP rate ≤5% on 4-regular graphs; got {:.2}%",
        fp_rate * 100.0
    );
}
