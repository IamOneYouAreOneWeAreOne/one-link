//! Phase D acceptance gate for `ol_routing`:
//!
//!     Tau-field routing beats shortest-path on a fragile-graph
//!     benchmark by stated margin (≥20% reduction in chunks-lost-
//!     on-partition).
//!
//! The benchmark: build a graph with two parallel paths source→target:
//!
//! - **Short fragile path** (1 hop, very short distance, but
//!   high loss). Naive shortest-path picks this because hop count
//!   is minimal.
//!
//! - **Long stable path** (3 hops, longer aggregate distance,
//!   essentially zero loss).
//!
//! Tau-field routing folds loss into the edge cost via the
//! [`crate::loss_penalty`] term, so the stable path wins despite
//! more hops. We then simulate chunk delivery across each picked
//! route and count "chunks lost on partition" (chunks that hit a
//! lossy edge and get dropped). Tau-field routing must reduce that
//! count by ≥20% over naive shortest-path.

use ol_routing::{edge_cost, shortest_path, AdjacencyGraph};

/// "Naive shortest path" = unweighted hop count (cost-1 per edge).
/// This is what hop-count-only routing would pick when ignoring
/// loss / stability.
fn naive_unit_cost_graph() -> AdjacencyGraph {
    let mut g = AdjacencyGraph::new();
    // Short fragile route: source → relay_lossy → target (2 hops).
    g.add_edge("source", "relay_lossy", 1.0);
    g.add_edge("relay_lossy", "target", 1.0);
    // Long stable route: source → relay_a → relay_b → relay_c → target (4 hops).
    g.add_edge("source", "relay_a", 1.0);
    g.add_edge("relay_a", "relay_b", 1.0);
    g.add_edge("relay_b", "relay_c", 1.0);
    g.add_edge("relay_c", "target", 1.0);
    g
}

/// τ_c-aware cost graph using the same topology. Lossy relay has 70%
/// loss (penalty ~11x); stable relays have 0% loss (penalty 1x).
fn tau_field_graph() -> AdjacencyGraph {
    let mut g = AdjacencyGraph::new();
    // Short fragile route: heavy loss.
    g.add_edge("source", "relay_lossy", edge_cost(0.001, 100.0, 0.70));
    g.add_edge("relay_lossy", "target", edge_cost(0.001, 100.0, 0.70));
    // Long stable route: zero loss across more hops.
    g.add_edge("source", "relay_a", edge_cost(0.001, 100.0, 0.0));
    g.add_edge("relay_a", "relay_b", edge_cost(0.001, 100.0, 0.0));
    g.add_edge("relay_b", "relay_c", edge_cost(0.001, 100.0, 0.0));
    g.add_edge("relay_c", "target", edge_cost(0.001, 100.0, 0.0));
    g
}

/// Walk the produced path and count chunks lost. The "lossy" relays
/// drop `lossy_drop_rate` of chunks; "stable" relays drop nothing.
fn count_chunks_lost(path: &[String], n_chunks: usize, lossy_drop_rate: f64) -> usize {
    // The path includes a lossy hop iff any edge touches the lossy relay.
    let touches_lossy = path
        .windows(2)
        .any(|w| w[0] == "relay_lossy" || w[1] == "relay_lossy");
    if !touches_lossy {
        return 0;
    }
    // Each hop through the lossy relay independently drops; the
    // total survival probability is (1 - lossy_drop_rate)^hops_through_lossy.
    let hops_lossy = path
        .windows(2)
        .filter(|w| w[0] == "relay_lossy" || w[1] == "relay_lossy")
        .count();
    let survival = (1.0 - lossy_drop_rate).powi(hops_lossy as i32);
    let survived = (n_chunks as f64 * survival).round() as usize;
    n_chunks - survived
}

#[test]
fn tau_field_routing_reduces_chunks_lost_on_partition_by_at_least_20_percent() {
    let n_chunks = 1000;
    let lossy_drop_rate = 0.70;

    // Naive: tie-break picks one of the equal-cost paths; we
    // construct the graph so the short (lossy) path is strictly
    // shorter in hop count.
    let naive_path = shortest_path(&naive_unit_cost_graph(), "source", "target")
        .unwrap()
        .path;
    let tau_path = shortest_path(&tau_field_graph(), "source", "target")
        .unwrap()
        .path;

    let naive_lost = count_chunks_lost(&naive_path, n_chunks, lossy_drop_rate);
    let tau_lost = count_chunks_lost(&tau_path, n_chunks, lossy_drop_rate);

    eprintln!(
        "naive path: {:?} → lost {} / {} chunks",
        naive_path, naive_lost, n_chunks
    );
    eprintln!(
        "tau path:   {:?} → lost {} / {} chunks",
        tau_path, tau_lost, n_chunks
    );

    assert!(
        naive_lost > 0,
        "naive shortest-path should pick the fragile route + lose chunks"
    );
    assert_eq!(
        tau_lost, 0,
        "tau_field routing should avoid the lossy edge entirely"
    );

    let reduction = if naive_lost == 0 {
        0.0
    } else {
        (naive_lost as f64 - tau_lost as f64) / naive_lost as f64
    };
    eprintln!("chunk-loss reduction: {:.1}%", reduction * 100.0);
    assert!(
        reduction >= 0.20,
        "Phase D gate: ≥20% chunk-loss reduction; got {:.1}%",
        reduction * 100.0
    );
}
