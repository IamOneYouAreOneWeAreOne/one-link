//! Property-based tests for `ol_routing` using `proptest`.

use ol_routing::{edge_cost, edge_weight, loss_penalty, shortest_path, AdjacencyGraph};
use proptest::prelude::*;

proptest! {
    /// edge_weight is monotonic in dist_m for fixed tau_c_s.
    #[test]
    fn edge_weight_monotonic_in_distance(
        tau in 1.0e-4f64..1.0e-2,
        dist_a in 1.0f64..10000.0,
        dist_b in 1.0f64..10000.0,
    ) {
        let w_a = edge_weight(tau, dist_a);
        let w_b = edge_weight(tau, dist_b);
        if dist_a < dist_b {
            prop_assert!(w_a <= w_b);
        } else if dist_a > dist_b {
            prop_assert!(w_a >= w_b);
        }
    }

    /// edge_weight is anti-monotonic in tau_c_s for fixed dist.
    /// Higher tau_c (more stable link) → lower cost.
    #[test]
    fn edge_weight_anti_monotonic_in_tau(
        dist in 1.0f64..1000.0,
        tau_a in 1.0e-4f64..1.0e-1,
        tau_b in 1.0e-4f64..1.0e-1,
    ) {
        let w_a = edge_weight(tau_a, dist);
        let w_b = edge_weight(tau_b, dist);
        if tau_a < tau_b {
            prop_assert!(w_a >= w_b);
        } else if tau_a > tau_b {
            prop_assert!(w_a <= w_b);
        }
    }

    /// loss_penalty is bounded in [1.0, INFINITY) and monotonic.
    #[test]
    fn loss_penalty_bounded_monotonic(
        loss in 0.0f64..1.0,
    ) {
        let p = loss_penalty(loss);
        prop_assert!(p >= 1.0);
        prop_assert!(p.is_finite());
        // Monotonic: more loss → higher penalty.
        if loss > 0.5 {
            prop_assert!(p >= loss_penalty(0.5));
        }
    }

    /// edge_cost is the product of weight and penalty.
    #[test]
    fn edge_cost_is_product(
        tau in 1.0e-4f64..1.0e-2,
        dist in 1.0f64..1000.0,
        loss in 0.0f64..0.99,
    ) {
        let c = edge_cost(tau, dist, loss);
        let expected = edge_weight(tau, dist) * loss_penalty(loss);
        prop_assert!((c - expected).abs() < 1e-9);
    }

    /// shortest_path always finds a route on a fully-connected graph.
    #[test]
    fn shortest_path_always_finds_route_on_complete_graph(
        n_nodes in 3usize..8,
    ) {
        let mut g = AdjacencyGraph::new();
        let nodes: Vec<String> = (0..n_nodes).map(|i| format!("n{i}")).collect();
        for i in 0..n_nodes {
            for j in 0..n_nodes {
                if i != j {
                    g.add_edge(nodes[i].clone(), nodes[j].clone(), 1.0);
                }
            }
        }
        let r = shortest_path(&g, &nodes[0], &nodes[n_nodes - 1]).unwrap();
        prop_assert!(!r.path.is_empty());
        prop_assert!(r.total_cost >= 0.0);
    }
}
