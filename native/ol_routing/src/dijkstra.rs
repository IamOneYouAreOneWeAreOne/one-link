//! Dijkstra shortest-path over an adjacency-list graph keyed on
//! `String` node ids. Weights are produced by [`crate::edge_cost`] so
//! callers get τ_c-aware routing for free.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};

use thiserror::Error;

/// String node id. Callers use peer fingerprints / relay urls /
/// whatever stable identifier fits their topology.
pub type NodeId = String;

#[derive(Debug, Error)]
pub enum RoutingError {
    #[error("no path from {0} to {1}")]
    NoPath(NodeId, NodeId),
}

/// Adjacency list. Each entry maps `from -> [(to, edge_cost)]`. The
/// caller computes edge_cost via [`crate::edge_cost`] (or any pure
/// f64 monotonic-in-quality metric).
#[derive(Debug, Clone, Default)]
pub struct AdjacencyGraph {
    /// Outgoing edges keyed by source node; each entry is a list of
    /// `(destination_node, edge_cost)` tuples.
    pub edges: HashMap<NodeId, Vec<(NodeId, f64)>>,
}

impl AdjacencyGraph {
    /// Construct an empty graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a directed edge `from -> to` with the given cost. Call
    /// twice (a→b and b→a) for an undirected link.
    pub fn add_edge(&mut self, from: impl Into<NodeId>, to: impl Into<NodeId>, cost: f64) {
        self.edges.entry(from.into()).or_default().push((to.into(), cost));
    }

    /// All neighbors of `node`, if any.
    pub fn neighbors(&self, node: &str) -> &[(NodeId, f64)] {
        self.edges.get(node).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Number of distinct source nodes (nodes that appear as a `from`
    /// in any edge). Useful for diagnostics; callers needing total
    /// node count should pre-compute the union of `from` + `to`.
    pub fn node_count(&self) -> usize {
        self.edges.len()
    }
}

/// Result of a single shortest-path query.
#[derive(Debug, Clone, PartialEq)]
pub struct PathResult {
    /// Ordered sequence of nodes from `start` to `goal`.
    pub path: Vec<NodeId>,
    /// Sum of edge costs along `path`.
    pub total_cost: f64,
}

/// Heap entry — we negate the cost since BinaryHeap is max-heap.
#[derive(Debug)]
struct HeapEntry {
    cost: f64,
    node: NodeId,
}

impl PartialEq for HeapEntry {
    fn eq(&self, other: &Self) -> bool {
        self.cost == other.cost
    }
}
impl Eq for HeapEntry {}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        // Reverse so the heap is a min-heap.
        other.cost.partial_cmp(&self.cost)
    }
}
impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // NaN should never appear (callers pass f64 costs from
        // edge_cost, which is well-defined for any non-negative
        // input). If it ever does, treat NaN as equal.
        self.partial_cmp(other).unwrap_or(Ordering::Equal)
    }
}

/// Dijkstra shortest path from `start` to `goal`. Returns
/// `Ok(PathResult)` with the path (start → ... → goal) and the total
/// cost; `Err(RoutingError::NoPath)` when goal is unreachable.
pub fn shortest_path(
    graph: &AdjacencyGraph,
    start: &str,
    goal: &str,
) -> Result<PathResult, RoutingError> {
    if start == goal {
        return Ok(PathResult {
            path: vec![start.to_string()],
            total_cost: 0.0,
        });
    }

    let mut dist: HashMap<NodeId, f64> = HashMap::new();
    let mut prev: HashMap<NodeId, NodeId> = HashMap::new();
    let mut heap: BinaryHeap<HeapEntry> = BinaryHeap::new();

    dist.insert(start.to_string(), 0.0);
    heap.push(HeapEntry {
        cost: 0.0,
        node: start.to_string(),
    });

    while let Some(HeapEntry { cost, node }) = heap.pop() {
        if node == goal {
            // Reconstruct path by walking prev.
            let mut path = vec![node.clone()];
            let mut cur = &node;
            while let Some(p) = prev.get(cur) {
                path.push(p.clone());
                cur = p;
            }
            path.reverse();
            return Ok(PathResult { path, total_cost: cost });
        }
        // Stale entry — we already found a better path to `node`.
        if cost > *dist.get(&node).unwrap_or(&f64::INFINITY) {
            continue;
        }
        for (neighbor, edge_cost) in graph.neighbors(&node) {
            let next_cost = cost + edge_cost;
            let cur_best = dist.get(neighbor).copied().unwrap_or(f64::INFINITY);
            if next_cost < cur_best {
                dist.insert(neighbor.clone(), next_cost);
                prev.insert(neighbor.clone(), node.clone());
                heap.push(HeapEntry {
                    cost: next_cost,
                    node: neighbor.clone(),
                });
            }
        }
    }
    Err(RoutingError::NoPath(start.to_string(), goal.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_graph() -> AdjacencyGraph {
        // A → B (1) → C (1)
        // A → C (5)
        let mut g = AdjacencyGraph::new();
        g.add_edge("A", "B", 1.0);
        g.add_edge("B", "C", 1.0);
        g.add_edge("A", "C", 5.0);
        g
    }

    #[test]
    fn shortest_path_picks_two_hop_when_cheaper() {
        let g = simple_graph();
        let r = shortest_path(&g, "A", "C").unwrap();
        assert_eq!(r.path, vec!["A".to_string(), "B".to_string(), "C".to_string()]);
        assert!((r.total_cost - 2.0).abs() < 1e-9);
    }

    #[test]
    fn shortest_path_self_to_self() {
        let g = simple_graph();
        let r = shortest_path(&g, "A", "A").unwrap();
        assert_eq!(r.path, vec!["A".to_string()]);
        assert_eq!(r.total_cost, 0.0);
    }

    #[test]
    fn shortest_path_no_route() {
        let g = AdjacencyGraph::new(); // empty
        let err = shortest_path(&g, "A", "B").unwrap_err();
        assert!(matches!(err, RoutingError::NoPath(_, _)));
    }

    #[test]
    fn shortest_path_disconnected_components() {
        let mut g = AdjacencyGraph::new();
        g.add_edge("A", "B", 1.0);
        g.add_edge("C", "D", 1.0);
        // No edge between {A,B} and {C,D}.
        let err = shortest_path(&g, "A", "D").unwrap_err();
        assert!(matches!(err, RoutingError::NoPath(_, _)));
    }

    #[test]
    fn shortest_path_prefers_low_loss_route() {
        // Two paths A→C:
        //   direct A→C with high loss (cost 100)
        //   indirect A→B→C with low loss (cost 2)
        let mut g = AdjacencyGraph::new();
        g.add_edge("A", "C", crate::edge_cost(0.001, 100.0, 0.95));
        g.add_edge("A", "B", crate::edge_cost(0.001, 100.0, 0.0));
        g.add_edge("B", "C", crate::edge_cost(0.001, 100.0, 0.0));
        let r = shortest_path(&g, "A", "C").unwrap();
        assert_eq!(
            r.path,
            vec!["A".to_string(), "B".to_string(), "C".to_string()]
        );
    }
}
