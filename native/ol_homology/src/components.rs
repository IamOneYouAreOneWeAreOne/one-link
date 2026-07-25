//! Union-find connected components of the chunk-co-hold graph.

use std::collections::HashMap;

fn find(parent: &mut HashMap<String, String>, x: &str) -> String {
    let mut node = x.to_string();
    loop {
        let parent_node = parent.get(&node).cloned().unwrap_or(node.clone());
        if parent_node == node {
            return node;
        }
        // Path compression.
        let grandparent = parent
            .get(&parent_node)
            .cloned()
            .unwrap_or(parent_node.clone());
        parent.insert(node.clone(), grandparent);
        node = parent_node;
    }
}

fn union(
    parent: &mut HashMap<String, String>,
    rank: &mut HashMap<String, usize>,
    a: &str,
    b: &str,
) {
    let root_a = find(parent, a);
    let root_b = find(parent, b);
    if root_a == root_b {
        return;
    }
    let rank_a = *rank.get(&root_a).unwrap_or(&0);
    let rank_b = *rank.get(&root_b).unwrap_or(&0);
    match rank_a.cmp(&rank_b) {
        std::cmp::Ordering::Less => {
            parent.insert(root_a, root_b);
        }
        std::cmp::Ordering::Greater => {
            parent.insert(root_b, root_a);
        }
        std::cmp::Ordering::Equal => {
            parent.insert(root_b, root_a.clone());
            *rank.entry(root_a).or_insert(0) += 1;
        }
    }
}

/// Per-component summary.
#[derive(Debug, Clone, PartialEq)]
pub struct ComponentReport {
    /// Number of connected components.
    pub n_components: usize,
    /// Component sizes, sorted descending.
    pub sizes: Vec<usize>,
    /// Singletons — chunks held by exactly one peer with no co-holds.
    pub singletons: Vec<String>,
}

/// Compute connected components of a chunk-co-hold graph.
///
/// `nodes` is the set of chunk ids (string for convenience). `edges`
/// are (`chunk_a`, `chunk_b`) pairs meaning "some peer holds BOTH".
/// Symmetric edges are derived automatically — provide each
/// undirected edge once.
pub fn components_of(nodes: &[String], edges: &[(String, String)]) -> ComponentReport {
    // Union-find.
    let mut parent: HashMap<String, String> =
        nodes.iter().map(|n| (n.clone(), n.clone())).collect();
    let mut rank: HashMap<String, usize> = nodes.iter().map(|n| (n.clone(), 0)).collect();

    for (a, b) in edges {
        if !parent.contains_key(a) {
            parent.insert(a.clone(), a.clone());
            rank.insert(a.clone(), 0);
        }
        if !parent.contains_key(b) {
            parent.insert(b.clone(), b.clone());
            rank.insert(b.clone(), 0);
        }
        union(&mut parent, &mut rank, a, b);
    }

    let nodes_owned: Vec<String> = parent.keys().cloned().collect();
    let mut comp_sizes: HashMap<String, Vec<String>> = HashMap::new();
    for n in &nodes_owned {
        let root = find(&mut parent, n);
        comp_sizes.entry(root).or_default().push(n.clone());
    }

    let mut sizes: Vec<usize> = comp_sizes.values().map(std::vec::Vec::len).collect();
    sizes.sort_unstable_by(|a, b| b.cmp(a));
    let singletons: Vec<String> = comp_sizes
        .values()
        .filter_map(|v| {
            if v.len() == 1 {
                Some(v[0].clone())
            } else {
                None
            }
        })
        .collect();

    ComponentReport {
        n_components: comp_sizes.len(),
        sizes,
        singletons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> String {
        x.to_string()
    }

    #[test]
    fn single_chunk_no_edges_is_singleton() {
        let r = components_of(&[s("a")], &[]);
        assert_eq!(r.n_components, 1);
        assert_eq!(r.sizes, vec![1]);
        assert_eq!(r.singletons, vec![s("a")]);
    }

    #[test]
    fn two_disconnected_chunks() {
        let r = components_of(&[s("a"), s("b")], &[]);
        assert_eq!(r.n_components, 2);
        assert_eq!(r.sizes, vec![1, 1]);
        assert_eq!(r.singletons.len(), 2);
    }

    #[test]
    fn two_co_held_chunks_one_component() {
        let r = components_of(&[s("a"), s("b")], &[(s("a"), s("b"))]);
        assert_eq!(r.n_components, 1);
        assert_eq!(r.sizes, vec![2]);
        assert!(r.singletons.is_empty());
    }

    #[test]
    fn chain_topology_one_component() {
        let r = components_of(
            &[s("a"), s("b"), s("c"), s("d")],
            &[(s("a"), s("b")), (s("b"), s("c")), (s("c"), s("d"))],
        );
        assert_eq!(r.n_components, 1);
        assert_eq!(r.sizes, vec![4]);
    }

    #[test]
    fn two_components_with_sizes() {
        let r = components_of(
            &[s("a"), s("b"), s("c"), s("d"), s("e")],
            &[(s("a"), s("b")), (s("c"), s("d")), (s("d"), s("e"))],
        );
        assert_eq!(r.n_components, 2);
        assert_eq!(r.sizes, vec![3, 2]);
    }
}
