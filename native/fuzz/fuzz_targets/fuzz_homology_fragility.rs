#![no_main]
//! Fuzz fragility_score over arbitrary graphs. Must never panic;
//! every returned score must be in [0, 1].

use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;
use ol_homology::fragility_score;

fn take_byte(input: &mut &[u8]) -> Option<u8> {
    let b = *input.first()?;
    *input = &input[1..];
    Some(b)
}

fuzz_target!(|data: &[u8]| {
    let mut input = data;
    let Some(n_nodes) = take_byte(&mut input) else { return };
    let n_nodes = (n_nodes % 16) as usize + 1;
    let nodes: Vec<String> = (0..n_nodes).map(|i| format!("n{}", i)).collect();
    let mut edges: Vec<(String, String)> = Vec::new();
    let Some(n_edges) = take_byte(&mut input) else { return };
    for _ in 0..(n_edges % 32) {
        let Some(a) = take_byte(&mut input) else { break };
        let Some(b) = take_byte(&mut input) else { break };
        let ai = (a as usize) % nodes.len();
        let bi = (b as usize) % nodes.len();
        if ai != bi {
            edges.push((nodes[ai].clone(), nodes[bi].clone()));
        }
    }
    let mut holders: HashMap<String, usize> = HashMap::new();
    for n in &nodes {
        let h = take_byte(&mut input).unwrap_or(1) as usize % 10;
        holders.insert(n.clone(), h);
    }
    let report = fragility_score(&nodes, &edges, &holders);
    for s in &report.scores {
        assert!(
            (0.0..=1.0).contains(&s.score),
            "fragility score out of bounds: {}",
            s.score
        );
    }
});
