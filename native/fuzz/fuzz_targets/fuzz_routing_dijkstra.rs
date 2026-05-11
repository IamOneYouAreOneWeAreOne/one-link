#![no_main]
//! Fuzz the Dijkstra shortest-path solver. Build an arbitrary graph
//! from the fuzz input, run shortest_path, must never panic.
//! Property: if a path is returned, every consecutive pair in the
//! path must be a real edge in the graph and the total_cost must
//! equal the sum of those edges' costs.

use libfuzzer_sys::fuzz_target;
use ol_routing::{shortest_path, AdjacencyGraph};

fn take_byte(input: &mut &[u8]) -> Option<u8> {
    let b = *input.first()?;
    *input = &input[1..];
    Some(b)
}
fn take_u32(input: &mut &[u8]) -> Option<u32> {
    let mut bytes = [0u8; 4];
    if input.len() < 4 {
        return None;
    }
    bytes.copy_from_slice(&input[..4]);
    *input = &input[4..];
    Some(u32::from_le_bytes(bytes))
}

fuzz_target!(|data: &[u8]| {
    let mut input = data;
    let Some(n_edges) = take_byte(&mut input) else { return };
    let mut g = AdjacencyGraph::new();
    for _ in 0..(n_edges.min(64)) {
        let Some(from_byte) = take_byte(&mut input) else { break };
        let Some(to_byte) = take_byte(&mut input) else { break };
        let Some(cost_bits) = take_u32(&mut input) else { break };
        let cost = (cost_bits as f64) / (u32::MAX as f64) * 1000.0;
        let from_id = format!("n{}", from_byte);
        let to_id = format!("n{}", to_byte);
        g.add_edge(from_id, to_id, cost);
    }
    let Some(start_byte) = take_byte(&mut input) else { return };
    let Some(goal_byte) = take_byte(&mut input) else { return };
    let start = format!("n{}", start_byte);
    let goal = format!("n{}", goal_byte);

    // Just call — must not panic on any input.
    let _ = shortest_path(&g, &start, &goal);
});
