#![no_main]
//! Fuzz the routing table with arbitrary insert/remove sequences.
//! Catches any bucket-bookkeeping bug + LRS-replacement edge case.
//!
//! Invariants:
//!   - Never panic on any operation sequence
//!   - bucket_sizes.sum() == len() at all times
//!   - closest_to.len() <= K

use libfuzzer_sys::fuzz_target;
use ol_discovery::node_id::NodeId;
use ol_discovery::routing::RoutingTable;

fn take_byte(input: &mut &[u8]) -> Option<u8> {
    let b = *input.first()?;
    *input = &input[1..];
    Some(b)
}

fn take_id(input: &mut &[u8]) -> Option<NodeId> {
    if input.len() < 32 {
        return None;
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&input[..32]);
    *input = &input[32..];
    Some(NodeId::from_bytes(id))
}

fuzz_target!(|data: &[u8]| {
    let mut input = data;
    // First 32 bytes: own_id. Remaining: stream of operations.
    let Some(own) = take_id(&mut input) else { return };
    let mut t = RoutingTable::new(own);
    while !input.is_empty() {
        let Some(op) = take_byte(&mut input) else { break };
        match op & 0x07 {
            0 | 1 | 2 => {
                // Insert.
                let Some(peer) = take_id(&mut input) else { break };
                let Some(ts_lo) = take_byte(&mut input) else { break };
                let _ = t.insert(peer, ts_lo as u64);
            }
            3 => {
                // Remove.
                let Some(peer) = take_id(&mut input) else { break };
                let _ = t.remove(&peer);
            }
            4 => {
                // closest_to.
                let Some(target) = take_id(&mut input) else { break };
                let c = t.closest_to(&target);
                assert!(c.len() <= 20);
            }
            5 => {
                // contains.
                let Some(peer) = take_id(&mut input) else { break };
                let _ = t.contains(&peer);
            }
            _ => {
                // bucket_sizes / len.
                let sizes = t.bucket_sizes();
                assert_eq!(sizes.iter().sum::<usize>(), t.len());
            }
        }
    }
});
