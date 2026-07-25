//! Property tests for `ol_netcode`.
//!
//! Per the plan's "every operation round-trips" mandate: for every
//! degree-N coded packet, dropping any single participant must
//! recover that exact participant from the rest.
//!
//! Iteration count configurable via ``OL_NETCODE_GATE_ITERS`` —
//! default `10_000`.

use ol_netcode::{decode_coded_packet, encode_coded_packet, ChunkId, NetcodeError};

fn next_rng(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn random_id(state: &mut u64) -> ChunkId {
    let mut out = [0u8; 32];
    for slot in &mut out {
        *slot = (next_rng(state) & 0xFF) as u8;
    }
    out
}

fn random_payload(state: &mut u64, len: usize) -> Vec<u8> {
    (0..len).map(|_| (next_rng(state) & 0xFF) as u8).collect()
}

#[test]
fn property_recover_any_single_drop() {
    let iters: u64 = std::env::var("OL_NETCODE_GATE_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);
    let mut state: u64 = 0xC0DE_BEAD_BEEF_CAFE;
    let mut fail = 0u64;
    for _ in 0..iters {
        // Degree N between 2 and 6, payload length between 1 and 256.
        let degree = 2 + (next_rng(&mut state) % 5) as usize;
        let len = 1 + (next_rng(&mut state) % 256) as usize;
        let chunks: Vec<(ChunkId, Vec<u8>)> = (0..degree)
            .map(|_| (random_id(&mut state), random_payload(&mut state, len)))
            .collect();

        let participants: Vec<(ChunkId, &[u8])> =
            chunks.iter().map(|(id, p)| (*id, p.as_slice())).collect();
        let packet = encode_coded_packet(&participants).unwrap();

        // Pick a random index to "drop" — the recipient is missing that
        // chunk. Hand the rest as known + verify we recover the drop.
        let degree_u64 = u64::try_from(degree).unwrap_or(u64::MAX);
        let drop_idx = usize::try_from(next_rng(&mut state) % degree_u64).unwrap_or_default();
        let known: Vec<(ChunkId, &[u8])> = chunks
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != drop_idx)
            .map(|(_, (id, p))| (*id, p.as_slice()))
            .collect();
        let (recovered_id, recovered_bytes) = decode_coded_packet(&packet, &known).unwrap();
        if recovered_id != chunks[drop_idx].0 || recovered_bytes != chunks[drop_idx].1 {
            eprintln!("mismatch at degree={degree} len={len} drop_idx={drop_idx}");
            fail += 1;
        }
    }
    assert_eq!(fail, 0, "{fail} / {iters} coded-packet recoveries failed");
}

#[test]
fn property_tampered_manifest_always_caught() {
    let iters: u64 = std::env::var("OL_NETCODE_GATE_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);
    let mut state: u64 = 0xDEAD_C0DE_FEED_BABE;
    let mut leaked = 0u64;
    for _ in 0..iters {
        let degree = 2 + (next_rng(&mut state) % 4) as usize;
        let len = 16 + (next_rng(&mut state) % 64) as usize;
        let chunks: Vec<(ChunkId, Vec<u8>)> = (0..degree)
            .map(|_| (random_id(&mut state), random_payload(&mut state, len)))
            .collect();
        let participants: Vec<(ChunkId, &[u8])> =
            chunks.iter().map(|(id, p)| (*id, p.as_slice())).collect();
        let mut packet = encode_coded_packet(&participants).unwrap();
        // Flip one bit in a random participant id.
        let degree_u64 = u64::try_from(degree).unwrap_or(u64::MAX);
        let idx = usize::try_from(next_rng(&mut state) % degree_u64).unwrap_or_default();
        let byte = (next_rng(&mut state) % 32) as usize;
        packet.participants[idx][byte] ^= 0x01;
        // Decoding with the OLD ids should fail because the
        // integrity tag was bound to the original list.
        let known: Vec<(ChunkId, &[u8])> = chunks
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != idx)
            .map(|(_, (id, p))| (*id, p.as_slice()))
            .collect();
        match decode_coded_packet(&packet, &known) {
            Ok(_) => leaked += 1,
            Err(NetcodeError::IntegrityMismatch) => { /* integrity rejection */ }
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }
    assert_eq!(
        leaked, 0,
        "tampered manifest passed integrity check in {leaked} / {iters} cases"
    );
}
