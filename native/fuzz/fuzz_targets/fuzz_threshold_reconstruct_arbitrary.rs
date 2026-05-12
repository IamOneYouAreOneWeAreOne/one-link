#![no_main]
//! Fuzz the reconstruct surface with arbitrary input: arbitrary
//! x-values, arbitrary stream bytes, arbitrary k. Must NEVER panic
//! — every malformed input must return a clean error. Recovery may
//! produce garbage on bad input but must not crash.

use libfuzzer_sys::fuzz_target;
use ol_threshold_recovery::shamir::reconstruct_bytes;

fn take_byte(input: &mut &[u8]) -> Option<u8> {
    let b = *input.first()?;
    *input = &input[1..];
    Some(b)
}

fuzz_target!(|data: &[u8]| {
    let mut input = data;
    let Some(k_raw) = take_byte(&mut input) else { return };
    let k = (k_raw % 16).saturating_add(1) as u32;
    let Some(n_streams) = take_byte(&mut input) else { return };
    let n_streams = (n_streams % 16) as usize + 1;
    let Some(stream_len) = take_byte(&mut input) else { return };
    let stream_len = stream_len as usize;

    // Build x-values: arbitrary bytes 0..255 (may include 0 -> error).
    let mut xs: Vec<u8> = Vec::with_capacity(n_streams);
    for _ in 0..n_streams {
        let Some(x) = take_byte(&mut input) else { return };
        xs.push(x);
    }

    // Build streams of stream_len bytes each.
    let mut owned: Vec<Vec<u8>> = Vec::with_capacity(n_streams);
    for _ in 0..n_streams {
        if input.len() < stream_len {
            return;
        }
        owned.push(input[..stream_len].to_vec());
        input = &input[stream_len..];
    }
    let streams: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();

    // Reconstruction MAY error — that's fine. MUST NOT panic.
    let _ = reconstruct_bytes(&xs, &streams, k);
});
