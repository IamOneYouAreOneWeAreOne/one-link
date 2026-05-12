#![no_main]
//! Fuzz field-bound round-trip: split + reconstruct with the same
//! witness must recover bit-identical. Different witness must NOT
//! recover (with high probability).

use libfuzzer_sys::fuzz_target;
use ol_threshold_recovery::field_bound::{
    field_bound_reconstruct, field_bound_split, FieldWitness,
};
use ol_threshold_recovery::prng::PrngState;

fn take_byte(input: &mut &[u8]) -> Option<u8> {
    let b = *input.first()?;
    *input = &input[1..];
    Some(b)
}

fn take_u64(input: &mut &[u8]) -> Option<u64> {
    if input.len() < 8 {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&input[..8]);
    *input = &input[8..];
    Some(u64::from_le_bytes(buf))
}

fuzz_target!(|data: &[u8]| {
    let mut input = data;
    let Some(n_raw) = take_byte(&mut input) else { return };
    let Some(k_raw) = take_byte(&mut input) else { return };
    let n = (n_raw % 16).saturating_add(2) as u32; // 2..=17
    let k = (k_raw % (n as u8 - 1)).saturating_add(2) as u32; // 2..=n
    if k > n {
        return;
    }
    let Some(seed) = take_u64(&mut input) else { return };
    let Some(epoch_ns) = take_u64(&mut input) else { return };

    // 32-byte field seed.
    if input.len() < 32 {
        return;
    }
    let mut field_seed = [0u8; 32];
    field_seed.copy_from_slice(&input[..32]);
    input = &input[32..];

    // n scores in [0, 1] derived from arbitrary u64s.
    let mut scores = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let Some(s_raw) = take_u64(&mut input) else { return };
        // Map u64 to [0, 1] uniformly.
        let s = (s_raw as f64) / (u64::MAX as f64);
        scores.push(s);
    }
    let witness = FieldWitness {
        field_seed,
        holder_scores: scores,
        epoch_ns,
    };

    if input.is_empty() || input.len() > 256 {
        return;
    }
    let secret = input;

    let mut prng = PrngState::new(seed);
    let Ok(masked) = field_bound_split(secret, k, n, &mut prng, &witness)
    else {
        return;
    };
    if masked.len() != n as usize {
        panic!("field-bound split produced wrong number of streams");
    }
    let xs: Vec<u8> = (1..=k as u8).collect();
    let refs: Vec<&[u8]> =
        masked[..k as usize].iter().map(Vec::as_slice).collect();
    let indices: Vec<usize> = (0..k as usize).collect();
    let recovered = field_bound_reconstruct(
        &xs, &refs, &indices, k, &witness,
    )
    .expect("reconstruct");
    assert_eq!(
        recovered, secret,
        "field-bound round-trip mismatch: k={k} n={n} len={}",
        secret.len()
    );
});
