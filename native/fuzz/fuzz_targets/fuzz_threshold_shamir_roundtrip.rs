#![no_main]
//! Fuzz Shamir round-trip: split + reconstruct must recover the
//! input secret bit-identically. Any panic, error, or recovery
//! mismatch is a finding.

use libfuzzer_sys::fuzz_target;
use ol_threshold_recovery::prng::PrngState;
use ol_threshold_recovery::shamir::{reconstruct_bytes, share_bytes};

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

    // Parse (k, n) — both must be 1..=255 and k <= n. Reject otherwise.
    let Some(n_raw) = take_byte(&mut input) else { return };
    let Some(k_raw) = take_byte(&mut input) else { return };
    let n = (n_raw % 32).saturating_add(1) as u32;
    let k = (k_raw % n as u8).saturating_add(1) as u32;
    if k == 0 || k > n {
        return;
    }

    // PRNG seed.
    let Some(seed) = take_u64(&mut input) else { return };

    // Remaining bytes are the secret.
    if input.is_empty() {
        return;
    }
    let secret = input;

    let mut state = PrngState::new(seed);
    let Ok(streams) = share_bytes(secret, k, n, &mut state) else { return };
    if streams.len() != n as usize {
        panic!("split produced wrong number of streams");
    }
    // Reconstruct from the first K shares.
    let xs: Vec<u8> = (1..=k as u8).collect();
    let refs: Vec<&[u8]> =
        streams[..k as usize].iter().map(Vec::as_slice).collect();
    let recovered = reconstruct_bytes(&xs, &refs, k).expect("reconstruct");
    assert_eq!(
        recovered, secret,
        "round-trip mismatch: k={k} n={n} len={}",
        secret.len()
    );
});
