#![no_main]
//! Fuzz the DuressGate. Property: open() must never panic on any
//! input. Returns Rejected for unknown passphrases, Real or Duress
//! when checks match.

use libfuzzer_sys::fuzz_target;
use ol_duress::DuressGate;

fn take_array<const N: usize>(input: &mut &[u8]) -> Option<[u8; N]> {
    if input.len() < N {
        return None;
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&input[..N]);
    *input = &input[N..];
    Some(out)
}

fuzz_target!(|data: &[u8]| {
    let mut input = data;
    let Some(real_root) = take_array::<32>(&mut input) else {
        return;
    };
    let Some(duress_root) = take_array::<32>(&mut input) else {
        return;
    };
    let Some(pair_secret) = take_array::<32>(&mut input) else {
        return;
    };
    let Some(expected_real) = take_array::<32>(&mut input) else {
        return;
    };
    let Some(expected_duress) = take_array::<32>(&mut input) else {
        return;
    };
    let gate = DuressGate::new(real_root, duress_root, pair_secret);
    // Remaining input is the passphrase.
    let _ = gate.open(input, &expected_real, &expected_duress);
});
