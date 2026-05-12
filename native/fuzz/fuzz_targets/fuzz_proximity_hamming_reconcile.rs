#![no_main]
//! Fuzz Hamming reconciliation with arbitrary bit patterns + parity.
//! Must NEVER panic. Output length must equal input length.

use libfuzzer_sys::fuzz_target;
use ol_proximity_pair::hamming_reconcile;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // Split: first byte as parity_length, then parity bytes, then bits.
    let parity_len = (data[0] as usize) % 64;
    if data.len() < 1 + parity_len {
        return;
    }
    let parity = &data[1..1 + parity_len];
    let bits_raw = &data[1 + parity_len..];
    // Quantize to 0/1 per byte.
    let bits: Vec<u8> = bits_raw.iter().map(|b| b & 1).collect();
    let r = hamming_reconcile(&bits, parity);
    assert_eq!(r.len(), bits.len());
});
