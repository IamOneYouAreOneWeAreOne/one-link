#![no_main]
//! Fuzz the Re-Pair grammar compressor. Property: compress + decompress
//! is the identity function for ANY byte input.

use libfuzzer_sys::fuzz_target;
use ol_grammar::{compress, decompress};

fuzz_target!(|data: &[u8]| {
    // Cap input size to keep fuzzer fast; the property is identity
    // on any length, but >8 KiB makes individual iterations slow.
    let trimmed = if data.len() > 8192 {
        &data[..8192]
    } else {
        data
    };
    let grammar = compress(trimmed);
    let recovered = decompress(&grammar).expect("grammar must always decompress");
    assert_eq!(
        recovered,
        trimmed,
        "compress + decompress is not identity for input of length {}",
        trimmed.len()
    );
});
