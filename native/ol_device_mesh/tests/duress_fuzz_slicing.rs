//! Pin the slice arithmetic the duress fuzz harness uses.
//!
//! `fuzz (nightly)` was red on `fuzz_device_mesh_duress` for every run with a
//! panic at the decoy-plaintext slice. The harness computed
//!
//!     &data[len.min(16).min(len) .. len.min(32).max(len.min(16) + 1)]
//!
//! whose END is pushed past the buffer by that `.max(...)` whenever the input
//! is shorter than 17 bytes: a 5-byte input asks for `data[5..6]`.
//!
//! That was a bug in the harness, not a finding about the duress code, and
//! libFuzzer does not build on every workstation -- so the arithmetic is
//! pinned here where `cargo test` can reach it on any platform.

/// The corrected split, mirroring the fuzz target exactly.
fn split_real_and_decoy(data: &[u8]) -> (&[u8], &[u8]) {
    let split = data.len().min(16);
    let decoy_end = data.len().min(32);
    let real = &data[..split];
    let decoy: &[u8] = if decoy_end > split {
        &data[split..decoy_end]
    } else {
        &[]
    };
    (real, decoy)
}

#[test]
fn short_inputs_do_not_slice_out_of_range() {
    // 5 bytes is the shape that crashed CI. Sweep every small length so a
    // future rewrite cannot reintroduce an end-past-the-buffer range.
    for len in 0..64usize {
        // `i as u8` would be a truncating cast, which this workspace denies.
        let data: Vec<u8> = (0..len)
            .map(|i| u8::try_from(i % 256).unwrap_or(0))
            .collect();
        let (real, decoy) = split_real_and_decoy(&data);
        assert!(
            real.len() <= 16,
            "real plaintext exceeded 16 bytes at len={len}"
        );
        assert!(
            decoy.len() <= 16,
            "decoy plaintext exceeded 16 bytes at len={len}"
        );
        assert!(
            real.len() + decoy.len() <= data.len(),
            "split claimed more bytes than the input held at len={len}"
        );
    }
}

#[test]
fn the_decoy_is_the_chunk_after_the_real_plaintext() {
    let data: Vec<u8> = (0..40u8).collect();
    let (real, decoy) = split_real_and_decoy(&data);
    assert_eq!(real, &data[..16]);
    assert_eq!(decoy, &data[16..32]);
}

#[test]
fn a_short_input_yields_an_empty_decoy_rather_than_a_panic() {
    // The fuzz target guards on `!decoy_pt.is_empty()`, so an empty decoy
    // simply skips the envelope leg instead of crashing the run.
    let data = [1u8, 2, 3, 4, 5];
    let (real, decoy) = split_real_and_decoy(&data);
    assert_eq!(real, &data[..]);
    assert!(decoy.is_empty());
}
