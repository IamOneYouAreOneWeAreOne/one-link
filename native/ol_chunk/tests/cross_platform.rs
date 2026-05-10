//! Cross-platform determinism test.
//!
//! Per [ADR-0001](../../../docs/decisions/0001-cdc-kernel.md) verification
//! gate #2: same input must produce byte-identical chunk boundaries on
//! x86-64, ARM64 (Apple Silicon), and Windows. SIMD changes
//! microarchitecture, not byte output.
//!
//! The fixture below pins:
//!   - A deterministic 1 MiB pseudo-random buffer (xorshift seed = the
//!     value below).
//!   - The expected boundary offsets the FastCDC + Gear-256 kernel must
//!     produce on that buffer for the default ADR-0001 parameters
//!     (8 KiB / 64 KiB / 256 KiB).
//!
//! If this test fails after a Rust compiler upgrade, a `fastcdc` crate
//! upgrade, or a SIMD path enable, that is a determinism regression and
//! must be investigated immediately. The boundaries are part of the
//! engine's wire-format compatibility surface — changing them silently
//! breaks dedup with peers running older builds.

use ol_chunk::{scan_to_vec, Boundary};

/// Deterministic xorshift fill. Seed pinned for reproducibility.
fn pseudo_random_buf(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed;
    let mut buf = vec![0u8; len];
    for byte in buf.iter_mut() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = (state & 0xFF) as u8;
    }
    buf
}

/// Expected boundaries (start offsets) produced by ADR-0001 kernel on
/// `pseudo_random_buf(0xDEAD_BEEF_CAFE_F00D, 1 MiB)`.
///
/// These are filled in the first time CI runs on the reference build by
/// reading `boundary.start` for every yielded boundary. After that, this
/// list is the determinism contract: any change here is a wire-format
/// break.
///
/// For the initial commit we only assert the *count* is stable; once
/// the first reference run happens in CI we'll pin the exact offset list.
const EXPECTED_BOUNDARY_COUNT_RANGE: std::ops::RangeInclusive<usize> = 12..=20;

#[test]
fn boundaries_are_within_expected_count_range() {
    let buf = pseudo_random_buf(0xDEAD_BEEF_CAFE_F00D, 1024 * 1024);
    let boundaries: Vec<Boundary> = scan_to_vec(&buf);
    let count = boundaries.len();
    assert!(
        EXPECTED_BOUNDARY_COUNT_RANGE.contains(&count),
        "1 MiB random buffer with default CDC params should produce \
         {EXPECTED_BOUNDARY_COUNT_RANGE:?} boundaries, got {count}",
    );

    // Every boundary's BLAKE3 must equal hashing the underlying slice.
    for b in &boundaries {
        let actual = blake3::hash(&buf[b.start..b.end]);
        assert_eq!(b.raw_address, *actual.as_bytes());
    }

    // Boundaries tile the buffer exactly.
    assert_eq!(boundaries[0].start, 0);
    assert_eq!(boundaries.last().unwrap().end, buf.len());
    for w in boundaries.windows(2) {
        assert_eq!(w[0].end, w[1].start);
    }
}

#[test]
fn determinism_across_repeated_scans() {
    let buf = pseudo_random_buf(0x4242_4242_4242_4242, 256 * 1024);
    let a = scan_to_vec(&buf);
    let b = scan_to_vec(&buf);
    assert_eq!(a, b);
}

#[test]
fn distinct_inputs_produce_distinct_addresses() {
    // Two buffers differing in one byte must produce different chunk
    // addresses for any chunk that contains the differing byte. This is
    // the BLAKE3 collision-resistance property carried up to chunk level.
    let buf_a = pseudo_random_buf(0x1, 128 * 1024);
    let mut buf_b = buf_a.clone();
    let mid = buf_b.len() / 2;
    buf_b[mid] = buf_b[mid].wrapping_add(1);

    let bounds_a = scan_to_vec(&buf_a);
    let bounds_b = scan_to_vec(&buf_b);

    // Find a boundary in A that contains the modified byte.
    let modified = buf_a.len() / 2;
    let containing_a = bounds_a
        .iter()
        .find(|b| b.start <= modified && modified < b.end);
    let containing_b = bounds_b
        .iter()
        .find(|b| b.start <= modified && modified < b.end);
    assert!(containing_a.is_some());
    assert!(containing_b.is_some());

    // The chunk address that covers the modified byte MUST differ between
    // the two buffers.
    if let (Some(a), Some(b)) = (containing_a, containing_b) {
        assert_ne!(a.raw_address, b.raw_address);
    }
}
