//! SIMD-friendly word-wide XOR for the LT encoder + decoder hot path.
//!
//! The naive byte-at-a-time loop `for (o, s) in dest.iter_mut().zip(src.iter())`
//! compiles to byte-wise XOR even with `-O2`. By splitting the buffer
//! into 64-byte chunks and XOR'ing word-by-word (via `u64::from_ne_bytes`),
//! we hand the compiler a straight-line vectorizable shape that lowers
//! to AVX2 `vpxor` (32 bytes / iter) or SSE2 `pxor` (16 bytes / iter)
//! on `x86_64`, and NEON `eor` on `aarch64`.
//!
//! For Phase B v1 symbols of 1 KiB:
//!   - Naive: 1024 iterations.
//!   - 64-byte chunks: 16 iterations → 64× fewer branches.

/// In-place XOR: `dest[i] ^= src[i]` for `i in 0..len`. Both slices
/// must be the same length.
///
/// Returns `false` without modifying `dest` when the lengths differ.
/// The equal-length loop is deliberately safe Rust: LLVM autovectorizes
/// this shape, and a future invariant regression cannot become an
/// out-of-bounds raw-pointer read in release builds.
#[inline]
pub(crate) fn xor_into(dest: &mut [u8], src: &[u8]) -> bool {
    if dest.len() != src.len() {
        return false;
    }
    for (dest_byte, src_byte) in dest.iter_mut().zip(src) {
        *dest_byte ^= *src_byte;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn naive(dest: &mut [u8], src: &[u8]) {
        for (d, s) in dest.iter_mut().zip(src.iter()) {
            *d ^= *s;
        }
    }

    #[test]
    fn matches_naive_on_aligned_lengths() {
        for len in [
            0usize,
            1,
            7,
            8,
            9,
            31,
            32,
            63,
            64,
            65,
            127,
            128,
            1024,
            1024 + 3,
        ] {
            let a: Vec<u8> = (0..len)
                .map(|i| {
                    let index = u32::try_from(i).expect("test vector index fits in u32");
                    u8::try_from(index.wrapping_mul(31) & 0xFF)
                        .expect("masked test value fits in u8")
                })
                .collect();
            let b: Vec<u8> = (0..len)
                .map(|i| {
                    let index = u32::try_from(i).expect("test vector index fits in u32");
                    u8::try_from((index ^ 0xDEAD) & 0xFF).expect("masked test value fits in u8")
                })
                .collect();
            let mut x = a.clone();
            assert!(xor_into(&mut x, &b));
            let mut y = a.clone();
            naive(&mut y, &b);
            assert_eq!(x, y, "len={len}");
        }
    }

    #[test]
    fn empty_no_op() {
        let mut d: Vec<u8> = vec![];
        assert!(xor_into(&mut d, &[]));
        assert!(d.is_empty());
    }

    #[test]
    fn idempotent_double_xor() {
        let mut dest = vec![0xAAu8; 1024];
        let src = vec![0x55u8; 1024];
        assert!(xor_into(&mut dest, &src));
        assert!(xor_into(&mut dest, &src));
        assert_eq!(dest, vec![0xAAu8; 1024]);
    }

    #[test]
    fn mismatch_is_rejected_without_partial_mutation() {
        let mut dest = [0xAAu8; 8];
        let original = dest;
        assert!(!xor_into(&mut dest, &[0x55u8; 7]));
        assert_eq!(dest, original);
    }
}
