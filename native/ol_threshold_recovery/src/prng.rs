//! xoshiro256** PRNG with SplitMix64 seeding.
//!
//! Direct port of `OneField/onefield/privacy/sharding.cl` SECTION 2.
//! Deterministic given a caller-supplied seed; reproducibility is the
//! property — production callers derive seeds from reciprocity-channel
//! hashes + monotonic counters so coefficient draws are unpredictable
//! to adversaries but verifiable by the user's own future devices.

/// xoshiro256** internal state — four 64-bit lanes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrngState {
    s0: u64,
    s1: u64,
    s2: u64,
    s3: u64,
}

impl PrngState {
    /// Construct from a single 64-bit seed; expands via SplitMix64 to
    /// fill the four xoshiro lanes (standard recommendation).
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            s0: SplitMix64::next(seed),
            s1: SplitMix64::next(seed.wrapping_add(0x9E37_79B9_7F4A_7C15)),
            s2: SplitMix64::next(seed.wrapping_add(0xBF58_476D_1CE4_E5B9)),
            s3: SplitMix64::next(seed.wrapping_add(0x94D0_49BB_1331_11EB)),
        }
    }

    /// Produce the next 64-bit output and advance the state.
    pub fn next_u64(&mut self) -> u64 {
        let result = rotl64(self.s1.wrapping_mul(5), 7).wrapping_mul(9);
        let t = self.s1 << 17;
        let ns2 = self.s2 ^ self.s0;
        let ns3 = self.s3 ^ self.s1;
        let ns1 = self.s1 ^ ns2;
        let ns0 = self.s0 ^ ns3;
        let fs2 = ns2 ^ t;
        let fs3 = rotl64(ns3, 45);
        self.s0 = ns0;
        self.s1 = ns1;
        self.s2 = fs2;
        self.s3 = fs3;
        result
    }

    /// Produce one byte uniformly in [0, 256).
    pub fn next_byte(&mut self) -> u8 {
        (self.next_u64() & 0xFF) as u8
    }
}

/// SplitMix64 step used for seeding xoshiro lanes.
#[derive(Debug)]
pub struct SplitMix64;

impl SplitMix64 {
    /// One step. Pure function of input.
    #[must_use]
    pub const fn next(z: u64) -> u64 {
        let mut x = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
        x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        x ^ (x >> 31)
    }
}

#[inline]
const fn rotl64(x: u64, k: u32) -> u64 {
    x.rotate_left(k)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_from_same_seed() {
        let mut a = PrngState::new(0xBEEF_CAFE_1234_5678);
        let mut b = PrngState::new(0xBEEF_CAFE_1234_5678);
        for _ in 0..32 {
            assert_eq!(a.next_byte(), b.next_byte());
        }
    }

    #[test]
    fn different_seeds_produce_different_streams() {
        let mut a = PrngState::new(0x01);
        let mut b = PrngState::new(0x02);
        let mut diff = false;
        for _ in 0..16 {
            if a.next_byte() != b.next_byte() {
                diff = true;
                break;
            }
        }
        assert!(diff);
    }

    #[test]
    fn not_all_same_byte() {
        let mut s = PrngState::new(0xBEEF_CAFE_1234_5678);
        let first = s.next_byte();
        let mut all_same = true;
        for _ in 0..15 {
            if s.next_byte() != first {
                all_same = false;
                break;
            }
        }
        assert!(!all_same);
    }

    #[test]
    fn splitmix64_pure() {
        // SplitMix is deterministic — same input, same output, every time.
        assert_eq!(SplitMix64::next(0), SplitMix64::next(0));
        assert_eq!(SplitMix64::next(42), SplitMix64::next(42));
        // Different inputs differ.
        assert_ne!(SplitMix64::next(0), SplitMix64::next(1));
    }
}
