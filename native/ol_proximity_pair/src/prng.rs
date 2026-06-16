//! Minimal xoshiro256** PRNG (matching `ol_threshold_recovery::prng`).
//!
//! Used by the CASCADE permutation: both sides need the same byte
//! stream given the same seed so they agree on the permutation.

/// xoshiro256** state.
#[derive(Clone, Copy, Debug)]
pub struct PrngState {
    s0: u64,
    s1: u64,
    s2: u64,
    s3: u64,
}

impl PrngState {
    /// Construct from a 64-bit seed via SplitMix64 lane expansion.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            s0: splitmix64_next(seed),
            s1: splitmix64_next(seed.wrapping_add(0x9E37_79B9_7F4A_7C15)),
            s2: splitmix64_next(seed.wrapping_add(0xBF58_476D_1CE4_E5B9)),
            s3: splitmix64_next(seed.wrapping_add(0x94D0_49BB_1331_11EB)),
        }
    }

    /// Produce the next 64-bit output.
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
}

const fn splitmix64_next(z: u64) -> u64 {
    let mut x = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

#[inline]
const fn rotl64(x: u64, k: u32) -> u64 {
    x.rotate_left(k)
}
