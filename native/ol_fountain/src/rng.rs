//! Deterministic seeded PRNG used by the LT encoder + decoder.
//!
//! For wire interoperability between sender and receiver, both sides
//! MUST agree on:
//!
//! 1. The degree sampled for a given `symbol_id`.
//! 2. The set of source-symbol indices sampled for a given `symbol_id`.
//!
//! We derive a per-`symbol_id` seed via BLAKE3 keyed hash, then run a
//! tiny `SplitMix64`-compatible PRNG over it. `SplitMix64` is exact,
//! deterministic, and 1 multiply + 1 shift per 64-bit draw — fast
//! enough that encoding never bottlenecks on RNG.

const SEED_CONTEXT: &str = "ol-fountain-lt-v1";

/// Derive a 64-bit seed for `(k, symbol_id)`.
///
/// Uses `BLAKE3.derive_key` with [`SEED_CONTEXT`] and the 8-byte key
/// `[k_le; 4][symbol_id_le; 4]` → take the first 8 bytes of the output.
#[inline]
#[must_use]
pub fn seed_for(k: u32, symbol_id: u32) -> u64 {
    let mut input = [0u8; 8];
    input[0..4].copy_from_slice(&k.to_le_bytes());
    input[4..8].copy_from_slice(&symbol_id.to_le_bytes());
    let key = blake3::derive_key(SEED_CONTEXT, &input);
    let mut seed = [0u8; 8];
    seed.copy_from_slice(&key[..8]);
    u64::from_le_bytes(seed)
}

/// `SplitMix64` deterministic PRNG. See <https://prng.di.unimi.it/splitmix64.c>.
///
/// One `next` call is 1 multiply + 1 add + 1 xor; ~2 cycles on x86.
#[derive(Debug, Clone, Copy)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Construct from a seed.
    #[inline]
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Construct from `(k, symbol_id)` via [`seed_for`].
    #[inline]
    #[must_use]
    pub fn for_symbol(k: u32, symbol_id: u32) -> Self {
        Self::new(seed_for(k, symbol_id))
    }

    /// Draw the next 64-bit value.
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Draw a uniform `[0, range)` u32. Uses Lemire's nearly-divisionless
    /// method; bias is statistically undetectable for our K ≤ 65536.
    #[inline]
    pub fn next_u32_below(&mut self, range: u32) -> u32 {
        debug_assert!(range > 0);
        let r = u64::from(range);
        let x = self.next_u64() >> 32; // u32 reduced
        ((x.wrapping_mul(r)) >> 32) as u32
    }

    /// Draw a uniform `[0, 1)` float. Used by the degree CDF sampler.
    #[inline]
    pub fn next_f64_01(&mut self) -> f64 {
        // 53-bit mantissa.
        let bits = self.next_u64() >> 11;
        let high = u32::try_from(bits >> 32).expect("53-bit sample high half fits in u32");
        let low =
            u32::try_from(bits & u64::from(u32::MAX)).expect("masked sample low half fits in u32");
        let value = f64::from(high).mul_add(4_294_967_296.0, f64::from(low));
        value * (1.0 / 9_007_199_254_740_992.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_determinism() {
        assert_eq!(seed_for(64, 0), seed_for(64, 0));
        assert_ne!(seed_for(64, 0), seed_for(64, 1));
        assert_ne!(seed_for(64, 0), seed_for(128, 0));
    }

    #[test]
    fn rng_distinct_seeds_diverge_quickly() {
        let mut r1 = SplitMix64::new(0);
        let mut r2 = SplitMix64::new(1);
        let mut distinct = 0;
        for _ in 0..1000 {
            if r1.next_u64() != r2.next_u64() {
                distinct += 1;
            }
        }
        assert!(
            distinct >= 990,
            "expected near-total divergence, got {distinct}"
        );
    }

    #[test]
    fn u32_below_range_respects_bound() {
        let mut r = SplitMix64::new(42);
        for _ in 0..10_000 {
            let v = r.next_u32_below(7);
            assert!(v < 7);
        }
    }

    #[test]
    fn f64_in_unit_interval() {
        let mut r = SplitMix64::new(99);
        for _ in 0..10_000 {
            let f = r.next_f64_01();
            assert!(f >= 0.0);
            assert!(f < 1.0);
        }
    }
}
