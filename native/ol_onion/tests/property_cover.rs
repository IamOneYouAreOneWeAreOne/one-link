//! Property tests for the Row 6 cover-traffic primitives.
//!
//! Two distinct surfaces:
//!   - `CoverScheduler`: deterministic-per-seed Exp(λ) generator.
//!   - `RateEqualizer`: EWMA-based total-rate equalizer.
//!
//! Gate ladder: CI default 1M iters (matches F1.x bar); nightly 5M
//! via `ONE_LINK_F1_GATE=1`.

use proptest::prelude::*;

use ol_onion::sphinx::cover::{
    is_cover_payload, CoverScheduler, RateEqualizer, COVER_SENTINEL,
};

fn cases() -> u32 {
    if std::env::var("ONE_LINK_F1_GATE").as_deref() == Ok("1") {
        5_000_000
    } else {
        1_000_000
    }
}

// ── Cover-sentinel detection (cheap, pure) ─────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases(),
        max_global_rejects: cases() * 4,
        .. ProptestConfig::default()
    })]

    /// `is_cover_payload` is the COVER_SENTINEL prefix-equality check
    /// — must NEVER panic on any byte slice.
    #[test]
    fn is_cover_payload_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
        let _ = is_cover_payload(&bytes);
    }

    /// Bytes shorter than COVER_SENTINEL.len() always classify as
    /// non-cover (prefix can't match).
    #[test]
    fn short_bytes_never_cover(bytes in prop::collection::vec(any::<u8>(), 0..COVER_SENTINEL.len())) {
        prop_assert!(!is_cover_payload(&bytes));
    }

    /// Bytes whose first 8 bytes equal COVER_SENTINEL ARE cover.
    #[test]
    fn sentinel_prefix_always_cover(
        tail in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let mut v = COVER_SENTINEL.to_vec();
        v.extend_from_slice(&tail);
        prop_assert!(is_cover_payload(&v));
    }

    /// Random bytes with first 8 bytes differing from COVER_SENTINEL
    /// are NOT cover (with probability 1 - 2^-64 on uniform random).
    #[test]
    fn non_sentinel_prefix_never_cover(
        prefix in any::<[u8; 8]>(),
        tail in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        prop_assume!(prefix != *COVER_SENTINEL);
        let mut v = prefix.to_vec();
        v.extend_from_slice(&tail);
        prop_assert!(!is_cover_payload(&v));
    }
}

// ── CoverScheduler properties ──────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases() / 50,    // scheduler is heavier; reduce
        max_global_rejects: cases() * 2,
        .. ProptestConfig::default()
    })]

    /// Same (rate, seed) → identical sequence (determinism).
    #[test]
    fn scheduler_deterministic(
        seed in any::<[u8; 32]>(),
        rate_bits in 1u64..1_000_000u64,
    ) {
        let rate = rate_bits as f64 / 1000.0; // 0.001 .. 1000 Hz
        let mut a = CoverScheduler::new(rate, seed);
        let mut b = CoverScheduler::new(rate, seed);
        for _ in 0..32 {
            prop_assert_eq!(a.next_wait_ms(), b.next_wait_ms());
        }
    }

    /// Different seeds → at least one differing wait among 32 samples
    /// (collision probability vanishingly small).
    #[test]
    fn scheduler_seed_differentiates(
        s1 in any::<[u8; 32]>(),
        s2 in any::<[u8; 32]>(),
    ) {
        prop_assume!(s1 != s2);
        let mut a = CoverScheduler::new(1.0, s1);
        let mut b = CoverScheduler::new(1.0, s2);
        let mut differ = false;
        for _ in 0..32 {
            if a.next_wait_ms() != b.next_wait_ms() {
                differ = true;
                break;
            }
        }
        prop_assert!(differ);
    }

    /// `next_wait_ms` always returns a finite u64 (never overflows
    /// or panics) for any rate > 0.
    #[test]
    fn scheduler_finite_for_any_positive_rate(
        seed in any::<[u8; 32]>(),
        rate_bits in 1u64..1_000_000u64,
    ) {
        let rate = rate_bits as f64 / 1000.0;
        let mut s = CoverScheduler::new(rate, seed);
        let _ = s.next_wait_ms();
    }
}

// ── RateEqualizer properties ───────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases() / 10,
        max_global_rejects: cases(),
        .. ProptestConfig::default()
    })]

    /// `current_cover_rate` is always in `[0, target_total_hz]`.
    #[test]
    fn cover_rate_in_bounds(
        target_bits in 1u64..1_000_000u64,
        timestamps in prop::collection::vec(any::<u64>(), 0..32),
    ) {
        let target = target_bits as f64 / 1000.0;
        let mut eq = RateEqualizer::new(target);
        for ts in &timestamps {
            eq.observe_real_emission(*ts);
        }
        let cover = eq.current_cover_rate();
        prop_assert!(cover >= 0.0);
        prop_assert!(cover <= target + 1e-9);
    }

    /// `observed_real_rate` is always non-negative.
    #[test]
    fn observed_rate_non_negative(
        target_bits in 1u64..1_000_000u64,
        timestamps in prop::collection::vec(any::<u64>(), 0..32),
    ) {
        let target = target_bits as f64 / 1000.0;
        let mut eq = RateEqualizer::new(target);
        for ts in &timestamps {
            eq.observe_real_emission(*ts);
        }
        prop_assert!(eq.observed_real_rate() >= 0.0);
    }

    /// observe_real_emission + observe_idle_tick are total — never
    /// panic on any sequence of arbitrary timestamps.
    #[test]
    fn observe_total(
        target_bits in 1u64..1_000_000u64,
        ops in prop::collection::vec((any::<bool>(), any::<u64>()), 0..32),
    ) {
        let target = target_bits as f64 / 1000.0;
        let mut eq = RateEqualizer::new(target);
        for (is_emit, ts) in &ops {
            if *is_emit {
                eq.observe_real_emission(*ts);
            } else {
                eq.observe_idle_tick(*ts);
            }
        }
    }

    /// Long idle ALWAYS decays observed_real_rate toward zero (cover
    /// fills to target). This is the load-bearing equalizer property.
    #[test]
    fn long_idle_returns_to_full_cover(
        target_bits in 1u64..1_000_000u64,
        ts_a in 1_000u64..10_000u64,
        ts_b_offset in 1u64..100u64,
    ) {
        let target = target_bits as f64 / 1000.0;
        let mut eq = RateEqualizer::new(target);
        eq.set_half_life_sec(1.0);
        eq.observe_real_emission(ts_a);
        eq.observe_real_emission(ts_a + ts_b_offset);
        // Now idle for a million seconds — observed → 0; cover → target.
        eq.observe_idle_tick(ts_a + 1_000_000_000);
        prop_assert!(eq.observed_real_rate() < 1e-9);
        prop_assert!((eq.current_cover_rate() - target).abs() < 1e-6);
    }
}
