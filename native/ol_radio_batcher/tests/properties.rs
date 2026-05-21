//! Property-based tests for `ol_radio_batcher`.
//!
//! These verify invariants that must hold across the entire input
//! space, beyond the targeted unit tests in the crate.

use ol_radio_batcher::{Batcher, BatcherError, Priority};
use proptest::prelude::*;

fn arb_priority() -> impl Strategy<Value = Priority> {
    prop_oneof![
        Just(Priority::Urgent),
        Just(Priority::Normal),
        Just(Priority::Background),
    ]
}

proptest! {
    /// `drain` is total: never panics for any (queue state, now_ms).
    /// queue.len() + drained.len() == prior queue.len() (no loss).
    #[test]
    fn drain_preserves_count(
        n_enqueue in 0usize..50,
        prio in arb_priority(),
        start_ms in 1_000u64..100_000,
        drain_offset_ms in 0u64..30_000,
    ) {
        let mut b: Batcher<u32> = Batcher::new();
        for i in 0..n_enqueue {
            b.enqueue(format!("p{i}"), i as u32, prio, start_ms).unwrap();
        }
        let prior_len = b.len();
        let (drained, outcome) = b.drain(start_ms + drain_offset_ms);
        prop_assert_eq!(drained.len() + b.len(), prior_len);
        prop_assert_eq!(outcome.drained, drained.len());
        prop_assert_eq!(outcome.remaining, b.len());
    }

    /// `enqueue` either succeeds (size increments by 1) or returns
    /// QueueFull (size unchanged).
    #[test]
    fn enqueue_is_total(
        max_size in 1usize..32,
        n_attempts in 0usize..50,
        start_ms in 0u64..1_000_000,
    ) {
        let mut b: Batcher<u32> = Batcher::with_config(50, max_size, 20_000).unwrap();
        for i in 0..n_attempts {
            let prior = b.len();
            match b.enqueue(format!("p{i}"), i as u32, Priority::Normal, start_ms + i as u64) {
                Ok(()) => {
                    prop_assert_eq!(b.len(), prior + 1);
                }
                Err(BatcherError::QueueFull { size, max }) => {
                    prop_assert_eq!(b.len(), prior);
                    prop_assert_eq!(size, max_size);
                    prop_assert_eq!(max, max_size);
                }
                Err(other) => prop_assert!(false, "unexpected error: {other:?}"),
            }
        }
        prop_assert!(b.len() <= max_size);
    }

    /// Urgent entries drain at any non-negative age.
    #[test]
    fn urgent_drains_at_any_age(
        start_ms in 1_000u64..1_000_000,
        drain_delta in 0u64..u64::from(u32::MAX),
    ) {
        let mut b: Batcher<u32> = Batcher::new();
        b.enqueue("p", 1, Priority::Urgent, start_ms).unwrap();
        let now = start_ms.saturating_add(drain_delta);
        let (drained, _) = b.drain(now);
        prop_assert_eq!(drained.len(), 1);
    }

    /// FIFO ordering: drained entries' enqueue timestamps are
    /// non-decreasing (assuming we enqueue with non-decreasing ms).
    #[test]
    fn fifo_ordering(
        n in 1usize..20,
        prio in arb_priority(),
        start_ms in 1_000u64..100_000,
    ) {
        let mut b: Batcher<u32> = Batcher::new();
        for i in 0..n {
            b.enqueue("p", i as u32, prio, start_ms + i as u64).unwrap();
        }
        // Drain far in the future so everything is eligible.
        let (drained, _) = b.drain(start_ms + 1_000_000);
        prop_assert_eq!(drained.len(), n);
        for window in drained.windows(2) {
            prop_assert!(window[0].enqueued_at_ms <= window[1].enqueued_at_ms);
        }
    }

    /// drain_all leaves the queue empty.
    #[test]
    fn drain_all_empties_queue(
        n in 0usize..50,
        prio in arb_priority(),
    ) {
        let mut b: Batcher<u32> = Batcher::new();
        for i in 0..n {
            b.enqueue("p", i as u32, prio, 1000).unwrap();
        }
        let drained = b.drain_all();
        prop_assert_eq!(drained.len(), n);
        prop_assert!(b.is_empty());
    }

    /// Time-skew backward: drain returns nothing extra.
    /// (Worst case: entries simply remain queued; no panic.)
    #[test]
    fn time_skew_backward_no_panic(
        enqueue_ms in 10_000u64..100_000,
        skew_back in 0u64..10_000,
    ) {
        let mut b: Batcher<u32> = Batcher::new();
        b.enqueue("p", 1, Priority::Normal, enqueue_ms).unwrap();
        let earlier = enqueue_ms.saturating_sub(skew_back);
        let (drained, _) = b.drain(earlier);
        // Either zero (if skew>0 so age=0 < window) or one (if skew=0,
        // but window > 0 so still zero).
        prop_assert!(drained.is_empty());
        prop_assert_eq!(b.len(), 1);
    }

    /// Stats counters never decrease over time (monotone).
    #[test]
    fn stats_monotone(
        ops in proptest::collection::vec((arb_priority(), 0u32..100), 0..30),
    ) {
        let mut b: Batcher<u32> = Batcher::new();
        let mut prev_enqueued = 0u64;
        let mut prev_drained = 0u64;
        let mut prev_rejected = 0u64;
        let mut prev_aged = 0u64;
        for (i, (prio, val)) in ops.iter().enumerate() {
            let now = 1000 + i as u64 * 10;
            let _ = b.enqueue(format!("p{i}"), *val, *prio, now);
            // Periodic drain.
            if i % 5 == 4 {
                let _ = b.drain(now + 60);
            }
            let s = b.stats();
            prop_assert!(s.enqueued_total >= prev_enqueued);
            prop_assert!(s.drained_total >= prev_drained);
            prop_assert!(s.rejected_full >= prev_rejected);
            prop_assert!(s.aged_out >= prev_aged);
            prev_enqueued = s.enqueued_total;
            prev_drained = s.drained_total;
            prev_rejected = s.rejected_full;
            prev_aged = s.aged_out;
        }
    }
}
