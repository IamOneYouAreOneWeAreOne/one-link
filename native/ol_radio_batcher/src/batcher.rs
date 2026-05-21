//! The core `Batcher` state machine.

use std::collections::VecDeque;

use crate::error::BatcherError;
use crate::priority::Priority;
use crate::state::RadioState;
use crate::{DEFAULT_DRX_WINDOW_MS, DEFAULT_MAX_AGE_MS, DEFAULT_MAX_QUEUE_SIZE};

/// One queued entry awaiting drain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueEntry<T> {
    /// Peer fingerprint (or any logical destination tag).
    pub peer_fp: String,
    /// Caller payload (the actual transmission body).
    pub payload: T,
    /// Priority level set by the selector.
    pub priority: Priority,
    /// Wall-clock timestamp (ms) when this entry was enqueued.
    pub enqueued_at_ms: u64,
}

/// Per-call statistics returned by [`Batcher::drain`] for observability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DrainOutcome {
    /// Number of entries drained on this call.
    pub drained: usize,
    /// Number of entries still in the queue (deferred).
    pub remaining: usize,
    /// Number of entries force-drained because they hit `max_age_ms`.
    pub force_drained_due_to_age: usize,
}

/// Aggregate counters for observability / health endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BatcherStats {
    /// Total entries ever enqueued.
    pub enqueued_total: u64,
    /// Total entries ever drained.
    pub drained_total: u64,
    /// Total enqueues rejected due to QueueFull.
    pub rejected_full: u64,
    /// Total entries force-drained due to age.
    pub aged_out: u64,
}

/// A radio-aware deterministic batcher.
///
/// All methods are total (never panic) for any caller input. Time is
/// passed in by the caller, never read from the system clock. State
/// is fully serializable in principle (the `T` type parameter is the
/// payload; if `T: Clone`, `Batcher<T>` is `Clone`).
///
/// Invariants:
///   - `queue.len() <= max_queue_size` at all times
///   - `drx_window_ms > 0` and `max_queue_size > 0` (enforced by ctor)
///   - Entries are FIFO within a priority tier (drained in enqueue
///     order subject to age-windowed eligibility)
#[derive(Debug, Clone)]
pub struct Batcher<T> {
    queue: VecDeque<QueueEntry<T>>,
    drx_window_ms: u32,
    max_queue_size: usize,
    max_age_ms: u32,
    radio_state: RadioState,
    stats: BatcherStats,
}

impl<T> Batcher<T> {
    /// Construct a batcher with default tuning (Gap 11 / Gap 14 derived).
    ///
    /// - `drx_window_ms` = 50 (Gap 11 finding)
    /// - `max_queue_size` = 4096 (enough for thousands of paired peers)
    /// - `max_age_ms` = 20000 (force-drain stale entries)
    #[must_use]
    pub fn new() -> Self {
        // Constructor parameters are valid by construction so the
        // `Result` would always be Ok; unwrap is safe.
        Self::with_config(DEFAULT_DRX_WINDOW_MS, DEFAULT_MAX_QUEUE_SIZE, DEFAULT_MAX_AGE_MS)
            .expect("default config is always valid")
    }

    /// Construct with explicit configuration.
    ///
    /// # Errors
    /// Returns [`BatcherError::InvalidDrxWindow`] if `drx_window_ms == 0`.
    /// Returns [`BatcherError::InvalidMaxQueueSize`] if `max_queue_size == 0`.
    pub fn with_config(
        drx_window_ms: u32,
        max_queue_size: usize,
        max_age_ms: u32,
    ) -> Result<Self, BatcherError> {
        if drx_window_ms == 0 {
            return Err(BatcherError::InvalidDrxWindow { got: drx_window_ms });
        }
        if max_queue_size == 0 {
            return Err(BatcherError::InvalidMaxQueueSize {
                got: max_queue_size,
            });
        }
        Ok(Self {
            queue: VecDeque::with_capacity(64),
            drx_window_ms,
            max_queue_size,
            max_age_ms,
            radio_state: RadioState::default(),
            stats: BatcherStats::default(),
        })
    }

    /// Enqueue an entry for batched delivery.
    ///
    /// # Errors
    /// Returns [`BatcherError::QueueFull`] when the queue is at
    /// `max_queue_size`. The caller's selector should fall through to
    /// emit-now in that case.
    pub fn enqueue(
        &mut self,
        peer_fp: impl Into<String>,
        payload: T,
        priority: Priority,
        now_ms: u64,
    ) -> Result<(), BatcherError> {
        if self.queue.len() >= self.max_queue_size {
            self.stats.rejected_full = self.stats.rejected_full.saturating_add(1);
            return Err(BatcherError::QueueFull {
                size: self.queue.len(),
                max: self.max_queue_size,
            });
        }
        self.queue.push_back(QueueEntry {
            peer_fp: peer_fp.into(),
            payload,
            priority,
            enqueued_at_ms: now_ms,
        });
        self.stats.enqueued_total = self.stats.enqueued_total.saturating_add(1);
        Ok(())
    }

    /// Return all entries that are eligible to drain at `now_ms`.
    ///
    /// "Eligible" means one of:
    ///   - `Priority::Urgent` (drains immediately)
    ///   - Age >= `priority.window_multiplier() * drx_window_ms`
    ///   - Age >= `max_age_ms` (force-drain stale)
    ///
    /// Time-monotone but tolerant of clock skew: if `now_ms` somehow
    /// goes backward, entries simply stay queued until time moves
    /// forward again. No panic, no data loss.
    pub fn drain(&mut self, now_ms: u64) -> (Vec<QueueEntry<T>>, DrainOutcome) {
        let mut drained = Vec::with_capacity(self.queue.len());
        let mut force_drained = 0usize;

        // Split off eligible entries while preserving FIFO order
        // across the remaining queue. We walk the queue once and
        // bucket by eligibility.
        let mut remaining = VecDeque::with_capacity(self.queue.len());
        while let Some(entry) = self.queue.pop_front() {
            let age = now_ms.saturating_sub(entry.enqueued_at_ms);
            let window = u64::from(entry.priority.window_multiplier())
                .saturating_mul(u64::from(self.drx_window_ms));
            let aged_out = age >= u64::from(self.max_age_ms);
            let window_due = age >= window;
            if aged_out || window_due {
                if aged_out && !window_due {
                    force_drained += 1;
                }
                drained.push(entry);
            } else {
                remaining.push_back(entry);
            }
        }
        self.queue = remaining;

        let outcome = DrainOutcome {
            drained: drained.len(),
            remaining: self.queue.len(),
            force_drained_due_to_age: force_drained,
        };

        self.stats.drained_total = self
            .stats
            .drained_total
            .saturating_add(drained.len() as u64);
        self.stats.aged_out = self.stats.aged_out.saturating_add(force_drained as u64);

        (drained, outcome)
    }

    /// Force-drain everything regardless of age.
    ///
    /// Used by the daemon at shutdown or when the selector explicitly
    /// signals an emergency flush.
    pub fn drain_all(&mut self) -> Vec<QueueEntry<T>> {
        let drained: Vec<_> = self.queue.drain(..).collect();
        self.stats.drained_total = self
            .stats
            .drained_total
            .saturating_add(drained.len() as u64);
        drained
    }

    /// Current queue length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// True iff the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Configured DRX window in milliseconds.
    #[must_use]
    pub fn drx_window_ms(&self) -> u32 {
        self.drx_window_ms
    }

    /// Currently-observed radio state.
    ///
    /// Note: the deterministic core does NOT vary scheduling based
    /// on this. It's a daemon-side observability signal only.
    #[must_use]
    pub fn radio_state(&self) -> RadioState {
        self.radio_state
    }

    /// Update the observed radio state.
    pub fn set_radio_state(&mut self, state: RadioState) {
        self.radio_state = state;
    }

    /// Aggregate counters since construction.
    #[must_use]
    pub fn stats(&self) -> BatcherStats {
        self.stats
    }
}

impl<T> Default for Batcher<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b() -> Batcher<u32> {
        Batcher::new()
    }

    // ───── Construction ──────────────────────────────────────────────

    #[test]
    fn new_is_empty() {
        let b: Batcher<u32> = b();
        assert_eq!(b.len(), 0);
        assert!(b.is_empty());
        assert_eq!(b.drx_window_ms(), DEFAULT_DRX_WINDOW_MS);
    }

    #[test]
    fn zero_window_rejected() {
        assert!(matches!(
            Batcher::<u32>::with_config(0, 10, 1000),
            Err(BatcherError::InvalidDrxWindow { .. })
        ));
    }

    #[test]
    fn zero_max_size_rejected() {
        assert!(matches!(
            Batcher::<u32>::with_config(50, 0, 1000),
            Err(BatcherError::InvalidMaxQueueSize { .. })
        ));
    }

    // ───── Enqueue + Drain ───────────────────────────────────────────

    #[test]
    fn fresh_entry_not_drained_immediately() {
        let mut b = b();
        b.enqueue("p1", 1, Priority::Normal, 1000).unwrap();
        // Drain at same ms: window hasn't elapsed.
        let (drained, _) = b.drain(1000);
        assert!(drained.is_empty());
        assert_eq!(b.len(), 1);
    }

    #[test]
    fn entry_drains_after_window() {
        let mut b = b();
        b.enqueue("p1", 1, Priority::Normal, 1000).unwrap();
        // Past DRX window (50ms default).
        let (drained, outcome) = b.drain(1100);
        assert_eq!(drained.len(), 1);
        assert_eq!(outcome.drained, 1);
        assert_eq!(outcome.remaining, 0);
        assert_eq!(outcome.force_drained_due_to_age, 0);
        assert_eq!(b.len(), 0);
    }

    #[test]
    fn urgent_drains_immediately() {
        let mut b = b();
        b.enqueue("p1", 1, Priority::Urgent, 1000).unwrap();
        // Same ms — Urgent multiplier is 0, so age 0 >= 0 holds.
        let (drained, _) = b.drain(1000);
        assert_eq!(drained.len(), 1);
    }

    #[test]
    fn background_waits_longer_than_normal() {
        let mut b = b();
        b.enqueue("p1", 1, Priority::Normal, 1000).unwrap();
        b.enqueue("p2", 2, Priority::Background, 1000).unwrap();
        // Past 1× DRX window: Normal drains, Background does not.
        let (drained, _) = b.drain(1060);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].peer_fp, "p1");
        assert_eq!(b.len(), 1);

        // Past 3× DRX window: Background drains too.
        let (drained, _) = b.drain(1200);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].peer_fp, "p2");
        assert_eq!(b.len(), 0);
    }

    #[test]
    fn fifo_within_priority() {
        let mut b = b();
        b.enqueue("p1", 1, Priority::Normal, 1000).unwrap();
        b.enqueue("p2", 2, Priority::Normal, 1010).unwrap();
        b.enqueue("p3", 3, Priority::Normal, 1020).unwrap();
        let (drained, _) = b.drain(1100);
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0].payload, 1);
        assert_eq!(drained[1].payload, 2);
        assert_eq!(drained[2].payload, 3);
    }

    #[test]
    fn mixed_priority_drains_eligible_only() {
        let mut b = b();
        b.enqueue("urgent", 0, Priority::Urgent, 1000).unwrap();
        b.enqueue("normal", 1, Priority::Normal, 1000).unwrap();
        b.enqueue("bg", 2, Priority::Background, 1000).unwrap();
        let (drained, _) = b.drain(1010);
        // Urgent: age 10 >= 0     ✓
        // Normal: age 10 >= 50    ✗
        // BG:     age 10 >= 150   ✗
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].priority, Priority::Urgent);
        assert_eq!(b.len(), 2);
    }

    // ───── Age force-drain ──────────────────────────────────────────

    #[test]
    fn aged_out_force_drained() {
        // max_age 20s, window 50ms. Entry sits for 30s — must drain
        // even though it's Background (which would only need 150ms
        // anyway; this is mostly a corner-case smoke test).
        let mut b = b();
        b.enqueue("stale", 1, Priority::Background, 1000).unwrap();
        let (drained, outcome) = b.drain(1000 + 30_000);
        assert_eq!(drained.len(), 1);
        // The age check fires for Background after 150ms; this just
        // confirms aged_out doesn't cause double-count.
        assert_eq!(outcome.drained, 1);
    }

    #[test]
    fn aged_out_counter_increments_only_when_window_not_met() {
        // Window 1000ms (long), max_age 500ms (short).
        // After 600ms: window NOT met (1000ms not elapsed), age WAS met.
        let mut b = Batcher::<u32>::with_config(1000, 100, 500).unwrap();
        b.enqueue("p1", 1, Priority::Normal, 1000).unwrap();
        let (drained, outcome) = b.drain(1600);
        assert_eq!(drained.len(), 1);
        assert_eq!(outcome.force_drained_due_to_age, 1);
        assert_eq!(b.stats().aged_out, 1);
    }

    // ───── Queue full ────────────────────────────────────────────────

    #[test]
    fn queue_full_rejected() {
        let mut b = Batcher::<u32>::with_config(50, 3, 20_000).unwrap();
        for i in 0..3 {
            b.enqueue("p", i, Priority::Normal, 1000).unwrap();
        }
        let r = b.enqueue("p", 99, Priority::Normal, 1000);
        assert!(matches!(r, Err(BatcherError::QueueFull { size: 3, max: 3 })));
        assert_eq!(b.stats().rejected_full, 1);
    }

    // ───── Time skew tolerance ───────────────────────────────────────

    #[test]
    fn time_skew_backward_does_not_lose_entries() {
        let mut b = b();
        b.enqueue("p1", 1, Priority::Normal, 5000).unwrap();
        // Time goes backward (NTP adjust).
        let (drained, _) = b.drain(4000);
        // Saturating-sub means age is 0 — entry stays queued.
        assert!(drained.is_empty());
        assert_eq!(b.len(), 1);
        // When time moves forward again, drain works normally.
        let (drained, _) = b.drain(6000);
        assert_eq!(drained.len(), 1);
    }

    // ───── Drain-all ─────────────────────────────────────────────────

    #[test]
    fn drain_all_force_flushes() {
        let mut b = b();
        b.enqueue("p1", 1, Priority::Background, 1000).unwrap();
        b.enqueue("p2", 2, Priority::Normal, 1010).unwrap();
        let drained = b.drain_all();
        assert_eq!(drained.len(), 2);
        assert_eq!(b.len(), 0);
    }

    // ───── Stats + radio state ──────────────────────────────────────

    #[test]
    fn stats_track_lifecycle() {
        let mut b = b();
        b.enqueue("p1", 1, Priority::Normal, 1000).unwrap();
        b.enqueue("p2", 2, Priority::Normal, 1000).unwrap();
        let (_, _) = b.drain(2000);
        let s = b.stats();
        assert_eq!(s.enqueued_total, 2);
        assert_eq!(s.drained_total, 2);
        assert_eq!(s.rejected_full, 0);
    }

    #[test]
    fn radio_state_round_trip() {
        let mut b = b();
        assert_eq!(b.radio_state(), RadioState::Active);
        b.set_radio_state(RadioState::LongDrx);
        assert_eq!(b.radio_state(), RadioState::LongDrx);
    }

    // ───── Default impl ──────────────────────────────────────────────

    #[test]
    fn default_matches_new() {
        let d: Batcher<u32> = Batcher::default();
        let n: Batcher<u32> = Batcher::new();
        assert_eq!(d.drx_window_ms(), n.drx_window_ms());
    }
}
