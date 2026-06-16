//! Aggregated routing history.

use std::collections::BTreeMap;

use crate::subkey::DEVICE_ID_LEN;

use super::record::DeviceActionRecord;

/// Composite key: `(context_hash, device_id)`.
type RecordKey = ([u8; 32], [u8; DEVICE_ID_LEN]);

/// Local routing-history table.
#[derive(Debug, Clone, Default)]
pub struct RoutingHistory {
    records: BTreeMap<RecordKey, DeviceActionRecord>,
}

impl RoutingHistory {
    /// Empty history.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Observe an action. Creates a fresh record (with the supplied
    /// prior `α / β`) if one doesn't exist; otherwise updates the
    /// existing record's posterior.
    pub fn observe(
        &mut self,
        context_hash: [u8; 32],
        device_id: [u8; DEVICE_ID_LEN],
        acted: bool,
        now_unix: u64,
        prior_alpha: u32,
        prior_beta: u32,
    ) {
        let key = (context_hash, device_id);
        let rec = self
            .records
            .entry(key)
            .or_insert_with(|| DeviceActionRecord {
                context_hash,
                device_id,
                alpha: prior_alpha.max(1),
                beta: prior_beta.max(1),
                last_updated_unix: now_unix,
            });
        rec.observe(acted, now_unix);
    }

    /// Look up the record for `(context_hash, device_id)`. Returns
    /// `None` if we've never observed this pair.
    #[must_use]
    pub fn record(
        &self,
        context_hash: &[u8; 32],
        device_id: &[u8; DEVICE_ID_LEN],
    ) -> Option<&DeviceActionRecord> {
        self.records.get(&(*context_hash, *device_id))
    }

    /// Total record count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// True iff no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Apply a global half-life decay sweep at `now_unix`. Daemon
    /// runs this periodically (e.g., once per day).
    pub fn decay_all(&mut self, now_unix: u64, half_life_secs: u64) {
        for r in self.records.values_mut() {
            r.decay(now_unix, half_life_secs);
        }
    }

    /// Iterate `(context_hash, device_id, record)` in deterministic
    /// order.
    pub fn iter(
        &self,
    ) -> impl Iterator<Item = (&[u8; 32], &[u8; DEVICE_ID_LEN], &DeviceActionRecord)> {
        self.records.iter().map(|((ctx, dev), rec)| (ctx, dev, rec))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn d(byte: u8) -> [u8; DEVICE_ID_LEN] {
        [byte; DEVICE_ID_LEN]
    }

    #[test]
    fn observe_creates_then_updates() {
        let mut hist = RoutingHistory::empty();
        hist.observe(h(1), d(1), true, 100, 1, 1);
        let rec = hist.record(&h(1), &d(1)).unwrap();
        assert_eq!(rec.alpha, 2);
        assert_eq!(rec.beta, 1);
        hist.observe(h(1), d(1), false, 200, 1, 1);
        let rec = hist.record(&h(1), &d(1)).unwrap();
        assert_eq!(rec.alpha, 2);
        assert_eq!(rec.beta, 2);
        assert_eq!(rec.last_updated_unix, 200);
    }

    #[test]
    fn decay_all_applies_across_records() {
        let mut hist = RoutingHistory::empty();
        // 10 acts on dev1 + 5 dismisses → alpha=11, beta=6.
        for _ in 0..10 {
            hist.observe(h(1), d(1), true, 100, 1, 1);
        }
        for _ in 0..5 {
            hist.observe(h(1), d(1), false, 100, 1, 1);
        }
        hist.decay_all(200, 100); // one half-life
        let rec = hist.record(&h(1), &d(1)).unwrap();
        assert!(rec.alpha <= 11 / 2 + 1);
        assert!(rec.beta <= 6 / 2 + 1);
    }

    #[test]
    fn iter_returns_records() {
        let mut hist = RoutingHistory::empty();
        hist.observe(h(1), d(1), true, 1, 1, 1);
        hist.observe(h(2), d(2), false, 1, 1, 1);
        let items: Vec<_> = hist.iter().collect();
        assert_eq!(items.len(), 2);
    }
}
