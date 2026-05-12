//! Predictor: tracks (peer, file_id, t) access traces, predicts next file.

use std::collections::HashMap;

use thiserror::Error;

/// Errors the predictor surface can produce.
#[derive(Debug, Error)]
pub enum PrefetchError {
    /// Decay factor argument was outside the valid `(0.0, 1.0]` range.
    #[error("decay factor must be in (0.0, 1.0], got {0}")]
    InvalidDecay(f64),
    /// Half-life argument was zero — must be positive milliseconds.
    #[error("co-occurrence half-life must be positive, got {0} ms")]
    InvalidHalfLife(u64),
}

/// Maximum gap between two accesses we still treat as "linked" for
/// the co-occurrence model. Beyond this, the time-weighted count
/// drops below 1% and we don't bother updating.
pub const MAX_CO_OCCURRENCE_GAP_MS: u64 = 600_000; // 10 minutes

/// Predicted next file with a normalized confidence score (0.0 - 1.0).
#[derive(Debug, Clone, PartialEq)]
pub struct Prediction {
    /// 32-byte content-addressed id of the predicted next file.
    pub file_id: [u8; 32],
    /// Posterior probability the predictor assigns to this file
    /// being accessed next, normalized into `[0, 1]`.
    pub confidence: f64,
}

/// Per-peer access state.
#[derive(Debug, Clone, Default)]
struct PeerState {
    last_file: Option<[u8; 32]>,
    last_t_ms: u64,
    /// (last_file, next_file) → time-weighted co-occurrence count.
    pairs: HashMap<([u8; 32], [u8; 32]), f64>,
    /// per-file access counts (for cold-start fallback).
    files: HashMap<[u8; 32], f64>,
}

/// Active-inference-style prefetch predictor.
#[derive(Debug, Clone)]
pub struct PrefetchPredictor {
    /// Half-life (ms) for the time-weighting kernel
    /// `weight = exp(-gap_ms * ln(2) / half_life_ms)`.
    pub half_life_ms: u64,
    /// Decay factor applied on `decay_counts()` (typically 0.5).
    pub decay_factor: f64,
    peers: HashMap<[u8; 32], PeerState>,
}

impl Default for PrefetchPredictor {
    fn default() -> Self {
        Self {
            half_life_ms: 60_000, // 1 minute
            decay_factor: 0.5,
            peers: HashMap::new(),
        }
    }
}

impl PrefetchPredictor {
    /// Build a predictor with explicit `half_life_ms` + `decay_factor`.
    /// Returns `Err` if either arg is out of its valid range.
    pub fn new(half_life_ms: u64, decay_factor: f64) -> Result<Self, PrefetchError> {
        if half_life_ms == 0 {
            return Err(PrefetchError::InvalidHalfLife(half_life_ms));
        }
        if decay_factor <= 0.0 || decay_factor > 1.0 {
            return Err(PrefetchError::InvalidDecay(decay_factor));
        }
        Ok(Self {
            half_life_ms,
            decay_factor,
            peers: HashMap::new(),
        })
    }

    /// Record one access: peer P accessed file F at time t_ms.
    pub fn observe(&mut self, peer: &[u8; 32], file_id: [u8; 32], t_ms: u64) {
        let state = self.peers.entry(*peer).or_default();
        *state.files.entry(file_id).or_insert(0.0) += 1.0;
        if let Some(prev) = state.last_file {
            if t_ms >= state.last_t_ms {
                let gap = t_ms - state.last_t_ms;
                if gap <= MAX_CO_OCCURRENCE_GAP_MS {
                    // weight = exp(-gap * ln(2) / half_life)
                    let kernel =
                        (-(gap as f64) * std::f64::consts::LN_2 / self.half_life_ms as f64).exp();
                    let key = (prev, file_id);
                    *state.pairs.entry(key).or_insert(0.0) += kernel;
                }
            }
        }
        state.last_file = Some(file_id);
        state.last_t_ms = t_ms;
    }

    /// Predict the top `n` next files for a peer given their last
    /// access. Returns a Vec sorted by confidence (highest first).
    /// Empty if the peer has no recorded sequences.
    pub fn predict_top_n(&self, peer: &[u8; 32], n: usize) -> Vec<Prediction> {
        let Some(state) = self.peers.get(peer) else {
            return Vec::new();
        };
        let Some(last) = state.last_file else {
            // No "last" → fall back to most-frequent files for this peer.
            let mut all: Vec<_> = state.files.iter().collect();
            all.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));
            let total: f64 = state.files.values().sum();
            return all
                .into_iter()
                .take(n)
                .map(|(&fid, &c)| Prediction {
                    file_id: fid,
                    confidence: if total > 0.0 { c / total } else { 0.0 },
                })
                .collect();
        };
        let mut candidates: Vec<(([u8; 32], [u8; 32]), f64)> = state
            .pairs
            .iter()
            .filter(|((from, _), _)| from == &last)
            .map(|(k, &v)| (*k, v))
            .collect();
        if candidates.is_empty() {
            return Vec::new();
        }
        let total: f64 = candidates.iter().map(|(_, v)| *v).sum();
        candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        candidates
            .into_iter()
            .take(n)
            .map(|((_, fid), v)| Prediction {
                file_id: fid,
                confidence: if total > 0.0 { v / total } else { 0.0 },
            })
            .collect()
    }

    /// Bulk-decay all counters by `self.decay_factor`. Call periodically
    /// to let stale patterns fade + bound storage growth.
    pub fn decay_counts(&mut self) {
        for state in self.peers.values_mut() {
            for v in state.pairs.values_mut() {
                *v *= self.decay_factor;
            }
            for v in state.files.values_mut() {
                *v *= self.decay_factor;
            }
        }
    }

    /// Transfer a cohort prior: mix `source_peer`'s pairs into
    /// `target_peer` scaled by `weight`. Used to bootstrap a fresh
    /// peer (lukewarm start) from a similar peer's history.
    pub fn transfer_prior_from(
        &mut self,
        source_peer: &[u8; 32],
        target_peer: [u8; 32],
        weight: f64,
    ) {
        let source_pairs: Vec<_> = self
            .peers
            .get(source_peer)
            .map(|s| s.pairs.iter().map(|(k, v)| (*k, *v)).collect())
            .unwrap_or_default();
        let source_files: Vec<_> = self
            .peers
            .get(source_peer)
            .map(|s| s.files.iter().map(|(k, v)| (*k, *v)).collect())
            .unwrap_or_default();
        let target = self.peers.entry(target_peer).or_default();
        for (k, v) in source_pairs {
            *target.pairs.entry(k).or_insert(0.0) += v * weight;
        }
        for (k, v) in source_files {
            *target.files.entry(k).or_insert(0.0) += v * weight;
        }
    }

    /// Per-peer storage cost — sum of `(pairs.len() + files.len())`.
    pub fn storage_entries(&self) -> usize {
        self.peers
            .values()
            .map(|s| s.pairs.len() + s.files.len())
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(b: u8) -> [u8; 32] {
        [b; 32]
    }
    fn file(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn predict_top_n_empty_on_fresh_predictor() {
        let p = PrefetchPredictor::default();
        assert!(p.predict_top_n(&peer(1), 3).is_empty());
    }

    #[test]
    fn observe_then_predict_returns_co_occurring_files() {
        let mut p = PrefetchPredictor::default();
        // Alice: A → B → C, repeated.
        for i in 0..10u64 {
            p.observe(&peer(1), file(0xA), i * 100);
            p.observe(&peer(1), file(0xB), i * 100 + 10);
            p.observe(&peer(1), file(0xC), i * 100 + 20);
        }
        // After A, predict B (most likely next).
        p.observe(&peer(1), file(0xA), 9999);
        let preds = p.predict_top_n(&peer(1), 3);
        assert!(!preds.is_empty());
        assert_eq!(preds[0].file_id, file(0xB));
        assert!(preds[0].confidence > 0.0);
    }

    #[test]
    fn recent_co_occurrences_outweigh_distant_ones() {
        let mut p = PrefetchPredictor::default();
        // Old pattern: A → X, but the gap is long (5 minutes).
        p.observe(&peer(1), file(0xA), 0);
        p.observe(&peer(1), file(0xC8), 300_000);
        // Recent pattern: A → Y, tight.
        p.observe(&peer(1), file(0xA), 1_000_000);
        p.observe(&peer(1), file(0xD2), 1_000_010);
        // Set last to A.
        p.observe(&peer(1), file(0xA), 2_000_000);
        let preds = p.predict_top_n(&peer(1), 2);
        assert!(!preds.is_empty());
        // The tight pattern should win — D2 ranks above C8.
        let positions: Vec<u8> = preds.iter().map(|p| p.file_id[0]).collect();
        let pos_d2 = positions.iter().position(|&b| b == 0xD2).unwrap_or(99);
        let pos_c8 = positions.iter().position(|&b| b == 0xC8).unwrap_or(99);
        assert!(
            pos_d2 < pos_c8,
            "recent D2 should outrank old C8; got positions {:?}",
            positions
        );
    }

    #[test]
    fn decay_counts_lets_fresh_co_occurrences_overtake_old_ones() {
        let mut p = PrefetchPredictor::default();
        // Build pair A→B with full weight.
        p.observe(&peer(1), file(0xA), 0);
        p.observe(&peer(1), file(0xB), 50);
        // Decay so A→B's weight halves.
        p.decay_counts();
        // Now record a fresh pair A→C at full weight.
        p.observe(&peer(1), file(0xA), 1000);
        p.observe(&peer(1), file(0xC), 1050);
        // Reset last_file to A and predict.
        p.observe(&peer(1), file(0xA), 2000);
        let preds = p.predict_top_n(&peer(1), 2);
        // C (fresh, full weight) should rank above B (decayed half-weight).
        let positions: Vec<u8> = preds.iter().map(|p| p.file_id[0]).collect();
        let pos_c = positions.iter().position(|&b| b == 0xC).unwrap_or(99);
        let pos_b = positions.iter().position(|&b| b == 0xB).unwrap_or(99);
        assert!(
            pos_c < pos_b,
            "fresh C should outrank decayed B; positions={:?}",
            positions
        );
    }

    #[test]
    fn cohort_prior_transfer_warms_a_fresh_peer() {
        let mut p = PrefetchPredictor::default();
        // Alice observed A → B.
        p.observe(&peer(1), file(0xA), 0);
        p.observe(&peer(1), file(0xB), 50);
        // Bob is brand new; transfer Alice's pattern with weight 1.0.
        p.transfer_prior_from(&peer(1), peer(2), 1.0);
        // Bob's last-file would still be unknown. Seed Bob's current
        // location to A and predict next.
        p.observe(&peer(2), file(0xA), 1000);
        let preds = p.predict_top_n(&peer(2), 1);
        assert!(
            !preds.is_empty(),
            "Bob's cohort prior should produce a prediction"
        );
        assert_eq!(preds[0].file_id, file(0xB));
    }

    #[test]
    fn predictor_rejects_invalid_decay_or_half_life() {
        assert!(PrefetchPredictor::new(0, 0.5).is_err());
        assert!(PrefetchPredictor::new(100, 0.0).is_err());
        assert!(PrefetchPredictor::new(100, 1.5).is_err());
        assert!(PrefetchPredictor::new(100, -0.1).is_err());
    }

    #[test]
    fn no_predictions_when_only_one_access() {
        let mut p = PrefetchPredictor::default();
        p.observe(&peer(1), file(0xA), 0);
        // No co-occurrence yet — but the "most-frequent file" fallback
        // should still surface A as the only known file.
        let preds = p.predict_top_n(&peer(1), 1);
        // Either empty (no last-pair) or returns A as the only file.
        // Current implementation: last is set to A; predict_top_n
        // filters pairs[from == A], which is empty → returns [].
        assert!(preds.is_empty());
    }
}
