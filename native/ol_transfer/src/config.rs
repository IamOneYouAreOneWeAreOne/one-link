//! `TransferConfig` knobs for the engine.

use ol_bloom::DEFAULT_TARGET_FP_RATE;

/// Hard concurrency ceiling protecting Tokio's semaphore/task scheduler.
pub const MAX_INFLIGHT_PER_PEER: usize = 1_024;

/// Configuration for [`crate::TransferEngine`].
///
/// Defaults are chosen per [ADR-0013](../../../docs/decisions/0013-transfer-engine.md).
#[derive(Debug, Clone)]
pub struct TransferConfig {
    /// Maximum simultaneous in-flight chunk fetches per peer. Excess
    /// fetches wait via a semaphore. Default 32.
    pub max_inflight_per_peer: usize,

    /// How long to wait for a single chunk request before failing.
    /// Default 10 seconds (chunk records are at most 1 MiB; even a slow
    /// peer should reply within this).
    pub chunk_request_timeout_ms: u64,

    /// How long to wait for the bloom-init reply before failing.
    /// Default 30 seconds (server side may iterate a large manifest).
    pub bloom_handshake_timeout_ms: u64,

    /// How long an idle cached connection stays alive without being
    /// reused. Default matches the QUIC endpoint's `idle_timeout_ms`.
    pub connection_idle_ms: u64,

    /// Bloom filter target false-positive rate for `bloom_handshake`.
    /// Default 0.01 (1%) per ADR-0011.
    pub bloom_target_fp: f64,
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            max_inflight_per_peer: 32,
            chunk_request_timeout_ms: 10_000,
            bloom_handshake_timeout_ms: 30_000,
            connection_idle_ms: 30_000,
            bloom_target_fp: DEFAULT_TARGET_FP_RATE,
        }
    }
}

impl TransferConfig {
    pub(crate) fn normalized(mut self) -> Self {
        self.max_inflight_per_peer = self.max_inflight_per_peer.clamp(1, MAX_INFLIGHT_PER_PEER);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrency_is_never_zero_or_above_hard_ceiling() {
        let config = TransferConfig {
            max_inflight_per_peer: 0,
            ..TransferConfig::default()
        };
        assert_eq!(config.normalized().max_inflight_per_peer, 1);

        let config = TransferConfig {
            max_inflight_per_peer: usize::MAX,
            ..TransferConfig::default()
        };
        assert_eq!(
            config.normalized().max_inflight_per_peer,
            MAX_INFLIGHT_PER_PEER
        );
    }
}
