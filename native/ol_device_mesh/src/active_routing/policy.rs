//! Active-routing policy.

/// Default half-life for routing-history decay (30 days). Older
/// observations are halved every 30 days so the picker tracks
/// drifting user preferences over time.
pub const ROUTING_HISTORY_DECAY_DEFAULT_SECS: u64 = 30 * 24 * 3600;

/// Per-daemon policy controlling the routing-history behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutingPolicy {
    /// Half-life (seconds) for the periodic decay sweep on
    /// [`super::RoutingHistory`].
    pub history_decay_half_life_secs: u64,
    /// Minimum number of observations under a `(context, device)`
    /// pair before the picker is allowed to exploit. Below this,
    /// Thompson sampling falls back to the cohort prior with a
    /// flat posterior. Useful for honest cold-start behaviour.
    pub min_observations_before_exploit: u32,
    /// If `true`, the daemon writes signed copies of every
    /// observation to a Layer-3 CRDT subtree so sibling devices
    /// mirror the routing history.
    pub mirror_to_siblings: bool,
}

impl RoutingPolicy {
    /// Conservative default: 30-day half-life, 10-observation
    /// warmup, mirror to siblings.
    #[must_use]
    pub const fn conservative() -> Self {
        Self {
            history_decay_half_life_secs: ROUTING_HISTORY_DECAY_DEFAULT_SECS,
            min_observations_before_exploit: 10,
            mirror_to_siblings: true,
        }
    }

    /// Aggressive preset for high-volume mesh use: 7-day half-life,
    /// 3-observation warmup. Adapts to drift faster, less stable.
    #[must_use]
    pub const fn aggressive() -> Self {
        Self {
            history_decay_half_life_secs: 7 * 24 * 3600,
            min_observations_before_exploit: 3,
            mirror_to_siblings: true,
        }
    }
}

impl Default for RoutingPolicy {
    fn default() -> Self {
        Self::conservative()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conservative_defaults() {
        let p = RoutingPolicy::conservative();
        assert_eq!(p.history_decay_half_life_secs, 30 * 24 * 3600);
        assert_eq!(p.min_observations_before_exploit, 10);
        assert!(p.mirror_to_siblings);
    }

    #[test]
    fn aggressive_shorter_half_life() {
        let p = RoutingPolicy::aggressive();
        assert!(p.history_decay_half_life_secs < ROUTING_HISTORY_DECAY_DEFAULT_SECS);
        assert!(p.min_observations_before_exploit <= 5);
    }
}
