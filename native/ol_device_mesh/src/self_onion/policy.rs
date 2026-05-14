//! Self-onion routing policy.
//!
//! Tells the daemon WHEN to switch from direct device-to-device
//! traffic to a self-onion circuit. The daemon owns the actual
//! hostile-network detection; this layer just expresses the
//! resulting decision.

/// Default minimum hop count for self-onion circuits. At 2 hops
/// (one intermediate device), the on-path observer can't link
/// `src → dst`; one peeling hop is enough to break the trivial
/// "same destination IP every connection" inference.
pub const DEFAULT_MIN_HOPS: usize = 2;

/// Policy controlling self-onion behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfOnionContext {
    /// Minimum number of intermediate devices in a circuit. 2+
    /// gives meaningful obscuring; 3+ for actively-monitored
    /// networks.
    pub min_hops: usize,
    /// `true` when the daemon believes the local network is
    /// untrusted. Higher layers populate this from Wi-Fi-SSID
    /// allow-lists, captive-portal detection, geolocation, etc.
    pub network_is_hostile: bool,
    /// Bytes-per-second of cover traffic the daemon SHOULD inject
    /// while in hostile mode. Zero means "no cover." See Phase B
    /// `ol_onion::sphinx::cover` for the actual emission primitive.
    pub cover_traffic_bps: u64,
}

impl SelfOnionContext {
    /// Sensible defaults for "trusted home network" — no self-onion,
    /// no cover.
    #[must_use]
    pub const fn trusted_home() -> Self {
        Self {
            min_hops: DEFAULT_MIN_HOPS,
            network_is_hostile: false,
            cover_traffic_bps: 0,
        }
    }

    /// "Hostile network" preset: 3-hop minimum + 100 KB/s cover.
    #[must_use]
    pub const fn hostile_network() -> Self {
        Self {
            min_hops: 3,
            network_is_hostile: true,
            cover_traffic_bps: 100_000,
        }
    }

    /// `true` if the current policy says "use self-onion."
    #[must_use]
    pub const fn requires_self_onion(&self) -> bool {
        self.network_is_hostile
    }
}

impl Default for SelfOnionContext {
    fn default() -> Self {
        Self::trusted_home()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_home_does_not_require_self_onion() {
        let c = SelfOnionContext::trusted_home();
        assert!(!c.requires_self_onion());
        assert_eq!(c.cover_traffic_bps, 0);
    }

    #[test]
    fn hostile_network_requires_self_onion() {
        let c = SelfOnionContext::hostile_network();
        assert!(c.requires_self_onion());
        assert_eq!(c.min_hops, 3);
        assert!(c.cover_traffic_bps > 0);
    }
}
