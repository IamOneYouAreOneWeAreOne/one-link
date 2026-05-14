//! Duress-mode policy.

/// Default time the daemon keeps the device in decoy-only mode
/// after a duress unlock. 24 hours. During this window:
///   - The real ciphertext is NEVER touched.
///   - Sibling-emitted commands targeting the seized device are
///     queued but not executed.
///   - The user's "I'm safe now" out-of-band signal lifts the
///     quarantine + re-enables the real state.
pub const DURESS_DEFAULT_QUARANTINE_SECS: u64 = 24 * 3600;

/// Duress policy controlling daemon behaviour after a decoy unlock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuressPolicy {
    /// `true` if the daemon should silently emit a [`super::DuressAlert`]
    /// the moment a decoy unlock succeeds.
    pub emit_alert_on_decoy_unlock: bool,
    /// Quarantine window in seconds.
    pub quarantine_secs: u64,
    /// `true` if siblings should automatically initiate a Layer-2
    /// quorum revocation once `min_alerts_for_revoke` alerts are
    /// received within `alert_dedup_window_secs`.
    pub auto_revoke_on_alert: bool,
    /// Minimum number of distinct alerts (with distinct nonces) the
    /// siblings need to see before escalating to revocation. 1 is
    /// the minimum; higher values reduce false-positive escalations
    /// from a flapping device.
    pub min_alerts_for_revoke: u8,
    /// Window over which `min_alerts_for_revoke` is counted.
    pub alert_dedup_window_secs: u64,
}

impl DuressPolicy {
    /// Conservative default: alert immediately, quarantine for 24h,
    /// auto-revoke after 1 alert, 1h dedup window.
    #[must_use]
    pub const fn conservative() -> Self {
        Self {
            emit_alert_on_decoy_unlock: true,
            quarantine_secs: DURESS_DEFAULT_QUARANTINE_SECS,
            auto_revoke_on_alert: true,
            min_alerts_for_revoke: 1,
            alert_dedup_window_secs: 3_600,
        }
    }

    /// Hardened preset for journalist / activist / dissident use:
    /// alert immediately, quarantine for 7 days, auto-revoke after
    /// 1 alert, 24h dedup window. Decoy-only mode persists across
    /// power cycles until the user explicitly clears it via the
    /// out-of-band recovery path.
    #[must_use]
    pub const fn hardened() -> Self {
        Self {
            emit_alert_on_decoy_unlock: true,
            quarantine_secs: 7 * DURESS_DEFAULT_QUARANTINE_SECS,
            auto_revoke_on_alert: true,
            min_alerts_for_revoke: 1,
            alert_dedup_window_secs: 24 * 3600,
        }
    }
}

impl Default for DuressPolicy {
    fn default() -> Self {
        Self::conservative()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conservative_emits_and_auto_revokes() {
        let p = DuressPolicy::conservative();
        assert!(p.emit_alert_on_decoy_unlock);
        assert!(p.auto_revoke_on_alert);
        assert_eq!(p.quarantine_secs, DURESS_DEFAULT_QUARANTINE_SECS);
    }

    #[test]
    fn hardened_quarantine_is_seven_days() {
        let p = DuressPolicy::hardened();
        assert_eq!(p.quarantine_secs, 7 * 24 * 3600);
    }
}
