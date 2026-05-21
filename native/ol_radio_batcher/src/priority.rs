//! Per-entry priority levels.

/// How urgently an entry needs to leave the batcher.
///
/// The selector tags every batch-able event with one of these; the
/// scheduler uses it to choose whether to drain on the next tick or
/// hold for the full DRX window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Priority {
    /// Drain at the next opportunity regardless of DRX window.
    ///
    /// Used by `urgent_bypass`-marked events that the daemon still
    /// chose to route through the batcher (e.g. because the radio
    /// happened to be in long-DRX). The batcher should never hold
    /// these.
    Urgent,
    /// Drain when the DRX window elapses (typical case).
    ///
    /// This is the default for selector-tagged `Batch` decisions.
    Normal,
    /// Drain when 3× the DRX window elapses (or max_age, whichever
    /// fires first).
    ///
    /// Used for genuinely-background work: discovery beacons,
    /// statistics, periodic resync. Maximum amortization.
    Background,
}

impl Priority {
    /// Returns the drain-window multiplier applied to the configured
    /// `drx_window_ms` for this priority.
    ///
    /// - Urgent:    0  (drain on next tick)
    /// - Normal:    1  (one DRX window)
    /// - Background: 3 (three DRX windows)
    #[must_use]
    pub fn window_multiplier(self) -> u32 {
        match self {
            Self::Urgent => 0,
            Self::Normal => 1,
            Self::Background => 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_is_intuitive() {
        // Urgent < Normal < Background — using the standard derive
        // direction (Urgent comes "first" in the enum).
        assert!(Priority::Urgent < Priority::Normal);
        assert!(Priority::Normal < Priority::Background);
    }

    #[test]
    fn window_multipliers_match_spec() {
        assert_eq!(Priority::Urgent.window_multiplier(), 0);
        assert_eq!(Priority::Normal.window_multiplier(), 1);
        assert_eq!(Priority::Background.window_multiplier(), 3);
    }
}
