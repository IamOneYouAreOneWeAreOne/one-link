//! Radio power state.

/// Current radio state, as observed from the OS or set externally.
///
/// Mirrors LTE/5G discontinuous-reception states. The daemon may
/// update this on receiving platform signals; the deterministic
/// batcher core stores it for the daemon's own use but does NOT
/// vary scheduling on it (scheduling is purely time-driven so it
/// remains testable without OS mocks).
///
/// Daemon-side use: when state is `LongDrx`, the daemon may choose
/// to call `Batcher::drain` slightly later than usual to amortize
/// the wake more, or earlier if an urgent bypass came in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum RadioState {
    /// Radio is currently transmitting; cheap to send immediately.
    #[default]
    Active,
    /// Short DRX (~10ms typical); inexpensive wake.
    ShortDrx,
    /// Long DRX (~100ms+ typical); waking is expensive.
    LongDrx,
}

impl RadioState {
    /// Parse from a string label.
    ///
    /// Accepts: `active`, `short_drx` / `short-drx`, `long_drx` /
    /// `long-drx`. Case-insensitive. Unknown labels default to
    /// `Active` (the safe choice: "no info" means "assume radio is
    /// awake, don't delay").
    #[must_use]
    pub fn from_label_or_default(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "short_drx" | "short-drx" | "shortdrx" => Self::ShortDrx,
            "long_drx" | "long-drx" | "longdrx" => Self::LongDrx,
            _ => Self::Active,
        }
    }

    /// Stable label for telemetry / Python adapter.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::ShortDrx => "short_drx",
            Self::LongDrx => "long_drx",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_labels() {
        for s in &["active", "short_drx", "long_drx"] {
            let parsed = RadioState::from_label_or_default(s);
            assert_eq!(parsed.as_str(), *s);
        }
    }

    #[test]
    fn unknown_label_defaults_active() {
        assert_eq!(
            RadioState::from_label_or_default("garbage"),
            RadioState::Active
        );
        assert_eq!(RadioState::from_label_or_default(""), RadioState::Active);
    }

    #[test]
    fn default_is_active() {
        assert_eq!(RadioState::default(), RadioState::Active);
    }
}
