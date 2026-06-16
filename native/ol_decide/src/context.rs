//! The `Context` struct + signal enums — universal input to every
//! `Decide` impl in One Link.

use crate::error::DecideError;

/// What kind of event triggered this decision.
///
/// Derived from the wire-protocol message type (see `wire.py`):
///   - `TEXT` -> `Msg`
///   - `FILE_OFFER` / `FILE_CHUNK` -> `File`
///   - `ACK` -> `Sync`
///   - `PING` / `PONG` -> `Heartbeat`
///   - pair-by-QR flow -> `Pair` (handled separately by ol_pair_qr)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
    /// Chat / text message.
    Msg,
    /// File offer or chunk.
    File,
    /// Sync / acknowledgement traffic.
    Sync,
    /// Heartbeat / keepalive.
    Heartbeat,
    /// Pairing handshake event.
    Pair,
}

impl EventKind {
    /// Parse from the daemon's wire-protocol type string.
    ///
    /// Accepts: `TEXT`, `FILE_OFFER`, `FILE_CHUNK`, `ACK`, `PING`, `PONG`,
    /// `PAIR_*` (any pair-flow prefix). Case-insensitive.
    pub fn from_wire_type(s: &str) -> Result<Self, DecideError> {
        let upper = s.to_ascii_uppercase();
        match upper.as_str() {
            "TEXT" | "MSG" => Ok(Self::Msg),
            "FILE_OFFER" | "FILE_CHUNK" | "FILE" => Ok(Self::File),
            "ACK" | "SYNC" => Ok(Self::Sync),
            "PING" | "PONG" | "HEARTBEAT" => Ok(Self::Heartbeat),
            _ if upper.starts_with("PAIR_") || upper == "PAIR" => Ok(Self::Pair),
            _ => Err(DecideError::UnknownLabel {
                field: "kind",
                got: s.to_owned(),
                expected: "TEXT|FILE_OFFER|FILE_CHUNK|ACK|PING|PONG|PAIR_*",
            }),
        }
    }
}

/// Trust tier between local and remote peer.
///
/// Maps to `PeerRecord.trust` in `state.py`:
///   - `'pinned'`   -> `Paired`
///   - `'pending'`  -> `Known`
///   - `'rejected'` -> `Stranger`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerRelationship {
    /// Pair-bonded peer (explicit, established trust).
    Paired,
    /// Known but not pair-bonded (introduced via a mutual).
    Known,
    /// Unknown / unverified / rejected.
    Stranger,
}

impl PeerRelationship {
    /// Parse from the daemon's `PeerRecord.trust` string.
    ///
    /// Accepts: `pinned`/`paired`, `pending`/`known`, `rejected`/`stranger`/`unknown`.
    /// Case-insensitive.
    pub fn from_label(s: &str) -> Result<Self, DecideError> {
        match s.to_ascii_lowercase().as_str() {
            "pinned" | "paired" => Ok(Self::Paired),
            "pending" | "known" => Ok(Self::Known),
            "rejected" | "stranger" | "unknown" | "" => Ok(Self::Stranger),
            _ => Err(DecideError::UnknownLabel {
                field: "peer",
                got: s.to_owned(),
                expected: "pinned|paired|pending|known|rejected|stranger|unknown",
            }),
        }
    }
}

/// Whether the event is user-facing (foreground) or behind-the-scenes
/// (background).
///
/// Default mapping by `EventKind`:
///   - `Msg`, `File`, `Pair` -> foreground (user-driven, latency matters)
///   - `Heartbeat`, `Sync` -> background (defer-friendly)
///
/// REST API callers may pass an explicit urgency hint that overrides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Urgency {
    /// User is actively waiting for this; latency matters.
    Foreground,
    /// Behind-the-scenes; can be batched / delayed.
    Background,
}

impl Urgency {
    /// Default urgency given an event kind.
    ///
    /// This is the safe "no explicit caller hint" derivation per the
    /// integration map signal table.
    #[must_use]
    pub fn from_kind(k: EventKind) -> Self {
        match k {
            EventKind::Msg | EventKind::File | EventKind::Pair => Self::Foreground,
            EventKind::Heartbeat | EventKind::Sync => Self::Background,
        }
    }
}

/// Radio state at the moment of decision.
///
/// Mirrors LTE / 5G discontinuous reception modes. Used by the radio
/// batcher to decide whether to coalesce small outbound packets onto
/// the next scheduled wake.
///
/// Until per-platform shims ship (`ol_radio_batcher`), defaults to
/// `Active` (the safe choice: never delay due to a presumed sleep state).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RadioState {
    /// Radio is currently transmitting; cheap to send immediately.
    Active,
    /// Short DRX (~10s of ms); inexpensive wake.
    ShortDrx,
    /// Long DRX (~100ms+); waking is expensive.
    LongDrx,
}

/// Network type at the moment of decision.
///
/// Until per-platform shims ship, defaults to `Wifi` (the safe choice:
/// no metered cost, no cellular tower wakeup).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkType {
    /// Wi-Fi (treated as cheap + non-metered by default).
    Wifi,
    /// Cellular (metered + radio-wake costly).
    Cellular,
    /// User-marked metered (e.g. tethered hotspot, capped plan).
    Metered,
}

/// User-declared operating mode. Stored in `state.py` settings table.
///
/// Defaults to `Normal`. Users explicitly opt into the other modes via
/// the REST API (`POST /api/user_mode`) for moments when they want the
/// system to make a specific trade-off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UserMode {
    /// Default: balanced privacy / latency / energy.
    Normal,
    /// Accept higher latency for full unobservability.
    Paranoid,
    /// Accept some latency for ~20% energy reduction.
    BatterySave,
    /// Accept lower privacy for sub-80ms p99 latency.
    LatencyStrict,
}

impl UserMode {
    /// Parse from the daemon settings string.
    ///
    /// Accepts: `normal`, `paranoid`, `battery_save`, `latency_strict`.
    /// Case-insensitive. Empty string and unknowns default to `Normal`
    /// (safe per Design Rule R3).
    #[must_use]
    pub fn from_label_or_default(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "paranoid" => Self::Paranoid,
            "battery_save" | "battery-save" | "batterysave" => Self::BatterySave,
            "latency_strict" | "latency-strict" | "latencystrict" => Self::LatencyStrict,
            _ => Self::Normal,
        }
    }
}

/// The 8-signal context passed to every `Decide` impl.
///
/// One vocabulary across the whole daemon, per Design Rule R2.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Context {
    /// What kind of event is being decided.
    pub kind: EventKind,
    /// Payload size in bytes.
    pub size: usize,
    /// Trust tier with the remote peer.
    pub peer: PeerRelationship,
    /// Whether the event is user-facing or background.
    pub urgency: Urgency,
    /// Current radio power state.
    pub radio_state: RadioState,
    /// Active network type (WiFi / cellular / metered).
    pub network: NetworkType,
    /// User-declared operating mode.
    pub user_mode: UserMode,
    /// EWMA loss rate observed for this peer / path in [0, 1].
    pub observed_loss: f32,
    /// Predictor confidence for this kind of event in [0, 1].
    pub pattern_strength: f32,
}

impl Context {
    /// Build a Context with strict validation of the f32 inputs.
    ///
    /// Most call sites should use this rather than struct-literal init
    /// so daemon-side feeds catch bad observations early.
    // One argument per validated `Context` field — the validation is
    // the whole point of this constructor, so it mirrors the struct.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        kind: EventKind,
        size: usize,
        peer: PeerRelationship,
        urgency: Urgency,
        radio_state: RadioState,
        network: NetworkType,
        user_mode: UserMode,
        observed_loss: f32,
        pattern_strength: f32,
    ) -> Result<Self, DecideError> {
        if !observed_loss.is_finite() || !(0.0..=1.0).contains(&observed_loss) {
            return Err(DecideError::InvalidLoss { got: observed_loss });
        }
        if !pattern_strength.is_finite() || !(0.0..=1.0).contains(&pattern_strength) {
            return Err(DecideError::InvalidPatternStrength {
                got: pattern_strength,
            });
        }
        Ok(Self {
            kind,
            size,
            peer,
            urgency,
            radio_state,
            network,
            user_mode,
            observed_loss,
            pattern_strength,
        })
    }

    /// Build a "safe-default" Context: anonymous stranger, foreground
    /// chat, no observed loss, no patterns. Used as a fallback when the
    /// daemon can't fully populate the signals.
    #[must_use]
    pub fn safe_default(kind: EventKind, size: usize) -> Self {
        Self {
            kind,
            size,
            peer: PeerRelationship::Stranger,
            urgency: Urgency::from_kind(kind),
            radio_state: RadioState::Active,
            network: NetworkType::Wifi,
            user_mode: UserMode::Normal,
            observed_loss: 0.0,
            pattern_strength: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_kind_parses_wire_types() {
        assert_eq!(EventKind::from_wire_type("TEXT").unwrap(), EventKind::Msg);
        assert_eq!(EventKind::from_wire_type("text").unwrap(), EventKind::Msg);
        assert_eq!(
            EventKind::from_wire_type("FILE_CHUNK").unwrap(),
            EventKind::File
        );
        assert_eq!(
            EventKind::from_wire_type("FILE_OFFER").unwrap(),
            EventKind::File
        );
        assert_eq!(EventKind::from_wire_type("ACK").unwrap(), EventKind::Sync);
        assert_eq!(
            EventKind::from_wire_type("PING").unwrap(),
            EventKind::Heartbeat
        );
        assert_eq!(
            EventKind::from_wire_type("PONG").unwrap(),
            EventKind::Heartbeat
        );
        assert_eq!(
            EventKind::from_wire_type("PAIR_INVITE").unwrap(),
            EventKind::Pair
        );
        assert!(EventKind::from_wire_type("UNKNOWN_TYPE").is_err());
    }

    #[test]
    fn peer_relationship_parses_daemon_labels() {
        assert_eq!(
            PeerRelationship::from_label("pinned").unwrap(),
            PeerRelationship::Paired
        );
        assert_eq!(
            PeerRelationship::from_label("paired").unwrap(),
            PeerRelationship::Paired
        );
        assert_eq!(
            PeerRelationship::from_label("PENDING").unwrap(),
            PeerRelationship::Known
        );
        assert_eq!(
            PeerRelationship::from_label("rejected").unwrap(),
            PeerRelationship::Stranger
        );
        // Empty string and "unknown" default to Stranger (safe).
        assert_eq!(
            PeerRelationship::from_label("").unwrap(),
            PeerRelationship::Stranger
        );
        assert!(PeerRelationship::from_label("bogus_tier").is_err());
    }

    #[test]
    fn urgency_default_per_kind() {
        assert_eq!(Urgency::from_kind(EventKind::Msg), Urgency::Foreground);
        assert_eq!(Urgency::from_kind(EventKind::File), Urgency::Foreground);
        assert_eq!(Urgency::from_kind(EventKind::Pair), Urgency::Foreground);
        assert_eq!(
            Urgency::from_kind(EventKind::Heartbeat),
            Urgency::Background
        );
        assert_eq!(Urgency::from_kind(EventKind::Sync), Urgency::Background);
    }

    #[test]
    fn user_mode_parses_with_safe_default() {
        assert_eq!(
            UserMode::from_label_or_default("paranoid"),
            UserMode::Paranoid
        );
        assert_eq!(
            UserMode::from_label_or_default("PARANOID"),
            UserMode::Paranoid
        );
        assert_eq!(
            UserMode::from_label_or_default("battery_save"),
            UserMode::BatterySave
        );
        assert_eq!(
            UserMode::from_label_or_default("battery-save"),
            UserMode::BatterySave
        );
        assert_eq!(
            UserMode::from_label_or_default("latency_strict"),
            UserMode::LatencyStrict
        );
        // Unknown labels default to Normal — Design Rule R3.
        assert_eq!(UserMode::from_label_or_default(""), UserMode::Normal);
        assert_eq!(UserMode::from_label_or_default("garbage"), UserMode::Normal);
    }

    #[test]
    fn context_build_validates_inputs() {
        let ok = Context::build(
            EventKind::Msg,
            1024,
            PeerRelationship::Paired,
            Urgency::Foreground,
            RadioState::Active,
            NetworkType::Wifi,
            UserMode::Normal,
            0.05,
            0.8,
        );
        assert!(ok.is_ok());

        let bad_loss = Context::build(
            EventKind::Msg,
            1024,
            PeerRelationship::Paired,
            Urgency::Foreground,
            RadioState::Active,
            NetworkType::Wifi,
            UserMode::Normal,
            -0.1,
            0.5,
        );
        assert!(matches!(bad_loss, Err(DecideError::InvalidLoss { .. })));

        let bad_pattern = Context::build(
            EventKind::Msg,
            1024,
            PeerRelationship::Paired,
            Urgency::Foreground,
            RadioState::Active,
            NetworkType::Wifi,
            UserMode::Normal,
            0.0,
            1.5,
        );
        assert!(matches!(
            bad_pattern,
            Err(DecideError::InvalidPatternStrength { .. })
        ));
    }

    #[test]
    fn safe_default_context_is_conservative() {
        let ctx = Context::safe_default(EventKind::Msg, 512);
        // Stranger trust, normal mode, wifi default, active radio.
        assert_eq!(ctx.peer, PeerRelationship::Stranger);
        assert_eq!(ctx.user_mode, UserMode::Normal);
        assert_eq!(ctx.network, NetworkType::Wifi);
        assert_eq!(ctx.radio_state, RadioState::Active);
        assert_eq!(ctx.urgency, Urgency::Foreground);
        assert_eq!(ctx.observed_loss, 0.0);
        assert_eq!(ctx.pattern_strength, 0.0);
    }
}
