//! The `Decision` struct + sub-decision enums emitted by the selector.

use crate::error::SelectorError;

/// Choice of transport for this event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// QUIC reliable bidirectional stream. Best for bulk file transfer.
    QuicStream,
    /// QUIC unreliable datagram. Best for foreground small messages
    /// (no head-of-line blocking).
    QuicDatagram,
    /// WebRTC data channel. Used for real-time pair flows.
    WebRtc,
    /// Multi-hop relay path. Hides direct sender from observer.
    Relay,
}

/// Path through the daemon's transfer pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Path {
    /// Classical byte stream (current default for small messages).
    /// No anchor floor cost; no CDC dedup; cheaper for small payloads.
    Classical,
    /// Coherence-substrate path with CDC chunking + anchor reconstruction.
    /// Higher fixed cost; wins on large files via dedup.
    Coherence,
}

/// Onion-circuit hop count.
///
/// Hop counts are quantized: 1 (minimal privacy), 3 (standard onion),
/// 5 (paranoid). Other values would require ol_onion API extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OnionHops {
    /// Single relay hop. Minimal privacy but lowest latency.
    One,
    /// Three hops. Standard onion-routing privacy.
    Three,
    /// Five hops. Maximum privacy at the cost of latency.
    Five,
}

impl OnionHops {
    /// Convert to the raw hop count expected by `ol_onion`.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            Self::One => 1,
            Self::Three => 3,
            Self::Five => 5,
        }
    }

    /// Construct from a raw hop count. Rejects anything not in {1, 3, 5}.
    pub fn from_u8(n: u8) -> Result<Self, SelectorError> {
        match n {
            1 => Ok(Self::One),
            3 => Ok(Self::Three),
            5 => Ok(Self::Five),
            _ => Err(SelectorError::UnsupportedOnionHops { got: n }),
        }
    }
}

/// What to do with the outbound packet's emission timing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BatchDecision {
    /// Emit immediately. Default for foreground or latency-strict traffic.
    EmitNow,
    /// Coalesce with other outbound packets on the next radio wake.
    /// Used for background traffic when the radio is in long DRX.
    Batch,
    /// Force the radio to wake immediately regardless of DRX state.
    /// Used for urgent small foreground messages — bypasses batching
    /// even when batching would otherwise apply (Gap 14 tail-fix).
    UrgentBypass,
}

/// The complete per-event decision emitted by the selector.
///
/// Every field is independently consumed by a different part of the
/// daemon's send path: transport picks the socket, path picks the
/// pipeline, onion_hops + cover_traffic configure ol_onion, batch
/// decides timing, anchor_lay configures ol_coherence_field anchors,
/// predictor_warm hints ol_prefetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Decision {
    /// Which transport to use.
    pub transport: Transport,
    /// Whether to ride the coherence-substrate path or classical bytes.
    pub path: Path,
    /// Onion-circuit hop count.
    pub onion_hops: OnionHops,
    /// Whether to mix cover traffic into the emission stream.
    pub cover_traffic: bool,
    /// Emission timing policy.
    pub batch_decision: BatchDecision,
    /// Whether to lay an anchor for sub-RTT loss recovery.
    pub anchor_lay: bool,
    /// Whether to pre-warm the predictor for this event.
    pub predictor_warm: bool,
}

impl Decision {
    /// The "always-safe" Decision used when context is incomplete or
    /// smart logic errors. Per Design Rule R3.
    ///
    /// Privacy = maximum (5-hop onion + cover ON), recovery = anchor on,
    /// latency = emit-now (never batch in default branch), path =
    /// classical (cheaper for small payloads which dominate event mix).
    #[must_use]
    pub fn safe_default() -> Self {
        Self {
            transport: Transport::QuicStream,
            path: Path::Classical,
            onion_hops: OnionHops::Five,
            cover_traffic: true,
            batch_decision: BatchDecision::EmitNow,
            anchor_lay: true,
            predictor_warm: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onion_hops_round_trip() {
        for n in [1u8, 3, 5] {
            assert_eq!(OnionHops::from_u8(n).unwrap().as_u8(), n);
        }
    }

    #[test]
    fn onion_hops_rejects_other() {
        for n in [0u8, 2, 4, 7, 100] {
            assert!(OnionHops::from_u8(n).is_err());
        }
    }

    #[test]
    fn safe_default_is_conservative() {
        let d = Decision::safe_default();
        assert_eq!(d.onion_hops, OnionHops::Five);
        assert!(d.cover_traffic);
        assert!(d.anchor_lay);
        assert_eq!(d.batch_decision, BatchDecision::EmitNow);
    }
}
