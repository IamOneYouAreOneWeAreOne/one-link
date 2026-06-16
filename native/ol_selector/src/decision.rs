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

    /// F4 — verify this Decision respects the contract for the given
    /// `user_mode`. Returns the list of violations (empty = pass).
    ///
    /// Mode contracts (from Gap 20 / Gap 28 of the forge shootouts):
    ///
    ///   Normal:         no specific structural requirements
    ///   Paranoid:       onion_hops >= 3 AND cover_traffic == true
    ///   BatterySave:    cover_traffic == false
    ///                   AND batch_decision != UrgentBypass (for any
    ///                       non-Msg kind)
    ///   LatencyStrict:  batch_decision != Batch
    ///                   AND transport != Relay (relay path doubles RTT)
    ///
    /// The contract is a runtime invariant the selector should
    /// uphold. This method is the gate the daemon can use to assert
    /// the selector's output matches the user's declared mode.
    #[must_use]
    pub fn verify_contract(&self, user_mode: ContractMode) -> Vec<ContractViolation> {
        let mut violations = Vec::new();
        match user_mode {
            ContractMode::Normal => {
                // No structural requirements.
            }
            ContractMode::Paranoid => {
                // Privacy floor: 3-hop onion minimum + cover traffic.
                if matches!(self.onion_hops, OnionHops::One) {
                    violations.push(ContractViolation::ParanoidUnderHops);
                }
                if !self.cover_traffic {
                    violations.push(ContractViolation::ParanoidNoCover);
                }
            }
            ContractMode::BatterySave => {
                // No cover-traffic burn.
                if self.cover_traffic {
                    violations.push(ContractViolation::BatterySaveCover);
                }
            }
            ContractMode::LatencyStrict => {
                // Never batch (adds latency); never relay (doubles RTT).
                if self.batch_decision == BatchDecision::Batch {
                    violations.push(ContractViolation::LatencyStrictBatched);
                }
                if self.transport == Transport::Relay {
                    violations.push(ContractViolation::LatencyStrictRelay);
                }
            }
        }
        violations
    }
}

/// The mode the contract is being checked against.
///
/// Mirrors `ol_decide::UserMode` but stays local to this crate so the
/// dependency surface is minimal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContractMode {
    /// Normal balanced default.
    Normal,
    /// Paranoid: privacy floor enforced.
    Paranoid,
    /// Battery save: energy ceiling enforced.
    BatterySave,
    /// Latency strict: latency ceiling enforced.
    LatencyStrict,
}

impl ContractMode {
    /// Parse from a string label. Unknown values default to Normal
    /// (safe-default per Design Rule R3).
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

/// A specific violation of a mode contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContractViolation {
    /// Paranoid mode: onion_hops < 3.
    ParanoidUnderHops,
    /// Paranoid mode: cover_traffic disabled.
    ParanoidNoCover,
    /// Battery save: cover_traffic enabled (wastes bandwidth + energy).
    BatterySaveCover,
    /// Latency strict: batched (adds wake-window latency).
    LatencyStrictBatched,
    /// Latency strict: relay path (doubles RTT vs direct).
    LatencyStrictRelay,
}

impl ContractViolation {
    /// Stable label for telemetry / logging.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ParanoidUnderHops => "paranoid_under_hops",
            Self::ParanoidNoCover => "paranoid_no_cover",
            Self::BatterySaveCover => "battery_save_cover",
            Self::LatencyStrictBatched => "latency_strict_batched",
            Self::LatencyStrictRelay => "latency_strict_relay",
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

    // ───── F4 contract enforcement ───────────────────────────────────

    fn d_with(
        path: Path,
        onion_hops: OnionHops,
        cover_traffic: bool,
        batch_decision: BatchDecision,
        transport: Transport,
    ) -> Decision {
        Decision {
            transport,
            path,
            onion_hops,
            cover_traffic,
            batch_decision,
            anchor_lay: false,
            predictor_warm: false,
        }
    }

    #[test]
    fn normal_contract_has_no_requirements() {
        let d = d_with(
            Path::Classical,
            OnionHops::One,
            false,
            BatchDecision::Batch,
            Transport::Relay,
        );
        assert_eq!(d.verify_contract(ContractMode::Normal), vec![]);
    }

    #[test]
    fn paranoid_contract_requires_hops_and_cover() {
        let bad = d_with(
            Path::Classical,
            OnionHops::One,
            false,
            BatchDecision::EmitNow,
            Transport::QuicStream,
        );
        let v = bad.verify_contract(ContractMode::Paranoid);
        assert!(v.contains(&ContractViolation::ParanoidUnderHops));
        assert!(v.contains(&ContractViolation::ParanoidNoCover));

        let good = d_with(
            Path::Classical,
            OnionHops::Three,
            true,
            BatchDecision::EmitNow,
            Transport::QuicStream,
        );
        assert_eq!(good.verify_contract(ContractMode::Paranoid), vec![]);
    }

    #[test]
    fn battery_save_contract_blocks_cover() {
        let bad = d_with(
            Path::Classical,
            OnionHops::Three,
            true,
            BatchDecision::EmitNow,
            Transport::QuicStream,
        );
        let v = bad.verify_contract(ContractMode::BatterySave);
        assert!(v.contains(&ContractViolation::BatterySaveCover));

        let good = d_with(
            Path::Classical,
            OnionHops::One,
            false,
            BatchDecision::EmitNow,
            Transport::QuicStream,
        );
        assert_eq!(good.verify_contract(ContractMode::BatterySave), vec![]);
    }

    #[test]
    fn latency_strict_contract_blocks_batch_and_relay() {
        let bad_batch = d_with(
            Path::Classical,
            OnionHops::Three,
            true,
            BatchDecision::Batch,
            Transport::QuicStream,
        );
        let v = bad_batch.verify_contract(ContractMode::LatencyStrict);
        assert!(v.contains(&ContractViolation::LatencyStrictBatched));

        let bad_relay = d_with(
            Path::Classical,
            OnionHops::Three,
            true,
            BatchDecision::EmitNow,
            Transport::Relay,
        );
        let v = bad_relay.verify_contract(ContractMode::LatencyStrict);
        assert!(v.contains(&ContractViolation::LatencyStrictRelay));

        let good = d_with(
            Path::Classical,
            OnionHops::Three,
            true,
            BatchDecision::EmitNow,
            Transport::QuicStream,
        );
        assert_eq!(good.verify_contract(ContractMode::LatencyStrict), vec![]);
    }

    #[test]
    fn contract_mode_parses_labels() {
        assert_eq!(
            ContractMode::from_label_or_default("paranoid"),
            ContractMode::Paranoid
        );
        assert_eq!(
            ContractMode::from_label_or_default("battery_save"),
            ContractMode::BatterySave
        );
        assert_eq!(
            ContractMode::from_label_or_default("battery-save"),
            ContractMode::BatterySave
        );
        assert_eq!(
            ContractMode::from_label_or_default("latency_strict"),
            ContractMode::LatencyStrict
        );
        assert_eq!(
            ContractMode::from_label_or_default("garbage"),
            ContractMode::Normal
        );
        assert_eq!(
            ContractMode::from_label_or_default(""),
            ContractMode::Normal
        );
    }

    #[test]
    fn contract_violation_labels_stable() {
        assert_eq!(
            ContractViolation::ParanoidUnderHops.as_str(),
            "paranoid_under_hops"
        );
        assert_eq!(
            ContractViolation::ParanoidNoCover.as_str(),
            "paranoid_no_cover"
        );
        assert_eq!(
            ContractViolation::BatterySaveCover.as_str(),
            "battery_save_cover"
        );
        assert_eq!(
            ContractViolation::LatencyStrictBatched.as_str(),
            "latency_strict_batched"
        );
        assert_eq!(
            ContractViolation::LatencyStrictRelay.as_str(),
            "latency_strict_relay"
        );
    }
}
