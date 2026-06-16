//! Steganographic cross-channel pairing.
//!
//! When pairing a new device, the pairing secret is committed
//! across THREE channels:
//!
//! - QR — visual code on the existing-device screen, scanned by the
//!   new device.
//! - Audio — sub-perceptible chirp / modulation in normal audio
//!   played by the existing device, picked up by the new device's
//!   microphone.
//! - Motion — accelerometer pattern observed when the user
//!   physically touches the two devices together for a moment.
//!
//! Each channel produces a [`PairingCommitment`]: a BLAKE3
//! commitment over `(channel_tag, pairing_secret, channel_nonce)`.
//! The receiver collects commitments from all three channels and
//! checks that they ALL commit to the same secret within a time
//! window. A remote attacker who photographs the QR from across the
//! room can't reproduce the audio + motion → the pairing fails.

use blake3::Hasher;
use subtle::ConstantTimeEq;

use crate::errors::{DeviceMeshError, DeviceMeshResult};

/// Domain-separation tag for pairing commitments.
pub const PAIR_COMMITMENT_DOMAIN: &[u8] = b"OL-mesh-pair-commitment-v1";

/// Number of channels that must agree.
pub const REQUIRED_PAIR_CHANNELS: usize = 3;

/// The three channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PairingChannel {
    /// Visual QR code.
    Qr,
    /// Sub-perceptible audio chirp.
    Audio,
    /// Accelerometer / motion pattern.
    Motion,
}

impl PairingChannel {
    /// Canonical 8-byte tag mixed into the commitment.
    #[must_use]
    pub const fn tag(self) -> [u8; 8] {
        match self {
            Self::Qr => *b"OL-PR-QR",
            Self::Audio => *b"OL-PR-AU",
            Self::Motion => *b"OL-PR-MO",
        }
    }
}

/// One channel's commitment over the pairing secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingCommitment {
    /// Which channel produced this commitment.
    pub channel: PairingChannel,
    /// BLAKE3 of `(domain || channel.tag() || pairing_secret || nonce)`.
    pub commitment: [u8; 32],
    /// Per-channel nonce that the verifier learns out-of-band
    /// (e.g., transmitted alongside the commitment over the same
    /// channel).
    pub nonce: [u8; 16],
    /// Wall-clock-millis when this commitment was emitted.
    pub timestamp_ms: u64,
}

impl PairingCommitment {
    /// Build a commitment for `channel` over `pairing_secret`.
    #[must_use]
    pub fn build(
        channel: PairingChannel,
        pairing_secret: &[u8],
        nonce: [u8; 16],
        timestamp_ms: u64,
    ) -> Self {
        let mut h = Hasher::new();
        h.update(PAIR_COMMITMENT_DOMAIN);
        h.update(&channel.tag());
        h.update(pairing_secret);
        h.update(&nonce);
        let digest = h.finalize();
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(digest.as_bytes());
        Self {
            channel,
            commitment,
            nonce,
            timestamp_ms,
        }
    }

    /// Constant-time check that this commitment matches an expected
    /// `pairing_secret`.
    #[must_use]
    pub fn matches(&self, pairing_secret: &[u8]) -> bool {
        let expected = Self::build(self.channel, pairing_secret, self.nonce, self.timestamp_ms);
        bool::from(expected.commitment.ct_eq(&self.commitment))
    }
}

/// Verify that the supplied commitments cross-confirm
/// `pairing_secret` across all three required channels within
/// `window_ms` of each other.
///
/// Returns `Ok(())` if and only if:
///   - the QR, Audio, AND Motion channels are ALL present
///   - each commitment matches the secret
///   - the gap between earliest and latest commitment is ≤ `window_ms`
pub fn verify_pairing_cross_channel(
    commitments: &[PairingCommitment],
    pairing_secret: &[u8],
    window_ms: u64,
) -> DeviceMeshResult<()> {
    let mut have_qr = false;
    let mut have_audio = false;
    let mut have_motion = false;
    let mut min_ts: Option<u64> = None;
    let mut max_ts: Option<u64> = None;
    for c in commitments {
        if !c.matches(pairing_secret) {
            return Err(DeviceMeshError::PairChannelCommitmentMismatch { channel: c.channel });
        }
        match c.channel {
            PairingChannel::Qr => have_qr = true,
            PairingChannel::Audio => have_audio = true,
            PairingChannel::Motion => have_motion = true,
        }
        min_ts = Some(min_ts.map_or(c.timestamp_ms, |x| x.min(c.timestamp_ms)));
        max_ts = Some(max_ts.map_or(c.timestamp_ms, |x| x.max(c.timestamp_ms)));
    }
    if !(have_qr && have_audio && have_motion) {
        return Err(DeviceMeshError::PairChannelMissing {
            qr: have_qr,
            audio: have_audio,
            motion: have_motion,
        });
    }
    let span = max_ts.unwrap_or(0).saturating_sub(min_ts.unwrap_or(0));
    if span > window_ms {
        return Err(DeviceMeshError::PairChannelOutOfWindow {
            span_ms: span,
            window_ms,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_channels_within_window_accept() {
        let secret = b"shared secret bytes";
        let commits = vec![
            PairingCommitment::build(PairingChannel::Qr, secret, [0; 16], 100),
            PairingCommitment::build(PairingChannel::Audio, secret, [1; 16], 110),
            PairingCommitment::build(PairingChannel::Motion, secret, [2; 16], 120),
        ];
        verify_pairing_cross_channel(&commits, secret, 1_000).unwrap();
    }

    #[test]
    fn missing_motion_rejected() {
        let secret = b"shared secret";
        let commits = vec![
            PairingCommitment::build(PairingChannel::Qr, secret, [0; 16], 100),
            PairingCommitment::build(PairingChannel::Audio, secret, [1; 16], 110),
        ];
        let err = verify_pairing_cross_channel(&commits, secret, 1_000).unwrap_err();
        assert!(matches!(err, DeviceMeshError::PairChannelMissing { .. }));
    }

    #[test]
    fn one_channel_committed_to_different_secret_rejected() {
        let real = b"real secret";
        let fake = b"fake secret";
        let commits = vec![
            PairingCommitment::build(PairingChannel::Qr, real, [0; 16], 100),
            PairingCommitment::build(PairingChannel::Audio, fake, [1; 16], 110),
            PairingCommitment::build(PairingChannel::Motion, real, [2; 16], 120),
        ];
        let err = verify_pairing_cross_channel(&commits, real, 1_000).unwrap_err();
        assert!(matches!(
            err,
            DeviceMeshError::PairChannelCommitmentMismatch { .. }
        ));
    }

    #[test]
    fn out_of_window_rejected() {
        let secret = b"shared";
        let commits = vec![
            PairingCommitment::build(PairingChannel::Qr, secret, [0; 16], 100),
            PairingCommitment::build(PairingChannel::Audio, secret, [1; 16], 110),
            PairingCommitment::build(PairingChannel::Motion, secret, [2; 16], 5_000),
        ];
        let err = verify_pairing_cross_channel(&commits, secret, 1_000).unwrap_err();
        assert!(matches!(
            err,
            DeviceMeshError::PairChannelOutOfWindow { .. }
        ));
    }

    #[test]
    fn distinct_nonces_yield_distinct_commitments() {
        let secret = b"shared";
        let a = PairingCommitment::build(PairingChannel::Qr, secret, [0; 16], 100);
        let b = PairingCommitment::build(PairingChannel::Qr, secret, [1; 16], 100);
        assert_ne!(a.commitment, b.commitment);
    }
}
