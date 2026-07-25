//! The Gaussian alignment kernel A(x, t) = exp(-(x^2 + t^2) / L).
//!
//! Per the Equation of ONE: alignment energy `E_alignment` governs large-
//! scale spatial-temporal coherence via this exact functional form (with
//! L the characteristic scale). For One Link, x = `hop_distance` and
//! t = staleness in days; L depends on relationship tier.

use crate::error::AlignError;

/// Default `L_session` for `Paired` peers, in days.
///
/// Paired peers have a long established session. Trust decays slowly —
/// a paired peer untouched for a month is still meaningfully trusted.
pub const DEFAULT_L_PAIRED: f32 = 100.0;

/// Default `L_session` for `Known` peers, in days.
///
/// Known peers (introduced via a trusted intermediary, not directly paired)
/// have a medium session. ~30 days of inactivity nearly fully decays trust.
pub const DEFAULT_L_KNOWN: f32 = 30.0;

/// Default `L_session` for `Stranger` peers, in days.
///
/// Strangers have no established session. Trust evaporates within days
/// of inactivity. New contacts must continually demonstrate alignment.
pub const DEFAULT_L_STRANGER: f32 = 5.0;

/// Relationship tier between two peers.
///
/// Maps to `PeerRecord.trust` in the Python daemon:
///   - `'pinned'`   -> `Paired`
///   - `'pending'`  -> `Known`
///   - `'rejected'` -> `Stranger`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relationship {
    /// Pinned / explicitly pair-bonded.
    Paired,
    /// Pending / introduced but not pair-bonded.
    Known,
    /// Rejected / unverified / unknown.
    Stranger,
}

impl Relationship {
    /// Default `L_session` for this relationship tier (days).
    #[must_use]
    pub fn default_l_session(self) -> f32 {
        match self {
            Self::Paired => DEFAULT_L_PAIRED,
            Self::Known => DEFAULT_L_KNOWN,
            Self::Stranger => DEFAULT_L_STRANGER,
        }
    }
}

/// Compute the alignment trust score A(x, t) = exp(-(x^2 + t^2) / L).
///
/// # Arguments
///
/// * `hop_distance` — non-negative hop count to the peer (0 if direct).
///   For direct paired peers this is typically 1; multi-hop through a
///   mutual contact is 2+.
/// * `staleness_seconds` — non-negative seconds since last interaction.
/// * `l_session` — session length scale in days; positive finite.
///
/// # Returns
///
/// A trust score in [0, 1]. Returns 1.0 when both inputs are zero.
/// Decays toward 0 as either input grows; at extreme decay the f32
/// `exp` underflows to exactly 0.0, which is the semantically correct
/// "trust fully exhausted" value.
///
/// # Errors
///
/// Returns [`AlignError`] for negative inputs, non-finite inputs, or
/// non-positive `l_session`.
///
/// # Example
///
/// ```
/// use ol_align::{trust_score, Relationship};
///
/// // Fresh paired peer (1 hop, just talked, paired session length).
/// let t = trust_score(1.0, 0.0, Relationship::Paired.default_l_session()).unwrap();
/// assert!(t > 0.99);
///
/// // Same paired peer after a year of silence.
/// let one_year_sec = 365.0 * 86_400.0;
/// let t = trust_score(1.0, one_year_sec, Relationship::Paired.default_l_session()).unwrap();
/// assert!(t < 0.001);
/// ```
pub fn trust_score(
    hop_distance: f32,
    staleness_seconds: f32,
    l_session: f32,
) -> Result<f32, AlignError> {
    // Reject NaN/Inf up front — the rest of the math assumes finite reals.
    if !hop_distance.is_finite() || !staleness_seconds.is_finite() || !l_session.is_finite() {
        return Err(AlignError::NonFinite {
            hop: hop_distance,
            staleness: staleness_seconds,
            l: l_session,
        });
    }
    if hop_distance < 0.0 {
        return Err(AlignError::NegativeHopDistance { got: hop_distance });
    }
    if staleness_seconds < 0.0 {
        return Err(AlignError::NegativeStaleness {
            got: staleness_seconds,
        });
    }
    if l_session <= 0.0 {
        return Err(AlignError::InvalidLSession { got: l_session });
    }

    // Convert staleness to days for parity with L_session units.
    let staleness_days = staleness_seconds / 86_400.0;

    // A(x, t) = exp(-(x^2 + t^2) / L)
    let exponent = -((hop_distance * hop_distance) + (staleness_days * staleness_days)) / l_session;
    Ok(exponent.exp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perfect_alignment_at_zero() {
        // Direct, fresh peer at any L_session -> 1.0.
        for l in [DEFAULT_L_STRANGER, DEFAULT_L_KNOWN, DEFAULT_L_PAIRED] {
            let t = trust_score(0.0, 0.0, l).unwrap();
            assert!((t - 1.0).abs() < 1e-6, "expected 1.0, got {t}");
        }
    }

    #[test]
    fn paired_decays_slower_than_stranger() {
        // After 5 days of silence at 1 hop:
        //   paired:   exp(-(1+25)/100) ≈ 0.77 — still trusted
        //   stranger: exp(-(1+25)/5)   ≈ 0.0055 — effectively gone
        // The decay timescale for each tier is sqrt(L_session) days:
        //   paired ≈ 10d, known ≈ 5.5d, stranger ≈ 2.2d. After ~that
        //   many days of silence trust drops to 1/e.
        let five_days = 5.0 * 86_400.0;
        let paired = trust_score(1.0, five_days, DEFAULT_L_PAIRED).unwrap();
        let stranger = trust_score(1.0, five_days, DEFAULT_L_STRANGER).unwrap();
        assert!(
            paired > 0.5,
            "paired should still be > 0.5 at 5d, got {paired}"
        );
        assert!(
            stranger < 0.01,
            "stranger should be < 0.01 at 5d, got {stranger}"
        );
        // Universally: paired trust >= stranger trust at the same inputs.
        assert!(paired > stranger);
    }

    #[test]
    fn hop_distance_decays_trust() {
        // At the same staleness, more hops -> less trust.
        let s = 86_400.0; // 1 day
        let t1 = trust_score(1.0, s, DEFAULT_L_KNOWN).unwrap();
        let t3 = trust_score(3.0, s, DEFAULT_L_KNOWN).unwrap();
        let t5 = trust_score(5.0, s, DEFAULT_L_KNOWN).unwrap();
        assert!(t1 > t3 && t3 > t5);
    }

    #[test]
    fn rejects_negative_hop() {
        assert!(matches!(
            trust_score(-1.0, 0.0, DEFAULT_L_PAIRED),
            Err(AlignError::NegativeHopDistance { .. })
        ));
    }

    #[test]
    fn rejects_negative_staleness() {
        assert!(matches!(
            trust_score(1.0, -1.0, DEFAULT_L_PAIRED),
            Err(AlignError::NegativeStaleness { .. })
        ));
    }

    #[test]
    fn rejects_nonfinite() {
        assert!(matches!(
            trust_score(f32::NAN, 0.0, DEFAULT_L_PAIRED),
            Err(AlignError::NonFinite { .. })
        ));
        assert!(matches!(
            trust_score(1.0, f32::INFINITY, DEFAULT_L_PAIRED),
            Err(AlignError::NonFinite { .. })
        ));
    }

    #[test]
    fn rejects_invalid_l_session() {
        assert!(matches!(
            trust_score(1.0, 0.0, 0.0),
            Err(AlignError::InvalidLSession { .. })
        ));
        assert!(matches!(
            trust_score(1.0, 0.0, -10.0),
            Err(AlignError::InvalidLSession { .. })
        ));
    }

    #[test]
    fn relationship_default_l_matches_constants() {
        assert!((Relationship::Paired.default_l_session() - DEFAULT_L_PAIRED).abs() < 1e-6);
        assert!((Relationship::Known.default_l_session() - DEFAULT_L_KNOWN).abs() < 1e-6);
        assert!((Relationship::Stranger.default_l_session() - DEFAULT_L_STRANGER).abs() < 1e-6);
    }
}
