//! Row 6 — cover traffic primitive for Sphinx Coherence.
//!
//! Sphinx alone defeats SPATIAL correlation across relays (alpha
//! blinding makes same-circuit packets pairwise indistinguishable
//! at every hop). It does NOT defeat TEMPORAL correlation: a global
//! passive adversary watching every relay's timeline can correlate
//! "packet ingress at R1 at time T" with "packet egress from R2 at
//! T+δ" for the same circuit.
//!
//! Cover traffic closes this gap. Each daemon emits "cover" Sphinx
//! packets at random intervals along random circuits. On the wire,
//! cover packets are indistinguishable from real packets (same
//! size, same encryption, same structure). An observer cannot tell
//! which packets carry real user data and which are cover.
//!
//! ## Design
//!
//! - **Cover-packet builder**: builds a valid Sphinx packet bound
//!   for a "self-mesh" destination (the sender's own pubkey) or a
//!   trusted-relay pool. The destination decrypts to discover the
//!   payload is the cover sentinel + drops it.
//! - **Poisson scheduler**: the daemon emits cover packets according
//!   to a Poisson process with configurable rate λ. The
//!   exponentially-distributed inter-arrival times make the cover
//!   traffic indistinguishable from "burst-then-idle" patterns of
//!   real traffic.
//! - **Cover sentinel**: a fixed magic prefix (8 bytes) in the
//!   payload tells the destination "this is cover, discard." The
//!   sentinel is encrypted inside the onion so observers can't
//!   distinguish cover from real on the wire.
//!
//! ## What this layer is NOT
//!
//! This is the PRIMITIVE for cover traffic, not the full mixnet.
//! It provides:
//! - A way to build cover packets.
//! - A scheduler that yields wait-times.
//!
//! It does NOT provide:
//! - Active-inference cover (Tier 2 item 6) — adaptive rate that
//!   maximizes observer entropy. That's a future polish.
//! - Loop circuits + reply-block (SURB) integration — separate ship.
//! - Daemon-level wiring (the actual "emit a packet now" call).
//!
//! ## References
//!
//! - Loopix (Piotrowska et al. 2017): the canonical mixnet cover
//!   traffic design using Poisson padding.
//! - Tor's "Padding Spec" (PROP254): a simpler client-relay cover
//!   scheme without true mix semantics.
//!
//! ## Example: equalized-rate cover scheduling
//!
//! ```
//! use ol_onion::sphinx::cover::{CoverScheduler, RateEqualizer, is_cover_payload, COVER_SENTINEL};
//!
//! // Aim for 5 packets/sec on the wire regardless of real traffic.
//! let mut eq = RateEqualizer::new(5.0);
//! eq.observe_real_emission(1_000);
//! eq.observe_real_emission(1_500);
//! eq.observe_real_emission(2_000);
//! // Real ≈ 2 Hz, so cover fills ≈ 3 Hz of the budget.
//! let cover_rate = eq.current_cover_rate();
//! assert!(cover_rate > 0.0 && cover_rate <= 5.0);
//!
//! // Schedule the next cover packet using an Exp(λ) sample.
//! let mut sched = CoverScheduler::new(cover_rate.max(0.001), [0x42; 32]);
//! let wait_ms = sched.next_wait_ms();
//! assert!(wait_ms < 60_000, "wait sample bounded under normal rates");
//!
//! // Cover packets carry the sentinel; receivers drop them.
//! let mut payload = COVER_SENTINEL.to_vec();
//! payload.extend_from_slice(&[0u8; 64]);
//! assert!(is_cover_payload(&payload));
//! ```

use blake3::Hasher;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};

use crate::errors::{OnionError, OnionResult};
use crate::sphinx::core::{build_sphinx_onion, SphinxHop, SphinxPacket};

/// Cover-packet sentinel that the destination uses to identify
/// cover traffic. Inside the Sphinx onion this looks identical to
/// any other payload byte; only the destination sees it.
pub const COVER_SENTINEL: &[u8; 8] = b"OL-COVER";

/// Minimum payload size for cover packets (after the sentinel
/// prefix). Cover packets pad up to a configurable size so they
/// match the size distribution of real traffic.
pub const COVER_PAYLOAD_MIN: usize = 64;

/// Default Poisson rate λ for the cover-traffic scheduler, in
/// packets per second. Higher = more cover, more bandwidth cost.
/// Loopix paper suggests λ_loop ≈ 1 pkt/sec; daemon can tune up or
/// down based on bandwidth budget.
pub const COVER_DEFAULT_RATE_HZ: f64 = 1.0;

/// Identify whether a delivered payload is a cover sentinel and
/// should be dropped rather than delivered to the application.
pub fn is_cover_payload(payload: &[u8]) -> bool {
    payload.len() >= COVER_SENTINEL.len()
        && &payload[..COVER_SENTINEL.len()] == COVER_SENTINEL
}

/// Build a cover Sphinx packet bound for `circuit` (typically a
/// self-mesh destination — the sender's own pubkey — or a trusted
/// cover-pool relay).
///
/// The payload is the [`COVER_SENTINEL`] prefix + a random-bytes
/// fill of size `cover_size` (must be ≥ [`COVER_PAYLOAD_MIN`]). The
/// destination sees `is_cover_payload(payload) == true` and drops.
pub fn build_cover_packet<R: RngCore + CryptoRng>(
    sender_eph_sk: &Scalar,
    circuit: &[SphinxHop],
    cover_size: usize,
    rng: &mut R,
) -> OnionResult<SphinxPacket> {
    if cover_size < COVER_PAYLOAD_MIN {
        return Err(OnionError::Internal(
            "cover payload below minimum size",
        ));
    }
    let total_payload_len = COVER_SENTINEL.len() + cover_size;
    let mut payload = vec![0u8; total_payload_len];
    payload[..COVER_SENTINEL.len()].copy_from_slice(COVER_SENTINEL);
    rng.fill_bytes(&mut payload[COVER_SENTINEL.len()..]);
    build_sphinx_onion(sender_eph_sk, circuit, &payload, rng)
}

/// Poisson-process scheduler for cover-packet emission times.
///
/// Maintains a current λ (rate) and a deterministic-on-seed RNG so
/// emission timing can be audited without exposing future emission
/// times to anyone but the daemon.
///
/// ## Usage
///
/// ```ignore
/// let mut sched = CoverScheduler::new(rate_hz, seed);
/// loop {
///     let wait_ms = sched.next_wait_ms();
///     sleep(wait_ms);
///     emit_cover_packet();
/// }
/// ```
#[derive(Debug, Clone)]
pub struct CoverScheduler {
    rate_hz: f64,
    /// Internal RNG state (seeded BLAKE3 keystream). Survives clone
    /// for replay, but each `next_wait_ms` advances it.
    counter: u64,
    seed: [u8; 32],
}

impl CoverScheduler {
    /// New scheduler with rate `rate_hz` (packets per second) seeded
    /// by `seed`. Different seeds give independent emission patterns.
    pub fn new(rate_hz: f64, seed: [u8; 32]) -> Self {
        assert!(rate_hz > 0.0, "rate must be positive");
        Self {
            rate_hz,
            counter: 0,
            seed,
        }
    }

    /// Construct with the default rate ([`COVER_DEFAULT_RATE_HZ`]).
    pub fn with_default_rate(seed: [u8; 32]) -> Self {
        Self::new(COVER_DEFAULT_RATE_HZ, seed)
    }

    /// Sample the next inter-arrival time in milliseconds from the
    /// exponential distribution Exp(λ).
    ///
    /// For a Poisson process with rate λ packets/sec, inter-arrival
    /// times are exponentially distributed with mean 1/λ.
    pub fn next_wait_ms(&mut self) -> u64 {
        // Sample a uniform u in (0, 1] from the BLAKE3 keystream.
        let mut h = Hasher::new();
        h.update(b"OL-cover-scheduler-v1");
        h.update(&self.seed);
        h.update(&self.counter.to_le_bytes());
        let digest = h.finalize();
        let bytes = digest.as_bytes();
        // First 8 bytes → u64 → scale to (0, 1].
        let raw = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        // Avoid raw == 0 to keep u > 0.
        let raw_nonzero = raw.max(1);
        let u = (raw_nonzero as f64) / (u64::MAX as f64);
        // Exponential sample: -ln(u) / λ in seconds.
        let wait_sec = -(u.ln()) / self.rate_hz;
        let wait_ms = (wait_sec * 1000.0) as u64;
        self.counter = self.counter.wrapping_add(1);
        wait_ms
    }

    /// Current configured rate.
    pub fn rate_hz(&self) -> f64 {
        self.rate_hz
    }

    /// Update the rate. Useful for adaptive-rate control (e.g.
    /// throttle during low-bandwidth conditions). Future polish:
    /// Tier 2 active-inference will set this from observer-entropy
    /// minimization.
    pub fn set_rate_hz(&mut self, rate_hz: f64) {
        assert!(rate_hz > 0.0, "rate must be positive");
        self.rate_hz = rate_hz;
    }
}

/// Adaptive rate equalizer for cover traffic.
///
/// Maintains a CONSTANT total emission rate (cover + real) regardless
/// of the real-traffic load. When real traffic spikes, cover rate
/// drops; when real traffic is idle, cover rate rises to fill the
/// gap. An observer sees a uniform-rate output stream and cannot
/// infer "is there real traffic now?" from packet timing alone.
///
/// ## How it differs from plain Poisson cover
///
/// - Plain Poisson: cover at fixed λ. Total observed rate = real_rate + λ.
///   An observer can subtract λ to estimate real_rate.
/// - Equalized: cover_rate = max(0, target_total - real_rate). Total
///   observed rate = target_total constant. Observer sees no signal.
///
/// ## Usage
///
/// ```ignore
/// let mut eq = RateEqualizer::new(target_total_hz=5.0);
/// // Daemon updates observed real rate every time it emits a real packet.
/// eq.observe_real_emission(now_ms);
/// // Daemon queries current cover rate when scheduling next cover packet.
/// let cover_rate = eq.current_cover_rate();
/// scheduler.set_rate_hz(cover_rate.max(0.001)); // floor to avoid stall
/// ```
#[derive(Debug, Clone)]
pub struct RateEqualizer {
    target_total_hz: f64,
    /// Sliding-window observed real rate (Hz). Exponentially weighted.
    observed_real_rate: f64,
    /// EWMA half-life in seconds. Determines how quickly the equalizer
    /// reacts to bursts vs steady state.
    half_life_sec: f64,
    /// Wall-clock ms of last observed real emission.
    last_emit_ms: u64,
}

/// Default EWMA half-life: 30 seconds. Bursts of real traffic
/// pull cover rate down for ~30 sec, then it recovers.
pub const RATE_EQ_DEFAULT_HALF_LIFE_SEC: f64 = 30.0;

impl RateEqualizer {
    /// Construct an equalizer targeting `target_total_hz` packets per
    /// second on the wire. Cover fills whatever real doesn't supply.
    pub fn new(target_total_hz: f64) -> Self {
        assert!(target_total_hz > 0.0, "target rate must be positive");
        Self {
            target_total_hz,
            observed_real_rate: 0.0,
            half_life_sec: RATE_EQ_DEFAULT_HALF_LIFE_SEC,
            last_emit_ms: 0,
        }
    }

    /// Set the EWMA half-life. Smaller = react faster to bursts;
    /// larger = smoother but slower to adapt.
    pub fn set_half_life_sec(&mut self, half_life_sec: f64) {
        assert!(half_life_sec > 0.0, "half_life must be positive");
        self.half_life_sec = half_life_sec;
    }

    /// Notify the equalizer that a real packet was emitted at
    /// `now_ms` wall-clock milliseconds. Updates the EWMA.
    pub fn observe_real_emission(&mut self, now_ms: u64) {
        if self.last_emit_ms == 0 {
            // First observation; seed with target rate as initial guess.
            self.observed_real_rate = 1.0;
            self.last_emit_ms = now_ms;
            return;
        }
        let dt_sec = (now_ms.saturating_sub(self.last_emit_ms)) as f64 / 1000.0;
        if dt_sec <= 0.0 {
            return;
        }
        // Instantaneous rate from this gap.
        let instant_rate = 1.0 / dt_sec;
        // EWMA weight from half-life: alpha = 1 - 0.5^(dt / half_life)
        let alpha = 1.0 - 0.5f64.powf(dt_sec / self.half_life_sec);
        let alpha = alpha.clamp(0.0, 1.0);
        self.observed_real_rate =
            (1.0 - alpha) * self.observed_real_rate + alpha * instant_rate;
        self.last_emit_ms = now_ms;
    }

    /// Notify that wall-clock time has advanced even without real
    /// emissions. Used to DECAY the observed_real_rate toward zero
    /// during idle periods so cover rate rises to fill the gap.
    pub fn observe_idle_tick(&mut self, now_ms: u64) {
        if self.last_emit_ms == 0 {
            self.last_emit_ms = now_ms;
            return;
        }
        let dt_sec = (now_ms.saturating_sub(self.last_emit_ms)) as f64 / 1000.0;
        if dt_sec <= 0.0 {
            return;
        }
        // Decay observed rate toward zero with the same half-life.
        let decay = 0.5f64.powf(dt_sec / self.half_life_sec);
        self.observed_real_rate *= decay;
        self.last_emit_ms = now_ms;
    }

    /// Current cover rate λ that would maintain target total emission.
    /// Floored at zero so we never get negative rates when real traffic
    /// exceeds target.
    pub fn current_cover_rate(&self) -> f64 {
        (self.target_total_hz - self.observed_real_rate).max(0.0)
    }

    /// Read the EWMA-smoothed observed real rate. For diagnostics.
    pub fn observed_real_rate(&self) -> f64 {
        self.observed_real_rate
    }

    /// Read the target total emission rate.
    pub fn target_total_hz(&self) -> f64 {
        self.target_total_hz
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sphinx::core::{generate_static_keypair, peel_sphinx_layer, SphinxPeelOutcome};
    use crate::HopId;
    use rand::rngs::OsRng;
    use rand::Rng;

    fn make_relay() -> (Scalar, SphinxHop) {
        let (sk, pk) = generate_static_keypair(&mut OsRng);
        let mut id = [0u8; 32];
        OsRng.fill(&mut id);
        (
            sk,
            SphinxHop {
                id: HopId::from_bytes(id),
                static_pk: pk,
            },
        )
    }

    #[test]
    fn cover_sentinel_detection() {
        assert!(is_cover_payload(COVER_SENTINEL));
        let mut padded = COVER_SENTINEL.to_vec();
        padded.extend_from_slice(b"random garbage");
        assert!(is_cover_payload(&padded));

        assert!(!is_cover_payload(b"OL-REAL"));
        assert!(!is_cover_payload(b"hello world"));
        assert!(!is_cover_payload(&[]));
        assert!(!is_cover_payload(&[0u8; 4]));
    }

    #[test]
    fn build_cover_packet_round_trip() {
        let (dest_sk, dest) = make_relay();
        let (eph_sk, _) = generate_static_keypair(&mut OsRng);
        let packet =
            build_cover_packet(&eph_sk, &[dest.clone()], 128, &mut OsRng).unwrap();
        let outcome = peel_sphinx_layer(&dest_sk, &packet).unwrap();
        match outcome {
            SphinxPeelOutcome::Deliver { payload } => {
                assert!(is_cover_payload(&payload));
                assert_eq!(payload.len(), COVER_SENTINEL.len() + 128);
            }
            _ => panic!("expected Deliver"),
        }
    }

    #[test]
    fn build_cover_packet_three_hop() {
        let (r1_sk, r1) = make_relay();
        let (r2_sk, r2) = make_relay();
        let (dest_sk, dest) = make_relay();
        let (eph_sk, _) = generate_static_keypair(&mut OsRng);
        let mut packet =
            build_cover_packet(&eph_sk, &[r1, r2, dest], 256, &mut OsRng).unwrap();

        // Cover packets are indistinguishable from real packets at
        // every hop (same size, same blinding, same peel result).
        for sk in [&r1_sk, &r2_sk, &dest_sk] {
            match peel_sphinx_layer(sk, &packet).unwrap() {
                SphinxPeelOutcome::Forward { next_packet, .. } => packet = next_packet,
                SphinxPeelOutcome::Deliver { payload } => {
                    assert!(is_cover_payload(&payload));
                    return;
                }
            }
        }
    }

    #[test]
    fn build_cover_packet_rejects_below_min() {
        let (_, dest) = make_relay();
        let (eph_sk, _) = generate_static_keypair(&mut OsRng);
        let err =
            build_cover_packet(&eph_sk, &[dest], COVER_PAYLOAD_MIN - 1, &mut OsRng).unwrap_err();
        assert!(matches!(err, OnionError::Internal(_)));
    }

    // ── Scheduler tests ──────────────────────────────────────────

    #[test]
    fn scheduler_deterministic_per_seed() {
        let mut s1 = CoverScheduler::new(1.0, [0x42; 32]);
        let mut s2 = CoverScheduler::new(1.0, [0x42; 32]);
        for _ in 0..100 {
            assert_eq!(s1.next_wait_ms(), s2.next_wait_ms());
        }
    }

    #[test]
    fn scheduler_different_seeds_yield_different_sequences() {
        let mut s1 = CoverScheduler::new(1.0, [0x42; 32]);
        let mut s2 = CoverScheduler::new(1.0, [0x43; 32]);
        let mut any_diff = false;
        for _ in 0..50 {
            if s1.next_wait_ms() != s2.next_wait_ms() {
                any_diff = true;
                break;
            }
        }
        assert!(any_diff);
    }

    /// Empirical mean inter-arrival should be ≈ 1/λ seconds for a
    /// Poisson process with rate λ. With 10000 samples and λ=1 Hz,
    /// expected mean is 1000 ms ± a few %.
    #[test]
    fn scheduler_mean_matches_poisson_rate() {
        let mut sched = CoverScheduler::new(1.0, [0xAB; 32]);
        let n = 10_000;
        let mut sum_ms = 0u64;
        for _ in 0..n {
            sum_ms += sched.next_wait_ms();
        }
        let mean_ms = sum_ms as f64 / n as f64;
        let expected_ms = 1000.0;
        let pct_err = (mean_ms - expected_ms).abs() / expected_ms;
        eprintln!("scheduler mean inter-arrival = {mean_ms:.1} ms (expected {expected_ms:.0} ms), err = {:.2}%", pct_err * 100.0);
        // 10% tolerance (exponential distribution has high variance;
        // 10k samples is enough for ±3-4% typically).
        assert!(pct_err < 0.10);
    }

    #[test]
    fn scheduler_rate_scaling() {
        // At rate 10 Hz, mean inter-arrival should be ~100 ms.
        let mut sched = CoverScheduler::new(10.0, [0xCD; 32]);
        let n = 5_000;
        let mut sum_ms = 0u64;
        for _ in 0..n {
            sum_ms += sched.next_wait_ms();
        }
        let mean_ms = sum_ms as f64 / n as f64;
        let pct_err = (mean_ms - 100.0).abs() / 100.0;
        assert!(pct_err < 0.15, "10 Hz mean = {mean_ms}, expected ~100");
    }

    #[test]
    fn cover_packet_indistinguishable_size_from_real() {
        // Cover packets are SPHINX_PACKET_LEN bytes — same as real.
        use crate::sphinx::core::{build_sphinx_onion, SPHINX_PACKET_LEN};
        let (_, dest) = make_relay();
        let (eph_sk, _) = generate_static_keypair(&mut OsRng);
        let cover = build_cover_packet(&eph_sk, &[dest.clone()], 256, &mut OsRng).unwrap();
        let real = build_sphinx_onion(&eph_sk, &[dest], b"real payload", &mut OsRng).unwrap();
        assert_eq!(cover.as_bytes().len(), SPHINX_PACKET_LEN);
        assert_eq!(real.as_bytes().len(), SPHINX_PACKET_LEN);
    }

    // ── Rate equalizer tests ─────────────────────────────────────

    #[test]
    fn rate_equalizer_fresh_starts_with_full_cover_rate() {
        let eq = RateEqualizer::new(5.0);
        // No observations → observed real rate is 0 → cover fills all.
        assert_eq!(eq.target_total_hz(), 5.0);
        assert_eq!(eq.current_cover_rate(), 5.0);
        assert_eq!(eq.observed_real_rate(), 0.0);
    }

    #[test]
    fn rate_equalizer_real_emissions_reduce_cover_rate() {
        let mut eq = RateEqualizer::new(5.0);
        // First emission seeds at 1.0.
        eq.observe_real_emission(1_000);
        assert!(eq.observed_real_rate() > 0.0);
        // Subsequent emissions at ~1 Hz (1000 ms gap) keep observed near 1 Hz.
        for i in 1..20 {
            eq.observe_real_emission(1_000 + i * 1000);
        }
        let real_rate = eq.observed_real_rate();
        assert!(
            (real_rate - 1.0).abs() < 0.3,
            "expected ~1 Hz observed, got {real_rate}"
        );
        // Cover rate = target (5) − observed (~1) ≈ 4.
        let cover_rate = eq.current_cover_rate();
        assert!(cover_rate > 3.5 && cover_rate < 4.5);
    }

    #[test]
    fn rate_equalizer_burst_doesnt_send_cover_negative() {
        let mut eq = RateEqualizer::new(1.0);
        eq.set_half_life_sec(5.0);
        // Burst of real emissions at 10 Hz (100 ms gaps), far exceeding target.
        for i in 0..20 {
            eq.observe_real_emission(100 + i * 100);
        }
        // Observed real should be near 10 Hz; cover should floor at 0.
        assert!(eq.observed_real_rate() > 1.0);
        assert_eq!(eq.current_cover_rate(), 0.0);
    }

    #[test]
    fn rate_equalizer_idle_decays_observed_to_zero() {
        let mut eq = RateEqualizer::new(5.0);
        eq.set_half_life_sec(1.0);
        // Push some real emissions.
        for i in 0..10 {
            eq.observe_real_emission(i * 500); // 2 Hz
        }
        let after_emissions = eq.observed_real_rate();
        assert!(after_emissions > 0.5);
        // Now idle for 10 seconds — observed should decay sharply.
        eq.observe_idle_tick(60_000);
        let after_idle = eq.observed_real_rate();
        assert!(after_idle < after_emissions);
        assert!(after_idle < 0.01, "after long idle, observed = {after_idle}");
        // Cover fills back to full target.
        assert!((eq.current_cover_rate() - 5.0).abs() < 0.01);
    }
}
