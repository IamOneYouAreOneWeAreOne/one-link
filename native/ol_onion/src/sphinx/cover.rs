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
//! ```no_run
//! use ol_onion::sphinx::cover::{CoverScheduler, RateEqualizer};
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
//! ```

use blake3::Hasher;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

use crate::errors::{OnionError, OnionResult};
use crate::sphinx::core::{
    build_sphinx_onion, compute_final_hop_shared_key, SphinxHop, SphinxPacket,
};

/// Cover-packet sentinel prefix. Provides a fast-path filter on
/// receive so the BLAKE3 verification only runs on packets that
/// could plausibly be cover (probability 2^-64 of a random payload
/// passing the prefix gate). The sentinel is INSIDE the encrypted
/// Sphinx onion, so a network observer cannot detect it; only the
/// final destination sees the cleartext payload.
///
/// **Audit M4 hardening note:** the sentinel alone is NOT
/// sufficient to authenticate cover status — a network attacker
/// who can bit-flip the encrypted payload at any relay could
/// transform a real packet's first 8 bytes to look like the
/// sentinel and cause the destination to drop a legitimate packet.
/// The authenticated trailer ([`COVER_TRAILER_LEN`] bytes) appended
/// after the random body cryptographically binds cover status to
/// the per-hop shared key — unforgeable without that key.
pub const COVER_SENTINEL: &[u8; 8] = b"OL-COVER";

/// Length of the authenticated cover-trailer MAC. 128 bits gives
/// 2^-128 forgery probability — way below practical concern. Audit M4.
pub const COVER_TRAILER_LEN: usize = 16;

/// Minimum payload size for cover packets (after the sentinel
/// prefix). Cover packets pad up to a configurable size so they
/// match the size distribution of real traffic.
pub const COVER_PAYLOAD_MIN: usize = 64;

/// Default Poisson rate λ for the cover-traffic scheduler, in
/// packets per second. Higher = more cover, more bandwidth cost.
/// Loopix paper suggests λ_loop ≈ 1 pkt/sec; daemon can tune up or
/// down based on bandwidth budget.
pub const COVER_DEFAULT_RATE_HZ: f64 = 1.0;

/// BLAKE3 domain separator for the cover-trailer MAC derivation.
/// Bumping the suffix invalidates all pre-existing cover packets
/// in flight — useful if the spec changes.
const COVER_TRAILER_DOMAIN: &str = "ol-sphinx-cover-trailer-v1";

/// Compute the authenticated cover trailer over `cover_body` keyed
/// by the destination's per-circuit shared key. Audit M4.
///
/// Implementation: BLAKE3 `derive_key(domain, shared_key)` produces
/// a context-bound MAC key, fed into a keyed BLAKE3 hash over the
/// body. Truncated to 16 bytes — sufficient since BLAKE3 outputs are
/// pseudorandom and the trailer's role is unforgeability-of-status,
/// not collision resistance over an enumerable space.
pub(crate) fn compute_cover_trailer(
    shared_key: &[u8; 32],
    cover_body: &[u8],
) -> [u8; COVER_TRAILER_LEN] {
    let mac_key = blake3::derive_key(COVER_TRAILER_DOMAIN, shared_key);
    let mut h = Hasher::new_keyed(&mac_key);
    h.update(cover_body);
    let digest = h.finalize();
    let mut tag = [0u8; COVER_TRAILER_LEN];
    tag.copy_from_slice(&digest.as_bytes()[..COVER_TRAILER_LEN]);
    tag
}

/// Constant-time test: does `payload` carry a valid authenticated
/// cover trailer keyed by `shared_key`? Audit M4.
///
/// Returns true iff:
///   1. `payload.len() >= COVER_SENTINEL.len() + COVER_TRAILER_LEN`,
///   2. `payload[..COVER_SENTINEL.len()] == COVER_SENTINEL`,
///   3. The trailing 16 bytes equal the BLAKE3-keyed MAC over
///      `payload[..len - COVER_TRAILER_LEN]`.
///
/// The body fed to the MAC INCLUDES the sentinel — binding the
/// sentinel prefix into the tag so an attacker can't append a
/// pre-computed valid trailer onto a random payload that happens
/// to start with a forged sentinel.
///
/// The prefix check is non-constant-time (sentinel is public), but
/// the trailer compare uses `subtle::ConstantTimeEq` so leaking
/// fine-grained body content via tag comparison timing is not
/// possible.
pub fn is_cover_payload_authenticated(shared_key: &[u8; 32], payload: &[u8]) -> bool {
    if payload.len() < COVER_SENTINEL.len() + COVER_TRAILER_LEN {
        return false;
    }
    if &payload[..COVER_SENTINEL.len()] != COVER_SENTINEL {
        return false;
    }
    let body_end = payload.len() - COVER_TRAILER_LEN;
    let body = &payload[..body_end];
    let actual_tag = &payload[body_end..];
    let expected = compute_cover_trailer(shared_key, body);
    bool::from(expected.ct_eq(actual_tag))
}

/// Identify whether a delivered payload carries the COVER_SENTINEL
/// prefix (FAST PATH; does NOT authenticate).
///
/// **Pre-M4 callers using this for cover detection are insecure** —
/// the sentinel-alone gate is forgeable by a network attacker who
/// bit-flips a real payload's first 8 bytes. Use
/// [`is_cover_payload_authenticated`] instead, which the Sphinx
/// peel layer now invokes internally before returning
/// [`crate::sphinx::core::SphinxPeelOutcome::Cover`].
///
/// Retained ONLY as a quick-rejection helper for benchmarks +
/// fast-path tests. Production receive paths MUST go through
/// the authenticated check.
#[deprecated(
    since = "0.21.0-alpha",
    note = "audit M4 — use is_cover_payload_authenticated; the plaintext-prefix check is forgeable"
)]
pub fn is_cover_payload(payload: &[u8]) -> bool {
    payload.len() >= COVER_SENTINEL.len() && &payload[..COVER_SENTINEL.len()] == COVER_SENTINEL
}

/// Build a cover Sphinx packet bound for `circuit` (typically a
/// self-mesh destination — the sender's own pubkey — or a trusted
/// cover-pool relay).
///
/// Audit M4 wire format:
///
/// ```text
///   payload = COVER_SENTINEL (8 bytes)
///           || random body  (cover_size bytes, ≥ COVER_PAYLOAD_MIN)
///           || MAC trailer  (COVER_TRAILER_LEN bytes, BLAKE3-keyed
///                            by the destination's per-circuit shared key)
/// ```
///
/// The destination derives the same shared key from its own static
/// secret + the incoming alpha, recomputes the MAC, and
/// constant-time-compares against the trailer. Only a packet from a
/// sender who knows the destination's static pubkey (and chose this
/// circuit) can produce a valid trailer — the MAC binds cover
/// status to the circuit's secret session material.
pub fn build_cover_packet<R: RngCore + CryptoRng>(
    sender_eph_sk: &Scalar,
    circuit: &[SphinxHop],
    cover_size: usize,
    rng: &mut R,
) -> OnionResult<SphinxPacket> {
    if cover_size < COVER_PAYLOAD_MIN {
        return Err(OnionError::Internal("cover payload below minimum size"));
    }
    if circuit.is_empty() {
        return Err(OnionError::EmptyCircuit);
    }
    // Walk the blinding chain to derive what the destination will
    // see as its shared key. Failing here surfaces small-order or
    // empty-circuit errors before we spend cycles on the packet build.
    let dest_shared_key = compute_final_hop_shared_key(sender_eph_sk, circuit)?;
    // Layout: sentinel (8) || random body (cover_size) || MAC (16).
    let total_len = COVER_SENTINEL.len() + cover_size + COVER_TRAILER_LEN;
    let mut payload = vec![0u8; total_len];
    payload[..COVER_SENTINEL.len()].copy_from_slice(COVER_SENTINEL);
    let body_start = COVER_SENTINEL.len();
    let body_end = body_start + cover_size;
    rng.fill_bytes(&mut payload[body_start..body_end]);
    let trailer = compute_cover_trailer(&dest_shared_key, &payload[..body_end]);
    payload[body_end..].copy_from_slice(&trailer);
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
        // Exponential sample: -ln(u) / λ in seconds. u ∈ (0, 1] →
        // ln(u) ≤ 0 → wait_sec ≥ 0 by construction, so sign-loss
        // is impossible. Clamp to u64::MAX as defense-in-depth.
        let wait_sec = -(u.ln()) / self.rate_hz;
        let wait_ms_f = (wait_sec * 1000.0).clamp(0.0, u64::MAX as f64);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let wait_ms = wait_ms_f as u64;
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
        self.observed_real_rate = (1.0 - alpha) * self.observed_real_rate + alpha * instant_rate;
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
    fn cover_trailer_authenticated_check() {
        // Two distinct shared-keys produce distinct, non-matching
        // trailers for the same body — replay/swap is detectable.
        let k1 = [0x11u8; 32];
        let k2 = [0x22u8; 32];
        let body = [0xAAu8; 32];
        let t1 = compute_cover_trailer(&k1, &body);
        let t2 = compute_cover_trailer(&k2, &body);
        assert_ne!(t1, t2);

        // Build a synthetic cover payload and check the verify path.
        let mut payload = COVER_SENTINEL.to_vec();
        payload.extend_from_slice(&body);
        let trailer = compute_cover_trailer(&k1, &payload);
        payload.extend_from_slice(&trailer);
        assert!(is_cover_payload_authenticated(&k1, &payload));
        // Wrong key fails.
        assert!(!is_cover_payload_authenticated(&k2, &payload));
        // Bit-flip in body invalidates the trailer.
        let mut tampered = payload.clone();
        tampered[20] ^= 1;
        assert!(!is_cover_payload_authenticated(&k1, &tampered));
        // Bit-flip in trailer invalidates.
        let mut bad_tag = payload.clone();
        let last = bad_tag.len() - 1;
        bad_tag[last] ^= 1;
        assert!(!is_cover_payload_authenticated(&k1, &bad_tag));
        // Real-looking payloads (no sentinel) reject immediately.
        assert!(!is_cover_payload_authenticated(&k1, b"hello world"));
        assert!(!is_cover_payload_authenticated(&k1, &[]));
        // A payload that's mostly cover-shaped but with a flipped
        // sentinel byte fails the prefix gate.
        let mut wrong_prefix = payload.clone();
        wrong_prefix[0] ^= 1;
        assert!(!is_cover_payload_authenticated(&k1, &wrong_prefix));
    }

    #[test]
    fn build_cover_packet_round_trip() {
        let (dest_sk, dest) = make_relay();
        let (eph_sk, _) = generate_static_keypair(&mut OsRng);
        let packet =
            build_cover_packet(&eph_sk, std::slice::from_ref(&dest), 128, &mut OsRng).unwrap();
        let outcome = peel_sphinx_layer(&dest_sk, &packet).unwrap();
        // Audit M4: peel returns the authenticated Cover variant for
        // a packet built via the cover-traffic path. The payload is
        // not surfaced to the caller (no plaintext leak via
        // mis-classified delivery).
        assert!(matches!(outcome, SphinxPeelOutcome::Cover));
    }

    #[test]
    fn build_cover_packet_three_hop() {
        let (r1_sk, r1) = make_relay();
        let (r2_sk, r2) = make_relay();
        let (dest_sk, dest) = make_relay();
        let (eph_sk, _) = generate_static_keypair(&mut OsRng);
        let mut packet = build_cover_packet(&eph_sk, &[r1, r2, dest], 256, &mut OsRng).unwrap();

        // Cover packets are indistinguishable from real packets at
        // every relay (same size, same blinding, Forward at intermediates).
        // The destination's peel returns Cover (audit M4).
        for sk in [&r1_sk, &r2_sk, &dest_sk] {
            match peel_sphinx_layer(sk, &packet).unwrap() {
                SphinxPeelOutcome::Forward { next_packet, .. } => packet = next_packet,
                SphinxPeelOutcome::Cover => return,
                SphinxPeelOutcome::Deliver { .. } => {
                    panic!("cover packet leaked as Deliver — MAC binding broken");
                }
            }
        }
    }

    #[test]
    fn real_payload_doesnt_mis_classify_as_cover() {
        use crate::sphinx::core::build_sphinx_onion;
        // A real payload starting with the SENTINEL bytes but with a
        // random tail (no authenticated trailer) must NOT classify
        // as cover. This is the audit-M4 protection: a network
        // attacker can't forge cover status by flipping bytes.
        let (dest_sk, dest) = make_relay();
        let (eph_sk, _) = generate_static_keypair(&mut OsRng);
        let mut fake_cover = COVER_SENTINEL.to_vec();
        fake_cover.extend_from_slice(&[0xCCu8; 128]); // body
        fake_cover.extend_from_slice(&[0xDDu8; COVER_TRAILER_LEN]); // bogus tag
        let packet = build_sphinx_onion(&eph_sk, &[dest], &fake_cover, &mut OsRng).unwrap();
        match peel_sphinx_layer(&dest_sk, &packet).unwrap() {
            SphinxPeelOutcome::Deliver { payload } => {
                assert_eq!(payload, fake_cover);
            }
            SphinxPeelOutcome::Cover => {
                panic!("forged cover status accepted — MAC binding broken!");
            }
            SphinxPeelOutcome::Forward { .. } => panic!("expected Deliver"),
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
        let cover =
            build_cover_packet(&eph_sk, std::slice::from_ref(&dest), 256, &mut OsRng).unwrap();
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
        assert!(
            after_idle < 0.01,
            "after long idle, observed = {after_idle}"
        );
        // Cover fills back to full target.
        assert!((eq.current_cover_rate() - 5.0).abs() < 0.01);
    }
}
