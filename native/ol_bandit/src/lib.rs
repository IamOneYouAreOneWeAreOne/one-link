//! `ol_bandit` — multi-armed bandit auto-tuning for One Link's
//! transfer engine per ADR-0019.
//!
//! Phase C item #5 (multi-armed bandit auto-tuning). Replaces the
//! shipping daemon's `transfer_brain.py` EMA route memory with a
//! Thompson-sampling bandit over each tunable knob (chunk size,
//! parallelism, FEC ratio, prefetch window, pacing, compression
//! threshold).
//!
//! ## Why Thompson sampling
//!
//! Each "arm" of the bandit is a candidate value for a knob (e.g.,
//! chunk size = {16, 32, 64, 128, 256 KiB}). For each arm we maintain
//! a posterior over its expected reward (here: success rate or
//! normalized throughput in `[0, 1]`). Thompson sampling picks an arm
//! by sampling from each arm's posterior and choosing the highest
//! sample — this naturally balances exploration (uncertain arms get
//! occasional plays) and exploitation (high-mean arms dominate).
//!
//! We use a **Beta(α, β) prior** with binary success/failure updates.
//! Continuous rewards in `[0, 1]` are handled via Bernoulli thinning:
//! a reward `r ∈ [0, 1]` updates as α += r, β += (1-r). This is the
//! standard "Beta-Bernoulli bandit with reward scaling" trick.
//!
//! ## Surface
//!
//! - [`Bandit`] — a single-knob bandit; one per (peer-pair, knob).
//! - [`Arm`] — a single arm's `(α, β)` Beta posterior.
//! - [`select`] / [`update`] — the loop.
//!
//! The engine holds a `HashMap<(PeerFingerprint, KnobId), Bandit>`.
//! The daemon's `transfer_brain.py` is the policy consumer.

#![doc(html_root_url = "https://docs.rs/ol_bandit/0.21.0")]

pub mod bandit;
pub mod error;

pub use bandit::{Arm, Bandit, BanditRng, BanditSeed};
pub use error::BanditError;

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
