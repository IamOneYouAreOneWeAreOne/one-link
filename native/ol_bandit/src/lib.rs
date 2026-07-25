//! `ol_bandit` — a policy-neutral multi-armed Thompson-sampling
//! primitive for One Link's transfer engine per ADR-0019.
//!
//! ## Production wiring
//!
//! The production-active consumer today is **route selection only**:
//! `transfer_brain.py` maps candidate routes to arms, records normalized
//! throughput/success rewards, and asks the bandit to narrow the route
//! axis before mode selection. Chunk-size, parallelism, FEC-ratio,
//! prefetch-window, pacing, and compression-threshold control loops are
//! future work; they are not implemented or production-active.
//!
//! This crate deliberately has no route or knob semantics. It provides
//! the generic posterior/update machinery; callers own arm identity,
//! persistence, reward design, safety bounds, and rollback behavior.
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
//! - [`Bandit`] — a generic bandit over caller-defined arms.
//! - [`Arm`] — a single arm's `(α, β)` Beta posterior.
//! - [`select`] / [`update`] — the loop.
//!
//! The daemon's `BanditRouteSelector` is the currently wired policy
//! consumer. A per-peer/per-knob controller remains a design target,
//! not a claim about the shipping runtime.

#![doc(html_root_url = "https://docs.rs/ol_bandit/0.21.0")]

pub mod bandit;
pub mod error;

pub use bandit::{Arm, Bandit, BanditRng, BanditSeed, MAX_ARMS};
pub use error::BanditError;

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
