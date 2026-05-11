//! `ol_prefetch` — active inference prefetch over peer access traces.
//!
//! Per `FILE_ENGINE_V2_PLAN.md` Phase D item #3:
//!
//! > Active inference prefetch — extends bandit (Phase C) with
//! > generative model of peer-pair demand. Cold-start prior
//! > transferred from user's other peer-pairs; "lukewarm" start via
//! > cohort priors.
//!
//! ## Approach
//!
//! Full Bayesian active inference (Friston free-energy minimization)
//! is too heavy for this layer. Instead we ship a focused predictor:
//!
//! - Track per-peer access sequences `(peer, file_id, t)`.
//! - For each `(a, b)` ordered pair, accumulate a co-occurrence count
//!   weighted by `exp(-lambda * gap)` where `gap` is the chunk-arrival
//!   time delta. Recent co-occurrences carry more signal.
//! - Predict `P(next = B | last = A, peer) ∝ co_occurrence[(A, B)]`
//!   normalized over candidate B's.
//!
//! This captures the "if Alice just downloaded report.pdf, she'll
//! probably download attachments-zip next" pattern — the wedge for
//! creator-class transfers where edits propagate in clusters.
//!
//! Cold-start handling:
//!
//! - **Empty trace** — no predictions, prefetch off.
//! - **Lukewarm via cohort prior** — `transfer_prior_from` mixes another
//!   peer's accumulated co-occurrences into a fresh peer's table.
//! - **Decay** — `decay_counts` halves all counters; called periodically
//!   to bound storage growth and let stale patterns fade.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod predictor;

pub use predictor::{
    Prediction, PrefetchError, PrefetchPredictor, MAX_CO_OCCURRENCE_GAP_MS,
};

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
