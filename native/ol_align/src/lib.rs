//! `ol_align` — Gaussian alignment trust function from the Equation of ONE.
//!
//! Implements the alignment function A(x, t) = exp(-(x^2 + t^2)/L) as a
//! per-peer trust score. The signal naturally combines spatial distance
//! (hop count to the peer) with temporal staleness (seconds since last
//! interaction), decaying via a session-length scale L that depends on
//! the relationship tier (Paired / Known / Stranger).
//!
//! ## Why this replaces ad-hoc trust thresholds
//!
//! The shipping daemon scatters trust decisions across `_capability_allowed`,
//! `_accept_pair`, and folder-sync gates as hand-tuned constants. Each gate
//! has its own logic; trust does not decay; revocation is binary.
//!
//! A(x, t) gives:
//!   - Continuous trust in [0, 1] — no all-or-nothing cliffs.
//!   - Natural temporal decay — stale peers lose trust gradually.
//!   - Hop-distance awareness — direct paired peers carry higher weight
//!     than peers two hops away through a mutual.
//!   - One function, all gates — replaces N hand-tuned thresholds.
//!
//! Evidence (Gap 26 from the forge shootouts):
//!   F1 = +6.5 to +27 pp better than ad-hoc trust across thresholds.
//!
//! ## Surface
//!
//! - [`trust_score`] — the pure function.
//! - [`L_session`] — relationship-tier session-length scales.
//! - [`Relationship`] — the tier enum.
//!
//! Pure stateless math. No allocation, no I/O, no async.

#![doc(html_root_url = "https://docs.rs/ol_align/0.21.0")]

pub mod align;
pub mod error;

pub use align::{trust_score, Relationship, DEFAULT_L_KNOWN, DEFAULT_L_PAIRED, DEFAULT_L_STRANGER};
pub use error::AlignError;

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
