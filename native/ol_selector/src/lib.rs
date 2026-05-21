//! `ol_selector` — the universal per-event selector for One Link.
//!
//! Implements the 14-rule Smart-Rules tree from forge_shootouts Gap 17,
//! which empirically demonstrates a 97% reduction in user-intent regret
//! versus the daemon's current static decision logic.
//!
//! ## What it decides per event
//!
//! Seven sub-decisions, all from one [`Context`](ol_decide::Context):
//!
//! 1. **Transport** — QUIC stream / QUIC datagram / WebRTC / relay
//! 2. **Path** — classical bytes vs coherence-substrate chunking
//! 3. **Onion hops** — 1, 3, or 5
//! 4. **Cover traffic** — on/off
//! 5. **Batch decision** — emit-now / batch / urgent-bypass
//! 6. **Anchor lay** — yes/no (sub-RTT loss recovery)
//! 7. **Predictor warm** — yes/no (prefetch pre-warm)
//!
//! ## Design
//!
//! - The rule tree is a pure function of `Context`. No state, no I/O.
//! - Implements [`Decide<Decision>`](ol_decide::Decide), so any other
//!   crate that wants to swap selectors (e.g. UnifiedMin in Phase H)
//!   plugs in trivially.
//! - The `safe_default` is "full conservative": 3-hop onion, cover ON,
//!   anchor laid, emit-now, classical path. Used when context is
//!   incomplete or smart logic errors.
//!
//! ## Evidence
//!
//! From the forge shootouts:
//! - Gap 17: Smart-Rules reduces regret by 97% vs Naive selector.
//! - Gap 22: Same rule tree IS the discretization of the continuous
//!   energy-minimization objective from the Equation of ONE.

#![doc(html_root_url = "https://docs.rs/ol_selector/0.21.0")]

pub mod decision;
pub mod error;
pub mod smart_rules;
pub mod unified_min;
pub mod weights;

pub use decision::{
    BatchDecision, ContractMode, ContractViolation, Decision, OnionHops, Path, Transport,
};
pub use error::SelectorError;
pub use smart_rules::SmartRules;
pub use unified_min::UnifiedMin;
pub use weights::Weights;

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
