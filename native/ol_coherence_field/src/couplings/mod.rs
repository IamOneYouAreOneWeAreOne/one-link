//! Cross-system couplings: how the coherence field exchanges
//! information with the other Phase D crates.
//!
//! These are the three "alien-tech" couplings the plan calls for —
//! they're what make the field not just a math primitive but a
//! living substrate of the engine.
//!
//! - [`homology`] — fragility events from `ol_homology` feed back
//!   into the field's source term so the field anticipates partitions
//!   *before* they fully open. Self-healing swarm.
//! - [`prefetch`] — field-gradient predictions tell `ol_prefetch`
//!   where to pre-position next-likely chunks along high-coherence
//!   paths. Negative latency.
//! - [`ratchet`] — per-peer ratchet rotation cadence scales with
//!   `δτ_c / τ_∞`; peers in low-coherence wells rotate faster per
//!   byte. Crypto strength as a function of network physics.

pub mod homology;
pub mod prefetch;
pub mod ratchet;

pub use homology::{inject_fragility_events, FragilityEvent};
pub use prefetch::{prefetch_priorities, PrefetchPriority};
pub use ratchet::{rotation_cadence_multiplier, RotationCadence};
