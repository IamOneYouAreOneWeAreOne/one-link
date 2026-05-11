//! Source functionals that feed `S(P, t)` into the reaction-diffusion
//! PDE. Three flavors:
//!
//! 1. [`linear_source`] — `S ∝ ρ` (density only). Subject to the
//!    linear-source no-go theorem: collapses to `g_coh ∝ g_bar`, i.e.
//!    nothing the linear potential already gave you. Kept as a sanity
//!    reference + regression-test baseline.
//!
//! 2. [`identity_dual_source`] — density + flux dual sourcing.
//!    `S = α · ρ + β · |J|`. Nonlinear in observables, escapes the
//!    no-go theorem. This is the production form for One Link.
//!
//! 3. [`support_phase_kernel`] — the boundary-layer kernel
//!    `k_phase(C_support) = tanh((c0 − C_support) / w_phase)`. Encodes
//!    the empirically-derived galaxy-side support-phase observation
//!    that the inner ~80% of support behaves "core-like" before the
//!    outer regime kicks in.

mod dual;
mod linear;
mod support_phase;

use thiserror::Error;

pub use dual::identity_dual_source;
pub use linear::linear_source;
pub use support_phase::{support_phase_kernel, SupportPhaseConfig};

/// Errors source-functional evaluation can surface.
#[derive(Debug, Error, PartialEq)]
pub enum SourceError {
    /// Vector length mismatch between density / flux arrays and
    /// the graph's node count.
    #[error("source vector length mismatch: expected {expected}, got {got}")]
    LengthMismatch {
        /// Expected length.
        expected: usize,
        /// Caller-supplied length.
        got: usize,
    },
    /// One of the calibration weights is non-finite or negative.
    #[error("source weight must be a non-negative real; got {0}")]
    InvalidWeight(f64),
}
