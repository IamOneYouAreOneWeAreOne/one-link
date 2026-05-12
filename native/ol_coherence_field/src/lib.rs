//! `ol_coherence_field` — coherence-field substrate for the One Link
//! engine (Phase E of `FILE_ENGINE_V2_PLAN.md`).
//!
//! This crate ports the **same scalar coherence field** the Coherence
//! Energy Labs S_One derivation identifies as the source of dark-matter
//! / dark-energy phenomenology, specialised to network routing. The
//! same algebra is consumed by `OneField Mesh` (RF τ_c routing) and
//! `BioMesh` (biological signals); only the calibration constants
//! `(D, Γ, S)` differ per domain.
//!
//! ## Canonical theorem stack
//!
//! ```text
//! S_One
//!   → Einstein + Klein-Gordon variation
//!   → tau_c = tau_∞ · √(-g_tt)                            [proper-time bridge]
//!   → δτ_c / τ_∞ = Φ / c²                                 [weak-field map]
//!   → ∂_t δτ_c = D · ∇²(δτ_c) − Γ · δτ_c + S              [reaction-diffusion]
//!   → ell_screen = √(D / Γ) = c / (√3 · H_0)              [screening length]
//!   → galaxy Poisson limit (ell_screen ≫ r_local)
//!   → g_coh = −c² · ∇ ln(τ_c)                              [coherence flux]
//!   → nu(y) = 1 / (1 − exp(−√y))                          [BE-RAR, α = 1/2]
//!   → g_A = c · H_0 / (2π)                                 [apparent-horizon anchor]
//! ```
//!
//! ## Source-of-truth design refs
//!
//! - `Coherence_Energy_Labs_Website/data/evidence/Dark_Matter_Cosmology/S_ONE_DERIVATION_STORY.md`
//! - `.../ALL_FORMS_OF_S_ONE.md`
//! - `.../COHERENCE_FIELD_THEORY_EVIDENCE.md`
//! - ONE Docs: `UNIFIED COHERENCE FIELD THEORY (UFT).md`
//! - `OneField/onefield/mesh/routing.cl` (production τ_c-weighted routing)
//! - `forge_shootouts/tau_field_lib.py` (Helmholtz FEM reference)
//!
//! ## Module map
//!
//! - [`pde`] — reaction-diffusion PDE solver on graph Laplacian +
//!   Helmholtz reduction + Poisson-limit gate.
//! - [`green`] — Green-function nonlocal kernel evaluator.
//! - [`source`] — source functionals: linear (no-go reference),
//!   identity-sector dual (density + flux), support-phase boundary.
//! - [`interpolation`] — BE-RAR `nu(y)` with α = 1/2 forced by Bose
//!   statistics; replaces ad-hoc loss penalties.
//! - [`anchor`] — apparent-horizon anchor `g_A` + screening length
//!   `ell_screen` calibration.
//! - [`calibration`] — per-domain (D, Γ) constants for One Link,
//!   OneField, BioMesh.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod anchor;
pub mod calibration;
pub mod couplings;
pub mod green;
pub mod interpolation;
pub mod pde;
pub mod source;

pub use anchor::{apparent_horizon_anchor, screening_length, ScreeningRegime};
pub use calibration::{Calibration, Domain};
pub use couplings::{
    inject_fragility_events, prefetch_priorities, rotation_cadence_multiplier,
    FragilityEvent, PrefetchPriority, RotationCadence,
};
pub use green::{green_function, GreenError};
pub use interpolation::{be_rar, BeRarError};
pub use pde::{
    solve_helmholtz, solve_reaction_diffusion_steady, CgConfig, CgConfigF32, CgWorkspace,
    CgWorkspaceF32, FieldError, GraphLaplacian, HelmholtzSolver, HelmholtzSolverF32,
    SolveResult, SolveResultF32,
};
pub use source::{
    align_source, alignment_scalars, identity_dual_source,
    identity_dual_source_with_phase, linear_source, support_phase_kernel, SourceError,
};

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
