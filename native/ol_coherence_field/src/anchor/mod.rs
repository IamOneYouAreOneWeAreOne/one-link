//! Anchor scales: the two physical constants that pin the absolute
//! scale of the coherence field.
//!
//! - `ell_screen = √(D / Γ)` — the screening length. Beyond this
//!   distance the coherence response decays exponentially (Yukawa);
//!   inside, it's long-range (Poisson).
//! - `g_A = c · H_0 / (2π)` — the apparent-horizon anchor acceleration.
//!   In cosmology this is the present-epoch Hubble-scale acceleration;
//!   in our network analog it's the swarm-wide bandwidth-jitter
//!   ceiling that no peer can exceed.

mod apparent_horizon;
mod screening;

pub use apparent_horizon::{apparent_horizon_anchor, ApparentHorizonInputs, G_A_GALAXY_PLANCK};
pub use screening::{classify_regime, screening_length, ScreeningRegime};
