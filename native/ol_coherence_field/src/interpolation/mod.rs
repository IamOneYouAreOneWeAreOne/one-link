//! Interpolation functions that bridge the deep-coherence and
//! low-coherence regimes of the field.

mod alpha_constraint;
mod be_rar_impl;

use thiserror::Error;

pub use be_rar_impl::be_rar;

/// Errors the interpolation layer can surface.
#[derive(Debug, Error, PartialEq)]
pub enum BeRarError {
    /// Argument was negative or NaN — `nu(y)` is only defined for
    /// non-negative reals.
    #[error("BE-RAR argument must be a non-negative real; got {0}")]
    InvalidArg(f64),
}
