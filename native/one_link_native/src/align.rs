//! `one_link_native.align` — Python binding for `ol_align`.
//!
//! Surfaces the Gaussian alignment trust function A(x, t) per the
//! Equation of ONE. The daemon's `_capability_allowed` and pair-trust
//! gates consume this instead of ad-hoc per-site thresholds.

use ol_align::{trust_score as native_trust_score, AlignError, Relationship};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// Compute the alignment trust score A(x, t).
///
/// # Arguments
///
/// * `hop_distance` — non-negative hop count to the peer.
/// * `staleness_seconds` — non-negative seconds since last interaction.
/// * `l_session` — session-length scale in days. Use one of
///   [`l_paired`] / [`l_known`] / [`l_stranger`] for the default tiers,
///   or pass a custom value for non-default profiles.
///
/// # Returns
///
/// Trust score in (0, 1]; 1.0 means perfectly aligned.
///
/// # Raises
///
/// `ValueError` on negative inputs, non-finite inputs, or non-positive
/// `l_session`.
#[pyfunction]
#[pyo3(signature = (hop_distance, staleness_seconds, l_session))]
fn trust_score(hop_distance: f32, staleness_seconds: f32, l_session: f32) -> PyResult<f32> {
    native_trust_score(hop_distance, staleness_seconds, l_session)
        .map_err(|error| align_err_to_py(&error))
}

/// Trust-score using the relationship tier as the `L_session` default.
///
/// `relationship` accepts `"paired"`, `"known"`, or `"stranger"`
/// (case-insensitive). Maps directly to `PeerRecord.trust` in the daemon:
/// `'pinned'` -> `"paired"`, `'pending'` -> `"known"`, `'rejected'` ->
/// `"stranger"`.
#[pyfunction]
#[pyo3(signature = (relationship, hop_distance, staleness_seconds))]
fn trust_for(relationship: &str, hop_distance: f32, staleness_seconds: f32) -> PyResult<f32> {
    let rel = parse_relationship(relationship)?;
    native_trust_score(hop_distance, staleness_seconds, rel.default_l_session())
        .map_err(|error| align_err_to_py(&error))
}

/// Default `L_session` (days) for paired peers.
#[pyfunction]
fn l_paired() -> f32 {
    ol_align::DEFAULT_L_PAIRED
}

/// Default `L_session` (days) for known peers.
#[pyfunction]
fn l_known() -> f32 {
    ol_align::DEFAULT_L_KNOWN
}

/// Default `L_session` (days) for stranger peers.
#[pyfunction]
fn l_stranger() -> f32 {
    ol_align::DEFAULT_L_STRANGER
}

fn parse_relationship(s: &str) -> PyResult<Relationship> {
    match s.to_ascii_lowercase().as_str() {
        "paired" | "pinned" => Ok(Relationship::Paired),
        "known" | "pending" => Ok(Relationship::Known),
        "stranger" | "rejected" | "unknown" => Ok(Relationship::Stranger),
        other => Err(PyValueError::new_err(format!(
            "unknown relationship tier: {other:?} (expected paired|known|stranger)"
        ))),
    }
}

fn align_err_to_py(err: &AlignError) -> PyErr {
    PyValueError::new_err(err.to_string())
}

/// Register the `align` submodule.
pub(crate) fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", ol_align::VERSION)?;
    m.add_function(wrap_pyfunction!(trust_score, m)?)?;
    m.add_function(wrap_pyfunction!(trust_for, m)?)?;
    m.add_function(wrap_pyfunction!(l_paired, m)?)?;
    m.add_function(wrap_pyfunction!(l_known, m)?)?;
    m.add_function(wrap_pyfunction!(l_stranger, m)?)?;
    Ok(())
}
