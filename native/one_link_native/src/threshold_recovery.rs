//! pyo3 bindings for [`ol_threshold_recovery`].
//!
//! Exposes the Shamir + field-bound recovery primitives to the Python
//! daemon as `one_link_native.threshold_recovery`.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList};

use ol_threshold_recovery::field_bound::{
    field_bound_reconstruct, field_bound_split, field_bound_split_secure, FieldBindingError,
    FieldWitness as InnerWitness,
};
use ol_threshold_recovery::prng::PrngState;
use ol_threshold_recovery::shamir::{
    max_participants, params_valid, reconstruct_bytes, share_bytes, share_bytes_secure, ShareError,
    MAX_SECRET_BYTES,
};

// ── Plain Shamir surface ──────────────────────────────────────────

fn extract_share_streams(streams: &Bound<'_, PyList>) -> PyResult<Vec<Vec<u8>>> {
    let max_shares = max_participants() as usize;
    if streams.len() > max_shares {
        return Err(PyValueError::new_err(format!(
            "at most {max_shares} share streams are supported, got {}",
            streams.len()
        )));
    }
    let mut total = 0usize;
    let mut owned = Vec::with_capacity(streams.len());
    for item in streams.iter() {
        let stream = item.extract::<&[u8]>()?;
        if stream.len() > MAX_SECRET_BYTES {
            return Err(PyValueError::new_err(format!(
                "share stream too large: {} > {MAX_SECRET_BYTES}",
                stream.len()
            )));
        }
        total = total
            .checked_add(stream.len())
            .ok_or_else(|| PyValueError::new_err("share stream byte count overflow"))?;
        if total > MAX_SECRET_BYTES * max_shares {
            return Err(PyValueError::new_err(
                "aggregate share stream budget exceeded",
            ));
        }
        owned.push(stream.to_vec());
    }
    Ok(owned)
}

fn extract_share_indices(indices: &Bound<'_, PyList>) -> PyResult<Vec<usize>> {
    let max_shares = max_participants() as usize;
    if indices.len() > max_shares {
        return Err(PyValueError::new_err(format!(
            "at most {max_shares} share indices are supported, got {}",
            indices.len()
        )));
    }
    indices.iter().map(|item| item.extract::<usize>()).collect()
}

/// Split `secret` into `n` shares with threshold `k`. Returns a list
/// of `n` bytes-objects; share i has length `len(secret)` and is the
/// y-stream of polynomial `p_b(x` = i+1) for each secret byte b.
///
/// `seed` is a 64-bit value the caller supplies for deterministic
/// coefficient generation. Production usage: derive from a hardware
/// RNG or reciprocity-channel hash + monotonic counter.
#[pyfunction]
#[pyo3(signature = (secret, k, n, seed))]
fn shamir_split<'py>(
    py: Python<'py>,
    secret: &[u8],
    k: u32,
    n: u32,
    seed: u64,
) -> PyResult<Vec<Bound<'py, PyBytes>>> {
    let mut state = PrngState::new(seed);
    let streams = share_bytes(secret, k, n, &mut state).map_err(map_share_err)?;
    Ok(streams.into_iter().map(|s| PyBytes::new(py, &s)).collect())
}

/// Production split using fresh operating-system CSPRNG entropy.
#[pyfunction]
#[pyo3(signature = (secret, k, n))]
fn shamir_split_secure<'py>(
    py: Python<'py>,
    secret: &[u8],
    k: u32,
    n: u32,
) -> PyResult<Vec<Bound<'py, PyBytes>>> {
    let streams = share_bytes_secure(secret, k, n).map_err(map_share_err)?;
    Ok(streams
        .into_iter()
        .map(|stream| PyBytes::new(py, &stream))
        .collect())
}

/// Reconstruct a secret from at least `k` shares.
///
/// `xs` is the list of x-values of the supplied shares (each in 1..=255).
/// `streams` is the list of y-byte-streams, parallel to `xs`. All streams
/// must have the same length.
#[pyfunction]
#[pyo3(signature = (xs, streams, k))]
fn shamir_reconstruct<'py>(
    py: Python<'py>,
    xs: &[u8],
    streams: &Bound<'py, PyList>,
    k: u32,
) -> PyResult<Bound<'py, PyBytes>> {
    if xs.len() > max_participants() as usize {
        return Err(PyValueError::new_err("too many x coordinates"));
    }
    let streams = extract_share_streams(streams)?;
    let refs: Vec<&[u8]> = streams.iter().map(Vec::as_slice).collect();
    let recovered = reconstruct_bytes(xs, &refs, k).map_err(map_share_err)?;
    Ok(PyBytes::new(py, &recovered))
}

/// Max participants the (k, n) scheme allows (255 — GF(2^8) limit).
#[pyfunction]
fn shamir_max_participants() -> u32 {
    max_participants()
}

/// Are (k, n) within valid bounds?
#[pyfunction]
fn shamir_params_valid(k: u32, n: u32) -> bool {
    params_valid(k, n)
}

// ── Field-bound surface (alien-tech layer) ────────────────────────

/// A coherence-field witness — public commitment to the field state
/// at mint time. Returned by [`field_bound_split`] alongside the
/// masked shares; required as input to [`field_bound_reconstruct`].
#[pyclass(from_py_object, module = "one_link_native.threshold_recovery", frozen)]
#[derive(Clone)]
struct PyFieldWitness {
    inner: InnerWitness,
}

#[pymethods]
impl PyFieldWitness {
    /// Construct a witness from a 32-byte field seed + per-share field
    /// scores (each in [0, 1]) + a mint epoch (ns since arbitrary epoch).
    #[new]
    #[pyo3(signature = (field_seed, holder_scores, epoch_ns))]
    fn new(field_seed: &[u8], holder_scores: &Bound<'_, PyList>, epoch_ns: u64) -> PyResult<Self> {
        if field_seed.len() != 32 {
            return Err(PyValueError::new_err(format!(
                "field_seed must be 32 bytes, got {}",
                field_seed.len()
            )));
        }
        if holder_scores.len() > max_participants() as usize {
            return Err(PyValueError::new_err(format!(
                "holder_scores supports at most {} entries, got {}",
                max_participants(),
                holder_scores.len()
            )));
        }
        let holder_scores = holder_scores
            .iter()
            .map(|item| item.extract::<f64>())
            .collect::<PyResult<Vec<_>>>()?;
        if let Some(score) = holder_scores
            .iter()
            .copied()
            .find(|score| !score.is_finite() || !(0.0..=1.0).contains(score))
        {
            return Err(PyValueError::new_err(format!(
                "holder score must be finite and in [0, 1], got {score}"
            )));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(field_seed);
        Ok(Self {
            inner: InnerWitness {
                field_seed: seed,
                holder_scores,
                epoch_ns,
            },
        })
    }

    /// Construct a no-op witness: field-binding becomes a passthrough.
    /// For callers without a coherence-field deployment so the same
    /// code path supports both alien-tech AND plain Shamir.
    #[staticmethod]
    fn placeholder(n: usize) -> PyResult<Self> {
        if n > max_participants() as usize {
            return Err(PyValueError::new_err(format!(
                "placeholder supports at most {} holders, got {n}",
                max_participants()
            )));
        }
        Ok(Self {
            inner: InnerWitness::placeholder(n),
        })
    }

    /// Is this a placeholder witness?
    fn is_placeholder(&self) -> bool {
        self.inner.is_placeholder()
    }

    /// The 32-byte field seed.
    fn field_seed<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.field_seed)
    }

    /// Per-holder field scores.
    fn holder_scores(&self) -> Vec<f64> {
        self.inner.holder_scores.clone()
    }

    /// Mint-time epoch.
    fn epoch_ns(&self) -> u64 {
        self.inner.epoch_ns
    }

    fn __repr__(&self) -> String {
        if self.inner.is_placeholder() {
            format!(
                "FieldWitness(placeholder, n={})",
                self.inner.holder_scores.len()
            )
        } else {
            format!(
                "FieldWitness(seed=<redacted>, n={}, epoch_ns={})",
                self.inner.holder_scores.len(),
                self.inner.epoch_ns
            )
        }
    }
}

/// Split `secret` into `n` field-bound shares with threshold `k`.
///
/// Each share-stream is XOR-masked with a one-time pad derived from
/// the witness. Recovery requires the same witness AND at least K
/// masked shares — the K-of-N raw shares alone are useless.
#[pyfunction]
#[pyo3(signature = (secret, k, n, seed, witness))]
fn field_bound_split_py<'py>(
    py: Python<'py>,
    secret: &[u8],
    k: u32,
    n: u32,
    seed: u64,
    witness: &PyFieldWitness,
) -> PyResult<Vec<Bound<'py, PyBytes>>> {
    let mut state = PrngState::new(seed);
    let masked =
        field_bound_split(secret, k, n, &mut state, &witness.inner).map_err(map_field_err)?;
    Ok(masked.into_iter().map(|s| PyBytes::new(py, &s)).collect())
}

/// Production field-bound split using operating-system CSPRNG entropy.
#[pyfunction]
#[pyo3(signature = (secret, k, n, witness))]
fn field_bound_split_secure_py<'py>(
    py: Python<'py>,
    secret: &[u8],
    k: u32,
    n: u32,
    witness: &PyFieldWitness,
) -> PyResult<Vec<Bound<'py, PyBytes>>> {
    let masked = field_bound_split_secure(secret, k, n, &witness.inner).map_err(map_field_err)?;
    Ok(masked
        .into_iter()
        .map(|stream| PyBytes::new(py, &stream))
        .collect())
}

/// Reconstruct from at least K field-bound shares.
///
/// `share_indices` is the 0-based original index of each supplied
/// share (so the right OTP is derived). E.g., when minting with N=5
/// and supplying shares 0, 2, 4 to recover, pass `share_indices=[0,2,4]`.
#[pyfunction]
#[pyo3(signature = (xs, streams, share_indices, k, witness))]
fn field_bound_reconstruct_py<'py>(
    py: Python<'py>,
    xs: &[u8],
    streams: &Bound<'py, PyList>,
    share_indices: &Bound<'py, PyList>,
    k: u32,
    witness: &PyFieldWitness,
) -> PyResult<Bound<'py, PyBytes>> {
    if xs.len() > max_participants() as usize {
        return Err(PyValueError::new_err("too many x coordinates"));
    }
    let streams = extract_share_streams(streams)?;
    let share_indices = extract_share_indices(share_indices)?;
    let refs: Vec<&[u8]> = streams.iter().map(Vec::as_slice).collect();
    let recovered = field_bound_reconstruct(xs, &refs, &share_indices, k, &witness.inner)
        .map_err(map_field_err)?;
    Ok(PyBytes::new(py, &recovered))
}

// ── Error mapping ────────────────────────────────────────────────

fn map_share_err(e: ShareError) -> PyErr {
    PyValueError::new_err(crate::errors::owned_error_message(e))
}

fn map_field_err(e: FieldBindingError) -> PyErr {
    PyValueError::new_err(crate::errors::owned_error_message(e))
}

// ── Module registration ──────────────────────────────────────────

pub fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("MAX_SECRET_BYTES", MAX_SECRET_BYTES)?;
    m.add_class::<PyFieldWitness>()?;
    m.add_function(wrap_pyfunction!(shamir_split, m)?)?;
    m.add_function(wrap_pyfunction!(shamir_split_secure, m)?)?;
    m.add_function(wrap_pyfunction!(shamir_reconstruct, m)?)?;
    m.add_function(wrap_pyfunction!(shamir_max_participants, m)?)?;
    m.add_function(wrap_pyfunction!(shamir_params_valid, m)?)?;
    m.add_function(wrap_pyfunction!(field_bound_split_py, m)?)?;
    m.add_function(wrap_pyfunction!(field_bound_split_secure_py, m)?)?;
    m.add_function(wrap_pyfunction!(field_bound_reconstruct_py, m)?)?;
    // Expose the human-friendly Python names for the field-bound functions.
    let split = m.getattr("field_bound_split_py")?;
    m.add("field_bound_split", split)?;
    let split_secure = m.getattr("field_bound_split_secure_py")?;
    m.add("field_bound_split_secure", split_secure)?;
    let reconstruct = m.getattr("field_bound_reconstruct_py")?;
    m.add("field_bound_reconstruct", reconstruct)?;
    // FieldWitness is the canonical name; alias the class.
    let cls = m.getattr("PyFieldWitness")?;
    m.add("FieldWitness", cls)?;
    Ok(())
}
