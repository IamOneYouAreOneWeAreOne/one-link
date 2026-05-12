//! pyo3 wrapper for [`ol_proximity_pair`] — Coherence Mesh F1.4.
//!
//! Exposes the 4-stage channel-reciprocity pipeline to the Python
//! daemon: quantize / reconcile / amplify, plus the multi-pass driver
//! and the convenience one-shot `derive_factor2_secret`.
//!
//! The daemon supplies the OBSERVATIONS (WiFi/BLE/mDNS scan results);
//! this layer crunches them to a 256-bit Factor-2 secret.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use ol_proximity_pair::{
    block_syndrome, derive_factor2_secret, hamming_reconcile,
    multi_pass_reconcile, multi_pass_syndromes, parity_bits_for_string,
    permutation_for_pass, privacy_amplify, quantize_observations,
    reconcile_with_syndrome, PairError, PipelineConfig, QuantizeConfig,
    AMPLIFIED_KEY_BYTES, CASCADE_PASSES_DEFAULT, GUARD_BAND_DEFAULT,
    HAMMING_CODEWORD_BITS, HAMMING_DATA_BITS, HAMMING_PARITY_BITS,
    OBSERVATION_BYTES_DEFAULT, SYNDROME_BLOCK_BITS_DEFAULT,
};

// ── Stage 1+2: Quantization ───────────────────────────────────────

/// Quantize an observation byte vector to a packed bit string
/// (one bit per byte, value 0 or 1). Observations inside the
/// guard band are skipped.
#[pyfunction]
#[pyo3(signature = (observations, min_bytes = OBSERVATION_BYTES_DEFAULT, guard_band = GUARD_BAND_DEFAULT))]
fn py_quantize_observations<'py>(
    py: Python<'py>,
    observations: &[u8],
    min_bytes: usize,
    guard_band: f64,
) -> PyResult<Bound<'py, PyBytes>> {
    let cfg = QuantizeConfig {
        min_bytes,
        guard_band,
    };
    let bits = quantize_observations(observations, &cfg).map_err(map_err)?;
    Ok(PyBytes::new_bound(py, &bits))
}

// ── Stage 3: Reconciliation ───────────────────────────────────────

/// Compute the block-syndrome of a bit string. Each byte of the
/// returned syndrome is the XOR-parity of one block of `block_bits`
/// bits from the input.
#[pyfunction]
#[pyo3(signature = (bits, block_bits = SYNDROME_BLOCK_BITS_DEFAULT))]
fn py_block_syndrome<'py>(
    py: Python<'py>,
    bits: &[u8],
    block_bits: usize,
) -> Bound<'py, PyBytes> {
    let s = block_syndrome(bits, block_bits);
    PyBytes::new_bound(py, &s)
}

/// One-pass reconciliation: flip bit 0 of each block where my parity
/// disagrees with peer's. Bandwidth-cheap but doesn't drive error
/// rate to zero; use [`py_multi_pass_reconcile`] for better results.
#[pyfunction]
#[pyo3(signature = (my_bits, peer_syndrome, block_bits = SYNDROME_BLOCK_BITS_DEFAULT))]
fn py_reconcile_with_syndrome<'py>(
    py: Python<'py>,
    my_bits: &[u8],
    peer_syndrome: &[u8],
    block_bits: usize,
) -> Bound<'py, PyBytes> {
    let r = reconcile_with_syndrome(my_bits, peer_syndrome, block_bits);
    PyBytes::new_bound(py, &r)
}

/// Multi-pass syndromes (one per CASCADE pass). The peer ships
/// these to the receiver via the public bootstrap channel.
#[pyfunction]
#[pyo3(signature = (my_bits, block_bits = SYNDROME_BLOCK_BITS_DEFAULT, passes = CASCADE_PASSES_DEFAULT, permutation_seed = 0))]
fn py_multi_pass_syndromes<'py>(
    py: Python<'py>,
    my_bits: &[u8],
    block_bits: usize,
    passes: usize,
    permutation_seed: u64,
) -> Vec<Bound<'py, PyBytes>> {
    multi_pass_syndromes(my_bits, block_bits, passes, permutation_seed)
        .into_iter()
        .map(|s| PyBytes::new_bound(py, &s))
        .collect()
}

/// Multi-pass reconciliation driver. Permutes between passes per
/// `permutation_seed` so both sides need the same seed.
#[pyfunction]
#[pyo3(signature = (my_bits, peer_syndromes, block_bits = SYNDROME_BLOCK_BITS_DEFAULT, passes = CASCADE_PASSES_DEFAULT, permutation_seed = 0))]
fn py_multi_pass_reconcile<'py>(
    py: Python<'py>,
    my_bits: &[u8],
    peer_syndromes: Vec<Vec<u8>>,
    block_bits: usize,
    passes: usize,
    permutation_seed: u64,
) -> Bound<'py, PyBytes> {
    let syndromes: Vec<Vec<u8>> = peer_syndromes;
    let r = multi_pass_reconcile(
        my_bits,
        &syndromes,
        block_bits,
        passes,
        permutation_seed,
    );
    PyBytes::new_bound(py, &r)
}

/// Deterministic Fisher-Yates permutation. Surfaced so the daemon
/// can verify both sides derive the same permutation from the same
/// seed.
#[pyfunction]
#[pyo3(signature = (seed, pass_idx, n))]
fn py_permutation_for_pass(seed: u64, pass_idx: usize, n: usize) -> Vec<usize> {
    permutation_for_pass(seed, pass_idx, n)
}

// ── Stage 3b: Hamming(127,120) SEC reconciliation ────────────────

/// Compute Hamming(127,120) parity bits for an entire bit string.
/// Block size = 120 data bits; 7 parity bits per block. Last partial
/// block is zero-padded internally.
#[pyfunction]
fn py_hamming_parity<'py>(
    py: Python<'py>,
    bits: &[u8],
) -> Bound<'py, PyBytes> {
    let p = parity_bits_for_string(bits);
    PyBytes::new_bound(py, &p)
}

/// One-pass Hamming reconciliation. Corrects up to 1 error per
/// 120-bit block (mathematically certain for the 1-error case;
/// miscorrects 2+ error blocks — combine with multi-pass +
/// permutation for those).
#[pyfunction]
fn py_hamming_reconcile<'py>(
    py: Python<'py>,
    my_bits: &[u8],
    peer_parity: &[u8],
) -> Bound<'py, PyBytes> {
    let r = hamming_reconcile(my_bits, peer_parity);
    PyBytes::new_bound(py, &r)
}

// ── Stage 4: Privacy Amplification ────────────────────────────────

/// BLAKE3-keyed privacy amplification. Hashes reconciled bits down
/// to 32 bytes. Salt MUST be 32 bytes; both sides must use the same
/// salt (typically transcript-hash of the Factor-1 QR scan).
#[pyfunction]
#[pyo3(signature = (reconciled_bits, salt))]
fn py_privacy_amplify<'py>(
    py: Python<'py>,
    reconciled_bits: &[u8],
    salt: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    if salt.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "salt must be 32 bytes, got {}",
            salt.len()
        )));
    }
    let mut salt_arr = [0u8; 32];
    salt_arr.copy_from_slice(salt);
    let key = privacy_amplify(reconciled_bits, &salt_arr);
    Ok(PyBytes::new_bound(py, &key))
}

// ── Convenience: one-shot full pipeline ──────────────────────────

/// Run the FULL pipeline: quantize → reconcile (one-pass) → amplify.
/// Returns the 32-byte Factor-2 secret.
#[pyfunction]
#[pyo3(signature = (my_observations, peer_syndrome, salt, min_bytes = OBSERVATION_BYTES_DEFAULT, guard_band = GUARD_BAND_DEFAULT, block_bits = SYNDROME_BLOCK_BITS_DEFAULT))]
fn py_derive_factor2_secret<'py>(
    py: Python<'py>,
    my_observations: &[u8],
    peer_syndrome: &[u8],
    salt: &[u8],
    min_bytes: usize,
    guard_band: f64,
    block_bits: usize,
) -> PyResult<Bound<'py, PyBytes>> {
    if salt.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "salt must be 32 bytes, got {}",
            salt.len()
        )));
    }
    let mut salt_arr = [0u8; 32];
    salt_arr.copy_from_slice(salt);
    let cfg = PipelineConfig {
        quantize: QuantizeConfig {
            min_bytes,
            guard_band,
        },
        syndrome_block_bits: block_bits,
        amplify_salt: salt_arr,
    };
    let key =
        derive_factor2_secret(my_observations, peer_syndrome, &cfg).map_err(map_err)?;
    Ok(PyBytes::new_bound(py, &key))
}

fn map_err(e: PairError) -> PyErr {
    PyValueError::new_err(e.to_string())
}

// ── Module registration ──────────────────────────────────────────

pub fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_quantize_observations, m)?)?;
    m.add_function(wrap_pyfunction!(py_block_syndrome, m)?)?;
    m.add_function(wrap_pyfunction!(py_reconcile_with_syndrome, m)?)?;
    m.add_function(wrap_pyfunction!(py_multi_pass_syndromes, m)?)?;
    m.add_function(wrap_pyfunction!(py_multi_pass_reconcile, m)?)?;
    m.add_function(wrap_pyfunction!(py_permutation_for_pass, m)?)?;
    m.add_function(wrap_pyfunction!(py_hamming_parity, m)?)?;
    m.add_function(wrap_pyfunction!(py_hamming_reconcile, m)?)?;
    m.add_function(wrap_pyfunction!(py_privacy_amplify, m)?)?;
    m.add_function(wrap_pyfunction!(py_derive_factor2_secret, m)?)?;
    // Friendly names: alias each py_* to its short name.
    for (short, long) in &[
        ("quantize_observations", "py_quantize_observations"),
        ("block_syndrome", "py_block_syndrome"),
        ("reconcile_with_syndrome", "py_reconcile_with_syndrome"),
        ("multi_pass_syndromes", "py_multi_pass_syndromes"),
        ("multi_pass_reconcile", "py_multi_pass_reconcile"),
        ("permutation_for_pass", "py_permutation_for_pass"),
        ("hamming_parity", "py_hamming_parity"),
        ("hamming_reconcile", "py_hamming_reconcile"),
        ("privacy_amplify", "py_privacy_amplify"),
        ("derive_factor2_secret", "py_derive_factor2_secret"),
    ] {
        let f = m.getattr(*long)?;
        m.add(*short, f)?;
    }
    // Constants.
    m.add("AMPLIFIED_KEY_BYTES", AMPLIFIED_KEY_BYTES)?;
    m.add("OBSERVATION_BYTES_DEFAULT", OBSERVATION_BYTES_DEFAULT)?;
    m.add("GUARD_BAND_DEFAULT", GUARD_BAND_DEFAULT)?;
    m.add("SYNDROME_BLOCK_BITS_DEFAULT", SYNDROME_BLOCK_BITS_DEFAULT)?;
    m.add("CASCADE_PASSES_DEFAULT", CASCADE_PASSES_DEFAULT)?;
    m.add("HAMMING_CODEWORD_BITS", HAMMING_CODEWORD_BITS)?;
    m.add("HAMMING_DATA_BITS", HAMMING_DATA_BITS)?;
    m.add("HAMMING_PARITY_BITS", HAMMING_PARITY_BITS)?;
    Ok(())
}
