//! pyo3 wrapper for `ol_onion::sphinx` — Sphinx Coherence layer.
//!
//! Exposes:
//! - Standard Sphinx (Ristretto255 alpha blinding): `generate_keypair`,
//!   `build_sphinx`, `peel_sphinx`.
//! - PQ-hybrid (ML-KEM-768 mixed at entry hop): `generate_pq_keypair`,
//!   `build_pq_sphinx`, `peel_pq_sphinx_entry`, `peel_pq_sphinx_intermediate`.
//! - Helpers: `derive_pubkey_from_scalar`.
//!
//! Field-bound binding is a derive-time concern handled internally
//! when `derive_hop_keys_with_witness` is wired into the build/peel
//! paths. The daemon supplies the witness via the existing build/peel
//! arguments (future extension).

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand_core_06::OsRng;

use ol_onion::sphinx::core::{
    build_sphinx_onion as core_build, generate_static_keypair as core_keypair,
    peel_sphinx_layer as core_peel, SphinxHop, SphinxPacket, SphinxPeelOutcome,
    SPHINX_MAX_USER_PAYLOAD, SPHINX_PACKET_LEN,
};
use ol_onion::sphinx::pq::{
    build_pq_sphinx_onion as pq_build, generate_pq_keypair as pq_keypair,
    peel_pq_sphinx_entry as pq_peel_entry, peel_pq_sphinx_intermediate as pq_peel_intermediate,
    PqSphinxHop, PqSphinxPacket, PqSphinxPeelOutcome, ML_KEM_CT_LEN, ML_KEM_EK_LEN,
    PQ_SPHINX_PACKET_LEN,
};
use ol_onion::sphinx::primitives::MAX_HOPS;
use ol_onion::{HopId, OnionError, HOP_ID_LEN};

// ── Helpers ──────────────────────────────────────────────────────

fn map_err(e: OnionError) -> PyErr {
    PyValueError::new_err(e.to_string())
}

fn scalar_from_bytes(b: &[u8]) -> PyResult<Scalar> {
    if b.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "scalar must be 32 bytes, got {}",
            b.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(b);
    Ok(Scalar::from_bytes_mod_order(arr))
}

fn point_from_bytes(b: &[u8]) -> PyResult<RistrettoPoint> {
    if b.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "Ristretto255 point must be 32 bytes, got {}",
            b.len()
        )));
    }
    CompressedRistretto::from_slice(b)
        .map_err(|_| PyValueError::new_err("invalid Ristretto255 point"))?
        .decompress()
        .ok_or_else(|| PyValueError::new_err("Ristretto255 point not on curve"))
}

fn hop_id_from_bytes(b: &[u8]) -> PyResult<HopId> {
    if b.len() != HOP_ID_LEN {
        return Err(PyValueError::new_err(format!(
            "hop_id must be {HOP_ID_LEN} bytes, got {}",
            b.len()
        )));
    }
    let mut arr = [0u8; HOP_ID_LEN];
    arr.copy_from_slice(b);
    Ok(HopId::from_bytes(arr))
}

fn parse_circuit(
    circuit: Vec<(Vec<u8>, Vec<u8>)>,
) -> PyResult<Vec<SphinxHop>> {
    let mut hops = Vec::with_capacity(circuit.len());
    for (id_bytes, pk_bytes) in circuit {
        let id = hop_id_from_bytes(&id_bytes)?;
        let pk = point_from_bytes(&pk_bytes)?;
        hops.push(SphinxHop {
            id,
            static_pk: pk,
        });
    }
    Ok(hops)
}

fn parse_pq_circuit(
    circuit: Vec<(Vec<u8>, Vec<u8>, Option<Vec<u8>>)>,
) -> PyResult<Vec<PqSphinxHop>> {
    let mut hops = Vec::with_capacity(circuit.len());
    for (id_bytes, x_pk_bytes, pq_pk_bytes) in circuit {
        let id = hop_id_from_bytes(&id_bytes)?;
        let x_pk = point_from_bytes(&x_pk_bytes)?;
        let pq_pk = match pq_pk_bytes {
            Some(b) => {
                if b.len() != ML_KEM_EK_LEN {
                    return Err(PyValueError::new_err(format!(
                        "ML-KEM pubkey must be {ML_KEM_EK_LEN} bytes, got {}",
                        b.len()
                    )));
                }
                use hybrid_array::Array;
                type EkSize = <<MlKem768 as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize;
                let arr: Array<u8, EkSize> = Array::try_from(b.as_slice())
                    .map_err(|_| PyValueError::new_err("ML-KEM pubkey size mismatch"))?;
                let ek = <<MlKem768 as KemCore>::EncapsulationKey as EncodedSizeUser>::from_bytes(&arr);
                Some(ek)
            }
            None => None,
        };
        hops.push(PqSphinxHop {
            id,
            static_x_pk: x_pk,
            static_pq_pk: pq_pk,
        });
    }
    Ok(hops)
}

fn parse_pq_dk(b: &[u8]) -> PyResult<<MlKem768 as KemCore>::DecapsulationKey> {
    use hybrid_array::Array;
    type DkSize = <<MlKem768 as KemCore>::DecapsulationKey as EncodedSizeUser>::EncodedSize;
    let arr: Array<u8, DkSize> = Array::try_from(b)
        .map_err(|_| PyValueError::new_err("ML-KEM decap key size mismatch"))?;
    Ok(<<MlKem768 as KemCore>::DecapsulationKey as EncodedSizeUser>::from_bytes(&arr))
}

// ── Standard Sphinx wrappers ─────────────────────────────────────

/// Generate a fresh Ristretto255 keypair. Returns (sk_bytes, pk_bytes)
/// where sk is a 32-byte scalar and pk is a 32-byte compressed point.
#[pyfunction]
fn generate_keypair<'py>(
    py: Python<'py>,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (sk, pk) = core_keypair(&mut OsRng);
    Ok((
        PyBytes::new_bound(py, sk.as_bytes()),
        PyBytes::new_bound(py, &pk.compress().to_bytes()),
    ))
}

/// Derive the public key from a 32-byte scalar (Ristretto basepoint mult).
#[pyfunction]
fn derive_pubkey_from_scalar<'py>(
    py: Python<'py>,
    sk_bytes: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let sk = scalar_from_bytes(sk_bytes)?;
    let pk = &sk * curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
    Ok(PyBytes::new_bound(py, &pk.compress().to_bytes()))
}

/// Build a standard Sphinx packet for `circuit`.
///
/// `eph_sk_bytes`: 32-byte ephemeral scalar (fresh per circuit).
/// `circuit`: list of (hop_id_32, pubkey_32) tuples ordered first→destination.
/// `payload`: up to SPHINX_MAX_USER_PAYLOAD bytes.
///
/// Returns the fixed-size SPHINX_PACKET_LEN wire bytes.
#[pyfunction]
fn build_sphinx<'py>(
    py: Python<'py>,
    eph_sk_bytes: &[u8],
    circuit: Vec<(Vec<u8>, Vec<u8>)>,
    payload: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let eph_sk = scalar_from_bytes(eph_sk_bytes)?;
    let hops = parse_circuit(circuit)?;
    let packet = core_build(&eph_sk, &hops, payload, &mut OsRng).map_err(map_err)?;
    Ok(PyBytes::new_bound(py, packet.as_bytes()))
}

/// Peel one Sphinx layer.
///
/// Returns `("forward", next_hop_id_32, inner_packet_bytes)` if the
/// caller should forward, or `("deliver", b"", payload)` if this
/// relay is the destination.
#[pyfunction]
fn peel_sphinx<'py>(
    py: Python<'py>,
    relay_sk_bytes: &[u8],
    packet_bytes: &[u8],
) -> PyResult<(String, Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let relay_sk = scalar_from_bytes(relay_sk_bytes)?;
    let packet = SphinxPacket::from_bytes(packet_bytes).map_err(map_err)?;
    let outcome = core_peel(&relay_sk, &packet).map_err(map_err)?;
    match outcome {
        SphinxPeelOutcome::Forward {
            next_hop,
            next_packet,
        } => Ok((
            "forward".to_string(),
            PyBytes::new_bound(py, next_hop.as_bytes()),
            PyBytes::new_bound(py, next_packet.as_bytes()),
        )),
        SphinxPeelOutcome::Deliver { payload } => Ok((
            "deliver".to_string(),
            PyBytes::new_bound(py, &[]),
            PyBytes::new_bound(py, &payload),
        )),
    }
}

// ── PQ-hybrid Sphinx wrappers ────────────────────────────────────

/// Generate a fresh ML-KEM-768 keypair. Returns (dk_bytes, ek_bytes)
/// where dk is the 2400-byte decapsulation key and ek is the
/// 1184-byte encapsulation key.
#[pyfunction]
fn generate_pq_keypair<'py>(
    py: Python<'py>,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (dk, ek) = pq_keypair(&mut OsRng);
    let dk_bytes = dk.as_bytes();
    let ek_bytes = ek.as_bytes();
    Ok((
        PyBytes::new_bound(py, dk_bytes.as_slice()),
        PyBytes::new_bound(py, ek_bytes.as_slice()),
    ))
}

/// Build a PQ-hybrid Sphinx packet.
///
/// `circuit`: list of (hop_id_32, x25519_pk_32, pq_pk_1184_or_None).
/// The FIRST hop MUST supply a PQ pubkey; downstream hops may pass None.
#[pyfunction]
fn build_pq_sphinx<'py>(
    py: Python<'py>,
    eph_sk_bytes: &[u8],
    circuit: Vec<(Vec<u8>, Vec<u8>, Option<Vec<u8>>)>,
    payload: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let eph_sk = scalar_from_bytes(eph_sk_bytes)?;
    let hops = parse_pq_circuit(circuit)?;
    let packet = pq_build(&eph_sk, &hops, payload, &mut OsRng).map_err(map_err)?;
    Ok(PyBytes::new_bound(py, packet.as_bytes()))
}

/// Peel a PQ-hybrid Sphinx packet at the ENTRY relay (decapsulates
/// the carried ML-KEM ciphertext).
#[pyfunction]
fn peel_pq_sphinx_entry<'py>(
    py: Python<'py>,
    relay_x_sk_bytes: &[u8],
    relay_pq_dk_bytes: &[u8],
    packet_bytes: &[u8],
) -> PyResult<(String, Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let x_sk = scalar_from_bytes(relay_x_sk_bytes)?;
    let pq_dk = parse_pq_dk(relay_pq_dk_bytes)?;
    let packet = PqSphinxPacket::from_bytes(packet_bytes).map_err(map_err)?;
    let outcome = pq_peel_entry(&x_sk, &pq_dk, &packet).map_err(map_err)?;
    match outcome {
        PqSphinxPeelOutcome::Forward {
            next_hop,
            next_packet,
        } => Ok((
            "forward".to_string(),
            PyBytes::new_bound(py, next_hop.as_bytes()),
            PyBytes::new_bound(py, next_packet.as_bytes()),
        )),
        PqSphinxPeelOutcome::Deliver { payload } => Ok((
            "deliver".to_string(),
            PyBytes::new_bound(py, &[]),
            PyBytes::new_bound(py, &payload),
        )),
    }
}

/// Peel a PQ-hybrid Sphinx packet at a downstream/intermediate relay
/// (uses classical Ristretto255 derivation; ignores the carried
/// ML-KEM ciphertext).
#[pyfunction]
fn peel_pq_sphinx_intermediate<'py>(
    py: Python<'py>,
    relay_x_sk_bytes: &[u8],
    packet_bytes: &[u8],
) -> PyResult<(String, Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let x_sk = scalar_from_bytes(relay_x_sk_bytes)?;
    let packet = PqSphinxPacket::from_bytes(packet_bytes).map_err(map_err)?;
    let outcome = pq_peel_intermediate(&x_sk, &packet).map_err(map_err)?;
    match outcome {
        PqSphinxPeelOutcome::Forward {
            next_hop,
            next_packet,
        } => Ok((
            "forward".to_string(),
            PyBytes::new_bound(py, next_hop.as_bytes()),
            PyBytes::new_bound(py, next_packet.as_bytes()),
        )),
        PqSphinxPeelOutcome::Deliver { payload } => Ok((
            "deliver".to_string(),
            PyBytes::new_bound(py, &[]),
            PyBytes::new_bound(py, &payload),
        )),
    }
}

// ── Registration ─────────────────────────────────────────────────

pub fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(derive_pubkey_from_scalar, m)?)?;
    m.add_function(wrap_pyfunction!(build_sphinx, m)?)?;
    m.add_function(wrap_pyfunction!(peel_sphinx, m)?)?;
    m.add_function(wrap_pyfunction!(generate_pq_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(build_pq_sphinx, m)?)?;
    m.add_function(wrap_pyfunction!(peel_pq_sphinx_entry, m)?)?;
    m.add_function(wrap_pyfunction!(peel_pq_sphinx_intermediate, m)?)?;
    m.add("HOP_ID_LEN", HOP_ID_LEN)?;
    m.add("MAX_HOPS", MAX_HOPS)?;
    m.add("SPHINX_MAX_USER_PAYLOAD", SPHINX_MAX_USER_PAYLOAD)?;
    m.add("SPHINX_PACKET_LEN", SPHINX_PACKET_LEN)?;
    m.add("PQ_SPHINX_PACKET_LEN", PQ_SPHINX_PACKET_LEN)?;
    m.add("ML_KEM_CT_LEN", ML_KEM_CT_LEN)?;
    m.add("ML_KEM_EK_LEN", ML_KEM_EK_LEN)?;
    Ok(())
}
