//! pyo3 wrapper for [`ol_onion`] — Coherence Mesh F3.
//!
//! Exposes the build + peel surface to the Python daemon so the
//! daemon can construct onion-wrapped messages for multi-hop
//! delivery and act as a relay for inbound onion packets.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use rand_core_06::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use ol_onion::{
    build_cover_packet as core_build_cover_packet, build_onion as core_build_onion,
    is_cover_payload as core_is_cover_payload, pad_packet_to_transport,
    peel_one_layer as core_peel_one_layer, unpad_packet_from_transport, Circuit, HopDescriptor,
    OnionError, OnionPacket, PeelOutcome, COVER_MAGIC, DEFAULT_COVER_BODY_LEN, HOP_ID_LEN,
    MAX_HOPS, MAX_USER_PAYLOAD, TRANSPORT_PAD_HINT,
};

fn map_err(e: OnionError) -> PyErr {
    PyValueError::new_err(e.to_string())
}

fn parse_hop(hop: (Vec<u8>, Vec<u8>)) -> PyResult<HopDescriptor> {
    let (id_bytes, pk_bytes) = hop;
    if id_bytes.len() != HOP_ID_LEN {
        return Err(PyValueError::new_err(format!(
            "hop id must be {HOP_ID_LEN} bytes, got {}",
            id_bytes.len()
        )));
    }
    if pk_bytes.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "hop pubkey must be 32 bytes, got {}",
            pk_bytes.len()
        )));
    }
    let mut id_arr = [0u8; HOP_ID_LEN];
    id_arr.copy_from_slice(&id_bytes);
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    Ok(HopDescriptor::new(id_arr, pk_arr))
}

/// Build an onion packet for a circuit. `circuit` is a list of
/// (hop_id_32_bytes, hop_pubkey_32_bytes) tuples in order from
/// first hop to destination.
#[pyfunction]
fn build_onion<'py>(
    py: Python<'py>,
    circuit: Vec<(Vec<u8>, Vec<u8>)>,
    payload: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let hops: Result<Vec<HopDescriptor>, PyErr> = circuit.into_iter().map(parse_hop).collect();
    let hops = hops?;
    let c = Circuit::new(hops).map_err(map_err)?;
    let packet = core_build_onion(&c, payload, &mut OsRng).map_err(map_err)?;
    Ok(PyBytes::new_bound(py, &packet.encode()))
}

/// Peel one layer of an onion packet at this relay.
///
/// Returns `("forward", next_hop_id_bytes, inner_packet_bytes)` if
/// this relay should forward, or `("deliver", b"", payload_bytes)`
/// if this relay is the destination.
#[pyfunction]
fn peel_one_layer<'py>(
    py: Python<'py>,
    relay_static_sk: &[u8],
    packet_bytes: &[u8],
) -> PyResult<(String, Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    if relay_static_sk.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "relay_static_sk must be 32 bytes, got {}",
            relay_static_sk.len()
        )));
    }
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(relay_static_sk);
    let sk = StaticSecret::from(sk_bytes);
    let packet = OnionPacket::decode(packet_bytes).map_err(map_err)?;
    let outcome = core_peel_one_layer(&sk, &packet).map_err(map_err)?;
    match outcome {
        PeelOutcome::Forward {
            next_hop,
            inner_packet_bytes,
        } => Ok((
            "forward".to_string(),
            PyBytes::new_bound(py, next_hop.as_bytes()),
            PyBytes::new_bound(py, &inner_packet_bytes),
        )),
        PeelOutcome::Deliver { payload } => Ok((
            "deliver".to_string(),
            PyBytes::new_bound(py, &[]),
            PyBytes::new_bound(py, &payload),
        )),
    }
}

/// Compute the public X25519 key for a 32-byte static secret. Helper
/// for daemons that need to publish their relay pubkey.
#[pyfunction]
fn derive_pubkey<'py>(py: Python<'py>, static_sk_bytes: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    if static_sk_bytes.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "static_sk must be 32 bytes, got {}",
            static_sk_bytes.len()
        )));
    }
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(static_sk_bytes);
    let sk = StaticSecret::from(sk_bytes);
    let pk = PublicKey::from(&sk);
    Ok(PyBytes::new_bound(py, pk.as_bytes()))
}

/// Pad a wire-encoded onion packet to TRANSPORT_PAD_HINT bytes.
/// Trailing pad bytes are key-derived from `pad_seed` (must be 32
/// bytes; pass a fresh value per packet).
#[pyfunction]
fn pad_to_transport<'py>(
    py: Python<'py>,
    packet_bytes: &[u8],
    pad_seed: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    if pad_seed.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "pad_seed must be 32 bytes, got {}",
            pad_seed.len()
        )));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(pad_seed);
    let out = pad_packet_to_transport(packet_bytes, &seed).map_err(map_err)?;
    Ok(PyBytes::new_bound(py, &out))
}

/// Strip transport padding from a TRANSPORT_PAD_HINT-byte input,
/// returning the original onion-packet wire bytes.
#[pyfunction]
fn unpad_from_transport<'py>(
    py: Python<'py>,
    padded_bytes: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let out = unpad_packet_from_transport(padded_bytes).map_err(map_err)?;
    Ok(PyBytes::new_bound(py, &out))
}

/// D05 — Build a cover-traffic onion packet for `circuit`. Returns
/// the same fixed-size on-wire bytes as a real packet of equivalent
/// shape; the innermost plaintext starts with `COVER_MAGIC` so the
/// destination can silently drop it.
///
/// `body_len = 0` uses the default body length (256 bytes).
#[pyfunction]
#[pyo3(signature = (circuit, body_len = 0))]
fn build_cover_packet<'py>(
    py: Python<'py>,
    circuit: Vec<(Vec<u8>, Vec<u8>)>,
    body_len: usize,
) -> PyResult<Bound<'py, PyBytes>> {
    let hops: Result<Vec<HopDescriptor>, PyErr> = circuit.into_iter().map(parse_hop).collect();
    let hops = hops?;
    let c = Circuit::new(hops).map_err(map_err)?;
    let body = if body_len == 0 {
        DEFAULT_COVER_BODY_LEN
    } else {
        body_len
    };
    let packet = core_build_cover_packet(&c, body, &mut OsRng).map_err(map_err)?;
    Ok(PyBytes::new_bound(py, &packet.encode()))
}

/// D05 — Check whether a decrypted innermost payload is a cover
/// packet (starts with COVER_MAGIC). Destinations call this and
/// silently drop cover packets before any application processing.
#[pyfunction]
fn is_cover_payload(payload: &[u8]) -> bool {
    core_is_cover_payload(payload)
}

pub fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(build_onion, m)?)?;
    m.add_function(wrap_pyfunction!(peel_one_layer, m)?)?;
    m.add_function(wrap_pyfunction!(derive_pubkey, m)?)?;
    m.add_function(wrap_pyfunction!(pad_to_transport, m)?)?;
    m.add_function(wrap_pyfunction!(unpad_from_transport, m)?)?;
    m.add_function(wrap_pyfunction!(build_cover_packet, m)?)?;
    m.add_function(wrap_pyfunction!(is_cover_payload, m)?)?;
    m.add("MAX_HOPS", MAX_HOPS)?;
    m.add("MAX_USER_PAYLOAD", MAX_USER_PAYLOAD)?;
    m.add("HOP_ID_LEN", HOP_ID_LEN)?;
    m.add("TRANSPORT_PAD_HINT", TRANSPORT_PAD_HINT)?;
    m.add("DEFAULT_COVER_BODY_LEN", DEFAULT_COVER_BODY_LEN)?;
    m.add("COVER_MAGIC", PyBytes::new_bound(_py, &COVER_MAGIC))?;
    Ok(())
}
