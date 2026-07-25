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
use pyo3::types::{PyBytes, PyList, PyTuple};

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use hybrid_array::Array;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand_core_06::OsRng;

type MlKemEncapsulationKeySize =
    <<MlKem768 as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize;
type MlKemDecapsulationKeySize =
    <<MlKem768 as KemCore>::DecapsulationKey as EncodedSizeUser>::EncodedSize;

use ol_onion::sphinx::core::{
    build_sphinx_onion as core_build, generate_static_keypair as core_keypair,
    peel_sphinx_layer as core_peel, SphinxHop, SphinxPacket, SphinxPeelOutcome,
    SPHINX_MAX_USER_PAYLOAD, SPHINX_PACKET_LEN,
};
// Audit M4: `is_cover_payload` (plaintext-prefix check) is deprecated
// in favor of the authenticated trailer check. We keep exporting it
// to Python as a fast-path / backwards-compat probe but the
// authenticated variant is the production-correct API.
#[allow(deprecated)]
use ol_onion::sphinx::cover::is_cover_payload as cover_is_sentinel;
use ol_onion::sphinx::cover::{
    build_cover_packet as cover_build, is_cover_payload_authenticated as cover_is_auth,
    CoverScheduler, RateEqualizer, COVER_DEFAULT_RATE_HZ, COVER_MAX_RATE_HZ, COVER_MIN_RATE_HZ,
    COVER_PAYLOAD_MIN, COVER_SENTINEL, COVER_TRAILER_LEN, RATE_EQ_DEFAULT_HALF_LIFE_SEC,
    RATE_EQ_MAX_HALF_LIFE_SEC,
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
    PyValueError::new_err(crate::errors::owned_error_message(e))
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
    let scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(arr))
        .ok_or_else(|| PyValueError::new_err("scalar encoding is non-canonical"))?;
    if scalar == Scalar::ZERO {
        return Err(PyValueError::new_err("scalar must be non-zero"));
    }
    Ok(scalar)
}

fn point_from_bytes(b: &[u8]) -> PyResult<RistrettoPoint> {
    if b.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "Ristretto255 point must be 32 bytes, got {}",
            b.len()
        )));
    }
    let point = CompressedRistretto::from_slice(b)
        .map_err(|_| PyValueError::new_err("invalid Ristretto255 point"))?
        .decompress()
        .ok_or_else(|| PyValueError::new_err("Ristretto255 point not on curve"))?;
    if point == RistrettoPoint::identity() {
        return Err(PyValueError::new_err(
            "Ristretto255 identity point rejected",
        ));
    }
    Ok(point)
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

fn parse_circuit(circuit: &Bound<'_, PyList>) -> PyResult<Vec<SphinxHop>> {
    if circuit.is_empty() || circuit.len() > MAX_HOPS {
        return Err(PyValueError::new_err(format!(
            "circuit must contain 1..={MAX_HOPS} hops, got {}",
            circuit.len()
        )));
    }
    let mut hops = Vec::with_capacity(circuit.len());
    for item in circuit.iter() {
        let tuple = item
            .cast::<PyTuple>()
            .map_err(|_| PyValueError::new_err("each circuit hop must be a 2-tuple"))?;
        if tuple.len() != 2 {
            return Err(PyValueError::new_err(
                "each circuit hop must contain exactly (hop_id, public_key)",
            ));
        }
        let id_item = tuple.get_item(0)?;
        let pk_item = tuple.get_item(1)?;
        let id = hop_id_from_bytes(id_item.extract::<&[u8]>()?)?;
        let pk = point_from_bytes(pk_item.extract::<&[u8]>()?)?;
        hops.push(SphinxHop { id, static_pk: pk });
    }
    Ok(hops)
}

fn parse_pq_circuit(circuit: &Bound<'_, PyList>) -> PyResult<Vec<PqSphinxHop>> {
    if circuit.is_empty() || circuit.len() > MAX_HOPS {
        return Err(PyValueError::new_err(format!(
            "circuit must contain 1..={MAX_HOPS} hops, got {}",
            circuit.len()
        )));
    }
    let mut hops = Vec::with_capacity(circuit.len());
    for item in circuit.iter() {
        let tuple = item
            .cast::<PyTuple>()
            .map_err(|_| PyValueError::new_err("each PQ circuit hop must be a 3-tuple"))?;
        if tuple.len() != 3 {
            return Err(PyValueError::new_err(
                "each PQ circuit hop must contain exactly (hop_id, public_key, pq_public_key_or_none)",
            ));
        }
        let id_item = tuple.get_item(0)?;
        let x_pk_item = tuple.get_item(1)?;
        let pq_pk_item = tuple.get_item(2)?;
        let id = hop_id_from_bytes(id_item.extract::<&[u8]>()?)?;
        let x_pk = point_from_bytes(x_pk_item.extract::<&[u8]>()?)?;
        let pq_pk = if pq_pk_item.is_none() {
            None
        } else {
            let b = pq_pk_item.extract::<&[u8]>()?;
            if b.len() != ML_KEM_EK_LEN {
                return Err(PyValueError::new_err(format!(
                    "ML-KEM pubkey must be {ML_KEM_EK_LEN} bytes, got {}",
                    b.len()
                )));
            }
            let arr: Array<u8, MlKemEncapsulationKeySize> = Array::try_from(b)
                .map_err(|_| PyValueError::new_err("ML-KEM pubkey size mismatch"))?;
            let ek = <<MlKem768 as KemCore>::EncapsulationKey as EncodedSizeUser>::from_bytes(&arr);
            Some(ek)
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
    let arr: Array<u8, MlKemDecapsulationKeySize> =
        Array::try_from(b).map_err(|_| PyValueError::new_err("ML-KEM decap key size mismatch"))?;
    Ok(<<MlKem768 as KemCore>::DecapsulationKey as EncodedSizeUser>::from_bytes(&arr))
}

// ── Standard Sphinx wrappers ─────────────────────────────────────

/// Generate a fresh Ristretto255 keypair. Returns (`sk_bytes`, `pk_bytes`)
/// where sk is a 32-byte scalar and pk is a 32-byte compressed point.
#[pyfunction]
fn generate_keypair(py: Python<'_>) -> (Bound<'_, PyBytes>, Bound<'_, PyBytes>) {
    let (sk, pk) = core_keypair(&mut OsRng);
    (
        PyBytes::new(py, sk.as_bytes()),
        PyBytes::new(py, &pk.compress().to_bytes()),
    )
}

/// Derive the public key from a 32-byte scalar (Ristretto basepoint mult).
#[pyfunction]
fn derive_pubkey_from_scalar<'py>(
    py: Python<'py>,
    sk_bytes: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let sk = scalar_from_bytes(sk_bytes)?;
    let pk = &sk * curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
    Ok(PyBytes::new(py, &pk.compress().to_bytes()))
}

/// Build a standard Sphinx packet for `circuit`.
///
/// `eph_sk_bytes`: 32-byte ephemeral scalar (fresh per circuit).
/// `circuit`: list of (`hop_id_32`, `pubkey_32`) tuples ordered first→destination.
/// `payload`: up to `SPHINX_MAX_USER_PAYLOAD` bytes.
///
/// Returns the fixed-size `SPHINX_PACKET_LEN` wire bytes.
#[pyfunction]
fn build_sphinx<'py>(
    py: Python<'py>,
    eph_sk_bytes: &[u8],
    circuit: &Bound<'py, PyList>,
    payload: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let eph_sk = scalar_from_bytes(eph_sk_bytes)?;
    let hops = parse_circuit(circuit)?;
    let packet = core_build(&eph_sk, &hops, payload, &mut OsRng).map_err(map_err)?;
    Ok(PyBytes::new(py, packet.as_bytes()))
}

/// Peel one Sphinx layer.
///
/// Returns:
///   - `("forward", next_hop_id_32, inner_packet_bytes)` — forward
///     to next relay.
///   - `("deliver", b"", payload)` — this relay is the destination;
///     deliver the payload to the app.
///   - `("cover", b"", b"")` — audit M4: this relay is the
///     destination AND the payload's authenticated cover trailer
///     verified. Drop silently without surfacing to the app.
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
            PyBytes::new(py, next_hop.as_bytes()),
            PyBytes::new(py, next_packet.as_bytes()),
        )),
        SphinxPeelOutcome::Deliver { payload } => Ok((
            "deliver".to_string(),
            PyBytes::new(py, &[]),
            PyBytes::new(py, &payload),
        )),
        SphinxPeelOutcome::Cover => Ok((
            "cover".to_string(),
            PyBytes::new(py, &[]),
            PyBytes::new(py, &[]),
        )),
    }
}

// ── PQ-hybrid Sphinx wrappers ────────────────────────────────────

/// Generate a fresh ML-KEM-768 keypair. Returns (`dk_bytes`, `ek_bytes`)
/// where dk is the 2400-byte decapsulation key and ek is the
/// 1184-byte encapsulation key.
#[pyfunction]
fn generate_pq_keypair(py: Python<'_>) -> (Bound<'_, PyBytes>, Bound<'_, PyBytes>) {
    let (dk, ek) = pq_keypair(&mut OsRng);
    let dk_bytes = dk.as_bytes();
    let ek_bytes = ek.as_bytes();
    (
        PyBytes::new(py, dk_bytes.as_slice()),
        PyBytes::new(py, ek_bytes.as_slice()),
    )
}

/// Build a PQ-hybrid Sphinx packet.
///
/// `circuit`: list of (`hop_id_32`, `x25519_pk_32`, `pq_pk_1184_or_None`).
/// The FIRST hop MUST supply a PQ pubkey; downstream hops may pass None.
#[pyfunction]
fn build_pq_sphinx<'py>(
    py: Python<'py>,
    eph_sk_bytes: &[u8],
    circuit: &Bound<'py, PyList>,
    payload: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let eph_sk = scalar_from_bytes(eph_sk_bytes)?;
    let hops = parse_pq_circuit(circuit)?;
    let packet = pq_build(&eph_sk, &hops, payload, &mut OsRng).map_err(map_err)?;
    Ok(PyBytes::new(py, packet.as_bytes()))
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
            PyBytes::new(py, next_hop.as_bytes()),
            PyBytes::new(py, next_packet.as_bytes()),
        )),
        PqSphinxPeelOutcome::Deliver { payload } => Ok((
            "deliver".to_string(),
            PyBytes::new(py, &[]),
            PyBytes::new(py, &payload),
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
            PyBytes::new(py, next_hop.as_bytes()),
            PyBytes::new(py, next_packet.as_bytes()),
        )),
        PqSphinxPeelOutcome::Deliver { payload } => Ok((
            "deliver".to_string(),
            PyBytes::new(py, &[]),
            PyBytes::new(py, &payload),
        )),
    }
}

// ── Cover traffic ────────────────────────────────────────────────

/// Build a cover Sphinx packet bound for `circuit`. Its encoded layout
/// and length match an equally shaped real Sphinx packet; this does not
/// establish traffic indistinguishability under timing, volume, or route
/// observation. The destination identifies the authenticated cover marker
/// during peel.
#[pyfunction]
fn build_cover_packet<'py>(
    py: Python<'py>,
    eph_sk_bytes: &[u8],
    circuit: &Bound<'py, PyList>,
    cover_size: usize,
) -> PyResult<Bound<'py, PyBytes>> {
    let eph_sk = scalar_from_bytes(eph_sk_bytes)?;
    let hops = parse_circuit(circuit)?;
    let packet = cover_build(&eph_sk, &hops, cover_size, &mut OsRng).map_err(map_err)?;
    Ok(PyBytes::new(py, packet.as_bytes()))
}

/// **Deprecated (audit M4):** plaintext-prefix sentinel check. A
/// network attacker who flips the first 8 bytes of any real Sphinx
/// payload can spoof cover status. Production receive paths use the
/// authenticated `peel_sphinx` ("cover" return code) instead, which
/// verifies a MAC bound to the per-circuit shared key.
///
/// Retained as a fast-path / backwards-compat probe.
#[pyfunction]
fn is_cover_payload(payload: &[u8]) -> bool {
    #[allow(deprecated)]
    cover_is_sentinel(payload)
}

/// Audit M4: authenticated cover-payload check.
///
/// Returns true iff `payload` (the cleartext after Sphinx peel)
/// carries a valid MAC trailer for `shared_key`. The sender is
/// expected to have derived the trailer with the same circuit shared key
/// the destination computes locally during `peel_sphinx`. This prevents
/// an in-path party without that key from retagging an existing payload;
/// it is not user-identity authentication for freshly built circuits.
///
/// Daemon code that bypasses `peel_sphinx`'s built-in "cover"
/// return path can use this to verify cover status directly.
#[pyfunction]
fn is_cover_payload_authenticated(shared_key: &[u8], payload: &[u8]) -> PyResult<bool> {
    if shared_key.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "shared_key must be 32 bytes, got {}",
            shared_key.len()
        )));
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(shared_key);
    Ok(cover_is_auth(&k, payload))
}

/// Stateful Poisson scheduler for cover-traffic emission.
///
/// `next_wait_ms()` returns the next inter-arrival sleep in
/// milliseconds. Pass the result to your event loop's sleep
/// primitive; on wake, emit a cover packet.
#[pyclass(name = "CoverScheduler")]
pub struct PyCoverScheduler {
    inner: CoverScheduler,
}

#[pymethods]
impl PyCoverScheduler {
    #[new]
    #[pyo3(signature = (rate_hz, seed))]
    fn new(rate_hz: f64, seed: &[u8]) -> PyResult<Self> {
        if seed.len() != 32 {
            return Err(PyValueError::new_err(format!(
                "seed must be 32 bytes, got {}",
                seed.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(seed);
        Ok(Self {
            inner: CoverScheduler::new(rate_hz, arr).map_err(map_err)?,
        })
    }

    fn next_wait_ms(&mut self) -> u64 {
        self.inner.next_wait_ms()
    }

    fn rate_hz(&self) -> f64 {
        self.inner.rate_hz()
    }

    fn set_rate_hz(&mut self, rate_hz: f64) -> PyResult<()> {
        self.inner.set_rate_hz(rate_hz).map_err(map_err)
    }
}

/// Adaptive rate estimator for filling the difference between a target
/// and observed real-emission EWMA. It does not itself emit packets or
/// guarantee a constant observable traffic process.
#[pyclass(name = "RateEqualizer")]
pub struct PyRateEqualizer {
    inner: RateEqualizer,
}

#[pymethods]
impl PyRateEqualizer {
    #[new]
    fn new(target_total_hz: f64) -> PyResult<Self> {
        Ok(Self {
            inner: RateEqualizer::new(target_total_hz).map_err(map_err)?,
        })
    }

    fn observe_real_emission(&mut self, now_ms: u64) {
        self.inner.observe_real_emission(now_ms);
    }

    fn observe_idle_tick(&mut self, now_ms: u64) {
        self.inner.observe_idle_tick(now_ms);
    }

    fn current_cover_rate(&self) -> f64 {
        self.inner.current_cover_rate()
    }

    fn observed_real_rate(&self) -> f64 {
        self.inner.observed_real_rate()
    }

    fn target_total_hz(&self) -> f64 {
        self.inner.target_total_hz()
    }

    fn set_half_life_sec(&mut self, half_life_sec: f64) -> PyResult<()> {
        self.inner.set_half_life_sec(half_life_sec).map_err(map_err)
    }
}

// ── Registration ─────────────────────────────────────────────────

pub fn register(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(derive_pubkey_from_scalar, m)?)?;
    m.add_function(wrap_pyfunction!(build_sphinx, m)?)?;
    m.add_function(wrap_pyfunction!(peel_sphinx, m)?)?;
    m.add_function(wrap_pyfunction!(generate_pq_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(build_pq_sphinx, m)?)?;
    m.add_function(wrap_pyfunction!(peel_pq_sphinx_entry, m)?)?;
    m.add_function(wrap_pyfunction!(peel_pq_sphinx_intermediate, m)?)?;
    m.add_function(wrap_pyfunction!(build_cover_packet, m)?)?;
    m.add_function(wrap_pyfunction!(is_cover_payload, m)?)?;
    m.add_function(wrap_pyfunction!(is_cover_payload_authenticated, m)?)?;
    m.add_class::<PyCoverScheduler>()?;
    m.add_class::<PyRateEqualizer>()?;
    m.add("COVER_SENTINEL", PyBytes::new(py, COVER_SENTINEL))?;
    m.add("COVER_PAYLOAD_MIN", COVER_PAYLOAD_MIN)?;
    m.add("COVER_TRAILER_LEN", COVER_TRAILER_LEN)?;
    m.add("COVER_DEFAULT_RATE_HZ", COVER_DEFAULT_RATE_HZ)?;
    m.add("COVER_MIN_RATE_HZ", COVER_MIN_RATE_HZ)?;
    m.add("COVER_MAX_RATE_HZ", COVER_MAX_RATE_HZ)?;
    m.add(
        "RATE_EQ_DEFAULT_HALF_LIFE_SEC",
        RATE_EQ_DEFAULT_HALF_LIFE_SEC,
    )?;
    m.add("RATE_EQ_MAX_HALF_LIFE_SEC", RATE_EQ_MAX_HALF_LIFE_SEC)?;
    m.add("HOP_ID_LEN", HOP_ID_LEN)?;
    m.add("MAX_HOPS", MAX_HOPS)?;
    m.add("SPHINX_MAX_USER_PAYLOAD", SPHINX_MAX_USER_PAYLOAD)?;
    m.add("SPHINX_PACKET_LEN", SPHINX_PACKET_LEN)?;
    m.add("PQ_SPHINX_PACKET_LEN", PQ_SPHINX_PACKET_LEN)?;
    m.add("ML_KEM_CT_LEN", ML_KEM_CT_LEN)?;
    m.add("ML_KEM_EK_LEN", ML_KEM_EK_LEN)?;
    Ok(())
}
