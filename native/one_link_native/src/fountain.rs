//! `one_link_native.fountain` — Python binding for the `ol_fountain` crate.
//!
//! Exposes the LT-codes encoder, decoder, and on-wire packet codec per
//! ADR-0015. Python callers use the encoder to produce streams of
//! deterministic encoded symbols and the decoder to reconstruct the
//! original chunk plaintext from any sufficient subset.

use ol_fountain::{
    FountainPacket, LtDecoder, LtEncoder, MAX_ENCODED_PER_CHUNK, PACKET_HEADER_LEN,
};
use pyo3::buffer::PyBuffer;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::errors::fountain_error_to_pyerr;

/// Python LT encoder. Constructed once per chunk; `encode_symbol(symbol_id)`
/// returns one XORed payload of length `symbol_len`.
#[pyclass(name = "LtEncoder", module = "one_link_native.fountain")]
#[derive(Debug)]
pub struct PyLtEncoder {
    /// We hold the source buffer in an owned `Vec<u8>` so the encoder
    /// can borrow it for its lifetime.
    source: Vec<u8>,
    symbol_len: usize,
    cdf: Vec<f64>,
    k: u32,
}

#[pymethods]
impl PyLtEncoder {
    /// Build an encoder over `source` with `symbol_len`-byte symbols.
    #[new]
    fn new(py: Python<'_>, source: &Bound<'_, PyAny>, symbol_len: usize) -> PyResult<Self> {
        let source = bytes_from_buffer(py, source)?;
        if source.is_empty() {
            return Err(PyValueError::new_err("source buffer must be non-empty"));
        }
        if symbol_len == 0 {
            return Err(PyValueError::new_err("symbol_len must be > 0"));
        }
        let k = ((source.len() + symbol_len - 1) / symbol_len) as u32;
        let cdf = ol_fountain::robust_soliton_cdf(k);
        Ok(Self {
            source,
            symbol_len,
            cdf,
            k,
        })
    }

    /// K (source-symbol count).
    #[getter]
    fn k(&self) -> u32 {
        self.k
    }

    /// Symbol length in bytes.
    #[getter]
    fn symbol_len(&self) -> usize {
        self.symbol_len
    }

    /// Original source length in bytes (pre-padding).
    #[getter]
    fn source_len(&self) -> usize {
        self.source.len()
    }

    /// Encode one symbol with the given `symbol_id`.
    fn encode_symbol<'py>(&self, py: Python<'py>, symbol_id: u32) -> PyResult<Bound<'py, PyBytes>> {
        let enc = LtEncoder::new(&self.source, self.symbol_len).map_err(fountain_error_to_pyerr)?;
        let payload = py.allow_threads(|| enc.encode_symbol(symbol_id));
        let _ = &self.cdf; // kept for API stability
        Ok(PyBytes::new_bound(py, &payload))
    }

    fn __repr__(&self) -> String {
        format!(
            "LtEncoder(k={}, symbol_len={}, source_len={})",
            self.k,
            self.symbol_len,
            self.source.len(),
        )
    }
}

/// Python LT decoder.
#[pyclass(name = "LtDecoder", module = "one_link_native.fountain")]
#[derive(Debug)]
pub struct PyLtDecoder {
    inner: Option<LtDecoder>,
}

#[pymethods]
impl PyLtDecoder {
    /// Construct a decoder for a chunk with `k` source symbols of
    /// `symbol_len` bytes encoding an original of `source_length` bytes.
    #[new]
    fn new(k: u32, symbol_len: usize, source_length: usize) -> PyResult<Self> {
        let inner = LtDecoder::new(k, symbol_len, source_length).map_err(fountain_error_to_pyerr)?;
        Ok(Self { inner: Some(inner) })
    }

    /// Ingest one encoded packet. Returns `True` if this packet
    /// completed the decode.
    fn ingest(&mut self, py: Python<'_>, symbol_id: u32, payload: &Bound<'_, PyAny>) -> PyResult<bool> {
        let bytes = bytes_from_buffer(py, payload)?;
        let dec = self.inner.as_mut().ok_or_else(|| {
            PyValueError::new_err("decoder already consumed via finish()")
        })?;
        let r = py
            .allow_threads(|| dec.ingest(symbol_id, &bytes))
            .map_err(fountain_error_to_pyerr)?;
        Ok(r)
    }

    /// True iff all K source symbols are resolved.
    fn is_complete(&self) -> bool {
        self.inner.as_ref().is_some_and(LtDecoder::is_complete)
    }

    /// Number of source symbols resolved so far.
    #[getter]
    fn resolved_count(&self) -> u32 {
        self.inner.as_ref().map_or(0, LtDecoder::resolved_count)
    }

    /// K (source-symbol count).
    #[getter]
    fn k(&self) -> u32 {
        self.inner.as_ref().map_or(0, LtDecoder::k)
    }

    /// Consume the decoder + return the reconstructed source bytes.
    fn finish<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let dec = self.inner.take().ok_or_else(|| {
            PyValueError::new_err("decoder already consumed via finish()")
        })?;
        let bytes = py.allow_threads(|| dec.finish()).map_err(fountain_error_to_pyerr)?;
        Ok(PyBytes::new_bound(py, &bytes))
    }

    fn __repr__(&self) -> String {
        match &self.inner {
            Some(d) => format!(
                "LtDecoder(k={}, resolved={}/{}, complete={})",
                d.k(),
                d.resolved_count(),
                d.k(),
                d.is_complete()
            ),
            None => "LtDecoder(consumed)".to_string(),
        }
    }
}

/// Encode a fountain packet to wire bytes.
#[pyfunction]
fn encode_packet<'py>(
    py: Python<'py>,
    chunk_id: &Bound<'_, PyAny>,
    k: u32,
    symbol_id: u32,
    source_length: u32,
    payload: &Bound<'_, PyAny>,
) -> PyResult<Bound<'py, PyBytes>> {
    let chunk_id = chunk_id_32(py, chunk_id)?;
    let payload = bytes_from_buffer(py, payload)?;
    let p = FountainPacket::new(chunk_id, k, symbol_id, source_length, payload);
    Ok(PyBytes::new_bound(py, &p.encode()))
}

/// Decode a fountain packet from wire bytes. Returns
/// `(chunk_id, k, symbol_id, source_length, payload_bytes)`.
#[pyfunction]
fn decode_packet<'py>(
    py: Python<'py>,
    encoded: &Bound<'_, PyAny>,
) -> PyResult<(Bound<'py, PyBytes>, u32, u32, u32, Bound<'py, PyBytes>)> {
    let bytes = bytes_from_buffer(py, encoded)?;
    let p = FountainPacket::decode(&bytes).map_err(fountain_error_to_pyerr)?;
    Ok((
        PyBytes::new_bound(py, &p.chunk_id),
        p.k,
        p.symbol_id,
        p.source_length,
        PyBytes::new_bound(py, &p.payload),
    ))
}

fn bytes_from_buffer(py: Python<'_>, obj: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    let _ = py;
    let buf = PyBuffer::<u8>::get_bound(obj)?;
    let slice = unsafe {
        std::slice::from_raw_parts(buf.buf_ptr() as *const u8, buf.len_bytes())
    };
    Ok(slice.to_vec())
}

fn chunk_id_32(py: Python<'_>, obj: &Bound<'_, PyAny>) -> PyResult<[u8; 32]> {
    let v = bytes_from_buffer(py, obj)?;
    if v.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "chunk_id must be exactly 32 bytes, got {}",
            v.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

/// Register the `fountain` submodule on the given `PyModule`.
pub(crate) fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", ol_fountain::VERSION)?;
    m.add("PACKET_HEADER_LEN", PACKET_HEADER_LEN)?;
    m.add("MAX_ENCODED_PER_CHUNK", MAX_ENCODED_PER_CHUNK)?;
    m.add("C", ol_fountain::C)?;
    m.add("DELTA", ol_fountain::DELTA)?;
    m.add_class::<PyLtEncoder>()?;
    m.add_class::<PyLtDecoder>()?;
    m.add_function(wrap_pyfunction!(encode_packet, m)?)?;
    m.add_function(wrap_pyfunction!(decode_packet, m)?)?;
    Ok(())
}
