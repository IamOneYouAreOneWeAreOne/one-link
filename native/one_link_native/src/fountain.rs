//! `one_link_native.fountain` — Python binding for the `ol_fountain` crate.
//!
//! Exposes the LT-codes encoder, decoder, and on-wire packet codec per
//! ADR-0015. Python callers use the encoder to produce streams of
//! deterministic encoded symbols and the decoder to reconstruct the
//! original chunk plaintext from any sufficient subset.

use ol_fountain::{
    FountainPacket, LtDecoder, LtEncoder, MAX_DECODER_BUFFER_BYTES, MAX_ENCODED_PER_CHUNK,
    MAX_SOURCE_BYTES, MAX_SOURCE_SYMBOLS_PER_CHUNK, MAX_SYMBOL_LEN, PACKET_HEADER_LEN,
};
use pyo3::buffer::PyBuffer;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::errors::fountain_error_to_pyerr;

type DecodedPacket<'py> = (Bound<'py, PyBytes>, u32, u32, u32, Bound<'py, PyBytes>);

/// Python LT encoder. Constructed once per chunk; `encode_symbol(symbol_id)`
/// returns one `XORed` payload of length `symbol_len`.
#[pyclass(name = "LtEncoder", module = "one_link_native.fountain")]
#[derive(Debug)]
pub struct PyLtEncoder {
    /// The owned encoder caches its robust-soliton CDF and tail padding
    /// once rather than rebuilding both on every FFI call.
    inner: LtEncoder<'static>,
}

#[pymethods]
impl PyLtEncoder {
    /// Build an encoder over `source` with `symbol_len`-byte symbols.
    #[new]
    fn new(py: Python<'_>, source: &Bound<'_, PyAny>, symbol_len: usize) -> PyResult<Self> {
        let source = bytes_from_buffer_bounded(py, source, MAX_SOURCE_BYTES, "source")?;
        let inner = LtEncoder::from_owned(source, symbol_len).map_err(fountain_error_to_pyerr)?;
        Ok(Self { inner })
    }

    /// K (source-symbol count).
    #[getter]
    fn k(&self) -> u32 {
        self.inner.k()
    }

    /// Symbol length in bytes.
    #[getter]
    fn symbol_len(&self) -> usize {
        self.inner.symbol_len()
    }

    /// Original source length in bytes (pre-padding).
    #[getter]
    fn source_len(&self) -> usize {
        self.inner.source_len()
    }

    /// Encode one symbol with the given `symbol_id`.
    fn encode_symbol<'py>(&self, py: Python<'py>, symbol_id: u32) -> PyResult<Bound<'py, PyBytes>> {
        if symbol_id >= MAX_ENCODED_PER_CHUNK {
            return Err(fountain_error_to_pyerr(
                ol_fountain::error::FountainError::SymbolIdOverflow {
                    got: symbol_id,
                    max: MAX_ENCODED_PER_CHUNK,
                },
            ));
        }
        let payload = py.detach(|| self.inner.encode_symbol(symbol_id));
        Ok(PyBytes::new(py, &payload))
    }

    fn __repr__(&self) -> String {
        format!(
            "LtEncoder(k={}, symbol_len={}, source_len={})",
            self.inner.k(),
            self.inner.symbol_len(),
            self.inner.source_len(),
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
        let inner =
            LtDecoder::new(k, symbol_len, source_length).map_err(fountain_error_to_pyerr)?;
        Ok(Self { inner: Some(inner) })
    }

    /// Ingest one encoded packet. Returns `True` if this packet
    /// completed the decode.
    fn ingest(
        &mut self,
        py: Python<'_>,
        symbol_id: u32,
        payload: &Bound<'_, PyAny>,
    ) -> PyResult<bool> {
        let bytes = bytes_from_buffer_bounded(py, payload, MAX_SYMBOL_LEN, "payload")?;
        let dec = self
            .inner
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("decoder already consumed via finish()"))?;
        let r = py
            .detach(|| dec.ingest(symbol_id, &bytes))
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
        let dec = self
            .inner
            .take()
            .ok_or_else(|| PyValueError::new_err("decoder already consumed via finish()"))?;
        let bytes = py
            .detach(|| dec.finish())
            .map_err(fountain_error_to_pyerr)?;
        Ok(PyBytes::new(py, &bytes))
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
    let payload = bytes_from_buffer_bounded(py, payload, MAX_SYMBOL_LEN, "payload")?;
    let p = FountainPacket::new(chunk_id, k, symbol_id, source_length, payload);
    let encoded = p.encode().map_err(fountain_error_to_pyerr)?;
    Ok(PyBytes::new(py, &encoded))
}

/// Decode a fountain packet from wire bytes. Returns
/// `(chunk_id, k, symbol_id, source_length, payload_bytes)`.
#[pyfunction]
fn decode_packet<'py>(py: Python<'py>, encoded: &Bound<'_, PyAny>) -> PyResult<DecodedPacket<'py>> {
    let bytes = bytes_from_buffer_bounded(
        py,
        encoded,
        PACKET_HEADER_LEN + MAX_SYMBOL_LEN,
        "encoded packet",
    )?;
    let p = FountainPacket::decode(&bytes).map_err(fountain_error_to_pyerr)?;
    Ok((
        PyBytes::new(py, &p.chunk_id),
        p.k,
        p.symbol_id,
        p.source_length,
        PyBytes::new(py, &p.payload),
    ))
}

fn bytes_from_buffer(py: Python<'_>, obj: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    let buf = PyBuffer::<u8>::get(obj)?;
    buf.to_vec(py)
}

fn bytes_from_buffer_bounded(
    py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    max_len: usize,
    field: &'static str,
) -> PyResult<Vec<u8>> {
    let buf = PyBuffer::<u8>::get(obj)?;
    let len = buf.len_bytes();
    if len > max_len {
        return Err(PyValueError::new_err(format!(
            "{field} exceeds {max_len} byte cap (got {len})"
        )));
    }
    buf.to_vec(py)
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
    m.add("MAX_SOURCE_SYMBOLS_PER_CHUNK", MAX_SOURCE_SYMBOLS_PER_CHUNK)?;
    m.add("MAX_SOURCE_BYTES", MAX_SOURCE_BYTES)?;
    m.add("MAX_SYMBOL_LEN", MAX_SYMBOL_LEN)?;
    m.add("MAX_DECODER_BUFFER_BYTES", MAX_DECODER_BUFFER_BYTES)?;
    m.add("C", ol_fountain::C)?;
    m.add("DELTA", ol_fountain::DELTA)?;
    m.add_class::<PyLtEncoder>()?;
    m.add_class::<PyLtDecoder>()?;
    m.add_function(wrap_pyfunction!(encode_packet, m)?)?;
    m.add_function(wrap_pyfunction!(decode_packet, m)?)?;
    Ok(())
}
