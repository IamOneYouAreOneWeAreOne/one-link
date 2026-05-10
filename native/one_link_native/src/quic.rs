//! `one_link_native.quic` — Python binding for the `ol_quic` crate.
//!
//! Surfaces identity-bound QUIC transport to Python with a synchronous
//! call shape that hides the underlying tokio runtime.
//!
//! # Architecture
//!
//! A single shared tokio multi-thread runtime (lazily initialized on
//! first endpoint construction) drives all QUIC I/O. The Python side
//! sees synchronous methods that internally use `runtime.block_on` for
//! short-lived ops and `runtime.spawn` for long-lived ones (the accept
//! loop). This avoids any pyo3-asyncio dependency and gives the
//! existing daemon a familiar synchronous API while preserving the
//! benefits of QUIC's async substrate underneath.
//!
//! # API surface (Python)
//!
//! ```python
//! from one_link_native.quic import Identity, Endpoint, EndpointConfig
//!
//! identity = Identity.generate()
//! cfg = EndpointConfig()
//!
//! # Server
//! def is_paired(fingerprint: bytes) -> bool:
//!     return fingerprint in known_peers
//! server = Endpoint.server(identity, is_paired, cfg)
//! conn = server.accept_blocking(timeout_ms=30_000)  # -> Connection or None
//!
//! # Client
//! client = Endpoint.client(identity, cfg)
//! conn = client.connect_blocking(addr, expected_fingerprint, timeout_ms=10_000)
//!
//! # Round-trip
//! resp_kind, resp_payload = conn.send_frame_round_trip(0x01, chunk_id_bytes)
//!
//! # Server-side: accept a stream + read a request frame
//! kind, payload, stream_handle = conn.recv_frame_blocking(timeout_ms=30_000)
//! conn.send_response_on(stream_handle, 0x02, response_bytes)
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use ol_quic::{
    transport::{read_frame, write_frame},
    Endpoint as RustEndpoint, EndpointConfig as RustEndpointConfig, Frame, FrameKind,
    Identity as RustIdentity, PeerFingerprint, PeerRegistry,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyTuple};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};

use crate::errors::quic_error_to_pyerr;

// ───────────────────────────── runtime ─────────────────────────────────

/// Single shared tokio runtime for all QUIC I/O. Spawned with as many
/// worker threads as the host has cores (capped at 8 for sanity).
fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get().min(8))
            .unwrap_or(2);
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(cores)
            .thread_name("ol-quic")
            .enable_all()
            .build()
            .expect("tokio runtime")
    })
}

// ───────────────────────────── identity ────────────────────────────────

/// Python view of an Ed25519 peer identity.
#[pyclass(name = "Identity", module = "one_link_native.quic", frozen)]
#[derive(Debug)]
pub struct PyIdentity {
    inner: Arc<RustIdentity>,
}

#[pymethods]
impl PyIdentity {
    /// Generate a fresh random identity.
    #[staticmethod]
    fn generate() -> PyResult<Self> {
        let inner = Arc::new(RustIdentity::generate().map_err(quic_error_to_pyerr)?);
        Ok(Self { inner })
    }

    /// Restore an identity from a PKCS#8 PEM-encoded Ed25519 private key.
    #[staticmethod]
    fn from_pkcs8_pem(pem: &str) -> PyResult<Self> {
        let inner = Arc::new(RustIdentity::from_pkcs8_pem(pem).map_err(quic_error_to_pyerr)?);
        Ok(Self { inner })
    }

    /// 32-byte BLAKE3 fingerprint of the public key.
    #[getter]
    fn fingerprint<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.fingerprint())
    }

    /// Hex of the fingerprint.
    #[getter]
    fn fingerprint_hex(&self) -> String {
        hex_lower(&self.inner.fingerprint())
    }

    /// 32-byte raw Ed25519 public key.
    #[getter]
    fn public_key_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.public_key_bytes())
    }

    /// PKCS#8 PEM string for at-rest storage.
    fn to_pkcs8_pem(&self) -> String {
        self.inner.to_pkcs8_pem()
    }

    fn __repr__(&self) -> String {
        format!("Identity(fingerprint={}…)", &self.fingerprint_hex()[..16])
    }
}

// ───────────────────────────── endpoint config ─────────────────────────

/// Python view of `ol_quic::EndpointConfig`.
#[pyclass(name = "EndpointConfig", module = "one_link_native.quic")]
#[derive(Debug, Clone)]
pub struct PyEndpointConfig {
    inner: RustEndpointConfig,
}

#[pymethods]
impl PyEndpointConfig {
    /// Construct a config with optional keyword overrides.
    ///
    /// :param bind: UDP bind address as a string (e.g. "127.0.0.1:0").
    ///     Defaults to "[::]:0" (any IPv6 + ephemeral port).
    /// :param idle_timeout_ms: 30000 by default.
    /// :param keepalive_interval_ms: 10000 by default.
    /// :param max_concurrent_bidi_streams: 256 by default.
    #[new]
    #[pyo3(signature = (bind=None, idle_timeout_ms=None, keepalive_interval_ms=None, max_concurrent_bidi_streams=None))]
    fn new(
        bind: Option<&str>,
        idle_timeout_ms: Option<u64>,
        keepalive_interval_ms: Option<u64>,
        max_concurrent_bidi_streams: Option<u32>,
    ) -> PyResult<Self> {
        let mut inner = RustEndpointConfig::default();
        if let Some(b) = bind {
            inner.bind = b
                .parse::<SocketAddr>()
                .map_err(|e| PyValueError::new_err(format!("bind parse: {e}")))?;
        }
        if let Some(v) = idle_timeout_ms {
            inner.idle_timeout_ms = v;
        }
        if let Some(v) = keepalive_interval_ms {
            inner.keepalive_interval_ms = v;
        }
        if let Some(v) = max_concurrent_bidi_streams {
            inner.max_concurrent_bidi_streams = v;
        }
        Ok(Self { inner })
    }

    #[getter]
    fn bind(&self) -> String {
        self.inner.bind.to_string()
    }
    #[getter]
    fn idle_timeout_ms(&self) -> u64 {
        self.inner.idle_timeout_ms
    }
    #[getter]
    fn keepalive_interval_ms(&self) -> u64 {
        self.inner.keepalive_interval_ms
    }
    #[getter]
    fn max_concurrent_bidi_streams(&self) -> u32 {
        self.inner.max_concurrent_bidi_streams
    }

    fn __repr__(&self) -> String {
        format!(
            "EndpointConfig(bind={}, idle={}ms, keepalive={}ms, max_streams={})",
            self.inner.bind,
            self.inner.idle_timeout_ms,
            self.inner.keepalive_interval_ms,
            self.inner.max_concurrent_bidi_streams,
        )
    }
}

// ───────────────────────────── peer registry (Python callback) ─────────

/// Wraps a Python callable `(fingerprint: bytes) -> bool` as a
/// [`PeerRegistry`].
///
/// The callback is invoked with the GIL acquired. Verifier path is
/// short and direct — TLS handshake hot path; the callback should do
/// O(1) lookup work (peer registry hashmap).
struct PyCallbackRegistry {
    callback: Arc<Mutex<PyObject>>,
}

impl std::fmt::Debug for PyCallbackRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PyCallbackRegistry").finish()
    }
}

impl PeerRegistry for PyCallbackRegistry {
    fn is_paired_peer(&self, fingerprint: &PeerFingerprint) -> bool {
        Python::with_gil(|py| {
            let callback = self.callback.lock().expect("mutex");
            let fp_bytes = PyBytes::new_bound(py, fingerprint);
            match callback.bind(py).call1((fp_bytes,)) {
                Ok(result) => result.extract::<bool>().unwrap_or(false),
                Err(_) => false,
            }
        })
    }
}

// ───────────────────────────── endpoint ────────────────────────────────

/// Python view of `ol_quic::Endpoint`.
///
/// Holds the runtime-spawned `Endpoint` plus an `accept` channel used
/// by `accept_blocking`. The accept loop runs in the background as a
/// tokio task and pushes each incoming connection onto a bounded
/// channel; Python pulls from the channel synchronously.
///
/// `Send + Sync`: `quinn::Endpoint` is `Send + Sync`, and our wrapper
/// fields all are too. Python code may freely share `Endpoint` across
/// threads (the test harness routinely does this with one thread
/// running the accept loop and another doing connects).
#[pyclass(name = "Endpoint", module = "one_link_native.quic")]
pub struct PyEndpoint {
    inner: Arc<RustEndpoint>,
    /// Some(rx) if this is a server endpoint; None for client-only.
    accept_rx: Option<Arc<AsyncMutex<mpsc::Receiver<PyConnection>>>>,
    /// Background accept-loop join handle (server only).
    _accept_join: Option<tokio::task::JoinHandle<()>>,
}

#[pymethods]
impl PyEndpoint {
    /// Build a server endpoint that accepts incoming connections from
    /// peers approved by the given Python callable.
    #[staticmethod]
    fn server(
        identity: &PyIdentity,
        is_paired_callback: PyObject,
        config: PyEndpointConfig,
    ) -> PyResult<Self> {
        let registry = Arc::new(PyCallbackRegistry {
            callback: Arc::new(Mutex::new(is_paired_callback)),
        });
        let identity_arc = identity.inner.clone();
        let config_inner = config.inner;
        let endpoint = runtime()
            .block_on(async move {
                RustEndpoint::server_for_identity(identity_arc, registry, config_inner)
            })
            .map_err(quic_error_to_pyerr)?;
        let endpoint = Arc::new(endpoint);

        // Spawn the accept loop. Bounded channel so a slow Python consumer
        // doesn't accumulate unbounded inbound connections.
        let (tx, rx) = mpsc::channel::<PyConnection>(64);
        let endpoint_clone = endpoint.clone();
        let accept_join = runtime().spawn(async move {
            while let Some(maybe_conn) = endpoint_clone.accept().await {
                match maybe_conn {
                    Ok(conn) => {
                        let py_conn = PyConnection::new(conn);
                        if tx.send(py_conn).await.is_err() {
                            // Receiver dropped → endpoint shutting down.
                            break;
                        }
                    }
                    Err(_) => {
                        // Per-connection failure (cert rejected, etc).
                        // Continue accepting other connections.
                        continue;
                    }
                }
            }
        });

        Ok(Self {
            inner: endpoint,
            accept_rx: Some(Arc::new(AsyncMutex::new(rx))),
            _accept_join: Some(accept_join),
        })
    }

    /// Build a client-only endpoint (no listener; outbound only).
    #[staticmethod]
    fn client(identity: &PyIdentity, config: PyEndpointConfig) -> PyResult<Self> {
        let identity_arc = identity.inner.clone();
        let config_inner = config.inner;
        let endpoint = runtime()
            .block_on(async move { RustEndpoint::client_for_identity(identity_arc, config_inner) })
            .map_err(quic_error_to_pyerr)?;
        Ok(Self {
            inner: Arc::new(endpoint),
            accept_rx: None,
            _accept_join: None,
        })
    }

    /// Local socket address.
    #[getter]
    fn local_addr(&self) -> PyResult<String> {
        self.inner
            .local_addr()
            .map(|a| a.to_string())
            .map_err(quic_error_to_pyerr)
    }

    /// Our identity fingerprint.
    #[getter]
    fn fingerprint<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.identity().fingerprint())
    }

    /// Connect to a peer; blocks until the handshake completes.
    ///
    /// :param addr: peer socket address as "host:port".
    /// :param expected_fingerprint: 32-byte fingerprint we expect them
    ///     to present (verified at TLS layer per ADR-0010).
    /// :param timeout_ms: overall timeout for the handshake.
    fn connect_blocking(
        &self,
        py: Python<'_>,
        addr: &str,
        expected_fingerprint: &[u8],
        timeout_ms: u64,
    ) -> PyResult<PyConnection> {
        let socket_addr: SocketAddr = addr
            .parse()
            .map_err(|e| PyValueError::new_err(format!("addr parse: {e}")))?;
        if expected_fingerprint.len() != 32 {
            return Err(PyValueError::new_err(format!(
                "expected_fingerprint must be 32 bytes, got {}",
                expected_fingerprint.len(),
            )));
        }
        let mut fp = [0u8; 32];
        fp.copy_from_slice(expected_fingerprint);

        let endpoint = self.inner.clone();
        let timeout = Duration::from_millis(timeout_ms);
        let conn = py.allow_threads(|| {
            runtime().block_on(async move {
                tokio::time::timeout(timeout, endpoint.connect(socket_addr, fp))
                    .await
                    .map_err(|_| ol_quic::QuicError::Io(std::io::Error::other("connect timeout")))?
            })
        });
        let conn = conn.map_err(quic_error_to_pyerr)?;
        Ok(PyConnection::new(conn))
    }

    /// Accept the next inbound connection. Blocks until one arrives or
    /// the timeout expires (returns None on timeout).
    fn accept_blocking(
        &self,
        py: Python<'_>,
        timeout_ms: u64,
    ) -> PyResult<Option<PyConnection>> {
        let rx = self.accept_rx.clone().ok_or_else(|| {
            PyValueError::new_err("accept_blocking called on a client-only endpoint")
        })?;
        let timeout = Duration::from_millis(timeout_ms);
        let result = py.allow_threads(|| {
            runtime().block_on(async move {
                let mut guard = rx.lock().await;
                tokio::time::timeout(timeout, guard.recv()).await
            })
        });
        match result {
            Ok(Some(conn)) => Ok(Some(conn)),
            Ok(None) | Err(_) => Ok(None),
        }
    }

    /// Close the endpoint gracefully.
    fn close(&self, error_code: u32, reason: &[u8]) {
        self.inner.close(error_code, reason);
    }
}

// ───────────────────────────── connection ──────────────────────────────

/// A handle to a fresh inbound bidirectional stream that the server-side
/// caller hasn't replied to yet. Issued by [`PyConnection::recv_frame_blocking`].
///
/// (Reserved for a future API surface that returns the raw stream pair.
/// Currently unused; the public surface uses opaque `stream_id`s issued
/// by `PyConnection::pending_streams`.)
#[allow(dead_code)]
#[pyclass(name = "InboundStream", module = "one_link_native.quic")]
pub struct PyInboundStream {
    inner: Mutex<Option<(quinn::SendStream, quinn::RecvStream)>>,
}

/// Python view of `ol_quic::Connection`.
///
/// `Send + Sync`: all inner fields are. Python code shares connections
/// across threads (test harness pattern: one thread issues
/// `send_frame_round_trip` calls in a worker pool while another runs the
/// accept loop on the matching peer).
#[pyclass(name = "Connection", module = "one_link_native.quic")]
pub struct PyConnection {
    inner: Arc<ol_quic::Connection>,
    /// Per-connection counter so we can hand out stream handles
    /// uniquely. Used for diagnostics; no functional dependency.
    stream_counter: Arc<Mutex<u64>>,
    /// Live handles waiting for response writes (set by
    /// `recv_frame_blocking`, consumed by `send_response_on`).
    pending_streams: Arc<Mutex<HashMap<u64, (quinn::SendStream, quinn::RecvStream)>>>,
}

impl PyConnection {
    fn new(inner: ol_quic::Connection) -> Self {
        Self {
            inner: Arc::new(inner),
            stream_counter: Arc::new(Mutex::new(0)),
            pending_streams: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[pymethods]
impl PyConnection {
    /// Remote socket address.
    #[getter]
    fn remote_address(&self) -> String {
        self.inner.remote_address().to_string()
    }

    /// Round-trip: open a fresh bidirectional stream, send the request
    /// frame, read the response frame, close the stream.
    ///
    /// :param frame_kind: u8 frame kind (one of the values in `proto`).
    /// :param payload: request payload bytes.
    /// :return: (response_kind: int, response_payload: bytes)
    fn send_frame_round_trip<'py>(
        &self,
        py: Python<'py>,
        frame_kind: u8,
        payload: &[u8],
    ) -> PyResult<Bound<'py, PyTuple>> {
        let kind = FrameKind::from_u8(frame_kind).ok_or_else(|| {
            PyValueError::new_err(format!("unknown frame kind 0x{frame_kind:02x}"))
        })?;
        let request = Frame::new(kind, payload.to_vec()).map_err(quic_error_to_pyerr)?;

        let conn = self.inner.clone();
        let response = py.allow_threads(|| {
            runtime()
                .block_on(async move { conn.send_frame_request_response(request).await })
        });
        let response = response.map_err(quic_error_to_pyerr)?;
        let kind_int = response.kind.as_u8();
        let payload_bytes = PyBytes::new_bound(py, &response.payload);
        Ok(PyTuple::new_bound(
            py,
            vec![
                kind_int.into_py(py).into_bound(py),
                payload_bytes.into_any(),
            ],
        ))
    }

    /// Server-side: accept the next inbound bidirectional stream and
    /// read its first frame (the client's request).
    ///
    /// Returns a tuple `(stream_id, frame_kind, payload)`. The
    /// `stream_id` is opaque; pass it to `send_response_on` to write
    /// the response on the same stream.
    fn recv_frame_blocking<'py>(
        &self,
        py: Python<'py>,
        timeout_ms: u64,
    ) -> PyResult<Option<Bound<'py, PyTuple>>> {
        let conn = self.inner.clone();
        let timeout = Duration::from_millis(timeout_ms);

        let result = py.allow_threads(|| {
            runtime().block_on(async move {
                let pair = match tokio::time::timeout(timeout, conn.accept_bi_stream()).await {
                    Ok(Ok(p)) => p,
                    Ok(Err(e)) => return Ok::<_, ol_quic::QuicError>(Some(Err(e))),
                    Err(_) => return Ok(None),
                };
                let (send, mut recv) = pair;
                let frame = match read_frame(&mut recv).await {
                    Ok(f) => f,
                    Err(e) => return Ok(Some(Err(e))),
                };
                Ok(Some(Ok((send, recv, frame))))
            })
        });

        match result {
            Ok(Some(Ok((send, recv, frame)))) => {
                let stream_id = {
                    let mut counter = self.stream_counter.lock().expect("mutex");
                    *counter += 1;
                    *counter
                };
                self.pending_streams
                    .lock()
                    .expect("mutex")
                    .insert(stream_id, (send, recv));
                let kind_int = frame.kind.as_u8();
                let payload = PyBytes::new_bound(py, &frame.payload);
                Ok(Some(PyTuple::new_bound(
                    py,
                    vec![
                        stream_id.into_py(py).into_bound(py),
                        kind_int.into_py(py).into_bound(py),
                        payload.into_any(),
                    ],
                )))
            }
            Ok(Some(Err(e))) => Err(quic_error_to_pyerr(e)),
            Ok(None) => Ok(None), // timeout
            Err(e) => Err(quic_error_to_pyerr(e)),
        }
    }

    /// Server-side: write the response frame on a stream returned by
    /// `recv_frame_blocking` and close the stream.
    fn send_response_on(
        &self,
        py: Python<'_>,
        stream_id: u64,
        frame_kind: u8,
        payload: &[u8],
    ) -> PyResult<()> {
        let kind = FrameKind::from_u8(frame_kind).ok_or_else(|| {
            PyValueError::new_err(format!("unknown frame kind 0x{frame_kind:02x}"))
        })?;
        let frame = Frame::new(kind, payload.to_vec()).map_err(quic_error_to_pyerr)?;
        let pair = self
            .pending_streams
            .lock()
            .expect("mutex")
            .remove(&stream_id)
            .ok_or_else(|| PyValueError::new_err(format!("unknown stream_id {stream_id}")))?;
        let (mut send, _recv) = pair;
        let result = py.allow_threads(|| {
            runtime().block_on(async move {
                write_frame(&mut send, &frame).await?;
                send.finish()
                    .map_err(|e| ol_quic::QuicError::Io(std::io::Error::other(e.to_string())))?;
                Ok::<_, ol_quic::QuicError>(())
            })
        });
        result.map_err(quic_error_to_pyerr)
    }

    /// RTT estimate in milliseconds.
    #[getter]
    fn rtt_ms(&self) -> u64 {
        self.inner.rtt().as_millis().min(u64::MAX as u128) as u64
    }

    /// Close the connection gracefully.
    fn close(&self, error_code: u32, reason: &[u8]) {
        self.inner.close(error_code, reason);
    }
}

// ───────────────────────────── module registration ─────────────────────

pub fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    use ol_quic::{MAX_BULK_FRAME_BYTES, MAX_CONTROL_FRAME_BYTES, ALPN};
    m.add("ALPN", PyBytes::new_bound(m.py(), ALPN))?;
    m.add("MAX_BULK_FRAME_BYTES", MAX_BULK_FRAME_BYTES)?;
    m.add("MAX_CONTROL_FRAME_BYTES", MAX_CONTROL_FRAME_BYTES)?;

    // Frame kind constants — exported as module-level integers so Python
    // callers can pass `quic.FRAME_CHUNK_REQUEST` instead of memorizing 0x01.
    m.add("FRAME_CHUNK_REQUEST", FrameKind::ChunkRequest.as_u8())?;
    m.add("FRAME_CHUNK_RESPONSE", FrameKind::ChunkResponse.as_u8())?;
    m.add("FRAME_CHUNK_NOT_FOUND", FrameKind::ChunkNotFound.as_u8())?;
    m.add("FRAME_MANIFEST_SYNC", FrameKind::ManifestSync.as_u8())?;
    m.add("FRAME_MANIFEST_RECORD", FrameKind::ManifestRecord.as_u8())?;
    m.add("FRAME_MANIFEST_SYNC_END", FrameKind::ManifestSyncEnd.as_u8())?;
    m.add("FRAME_BLOOM_FILTER", FrameKind::BloomFilter.as_u8())?;
    m.add("FRAME_MISSING_CHUNKS", FrameKind::MissingChunks.as_u8())?;
    m.add("FRAME_CAPABILITY_CHECK", FrameKind::CapabilityCheck.as_u8())?;
    m.add("FRAME_CAPABILITY_ACK", FrameKind::CapabilityAck.as_u8())?;
    m.add("FRAME_PING", FrameKind::Ping.as_u8())?;
    m.add("FRAME_PONG", FrameKind::Pong.as_u8())?;
    m.add("FRAME_PROTO_ERROR", FrameKind::ProtoError.as_u8())?;
    m.add("FRAME_CLOSE", FrameKind::Close.as_u8())?;

    m.add_class::<PyIdentity>()?;
    m.add_class::<PyEndpointConfig>()?;
    m.add_class::<PyEndpoint>()?;
    m.add_class::<PyConnection>()?;
    m.add_class::<PyInboundStream>()?;
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}
