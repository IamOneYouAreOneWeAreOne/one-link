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
    proto::{decode_varint, encode_varint},
    transport::{read_frame, write_frame},
    Endpoint as RustEndpoint, EndpointConfig as RustEndpointConfig, Frame, FrameKind,
    Identity as RustIdentity, PeerFingerprint, PeerRegistry,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList, PyTuple};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, Mutex as AsyncMutex, Semaphore};
use tokio::task::JoinSet;

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
    /// :param stream_receive_window_bytes: 0 by default, meaning Quinn default.
    /// :param send_window_bytes: 0 by default, meaning Quinn default.
    /// :param send_fairness: true by default; callers can disable it for
    ///     specialized same-priority bulk-stream experiments.
    #[new]
    #[pyo3(signature = (bind=None, idle_timeout_ms=None, keepalive_interval_ms=None, max_concurrent_bidi_streams=None, stream_receive_window_bytes=None, send_window_bytes=None, send_fairness=None))]
    fn new(
        bind: Option<&str>,
        idle_timeout_ms: Option<u64>,
        keepalive_interval_ms: Option<u64>,
        max_concurrent_bidi_streams: Option<u32>,
        stream_receive_window_bytes: Option<u64>,
        send_window_bytes: Option<u64>,
        send_fairness: Option<bool>,
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
        if let Some(v) = stream_receive_window_bytes {
            inner.stream_receive_window_bytes = v;
        }
        if let Some(v) = send_window_bytes {
            inner.send_window_bytes = v;
        }
        if let Some(v) = send_fairness {
            inner.send_fairness = v;
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
    #[getter]
    fn stream_receive_window_bytes(&self) -> u64 {
        self.inner.stream_receive_window_bytes
    }
    #[getter]
    fn send_window_bytes(&self) -> u64 {
        self.inner.send_window_bytes
    }
    #[getter]
    fn send_fairness(&self) -> bool {
        self.inner.send_fairness
    }

    fn __repr__(&self) -> String {
        format!(
            "EndpointConfig(bind={}, idle={}ms, keepalive={}ms, max_streams={}, stream_window={}, send_window={}, fairness={})",
            self.inner.bind,
            self.inner.idle_timeout_ms,
            self.inner.keepalive_interval_ms,
            self.inner.max_concurrent_bidi_streams,
            self.inner.stream_receive_window_bytes,
            self.inner.send_window_bytes,
            self.inner.send_fairness,
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
    fn accept_blocking(&self, py: Python<'_>, timeout_ms: u64) -> PyResult<Option<PyConnection>> {
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
            runtime().block_on(async move { conn.send_frame_request_response(request).await })
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

    /// Batched request/response helper: enter the Rust async runtime once,
    /// then issue many sequential frame round-trips on the same connection.
    ///
    /// This avoids one Pythonâ†”Rust boundary crossing per chunk request,
    /// which matters for high-throughput loopback and LAN chunk pulls.
    fn send_frame_round_trips<'py>(
        &self,
        py: Python<'py>,
        frame_kind: u8,
        payloads: Vec<Vec<u8>>,
    ) -> PyResult<Bound<'py, PyList>> {
        let kind = FrameKind::from_u8(frame_kind).ok_or_else(|| {
            PyValueError::new_err(format!("unknown frame kind 0x{frame_kind:02x}"))
        })?;
        let mut requests = Vec::with_capacity(payloads.len());
        for payload in payloads {
            requests.push(Frame::new(kind, payload).map_err(quic_error_to_pyerr)?);
        }

        let conn = self.inner.clone();
        let responses = py.allow_threads(|| {
            runtime().block_on(async move {
                let mut out = Vec::with_capacity(requests.len());
                for request in requests {
                    out.push(conn.send_frame_request_response(request).await?);
                }
                Ok::<_, ol_quic::QuicError>(out)
            })
        });
        let responses = responses.map_err(quic_error_to_pyerr)?;
        frames_to_pylist(py, responses)
    }

    /// Parallel batched request/response helper. Opens multiple QUIC
    /// bidirectional streams concurrently while preserving response order
    /// in the returned Python list.
    #[pyo3(signature = (frame_kind, payloads, max_in_flight=None))]
    fn send_frame_round_trips_parallel<'py>(
        &self,
        py: Python<'py>,
        frame_kind: u8,
        payloads: Vec<Vec<u8>>,
        max_in_flight: Option<usize>,
    ) -> PyResult<Bound<'py, PyList>> {
        let kind = FrameKind::from_u8(frame_kind).ok_or_else(|| {
            PyValueError::new_err(format!("unknown frame kind 0x{frame_kind:02x}"))
        })?;
        let mut requests = Vec::with_capacity(payloads.len());
        for payload in payloads {
            requests.push(Frame::new(kind, payload).map_err(quic_error_to_pyerr)?);
        }
        let cap = max_in_flight.unwrap_or(64).clamp(1, 1024);
        let conn = self.inner.clone();
        let responses = py.allow_threads(|| {
            runtime().block_on(async move {
                let semaphore = Arc::new(Semaphore::new(cap));
                let mut set = JoinSet::new();
                let total = requests.len();
                for (idx, request) in requests.into_iter().enumerate() {
                    let conn = conn.clone();
                    let semaphore = semaphore.clone();
                    set.spawn(async move {
                        let permit = semaphore.acquire_owned().await.map_err(|e| {
                            ol_quic::QuicError::Io(std::io::Error::other(e.to_string()))
                        })?;
                        let _permit = permit;
                        let response = conn.send_frame_request_response(request).await?;
                        Ok::<_, ol_quic::QuicError>((idx, response))
                    });
                }
                let mut out: Vec<Option<Frame>> = vec![None; total];
                while let Some(joined) = set.join_next().await {
                    let (idx, response) = joined.map_err(|e| {
                        ol_quic::QuicError::Io(std::io::Error::other(e.to_string()))
                    })??;
                    out[idx] = Some(response);
                }
                let mut ordered = Vec::with_capacity(total);
                for item in out {
                    ordered.push(item.ok_or_else(|| {
                        ol_quic::QuicError::Io(std::io::Error::other(
                            "parallel QUIC batch missing response",
                        ))
                    })?);
                }
                Ok::<_, ol_quic::QuicError>(ordered)
            })
        });
        let responses = responses.map_err(quic_error_to_pyerr)?;
        frames_to_pylist(py, responses)
    }

    /// Bulk-stream request/response helper. Opens one bidirectional QUIC
    /// stream, writes many request frames, then reads the same number of
    /// response frames from that stream.
    ///
    /// This is One Link's high-throughput chunk-fetch shape: one session
    /// amortizes stream setup across many chunks while every frame remains
    /// independently typed and length-bounded.
    fn send_frame_stream_round_trips<'py>(
        &self,
        py: Python<'py>,
        frame_kind: u8,
        payloads: Vec<Vec<u8>>,
    ) -> PyResult<Bound<'py, PyList>> {
        let kind = FrameKind::from_u8(frame_kind).ok_or_else(|| {
            PyValueError::new_err(format!("unknown frame kind 0x{frame_kind:02x}"))
        })?;
        for payload in &payloads {
            if payload.len() as u64 > kind.max_payload_bytes() {
                return Err(quic_error_to_pyerr(ol_quic::QuicError::FrameTooLarge {
                    kind: kind.as_u8(),
                    got: payload.len() as u64,
                    max: kind.max_payload_bytes(),
                }));
            }
        }
        let conn = self.inner.clone();
        let responses = py.allow_threads(|| {
            runtime().block_on(async move {
                let total = payloads.len();
                let (mut send, mut recv) = conn.open_bi_stream().await?;
                for payload in payloads {
                    write_frame_parts(&mut send, kind, &payload).await?;
                }
                send.finish()
                    .map_err(|e| ol_quic::QuicError::Io(std::io::Error::other(e.to_string())))?;
                let mut out = Vec::with_capacity(total);
                for _ in 0..total {
                    out.push(read_frame(&mut recv).await?);
                }
                Ok::<_, ol_quic::QuicError>(out)
            })
        });
        let responses = responses.map_err(quic_error_to_pyerr)?;
        frames_to_pylist(py, responses)
    }

    /// Parallel bulk-stream request/response helper. Partitions payloads
    /// across a small number of long-lived bidirectional streams and returns
    /// responses in the original request order.
    #[pyo3(signature = (frame_kind, payloads, lanes=None))]
    fn send_frame_stream_round_trips_parallel<'py>(
        &self,
        py: Python<'py>,
        frame_kind: u8,
        payloads: Vec<Vec<u8>>,
        lanes: Option<usize>,
    ) -> PyResult<Bound<'py, PyList>> {
        let kind = FrameKind::from_u8(frame_kind).ok_or_else(|| {
            PyValueError::new_err(format!("unknown frame kind 0x{frame_kind:02x}"))
        })?;
        for payload in &payloads {
            if payload.len() as u64 > kind.max_payload_bytes() {
                return Err(quic_error_to_pyerr(ol_quic::QuicError::FrameTooLarge {
                    kind: kind.as_u8(),
                    got: payload.len() as u64,
                    max: kind.max_payload_bytes(),
                }));
            }
        }
        let total = payloads.len();
        let lane_count = lanes.unwrap_or(4).clamp(1, total.max(1)).min(256);
        let mut buckets: Vec<Vec<(usize, Vec<u8>)>> = (0..lane_count).map(|_| Vec::new()).collect();
        for (idx, payload) in payloads.into_iter().enumerate() {
            buckets[idx % lane_count].push((idx, payload));
        }
        let conn = self.inner.clone();
        let responses = py.allow_threads(|| {
            runtime().block_on(async move {
                let mut set = JoinSet::new();
                for bucket in buckets.into_iter().filter(|bucket| !bucket.is_empty()) {
                    let conn = conn.clone();
                    set.spawn(async move {
                        let (mut send, mut recv) = conn.open_bi_stream().await?;
                        let indices: Vec<usize> = bucket.iter().map(|(idx, _)| *idx).collect();
                        for (_idx, payload) in bucket {
                            write_frame_parts(&mut send, kind, &payload).await?;
                        }
                        send.finish().map_err(|e| {
                            ol_quic::QuicError::Io(std::io::Error::other(e.to_string()))
                        })?;
                        let mut lane_out = Vec::with_capacity(indices.len());
                        for idx in indices {
                            lane_out.push((idx, read_frame(&mut recv).await?));
                        }
                        Ok::<_, ol_quic::QuicError>(lane_out)
                    });
                }
                let mut out: Vec<Option<Frame>> = vec![None; total];
                while let Some(joined) = set.join_next().await {
                    for (idx, frame) in joined.map_err(|e| {
                        ol_quic::QuicError::Io(std::io::Error::other(e.to_string()))
                    })?? {
                        out[idx] = Some(frame);
                    }
                }
                let mut ordered = Vec::with_capacity(total);
                for item in out {
                    ordered.push(item.ok_or_else(|| {
                        ol_quic::QuicError::Io(std::io::Error::other(
                            "parallel QUIC stream batch missing response",
                        ))
                    })?);
                }
                Ok::<_, ol_quic::QuicError>(ordered)
            })
        });
        let responses = responses.map_err(quic_error_to_pyerr)?;
        frames_to_pylist(py, responses)
    }

    /// Bulk-stream request/response helper that verifies response kind and
    /// returns total response bytes without materializing payloads as Python
    /// objects. This mirrors the production direction: stream verified bytes
    /// into a native sink instead of copying every chunk through Python.
    fn send_frame_stream_round_trips_count(
        &self,
        py: Python<'_>,
        frame_kind: u8,
        payloads: Vec<Vec<u8>>,
        expected_response_kind: u8,
    ) -> PyResult<usize> {
        let kind = FrameKind::from_u8(frame_kind).ok_or_else(|| {
            PyValueError::new_err(format!("unknown frame kind 0x{frame_kind:02x}"))
        })?;
        let expected = FrameKind::from_u8(expected_response_kind).ok_or_else(|| {
            PyValueError::new_err(format!(
                "unknown response frame kind 0x{expected_response_kind:02x}"
            ))
        })?;
        for payload in &payloads {
            if payload.len() as u64 > kind.max_payload_bytes() {
                return Err(quic_error_to_pyerr(ol_quic::QuicError::FrameTooLarge {
                    kind: kind.as_u8(),
                    got: payload.len() as u64,
                    max: kind.max_payload_bytes(),
                }));
            }
        }
        let conn = self.inner.clone();
        let total = payloads.len();
        let bytes = py.allow_threads(|| {
            runtime().block_on(async move {
                let (mut send, mut recv) = conn.open_bi_stream().await?;
                let writer = async {
                    for payload in payloads {
                        write_frame_parts(&mut send, kind, &payload).await?;
                    }
                    send.finish().map_err(|e| {
                        ol_quic::QuicError::Io(std::io::Error::other(e.to_string()))
                    })?;
                    Ok::<_, ol_quic::QuicError>(())
                };
                let reader = async {
                    let mut bytes = 0usize;
                    for _ in 0..total {
                        bytes += read_expected_frame_payload_len(&mut recv, expected).await?;
                    }
                    Ok::<_, ol_quic::QuicError>(bytes)
                };
                let (_, bytes) = tokio::try_join!(writer, reader)?;
                Ok::<_, ol_quic::QuicError>(bytes)
            })
        });
        bytes.map_err(quic_error_to_pyerr)
    }

    /// Parallel form of [`send_frame_stream_round_trips_count`].
    #[pyo3(signature = (frame_kind, payloads, expected_response_kind, lanes=None))]
    fn send_frame_stream_round_trips_count_parallel(
        &self,
        py: Python<'_>,
        frame_kind: u8,
        payloads: Vec<Vec<u8>>,
        expected_response_kind: u8,
        lanes: Option<usize>,
    ) -> PyResult<usize> {
        let kind = FrameKind::from_u8(frame_kind).ok_or_else(|| {
            PyValueError::new_err(format!("unknown frame kind 0x{frame_kind:02x}"))
        })?;
        let expected = FrameKind::from_u8(expected_response_kind).ok_or_else(|| {
            PyValueError::new_err(format!(
                "unknown response frame kind 0x{expected_response_kind:02x}"
            ))
        })?;
        for payload in &payloads {
            if payload.len() as u64 > kind.max_payload_bytes() {
                return Err(quic_error_to_pyerr(ol_quic::QuicError::FrameTooLarge {
                    kind: kind.as_u8(),
                    got: payload.len() as u64,
                    max: kind.max_payload_bytes(),
                }));
            }
        }
        let total = payloads.len();
        let lane_count = lanes.unwrap_or(4).clamp(1, total.max(1)).min(256);
        let mut buckets: Vec<Vec<Vec<u8>>> = (0..lane_count).map(|_| Vec::new()).collect();
        for (idx, payload) in payloads.into_iter().enumerate() {
            buckets[idx % lane_count].push(payload);
        }
        let conn = self.inner.clone();
        let bytes = py.allow_threads(|| {
            runtime().block_on(async move {
                let mut set = JoinSet::new();
                for bucket in buckets.into_iter().filter(|bucket| !bucket.is_empty()) {
                    let conn = conn.clone();
                    set.spawn(async move {
                        let total = bucket.len();
                        let (mut send, mut recv) = conn.open_bi_stream().await?;
                        let writer = async {
                            for payload in bucket {
                                write_frame_parts(&mut send, kind, &payload).await?;
                            }
                            send.finish().map_err(|e| {
                                ol_quic::QuicError::Io(std::io::Error::other(e.to_string()))
                            })?;
                            Ok::<_, ol_quic::QuicError>(())
                        };
                        let reader = async {
                            let mut bytes = 0usize;
                            for _ in 0..total {
                                bytes += read_expected_frame_payload_len(&mut recv, expected).await?;
                            }
                            Ok::<_, ol_quic::QuicError>(bytes)
                        };
                        let (_, bytes) = tokio::try_join!(writer, reader)?;
                        Ok::<_, ol_quic::QuicError>(bytes)
                    });
                }
                let mut bytes = 0usize;
                while let Some(joined) = set.join_next().await {
                    bytes += joined.map_err(|e| {
                        ol_quic::QuicError::Io(std::io::Error::other(e.to_string()))
                    })??;
                }
                Ok::<_, ol_quic::QuicError>(bytes)
            })
        });
        bytes.map_err(quic_error_to_pyerr)
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

    /// Server-side: accept and read up to ``max_frames`` inbound streams in
    /// one native call. Blocks for the first frame up to ``timeout_ms`` and
    /// then coalesces any follow-up streams that arrive within a tiny idle
    /// window. Returned
    /// stream ids must be answered with ``send_response_on`` or
    /// ``send_responses_on``.
    #[pyo3(signature = (max_frames, timeout_ms, idle_timeout_us=None))]
    fn recv_frames_blocking<'py>(
        &self,
        py: Python<'py>,
        max_frames: usize,
        timeout_ms: u64,
        idle_timeout_us: Option<u64>,
    ) -> PyResult<Bound<'py, PyList>> {
        let max_frames = max_frames.clamp(1, 4096);
        let conn = self.inner.clone();
        let timeout = Duration::from_millis(timeout_ms);
        let idle = Duration::from_micros(idle_timeout_us.unwrap_or(250).min(50_000));

        let result = py.allow_threads(|| {
            runtime().block_on(async move {
                let mut out = Vec::with_capacity(max_frames);
                for idx in 0..max_frames {
                    let wait = if idx == 0 {
                        timeout
                    } else if idle.is_zero() {
                        Duration::from_millis(0)
                    } else {
                        idle
                    };
                    let pair = match tokio::time::timeout(wait, conn.accept_bi_stream()).await {
                        Ok(Ok(p)) => p,
                        Ok(Err(e)) => {
                            if idx == 0 {
                                return Err(e);
                            }
                            break;
                        }
                        Err(_) => break,
                    };
                    let (send, mut recv) = pair;
                    let frame = read_frame(&mut recv).await?;
                    out.push((send, recv, frame));
                }
                Ok::<_, ol_quic::QuicError>(out)
            })
        });
        let frames = result.map_err(quic_error_to_pyerr)?;

        let items = PyList::empty_bound(py);
        let mut pending = self.pending_streams.lock().expect("mutex");
        let mut counter = self.stream_counter.lock().expect("mutex");
        for (send, recv, frame) in frames {
            *counter += 1;
            let stream_id = *counter;
            pending.insert(stream_id, (send, recv));
            let payload = PyBytes::new_bound(py, &frame.payload);
            items.append(PyTuple::new_bound(
                py,
                vec![
                    stream_id.into_py(py).into_bound(py),
                    frame.kind.as_u8().into_py(py).into_bound(py),
                    payload.into_any(),
                ],
            ))?;
        }
        Ok(items)
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

    /// Server-side: write many responses in one native call. This is the
    /// fast path for chunk servers that receive a batch of request streams,
    /// prepare chunk payloads in Python, and then hand the whole response
    /// batch back to Rust for concurrent QUIC writes.
    #[pyo3(signature = (responses, max_in_flight=None))]
    fn send_responses_on(
        &self,
        py: Python<'_>,
        responses: Vec<(u64, u8, Vec<u8>)>,
        max_in_flight: Option<usize>,
    ) -> PyResult<()> {
        let mut streams = Vec::with_capacity(responses.len());
        {
            let mut pending = self.pending_streams.lock().expect("mutex");
            for (stream_id, frame_kind, payload) in responses {
                let kind = FrameKind::from_u8(frame_kind).ok_or_else(|| {
                    PyValueError::new_err(format!("unknown frame kind 0x{frame_kind:02x}"))
                })?;
                let frame = Frame::new(kind, payload).map_err(quic_error_to_pyerr)?;
                let pair = pending.remove(&stream_id).ok_or_else(|| {
                    PyValueError::new_err(format!("unknown stream_id {stream_id}"))
                })?;
                streams.push((pair, frame));
            }
        }

        let cap = max_in_flight.unwrap_or(64).clamp(1, 1024);
        let result = py.allow_threads(|| {
            runtime().block_on(async move {
                let semaphore = Arc::new(Semaphore::new(cap));
                let mut set = JoinSet::new();
                for ((mut send, _recv), frame) in streams {
                    let semaphore = semaphore.clone();
                    set.spawn(async move {
                        let permit = semaphore.acquire_owned().await.map_err(|e| {
                            ol_quic::QuicError::Io(std::io::Error::other(e.to_string()))
                        })?;
                        let _permit = permit;
                        write_frame(&mut send, &frame).await?;
                        send.finish().map_err(|e| {
                            ol_quic::QuicError::Io(std::io::Error::other(e.to_string()))
                        })?;
                        Ok::<_, ol_quic::QuicError>(())
                    });
                }
                while let Some(joined) = set.join_next().await {
                    joined.map_err(|e| {
                        ol_quic::QuicError::Io(std::io::Error::other(e.to_string()))
                    })??;
                }
                Ok::<_, ol_quic::QuicError>(())
            })
        });
        result.map_err(quic_error_to_pyerr)
    }

    /// Server-side hot path: serve a fixed response payload for a known
    /// number of inbound request streams entirely inside Rust.
    ///
    /// This is intentionally narrow: it measures and exercises QUIC stream
    /// scheduling without a per-frame Python loop, and it is the production
    /// shape we want once native chunk-store lookups can hand back borrowed
    /// chunk bytes directly.
    #[pyo3(signature = (requests, response_kind, payload, max_in_flight=None))]
    fn serve_fixed_responses_blocking(
        &self,
        py: Python<'_>,
        requests: usize,
        response_kind: u8,
        payload: Vec<u8>,
        max_in_flight: Option<usize>,
    ) -> PyResult<usize> {
        let kind = FrameKind::from_u8(response_kind).ok_or_else(|| {
            PyValueError::new_err(format!("unknown frame kind 0x{response_kind:02x}"))
        })?;
        if payload.len() as u64 > kind.max_payload_bytes() {
            return Err(quic_error_to_pyerr(ol_quic::QuicError::FrameTooLarge {
                kind: kind.as_u8(),
                got: payload.len() as u64,
                max: kind.max_payload_bytes(),
            }));
        }
        let cap = max_in_flight.unwrap_or(64).clamp(1, 1024);
        let conn = self.inner.clone();
        let payload = Arc::new(payload);
        let result = py.allow_threads(|| {
            runtime().block_on(async move {
                let semaphore = Arc::new(Semaphore::new(cap));
                let mut set = JoinSet::new();
                for _ in 0..requests {
                    let permit = semaphore.clone().acquire_owned().await.map_err(|e| {
                        ol_quic::QuicError::Io(std::io::Error::other(e.to_string()))
                    })?;
                    let conn = conn.clone();
                    let payload = payload.clone();
                    set.spawn(async move {
                        let _permit = permit;
                        let (mut send, mut recv) = conn.accept_bi_stream().await?;
                        let _request = read_frame(&mut recv).await?;
                        write_frame_parts(&mut send, kind, payload.as_ref()).await?;
                        send.finish().map_err(|e| {
                            ol_quic::QuicError::Io(std::io::Error::other(e.to_string()))
                        })?;
                        Ok::<_, ol_quic::QuicError>(())
                    });
                }
                let mut served = 0usize;
                while let Some(joined) = set.join_next().await {
                    joined.map_err(|e| {
                        ol_quic::QuicError::Io(std::io::Error::other(e.to_string()))
                    })??;
                    served += 1;
                }
                Ok::<_, ol_quic::QuicError>(served)
            })
        });
        result.map_err(quic_error_to_pyerr)
    }

    /// Server-side bulk-stream hot path. Accepts ``streams`` inbound
    /// bidirectional streams, reads exactly ``requests_per_stream`` frames
    /// from each, and writes a fixed response frame for every request.
    #[pyo3(signature = (streams, requests_per_stream, response_kind, payload, max_in_flight=None))]
    fn serve_fixed_stream_responses_blocking(
        &self,
        py: Python<'_>,
        streams: usize,
        requests_per_stream: usize,
        response_kind: u8,
        payload: Vec<u8>,
        max_in_flight: Option<usize>,
    ) -> PyResult<usize> {
        let kind = FrameKind::from_u8(response_kind).ok_or_else(|| {
            PyValueError::new_err(format!("unknown frame kind 0x{response_kind:02x}"))
        })?;
        if payload.len() as u64 > kind.max_payload_bytes() {
            return Err(quic_error_to_pyerr(ol_quic::QuicError::FrameTooLarge {
                kind: kind.as_u8(),
                got: payload.len() as u64,
                max: kind.max_payload_bytes(),
            }));
        }
        let cap = max_in_flight.unwrap_or(16).clamp(1, 256);
        let conn = self.inner.clone();
        let payload = Arc::new(payload);
        let result = py.allow_threads(|| {
            runtime().block_on(async move {
                let semaphore = Arc::new(Semaphore::new(cap));
                let mut set = JoinSet::new();
                for _ in 0..streams {
                    let permit = semaphore.clone().acquire_owned().await.map_err(|e| {
                        ol_quic::QuicError::Io(std::io::Error::other(e.to_string()))
                    })?;
                    let conn = conn.clone();
                    let payload = payload.clone();
                    set.spawn(async move {
                        let _permit = permit;
                        let (mut send, mut recv) = conn.accept_bi_stream().await?;
                        let mut served = 0usize;
                        for _ in 0..requests_per_stream {
                            let _request = read_frame(&mut recv).await?;
                            write_frame_parts(&mut send, kind, payload.as_ref()).await?;
                            served += 1;
                        }
                        send.finish().map_err(|e| {
                            ol_quic::QuicError::Io(std::io::Error::other(e.to_string()))
                        })?;
                        Ok::<_, ol_quic::QuicError>(served)
                    });
                }
                let mut served = 0usize;
                while let Some(joined) = set.join_next().await {
                    served += joined.map_err(|e| {
                        ol_quic::QuicError::Io(std::io::Error::other(e.to_string()))
                    })??;
                }
                Ok::<_, ol_quic::QuicError>(served)
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

pub(crate) fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    use ol_quic::{ALPN, MAX_BULK_FRAME_BYTES, MAX_CONTROL_FRAME_BYTES};
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
    m.add(
        "FRAME_MANIFEST_SYNC_END",
        FrameKind::ManifestSyncEnd.as_u8(),
    )?;
    m.add("FRAME_BLOOM_FILTER", FrameKind::BloomFilter.as_u8())?;
    m.add("FRAME_MISSING_CHUNKS", FrameKind::MissingChunks.as_u8())?;
    m.add("FRAME_FOUNTAIN_BURST", FrameKind::FountainBurst.as_u8())?;
    m.add("FRAME_FOUNTAIN_ACK", FrameKind::FountainAck.as_u8())?;
    m.add("FRAME_FOUNTAIN_REQUEST", FrameKind::FountainRequest.as_u8())?;
    m.add(
        "FRAME_SCOPED_BLOOM_FILTER",
        FrameKind::ScopedBloomFilter.as_u8(),
    )?;
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

fn frames_to_pylist<'py>(py: Python<'py>, frames: Vec<Frame>) -> PyResult<Bound<'py, PyList>> {
    let items = PyList::empty_bound(py);
    for frame in frames {
        let kind_int = frame.kind.as_u8();
        let payload_bytes = PyBytes::new_bound(py, &frame.payload);
        items.append(PyTuple::new_bound(
            py,
            vec![
                kind_int.into_py(py).into_bound(py),
                payload_bytes.into_any(),
            ],
        ))?;
    }
    Ok(items)
}

async fn write_frame_parts(
    send: &mut quinn::SendStream,
    kind: FrameKind,
    payload: &[u8],
) -> Result<(), ol_quic::QuicError> {
    let mut header = Vec::with_capacity(10);
    header.push(kind.as_u8());
    encode_varint(&mut header, payload.len() as u64);
    send.write_all(&header)
        .await
        .map_err(ol_quic::QuicError::StreamWrite)?;
    if !payload.is_empty() {
        send.write_all(payload)
            .await
            .map_err(ol_quic::QuicError::StreamWrite)?;
    }
    Ok(())
}

async fn read_expected_frame_payload_len(
    recv: &mut quinn::RecvStream,
    expected: FrameKind,
) -> Result<usize, ol_quic::QuicError> {
    let mut kind_buf = [0u8; 1];
    read_exact_parts(recv, &mut kind_buf).await?;
    let kind = FrameKind::from_u8(kind_buf[0]).ok_or(ol_quic::QuicError::MalformedFrame {
        offset: 0,
        reason: "unknown frame kind",
    })?;
    if kind != expected {
        return Err(ol_quic::QuicError::MalformedFrame {
            offset: 0,
            reason: "unexpected response kind",
        });
    }

    let mut varint_buf = Vec::with_capacity(9);
    loop {
        let mut b = [0u8; 1];
        read_exact_parts(recv, &mut b).await?;
        varint_buf.push(b[0]);
        if b[0] & 0x80 == 0 {
            break;
        }
        if varint_buf.len() > 9 {
            return Err(ol_quic::QuicError::MalformedFrame {
                offset: varint_buf.len() as u64,
                reason: "varint overflow",
            });
        }
    }
    let (length, _consumed) = decode_varint(&varint_buf, 0)?;
    let max = kind.max_payload_bytes();
    if length > max {
        return Err(ol_quic::QuicError::FrameTooLarge {
            kind: kind.as_u8(),
            got: length,
            max,
        });
    }
    drain_exact_parts(recv, length as usize).await?;
    Ok(length as usize)
}

async fn read_exact_parts(
    recv: &mut quinn::RecvStream,
    buf: &mut [u8],
) -> Result<(), ol_quic::QuicError> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let n = match recv.read(&mut buf[filled..]).await {
            Ok(Some(n)) => n,
            Ok(None) => {
                return Err(ol_quic::QuicError::StreamShortRead {
                    needed: buf.len(),
                    got: filled,
                });
            }
            Err(e) => return Err(ol_quic::QuicError::StreamRead(e)),
        };
        filled += n;
    }
    Ok(())
}

async fn drain_exact_parts(
    recv: &mut quinn::RecvStream,
    mut remaining: usize,
) -> Result<(), ol_quic::QuicError> {
    let mut buf = [0u8; 64 * 1024];
    while remaining > 0 {
        let want = remaining.min(buf.len());
        read_exact_parts(recv, &mut buf[..want]).await?;
        remaining -= want;
    }
    Ok(())
}
