//! QUIC endpoint + connection wrappers per [ADR-0009].
//!
//! [`Endpoint`] is a combined listener / dialer over a UDP socket. A
//! daemon typically runs ONE endpoint per identity. Two roles:
//!
//! - **Server**: `Endpoint::server_for_identity(...)` binds a local UDP
//!   socket and accepts incoming connections that present a paired-peer
//!   client cert.
//! - **Client**: `Endpoint::client_for_identity(...)` constructs a
//!   dial-only endpoint (no inbound). Useful when the daemon is purely
//!   outbound.
//!
//! [`Connection`] wraps `quinn::Connection` with our wire-protocol
//! helpers: [`Connection::send_frame_request_response`] sends a
//! request frame, awaits a response frame, and returns the response.
//! Long-lived bidirectional flows can call [`Connection::open_bi_stream`]
//! and use the wire-protocol [`crate::proto`] helpers directly.
//!
//! [ADR-0009]: ../../../docs/decisions/0009-quic-transport.md

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use quinn::{ClientConfig, Endpoint as QuinnEndpoint, ServerConfig, TransportConfig, VarInt};

use crate::error::QuicError;
use crate::identity::{Identity, PeerFingerprint};
use crate::proto::{decode_varint, Frame, FrameKind};
use crate::tls::{IdentityBoundClientVerifier, IdentityBoundServerVerifier, PeerRegistry, ALPN};

/// Configuration knobs for an endpoint. Defaults are chosen per ADR-0009.
#[derive(Debug, Clone)]
pub struct EndpointConfig {
    /// UDP bind address. `0.0.0.0:0` for an ephemeral local port.
    pub bind: SocketAddr,
    /// Idle timeout in milliseconds. Connections drop after this much
    /// silence with no traffic. Default 30 seconds per ADR-0009.
    pub idle_timeout_ms: u64,
    /// Keepalive interval in milliseconds. The endpoint sends an empty
    /// PING frame at this cadence to prevent NAT mappings from expiring
    /// and to detect zombie peers. Default 10 seconds per ADR-0009.
    pub keepalive_interval_ms: u64,
    /// Maximum concurrent inbound bidirectional streams per connection.
    /// Default 256 per ADR-0009.
    pub max_concurrent_bidi_streams: u32,
    /// Optional per-stream receive window in bytes. Large trusted file transfers
    /// routinely push 256 KiB-1 MiB frames; Quinn's conservative default
    /// is sized around 100 Mbps and can stall high-throughput LAN paths.
    /// Set to 0 to keep Quinn's platform-safe default.
    pub stream_receive_window_bytes: u64,
    /// Optional total send window in bytes. This caps unacknowledged outgoing data
    /// and should be large enough to keep Wi-Fi/Ethernet full without
    /// turning every connection into an unbounded memory promise.
    /// Set to 0 to keep Quinn's platform-safe default.
    pub send_window_bytes: u64,
    /// Whether Quinn should round-robin equal-priority send streams.
    /// One Link's chunk workload uses many short, same-priority streams;
    /// disabling fairness reduces fragmentation and scheduler overhead.
    pub send_fairness: bool,
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self {
            bind: "[::]:0".parse().expect("valid bind"),
            idle_timeout_ms: 30_000,
            keepalive_interval_ms: 10_000,
            max_concurrent_bidi_streams: 256,
            stream_receive_window_bytes: 0,
            send_window_bytes: 0,
            send_fairness: true,
        }
    }
}

impl EndpointConfig {
    fn into_transport_config(self) -> Result<TransportConfig, QuicError> {
        let mut t = TransportConfig::default();
        let idle_timeout = if self.idle_timeout_ms == 0 {
            None
        } else {
            Some(
                quinn::IdleTimeout::try_from(std::time::Duration::from_millis(
                    self.idle_timeout_ms,
                ))
                .map_err(|_| QuicError::InvalidConfig {
                    field: "idle_timeout_ms",
                    reason: "duration exceeds QUIC varint range",
                })?,
            )
        };
        t.max_idle_timeout(idle_timeout);
        t.keep_alive_interval(
            (self.keepalive_interval_ms > 0)
                .then(|| std::time::Duration::from_millis(self.keepalive_interval_ms)),
        );
        t.max_concurrent_bidi_streams(VarInt::from_u32(self.max_concurrent_bidi_streams));
        if self.stream_receive_window_bytes > 0 {
            let window = VarInt::from_u64(self.stream_receive_window_bytes).map_err(|_| {
                QuicError::InvalidConfig {
                    field: "stream_receive_window_bytes",
                    reason: "window exceeds QUIC varint range",
                }
            })?;
            t.stream_receive_window(window);
        }
        if self.send_window_bytes > 0 {
            t.send_window(self.send_window_bytes);
        }
        t.send_fairness(self.send_fairness);
        // Connection migration is on by default in quinn 0.11.
        Ok(t)
    }
}

/// Combined QUIC endpoint (listener + dialer).
pub struct Endpoint {
    inner: QuinnEndpoint,
    identity: Arc<Identity>,
    /// Stored as `Arc` so we can clone-and-share into per-connection
    /// configs without `TransportConfig: Clone` (which it isn't in
    /// quinn 0.11).
    transport_config: Arc<TransportConfig>,
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint")
            .field("local_addr", &self.inner.local_addr().ok())
            .field(
                "identity_fingerprint",
                &hex_lower(&self.identity.fingerprint()),
            )
            // The concrete Quinn transport configuration has no useful
            // stable Debug representation, so disclose its omission.
            .finish_non_exhaustive()
    }
}

impl Endpoint {
    /// Build a server endpoint that accepts incoming connections from
    /// peers in `registry` and presents `identity` as our cert.
    pub fn server_for_identity(
        identity: Arc<Identity>,
        registry: Arc<dyn PeerRegistry>,
        config: EndpointConfig,
    ) -> Result<Self, QuicError> {
        crate::install_default_crypto_provider();

        let server_crypto = build_server_crypto(&identity, registry)?;
        let server_quic = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| QuicError::Tls(rustls::Error::General(e.to_string())))?;
        let mut server_config = ServerConfig::with_crypto(Arc::new(server_quic));
        let bind = config.bind;
        let transport = Arc::new(config.into_transport_config()?);
        server_config.transport_config(transport.clone());

        let mut endpoint = QuinnEndpoint::server(server_config, bind)?;
        // Also configure the dial-side (clients can come from us too).
        let client_crypto = build_dialer_crypto_no_specific_peer(&identity)?;
        let client_quic = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .map_err(|e| QuicError::Tls(rustls::Error::General(e.to_string())))?;
        let mut client_cfg = ClientConfig::new(Arc::new(client_quic));
        client_cfg.transport_config(transport.clone());
        endpoint.set_default_client_config(client_cfg);

        Ok(Self {
            inner: endpoint,
            identity,
            transport_config: transport,
        })
    }

    /// Build a client-only endpoint (no listener). Use this when the
    /// daemon is purely outbound.
    pub fn client_for_identity(
        identity: Arc<Identity>,
        config: EndpointConfig,
    ) -> Result<Self, QuicError> {
        crate::install_default_crypto_provider();
        let client_crypto = build_dialer_crypto_no_specific_peer(&identity)?;
        let client_quic = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .map_err(|e| QuicError::Tls(rustls::Error::General(e.to_string())))?;
        let mut client_cfg = ClientConfig::new(Arc::new(client_quic));
        let bind = config.bind;
        let transport = Arc::new(config.into_transport_config()?);
        client_cfg.transport_config(transport.clone());

        let mut endpoint = QuinnEndpoint::client(bind)?;
        endpoint.set_default_client_config(client_cfg);
        Ok(Self {
            inner: endpoint,
            identity,
            transport_config: transport,
        })
    }

    /// Local socket address.
    pub fn local_addr(&self) -> Result<SocketAddr, QuicError> {
        Ok(self.inner.local_addr()?)
    }

    /// Our identity (for diagnostics).
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Dial out to a peer. The dialer must know the expected
    /// `peer_fingerprint` (from the registry / pairing flow).
    ///
    /// # Errors
    ///
    /// - [`QuicError::Connect`] if the QUIC handshake setup fails.
    /// - [`QuicError::Connection`] if the handshake completes with an
    ///   error (e.g. peer fingerprint mismatch — TLS rejected).
    pub async fn connect(
        &self,
        addr: SocketAddr,
        expected_fingerprint: PeerFingerprint,
    ) -> Result<Connection, QuicError> {
        // Build a fresh ClientConfig with this specific expected fingerprint.
        let client_crypto = build_dialer_crypto_for_peer(&self.identity, expected_fingerprint)?;
        let client_quic = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .map_err(|e| QuicError::Tls(rustls::Error::General(e.to_string())))?;
        let mut client_cfg = ClientConfig::new(Arc::new(client_quic));
        client_cfg.transport_config(self.transport_config.clone());

        // SNI: a static label. ADR-0010 originally specified a per-peer
        // SNI but DNS labels are capped at 63 chars and a 64-char hex
        // fingerprint plus prefix exceeds that. The verifier doesn't
        // consult SNI anyway — it checks the cert's SubjectPublicKey
        // against the expected fingerprint we've already pinned in the
        // ClientConfig. SNI is informational only; future ships that
        // run multiple peer identities on one daemon will encode the
        // identity index here, not the full fingerprint.
        let _ = expected_fingerprint; // kept for future SNI routing
        let sni = "one-link.local";
        let connecting = self
            .inner
            .connect_with(client_cfg, addr, sni)
            .map_err(QuicError::Connect)?;
        let conn = connecting.await?;
        Ok(Connection { inner: conn })
    }

    /// Accept the next inbound connection. Returns `None` when the
    /// endpoint is closed.
    pub async fn accept(&self) -> Option<Result<Connection, QuicError>> {
        let incoming = self.inner.accept().await?;
        Some(handshake_inbound(incoming).await)
    }

    /// Close the endpoint gracefully. New connections will be rejected;
    /// in-flight connections are notified of the close reason.
    pub fn close(&self, error_code: u32, reason: &[u8]) {
        self.inner.close(VarInt::from_u32(error_code), reason);
    }
}

async fn handshake_inbound(incoming: quinn::Incoming) -> Result<Connection, QuicError> {
    let conn = incoming.await?;
    Ok(Connection { inner: conn })
}

/// Wraps a successfully-handshaken QUIC connection with our wire-protocol
/// helpers.
pub struct Connection {
    inner: quinn::Connection,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("remote", &self.inner.remote_address())
            .field("rtt_ms", &self.inner.rtt().as_millis())
            .finish()
    }
}

impl Connection {
    /// Remote socket address.
    #[must_use]
    pub fn remote_address(&self) -> SocketAddr {
        self.inner.remote_address()
    }

    /// 2026-05-22 audit T1-H: extract the BLAKE3 fingerprint of the
    /// peer's Ed25519 public key directly from the negotiated TLS
    /// session.
    ///
    /// Returns `None` when the connection wasn't authenticated with
    /// a client cert (server-only) or when the peer-identity object
    /// isn't a rustls `CertificateDer` chain (different TLS provider
    /// at runtime — shouldn't happen with our build, but we surface
    /// `None` rather than panic).
    ///
    /// This closes the FIFO-race exposure where the Python daemon's
    /// accept-loop bound an accepted `Connection` to whichever fp
    /// was at the front of a "recently paired" deque. Now the daemon
    /// can call `conn.peer_fingerprint()` after `accept_blocking()`
    /// returns and bind by ground truth.
    #[must_use]
    pub fn peer_fingerprint(&self) -> Option<crate::identity::PeerFingerprint> {
        use rustls::pki_types::CertificateDer;
        let identity = self.inner.peer_identity()?;
        let certs: Box<Vec<CertificateDer<'static>>> = identity.downcast().ok()?;
        let first = certs.first()?;
        crate::tls::extract_pubkey_fingerprint(first).ok()
    }

    /// Round-trip: open a bidirectional stream, send a request frame,
    /// read a response frame, close the stream.
    ///
    /// This is the canonical pattern for `ChunkRequest`/`ChunkResponse`,
    /// `BloomFilter`/`MissingChunks`, etc.
    pub async fn send_frame_request_response(&self, request: Frame) -> Result<Frame, QuicError> {
        let (mut send, mut recv) = self.inner.open_bi().await?;
        write_owned_frame(&mut send, request).await?;
        send.finish()?;
        let response = read_frame(&mut recv).await?;
        Ok(response)
    }

    /// Open a fresh bidirectional stream. Caller is responsible for
    /// frame-level reads/writes via the helpers in this module.
    pub async fn open_bi_stream(
        &self,
    ) -> Result<(quinn::SendStream, quinn::RecvStream), QuicError> {
        Ok(self.inner.open_bi().await?)
    }

    /// Accept the next inbound bidirectional stream.
    pub async fn accept_bi_stream(
        &self,
    ) -> Result<(quinn::SendStream, quinn::RecvStream), QuicError> {
        Ok(self.inner.accept_bi().await?)
    }

    /// Wait for the connection to close, returning the reason.
    pub async fn closed(&self) -> quinn::ConnectionError {
        self.inner.closed().await
    }

    /// RTT estimate.
    #[must_use]
    pub fn rtt(&self) -> std::time::Duration {
        self.inner.rtt()
    }

    /// Close the connection gracefully.
    pub fn close(&self, error_code: u32, reason: &[u8]) {
        self.inner.close(VarInt::from_u32(error_code), reason);
    }
}

/// Write a frame to a `quinn::SendStream`. Caller is responsible for
/// closing the stream (e.g. via `send.finish()`).
pub async fn write_frame(send: &mut quinn::SendStream, frame: &Frame) -> Result<(), QuicError> {
    let (header, header_len) = frame.validated_wire_header()?;
    send.write_all(&header[..header_len])
        .await
        .map_err(QuicError::StreamWrite)?;
    if !frame.payload.is_empty() {
        send.write_all(&frame.payload)
            .await
            .map_err(QuicError::StreamWrite)?;
    }
    Ok(())
}

/// Write an owned frame without copying its payload into Quinn's send buffer.
///
/// Quinn accepts owned [`Bytes`] chunks directly. Converting the frame's
/// `Vec<u8>` payload into `Bytes` transfers the allocation instead of copying
/// it; a small independently owned header is submitted in the same vectored
/// write. Prefer this path whenever the caller no longer needs the frame.
/// [`write_frame`] remains available for borrowed/reusable frames and avoids a
/// separate full-frame staging buffer, but Quinn must copy that borrowed
/// payload into its owned transmit queue.
pub async fn write_owned_frame(
    send: &mut quinn::SendStream,
    frame: Frame,
) -> Result<(), QuicError> {
    let (header, header_len) = frame.validated_wire_header()?;
    let header = Bytes::copy_from_slice(&header[..header_len]);
    if frame.payload.is_empty() {
        send.write_chunk(header)
            .await
            .map_err(QuicError::StreamWrite)?;
    } else {
        let payload = Bytes::from(frame.payload);
        send.write_all_chunks(&mut [header, payload])
            .await
            .map_err(QuicError::StreamWrite)?;
    }
    Ok(())
}

/// Read a frame from a `quinn::RecvStream`.
///
/// Reads the kind byte + varint length, then exactly `length` bytes of
/// payload. Validates against the per-kind maximum.
pub async fn read_frame(recv: &mut quinn::RecvStream) -> Result<Frame, QuicError> {
    // Kind byte.
    let mut kind_buf = [0u8; 1];
    read_exact(recv, &mut kind_buf).await?;
    let kind = FrameKind::from_u8(kind_buf[0]).ok_or(QuicError::MalformedFrame {
        offset: 0,
        reason: "unknown frame kind",
    })?;

    // Varint length: read 1 byte at a time until high bit clears.
    // A u64 LEB128 is at most ten bytes. Keep the tiny parser state on the
    // stack: allocating it for every 1 MiB chunk was visible in the serial
    // request/response hot path.
    let mut varint_buf = [0u8; 10];
    let mut varint_len = 0usize;
    loop {
        if varint_len == varint_buf.len() {
            return Err(QuicError::MalformedFrame {
                offset: varint_len as u64,
                reason: "varint overflow",
            });
        }
        read_exact(recv, &mut varint_buf[varint_len..=varint_len]).await?;
        let byte = varint_buf[varint_len];
        varint_len += 1;
        if byte & 0x80 == 0 {
            break;
        }
        if varint_len == varint_buf.len() {
            return Err(QuicError::MalformedFrame {
                offset: varint_len as u64,
                reason: "varint overflow",
            });
        }
    }
    let (length, _consumed) = decode_varint(&varint_buf[..varint_len], 0)?;
    let max = kind.max_payload_bytes();
    if length > max {
        return Err(QuicError::FrameTooLarge {
            kind: kind.as_u8(),
            got: length,
            max,
        });
    }
    let payload_len = usize::try_from(length).map_err(|_| QuicError::MalformedFrame {
        offset: u64::try_from(varint_len).unwrap_or(u64::MAX),
        reason: "payload length does not fit this platform's address space",
    })?;
    let mut payload = vec![0u8; payload_len];
    if length > 0 {
        read_exact(recv, &mut payload).await?;
    }
    Frame::new(kind, payload)
}

async fn read_exact(recv: &mut quinn::RecvStream, buf: &mut [u8]) -> Result<(), QuicError> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = match recv.read(&mut buf[filled..]).await {
            Ok(Some(n)) => n,
            Ok(None) => {
                return Err(QuicError::StreamShortRead {
                    needed: buf.len(),
                    got: filled,
                });
            }
            Err(e) => return Err(QuicError::StreamRead(e)),
        };
        filled += n;
    }
    Ok(())
}

// ─────────────────────────── crypto plumbing ───────────────────────────

fn build_server_crypto(
    identity: &Identity,
    registry: Arc<dyn PeerRegistry>,
) -> Result<Arc<rustls::ServerConfig>, QuicError> {
    let cert_chain = vec![identity.cert_der().into_owned()];
    let key = identity.private_key_der();
    let verifier = Arc::new(IdentityBoundClientVerifier::new(registry));
    let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(QuicError::Tls)?
    .with_client_cert_verifier(verifier)
    .with_single_cert(cert_chain, key.into())
    .map_err(QuicError::Tls)?;
    server.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(server))
}

fn build_dialer_crypto_for_peer(
    identity: &Identity,
    expected_fingerprint: PeerFingerprint,
) -> Result<Arc<rustls::ClientConfig>, QuicError> {
    let cert_chain = vec![identity.cert_der().into_owned()];
    let key = identity.private_key_der();
    let verifier = Arc::new(IdentityBoundServerVerifier::new(expected_fingerprint));
    let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(QuicError::Tls)?
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_client_auth_cert(cert_chain, key.into())
    .map_err(QuicError::Tls)?;
    client.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(client))
}

/// Builds a "no specific peer fingerprint" client config for use as the
/// endpoint default. Calls to [`Endpoint::connect`] override this with
/// a per-peer config that pins the expected fingerprint.
fn build_dialer_crypto_no_specific_peer(
    identity: &Identity,
) -> Result<Arc<rustls::ClientConfig>, QuicError> {
    // Default config rejects ALL certs (zero fingerprint); per-connect
    // override via Endpoint::connect supplies the right one. This is
    // intentional: an unconfigured dial fails closed.
    build_dialer_crypto_for_peer(identity, [0u8; 32])
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

#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn oversized_transport_values_return_errors_instead_of_panicking() {
        let idle = EndpointConfig {
            idle_timeout_ms: u64::MAX,
            ..EndpointConfig::default()
        };
        assert!(matches!(
            idle.into_transport_config(),
            Err(QuicError::InvalidConfig {
                field: "idle_timeout_ms",
                ..
            })
        ));

        let receive_window = EndpointConfig {
            stream_receive_window_bytes: u64::MAX,
            ..EndpointConfig::default()
        };
        assert!(matches!(
            receive_window.into_transport_config(),
            Err(QuicError::InvalidConfig {
                field: "stream_receive_window_bytes",
                ..
            })
        ));
    }

    #[test]
    fn zero_timeouts_disable_optional_timers() {
        let config = EndpointConfig {
            idle_timeout_ms: 0,
            keepalive_interval_ms: 0,
            ..EndpointConfig::default()
        };
        assert!(config.into_transport_config().is_ok());
    }
}
