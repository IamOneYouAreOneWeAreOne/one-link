//! Error types for `ol_quic`.

use thiserror::Error;

/// Errors produced by the QUIC transport.
#[derive(Debug, Error)]
pub enum QuicError {
    /// I/O error from the underlying socket / quinn.
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    /// Connection error from quinn (peer reset, idle timeout, transport
    /// error, etc).
    #[error("connection: {0}")]
    Connection(#[from] quinn::ConnectionError),

    /// Stream error from quinn.
    #[error("stream-write: {0}")]
    StreamWrite(#[from] quinn::WriteError),

    /// Stream was already finished/closed when we tried to write.
    #[error("stream-closed: {0}")]
    StreamClosed(#[from] quinn::ClosedStream),

    /// Stream-read error.
    #[error("stream-read: {0}")]
    StreamRead(#[from] quinn::ReadError),

    /// Stream read exhausted before the expected number of bytes.
    #[error("stream-read-exact failed: needed {needed}, got {got}")]
    StreamShortRead {
        /// Bytes requested.
        needed: usize,
        /// Bytes received before EOF.
        got: usize,
    },

    /// rcgen cert generation failed.
    #[error("cert-generation: {0}")]
    Rcgen(#[from] rcgen::Error),

    /// rustls error during TLS setup or handshake.
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),

    /// X.509 parse error during cert verification.
    #[error("x509: {0}")]
    X509(String),

    /// QUIC connect failed before the handshake even started.
    #[error("connect: {0}")]
    Connect(#[from] quinn::ConnectError),

    /// Frame parsing failed (kind byte unrecognized, length mismatch,
    /// reserved bytes non-zero, etc).
    #[error("malformed frame at offset {offset}: {reason}")]
    MalformedFrame {
        /// Byte offset within the stream.
        offset: u64,
        /// Specific reason.
        reason: &'static str,
    },

    /// Frame body exceeded the per-kind maximum size.
    #[error("frame too large: kind=0x{kind:02x} got {got} > max {max}")]
    FrameTooLarge {
        /// Frame kind byte.
        kind: u8,
        /// Length received.
        got: u64,
        /// Maximum allowed.
        max: u64,
    },

    /// Peer fingerprint extracted from the presented cert doesn't match
    /// the expected one (per ADR-0010).
    #[error("peer fingerprint mismatch")]
    FingerprintMismatch,

    /// Cert presented by the peer wasn't an Ed25519 cert (per ADR-0010).
    #[error("non-Ed25519 cert")]
    NonEd25519Cert,

    /// Cert self-signature verification failed (someone holds the public
    /// key but not the corresponding signing key).
    #[error("cert self-signature invalid")]
    InvalidCertSelfSignature,

    /// Operation requested an `Endpoint` that wasn't configured for
    /// listening or for dialing.
    #[error("endpoint role: {0}")]
    EndpointRole(&'static str),
}

impl From<x509_parser::error::X509Error> for QuicError {
    fn from(err: x509_parser::error::X509Error) -> Self {
        Self::X509(err.to_string())
    }
}

impl<T> From<x509_parser::nom::Err<T>> for QuicError
where
    T: std::fmt::Debug,
{
    fn from(err: x509_parser::nom::Err<T>) -> Self {
        Self::X509(format!("{err:?}"))
    }
}
