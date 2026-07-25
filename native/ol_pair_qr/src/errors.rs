//! Typed errors for the pair-by-QR protocol.

use thiserror::Error;

/// Top-level error type for every public operation in `ol_pair_qr`.
///
/// Variants are deliberately granular — the daemon layer needs to
/// distinguish "the QR was malformed" (user re-scans) from "signature
/// mismatch" (active attacker; abort) from "invite expired" (user
/// re-generates a new invite).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PairError {
    /// The encoded byte slice is too short for the expected struct.
    #[error("truncated frame: needed {needed} bytes, got {got}")]
    Truncated {
        /// Bytes the decoder still needed.
        needed: usize,
        /// Bytes actually available.
        got: usize,
    },

    /// The wire frame exceeded the per-struct cap. Refused before
    /// any allocation to avoid resource amplification.
    #[error("frame oversize: {got} > cap {cap}")]
    Oversize {
        /// Declared length on the wire.
        got: usize,
        /// Per-struct cap enforced by the decoder.
        cap: usize,
    },

    /// The version byte didn't match what this build supports.
    #[error("unsupported protocol version: got {got}, supported {supported}")]
    UnsupportedVersion {
        /// Version byte read off the wire.
        got: u8,
        /// Version this build accepts.
        supported: u8,
    },

    /// A required tag byte was wrong (e.g. `PairResponse` parsed as Invite).
    #[error("type tag mismatch: expected 0x{expected:02x}, got 0x{got:02x}")]
    BadTag {
        /// Tag the decoder expected.
        expected: u8,
        /// Tag actually on the wire.
        got: u8,
    },

    /// An Ed25519 signature failed to verify. Treated as a hard error
    /// — abort the pairing flow.
    #[error("signature verification failed")]
    BadSignature,

    /// The transcript hash the responder committed to does not match
    /// what the inviter computed locally. Indicates active tampering.
    #[error("transcript hash mismatch — possible MITM")]
    TranscriptMismatch,

    /// The invite's wall-clock expiry has passed.
    #[error("invite expired: now_unix={now}, expiry_unix={expiry}")]
    Expired {
        /// Caller-supplied current wall-clock time, unix seconds.
        now: u64,
        /// Expiry baked into the invite, unix seconds.
        expiry: u64,
    },

    /// A nonce was the wrong length on the wire.
    #[error("nonce length wrong: expected {expected}, got {got}")]
    BadNonceLen {
        /// Required nonce length in bytes.
        expected: usize,
        /// Length actually decoded.
        got: usize,
    },

    /// The state machine was advanced from the wrong state (e.g.
    /// `Inviter::receive_response` called before `Inviter::new`).
    #[error("state machine called from wrong state")]
    WrongState,

    /// A public-key byte slice was the wrong length.
    #[error("bad pubkey length: expected {expected}, got {got}")]
    BadPubkeyLen {
        /// Required pubkey length in bytes.
        expected: usize,
        /// Length actually decoded.
        got: usize,
    },

    /// The ephemeral X25519 pubkey decoded to an all-zero / small-order
    /// point. Rejected to prevent confined-subgroup attacks.
    #[error("ephemeral X25519 public key is small-order")]
    SmallOrderPubkey,

    /// A Factor-2 confirmation frame or acknowledgement had the wrong
    /// fixed length. Variable-length parsing is deliberately forbidden.
    #[error("factor-2 confirmation length wrong: expected {expected}, got {got}")]
    BadFactor2ConfirmationLen {
        /// Required byte length for this protocol step.
        expected: usize,
        /// Byte length supplied by the peer.
        got: usize,
    },

    /// The peer did not prove possession of the same final Factor-2-mixed
    /// chain key. No chain key is released when this error is returned.
    #[error("factor-2 key confirmation failed")]
    Factor2KeyConfirmationFailed,

    /// Internal invariant failed. Indicates a bug, not an attack.
    #[error("internal invariant violated: {0}")]
    Internal(&'static str),
}

/// Result alias for crate operations.
pub type PairResult<T> = Result<T, PairError>;
