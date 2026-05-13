//! Row 7 — pluggable transport layer.
//!
//! Two-part stack:
//!
//! 1. [`primitive`]: ChaCha20-keyed byte XOR. Length-preserving,
//!    indistinguishable from random when the observer doesn't hold
//!    the key. The foundation.
//! 2. [`handshake`]: obfs4-style ECDH + bridge-identity HMAC binding.
//!    Negotiates the bulk-cipher key per connection, defends against
//!    active probe attackers via the bridge-id HMAC.
//! 3. [`session`]: stateful per-direction Sealer/Opener built on
//!    the handshake-derived keys + primitive obfuscate.
//!
//! Honest scope: this is the SECURITY layer for pluggable transport.
//! Full TLS-shape mimicry (Cloak / Snowflake JA3-perfect handshakes)
//! is its own ship on top — the keys + nonces are here, the
//! application-layer "look like Chrome ClientHello" is upstream.

pub mod handshake;
pub mod primitive;
pub mod session;

pub use handshake::{
    ClientHandshake, HandshakeError, HandshakeResult, ServerHandshake, BridgeKeypair,
    BRIDGE_ID_LEN, BRIDGE_PUBKEY_LEN, BRIDGE_SECRET_LEN, HANDSHAKE_LEN, HANDSHAKE_MAC_LEN,
    HANDSHAKE_EPOCH_SECS,
};
pub use primitive::{
    deobfuscate, deobfuscate_in_place, derive_nonce, obfuscate, obfuscate_in_place, ObfsError,
    OBFS_KEY_LEN, OBFS_NONCE_LEN,
};
pub use session::{Session, SessionDirection, SESSION_KEY_LEN};
