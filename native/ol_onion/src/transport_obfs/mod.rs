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
//!
//! ## Example: bridge ↔ client handshake + bidirectional traffic
//!
//! ```no_run
//! use ol_onion::transport_obfs::{
//!     BridgeKeypair, ClientHandshake, ServerHandshake,
//! };
//! use rand::rngs::OsRng;
//!
//! // Out-of-band setup: client learns (bridge_pubkey, bridge_id)
//! // via F2 pair-by-QR or a trusted-channel hand-off.
//! let bridge = BridgeKeypair::generate(&mut OsRng);
//! let bridge_pubkey = *bridge.public.as_bytes();
//! let bridge_id = bridge.id_bytes();
//! let now = 1_700_000_000u64;
//!
//! // Client starts the handshake; transmits client.first_message().
//! let client = ClientHandshake::start(&mut OsRng, &bridge_pubkey, &bridge_id, now);
//! let first = *client.first_message();
//!
//! // Server validates the MAC + replies; both sides derive matching keys.
//! let (reply, server_session) =
//!     ServerHandshake::accept(&mut OsRng, &bridge, &first, now).unwrap();
//! let client_session = client.finish(&reply).unwrap();
//!
//! // Each direction has a separate ChaCha20 stream; counters MUST be
//! // per-packet-unique to avoid (key, nonce) collisions.
//! let on_wire = client_session.seal_outbound(b"hello bridge", 1);
//! let recovered = server_session.open_inbound(&on_wire, 1).unwrap();
//! assert_eq!(recovered, b"hello bridge");
//! ```

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
