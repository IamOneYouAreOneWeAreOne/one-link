//! `ol_onion` — nested-AEAD onion circuits.
//!
//! Phase F3 / row 5 of the Coherence Mesh plan. Multi-hop privacy
//! preserving message routing where each hop only knows its
//! predecessor and successor.
//!
//! ## Design
//!
//! Nested ChaCha20-Poly1305 encryption with per-layer ephemeral
//! X25519 keys. The sender wraps the destination payload in N
//! layers, one per hop in the chosen circuit. Each relay decrypts
//! exactly one layer using its long-term X25519 secret + the
//! ephemeral X25519 public key carried in that layer's header.
//!
//! ## Threat model
//!
//! - Each relay is potentially malicious and curious.
//! - Network attacker can drop, reorder, modify, inject packets.
//! - Adversary cannot break X25519, BLAKE3, or ChaCha20-Poly1305.
//! - Global passive adversary (sees all packet sizes + timing) is
//!   addressed by:
//!   1. Fixed-size packets — every onion packet is exactly
//!      [`ONION_PACKET_SIZE`] bytes, so hop count does not leak.
//!   2. Cover traffic (Phase F4 / row 6) — out of scope here.
//!
//! ## What this layer provides
//!
//! - **Layer confidentiality**: relay R_i cannot decrypt layers
//!   intended for any other relay.
//! - **Layer integrity**: any in-flight tamper is detected at the
//!   next relay's AEAD verify step.
//! - **Forward secrecy**: each circuit uses fresh ephemeral X25519
//!   keys; compromise of a relay's long-term key reveals no past
//!   traffic (the ephemeral material is zeroized after the relay
//!   peels its layer).
//! - **Hop blindness**: a relay cannot determine its position in
//!   the circuit from packet contents (all layers look identical
//!   on the wire after decryption + AEAD verification).
//!
//! ## What this layer does NOT provide
//!
//! - Timing-correlation resistance (the global passive adversary
//!   can correlate ingress + egress timing). Cover traffic in row
//!   6 addresses this.
//! - Reply circuits — sender includes a return-path of its own
//!   construction if a reply is expected. This crate is one-way
//!   per packet; bidirectional flows wrap responses in their own
//!   onions.
//! - Replay defense for the destination — application layer
//!   responsibility (the payload typically carries a nonce or
//!   sequence number).
//!
//! ## Crate layout
//!
//! - [`hop`]: [`HopDescriptor`] + [`HopId`] types.
//! - [`circuit`]: [`Circuit`] — ordered list of hops.
//! - [`keyderiv`]: ECDH + BLAKE3 layer-key derivation.
//! - [`packet`]: [`OnionPacket`] wire format and fixed-size canon
//!   encoding.
//! - [`build`]: sender-side onion construction.
//! - [`peel`]: relay-side single-layer peel.
//! - [`errors`]: typed error surface.
//!
//! ## End-to-end example
//!
//! ```
//! use rand::rngs::OsRng;
//! use x25519_dalek::{PublicKey, StaticSecret};
//! use ol_onion::{
//!     build_onion, peel_one_layer, Circuit, HopDescriptor, HopId,
//!     OnionPacket, PeelOutcome, HOP_ID_LEN,
//! };
//!
//! // Build two relays + a destination.
//! let make = |i: u8| {
//!     let sk = StaticSecret::from([i; 32]);
//!     let pk = PublicKey::from(&sk);
//!     (sk, HopDescriptor {
//!         id: HopId::from_bytes([i; HOP_ID_LEN]),
//!         pubkey: pk,
//!     })
//! };
//! let (r1_sk, r1) = make(10);
//! let (r2_sk, r2) = make(20);
//! let (dest_sk, dest) = make(30);
//!
//! // Sender wraps a payload along [r1, r2, dest].
//! let circuit = Circuit::new(vec![r1, r2.clone(), dest.clone()]).unwrap();
//! let packet = build_onion(&circuit, b"hello", &mut OsRng).unwrap();
//!
//! // r1 peels its layer.
//! let outcome = peel_one_layer(&r1_sk, &packet).unwrap();
//! let inner_bytes = match outcome {
//!     PeelOutcome::Forward { next_hop, inner_packet_bytes } => {
//!         assert_eq!(next_hop, r2.id);
//!         inner_packet_bytes
//!     }
//!     _ => panic!(),
//! };
//!
//! // r2 peels its layer.
//! let p = OnionPacket::decode(&inner_bytes).unwrap();
//! let outcome = peel_one_layer(&r2_sk, &p).unwrap();
//! let final_bytes = match outcome {
//!     PeelOutcome::Forward { next_hop, inner_packet_bytes } => {
//!         assert_eq!(next_hop, dest.id);
//!         inner_packet_bytes
//!     }
//!     _ => panic!(),
//! };
//!
//! // dest delivers.
//! let p = OnionPacket::decode(&final_bytes).unwrap();
//! let outcome = peel_one_layer(&dest_sk, &p).unwrap();
//! match outcome {
//!     PeelOutcome::Deliver { payload } => assert_eq!(payload, b"hello"),
//!     _ => panic!(),
//! }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod build;
pub mod canon;
pub mod circuit;
pub mod cover;
pub mod errors;
pub mod hop;
pub mod keyderiv;
pub mod packet;
pub mod peel;
pub mod sphinx;
pub mod transport_obfs;

pub use build::build_onion;
pub use circuit::Circuit;
pub use cover::{
    build_cover_packet, build_default_cover_packet, is_cover_payload, COVER_MAGIC,
    DEFAULT_COVER_BODY_LEN,
};
pub use errors::{OnionError, OnionResult};
pub use hop::{HopDescriptor, HopId, HOP_ID_LEN};
pub use packet::{
    pad_packet_to_transport, unpad_packet_from_transport, OnionPacket, MAX_HOPS,
    MAX_USER_PAYLOAD, ONION_HEADER_LEN, ONION_PACKET_SIZE, ONION_PACKET_VERSION,
    TRANSPORT_PAD_HINT,
};
pub use peel::{peel_one_layer, PeelOutcome};

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Top-level domain-separation tag for every BLAKE3 derivation in
/// this crate.
pub const PROTOCOL_DOMAIN: &[u8] = b"OL-onion-v1";
