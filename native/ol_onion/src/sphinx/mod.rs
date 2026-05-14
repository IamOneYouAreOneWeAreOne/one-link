//! Sphinx Coherence — the alien-tech onion-routing layer.
//!
//! Implements the Sphinx packet format (Danezis-Goldberg 2009) plus
//! One Link's unique upgrades layered on top. See
//! [`SPHINX_COHERENCE_DESIGN.md`] in this crate's directory for the
//! full design.
//!
//! Module layout:
//! - `primitives`: key-derivation, MAC, stream cipher helpers, the
//!   filler-byte construction. Pure-byte math, no curves.
//! - `header`: Sphinx header build + peel logic (still pre-curves).
//! - `core`: full Sphinx packet build + peel with Ristretto255 alpha
//!   blinding.
//!
//! Tier-1 items 2-5 land as their own modules under this directory
//! once the core is verified:
//! - `pq`: PQ-hybrid blinding (ML-KEM-768).
//! - `field`: coherence-field-bound blinding.
//! - `route`: coherence-field hop selection.
//! - `aggsig`: Schnorr signature aggregation.

#![allow(missing_docs)]

pub mod aggsig;
pub mod core;
pub mod cover;
pub mod field;
pub mod header;
pub mod pq;
pub mod primitives;

pub use core::{
    build_sphinx_onion, generate_static_keypair, peel_sphinx_layer, SphinxHop, SphinxPacket,
    SphinxPeelOutcome, RISTRETTO_POINT_LEN, SPHINX_MAX_USER_PAYLOAD, SPHINX_PACKET_LEN,
    SPHINX_VERSION,
};

pub use aggsig::{
    batch_verify, bn_aggregate, bn_verify, verify as schnorr_verify, BnAggregateSignature,
    SchnorrSignature, SchnorrSigningKey, SchnorrVerifyingKey,
};
