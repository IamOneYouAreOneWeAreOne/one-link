//! `ol_canon` — canonical-bytes encoder for the One Link engine.
//!
//! Ported by hand from `coherence_lang/std/codec/canon.cl` (the
//! algebraic specification). Provides deterministic, self-describing
//! binary encoding that the CRDT lattice, capability calculus, and
//! every wire frame relies on.
//!
//! ## Determinism guarantees
//!
//! - Same value → same bytes, every time, on every platform.
//! - Map / vector-clock keys MUST be pre-sorted by caller (lexicographic
//!   on the encoded key bytes); the encoder writes them in iteration
//!   order to keep the hot path branch-free.
//! - Floats canonicalised: all NaNs collapse to a single quiet-NaN
//!   bit pattern; -0.0 collapses to +0.0.
//! - Integers use LEB128 varints (unsigned) and zigzag-LEB128 (signed)
//!   — same shape RFC 8949 (CBOR) mandates, plus the canonical-ordering
//!   extensions the CL spec adds.
//!
//! ## Type tags
//!
//! Wire format is self-describing: every value starts with a 1-byte
//! [`TypeTag`] discriminant. Decoders refuse to interpret a tag as a
//! different type — no implicit conversions on the wire.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod decoder;
mod encoder;
mod error;
mod tag;
mod varint;

pub use decoder::CanonDecoder;
pub use encoder::CanonEncoder;
pub use error::{DecodeError, EncodeError};
pub use tag::TypeTag;
pub use varint::{decode_varint, decode_zigzag, encode_varint, encode_zigzag};

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
