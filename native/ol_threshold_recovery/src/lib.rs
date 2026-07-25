//! Coherence Mesh Phase F1.1 — threshold secret sharing with optional
//! coherence-field-bound recovery.
//!
//! Ports the Shamir construction from
//! `OneField/onefield/privacy/sharding.cl` and adds a **field-context mask
//! layer**. The mask is cryptographically useful only when the witness
//! contains a separately generated, CSPRNG-grade secret binding key kept
//! outside the masked-share trust domain. Public field-solver output is
//! context, not sufficient key material by itself.
//!
//! ## Layers
//!
//! - [`gf256`] — constant-time GF(2^8) arithmetic, AES primitive polynomial.
//! - [`prng`] — xoshiro256** for deterministic coefficient generation.
//! - [`shamir`] — split + reconstruct + Lagrange interpolation. Plain
//!   Shamir, identical math to the `OneField` source so encoders interop.
//! - [`refresh`] — proactive secret-sharing arithmetic (HJK 1995); rotate
//!   shares without changing the secret. Static-breach resistance requires
//!   a complete authenticated refresh protocol, erasure, and an adversary
//!   that compromises fewer than K holders within each epoch.
//! - [`field_bound`] — shares are XOR-masked with a BLAKE3 keyed-XOF
//!   stream; reconstruction also requires the secret witness key and
//!   committed field context.
//!
//! ## Security properties
//!
//! Plain Shamir gives:
//! - **Correctness**: any K shares recover S exactly (Lagrange).
//! - **Perfect secrecy**: any K-1 shares statistically independent of S.
//!
//! Field-context masking adds defense in depth:
//! - **Separated-backup protection**: captured masked shares do not remove
//!   the mask when a high-entropy binding key is independently protected.
//! - **Context binding**: the secret key, holder scores, epoch, and share
//!   index select distinct mask streams.
//! - **Explicit limit**: storing the witness beside the shares, deriving
//!   its key from public/low-entropy field output, or using the placeholder
//!   removes this additional boundary. It does not make brute force
//!   impossible or replace the K-of-N Shamir threshold.
//!
//! ## Use cases (One Link)
//!
//! - Identity master-key recovery: split the 32-byte master seed across
//!   3-of-5 trusted contacts; optionally add a separately protected binding
//!   key so capture of only the masked-share files is insufficient.
//! - Group admission: split a join token across incumbents; quorum
//!   required.
//! - Capability escrow: split high-privilege capability secrets so no
//!   single device holds full authority.

#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]

pub mod field_bound;
pub mod gf256;
pub mod prng;
pub mod refresh;
pub mod shamir;

pub use field_bound::{
    field_bound_reconstruct, field_bound_split, field_bound_split_secure, FieldBindingError,
    FieldWitness,
};
pub use gf256::{
    gf_add, gf_div, gf_div_fast, gf_inv, gf_inv_fast, gf_mul, gf_mul_fast, gf_pow, gf_sub,
    GF_PRIMITIVE,
};
pub use prng::{PrngState, SplitMix64};
pub use refresh::{refresh_byte, refresh_bytes, zero_polynomial_byte};
pub use shamir::{
    max_participants, params_valid, reconstruct_byte, reconstruct_bytes, share_byte, share_bytes,
    share_bytes_secure, Share, ShareError, MAX_SECRET_BYTES,
};
