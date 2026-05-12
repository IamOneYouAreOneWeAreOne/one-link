//! Coherence Mesh Phase F1.1 — threshold secret sharing with optional
//! coherence-field-bound recovery.
//!
//! Ports `OneField/onefield/privacy/sharding.cl` (Tier 15 production, reviewed
//! 2026-04-19) to Rust + adds the **field-binding layer**: shares can be
//! XOR-masked with one-time pads derived from the coherence-field topology
//! at mint time, so even an attacker who captures all N raw shares cannot
//! reconstruct without ALSO reproducing the field witness.
//!
//! ## Layers
//!
//! - [`gf256`] — constant-time GF(2^8) arithmetic, AES primitive polynomial.
//! - [`prng`] — xoshiro256** for deterministic coefficient generation.
//! - [`shamir`] — split + reconstruct + Lagrange interpolation. Plain
//!   Shamir, identical math to the OneField source so encoders interop.
//! - [`refresh`] — proactive secret sharing (HJK 1995); rotate shares
//!   without changing the secret. Defeats static-breach attacks on N
//!   cloud-backed shares.
//! - [`field_bound`] — the alien-tech layer. Shares are XOR-masked with
//!   field-derived OTPs; reconstruction also requires the field witness.
//!
//! ## Security properties
//!
//! Plain Shamir gives:
//! - **Correctness**: any K shares recover S exactly (Lagrange).
//! - **Perfect secrecy**: any K-1 shares statistically independent of S.
//!
//! Field-bound recovery adds:
//! - **Topology-anchored secrecy**: even all N raw shares are useless
//!   without the field state at mint time + share-holder field scores.
//!   Cloud-backup captures and offline brute force become impossible.
//! - **Reproducibility gate**: the witness publicly commits to the field
//!   state, but knowing the commitment alone doesn't recover the OTPs.
//!
//! ## Use cases (One Link)
//!
//! - Identity master-key recovery: split the 32-byte master seed across
//!   3-of-5 trusted contacts; field-bind so cloud-backup leakage of all
//!   5 shares is harmless.
//! - Group admission: split a join token across incumbents; quorum
//!   required.
//! - Capability escrow: split high-privilege capability secrets so no
//!   single device holds full authority.

#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]

pub mod gf256;
pub mod prng;
pub mod shamir;
pub mod refresh;
pub mod field_bound;

pub use gf256::{
    gf_add, gf_div, gf_div_fast, gf_inv, gf_inv_fast, gf_mul, gf_mul_fast,
    gf_pow, gf_sub, GF_PRIMITIVE,
};
pub use prng::{PrngState, SplitMix64};
pub use shamir::{
    max_participants, params_valid, reconstruct_byte, reconstruct_bytes,
    share_byte, share_bytes, Share, ShareError,
};
pub use refresh::{refresh_byte, refresh_bytes, zero_polynomial_byte};
pub use field_bound::{
    field_bound_reconstruct, field_bound_split, FieldWitness,
    FieldBindingError,
};
