//! `ol_aead` — per-chunk AEAD pipeline for One Link's file engine v2.
//!
//! Implements [ADR-0002](../../../docs/decisions/0002-aead-frame.md):
//!
//! - **Primary cipher**: AES-256-GCM via the RustCrypto `aes-gcm` crate.
//!   Hardware-accelerated by AES-NI / VAES on x86 and ARMv8 cryptography
//!   extensions on ARM64. ~5 GiB/s/core sustained on modern hardware.
//! - **Fallback cipher**: ChaCha20-Poly1305 via the RustCrypto
//!   `chacha20poly1305` crate. Constant-time by construction in software;
//!   used when the runtime detects no hardware AES support. ~3 GiB/s/core.
//! - **Frame layout**: a CDC chunk (8-256 KiB per [ADR-0001]) is divided
//!   internally into one or more 16 KiB AEAD frames. Each frame has its
//!   own nonce + auth tag. FUSE random-access reads decrypt only the
//!   frame containing the requested offset, capping read amplification at
//!   16-32 KiB.
//! - **Nonce construction**: 96-bit nonce = `chunk_id_lo64 || frame_index_u32`.
//!   chunk_id_lo64 derives from the BLAKE3 chunk address (raw or
//!   convergent per [ADR-0006]). frame_index distinguishes frames within
//!   a chunk. Reuse-impossible by construction.
//! - **AAD binding**: each frame's authenticated additional data is the
//!   full 32-byte BLAKE3 chunk_id, so a tampered chunk_id invalidates
//!   the auth tag.
//! - **Per-chunk forward-secret keys**: callers derive keys via
//!   `ol_chunk::blake3_wrap::derive_aead_key` from a ratchet chain key
//!   plus the chunk_id. This crate accepts a 32-byte key and does not
//!   manage ratchet state itself; ratchet machinery lives in `ol_ratchet`
//!   (Phase C).
//! - **Constant-time tag compare**: handled by the underlying
//!   RustCrypto AEAD trait (uses `subtle::ConstantTimeEq`).
//! - **Zeroize**: all key material wraps in `Zeroizing` so dropping a
//!   key clears the memory. Side-channel hardening per [ADR-0002].
//!
//! ## Throughput target
//!
//! Phase A1 verification gate: ≥ 4 GiB/s/core (AES-NI) or ≥ 3 GiB/s/core
//! (ChaCha20-Poly1305) measured by `benches/aead_bench.rs`.
//!
//! ## Wire format
//!
//! For a chunk plaintext of length `L`, the on-wire ciphertext layout
//! follows [ADR-0003]:
//!
//! ```text
//! +-------------------+-------------------+----+-------------------+----+
//! | frame 0 plaintext | frame 1 plaintext | T0 | frame 2 plaintext | T1 |   ...
//! |   (16 KiB)        |   (16 KiB)        |16B |   (16 KiB)        |16B |
//! +-------------------+-------------------+----+-------------------+----+
//! ```
//!
//! ...where each `T_i` is the 16-byte authentication tag for the
//! preceding 16 KiB plaintext frame, and the LAST frame may be shorter
//! than 16 KiB. Total ciphertext length = `L + ceil(L/16384) * 16`.
//!
//! Wait — the layout above is informational, not normative. Implementations
//! pack as `[ct_frame_0 || tag_0 || ct_frame_1 || tag_1 || ...]` for
//! sequential streaming friendliness. The [`encrypt_chunk`] /
//! [`decrypt_chunk`] functions emit/consume that exact ordering.
//!
//! [ADR-0001]: ../../../docs/decisions/0001-cdc-kernel.md
//! [ADR-0002]: ../../../docs/decisions/0002-aead-frame.md
//! [ADR-0003]: ../../../docs/decisions/0003-on-disk-format.md
//! [ADR-0006]: ../../../docs/decisions/0006-blake3-derive-scheme.md

#![doc(html_root_url = "https://docs.rs/ol_aead/0.21.0")]

pub mod cipher;
pub mod convergent;
pub mod error;
pub mod frame;
pub mod key;
pub mod nonce;

pub use cipher::{AeadCipher, AeadKind, FrameKey};
pub use convergent::{
    content_type_from_extension, derive_convergent_aead_key, is_convergent_safe, resolve_mode,
    ContentType, ConvergentPolicy, EncryptionMode, CONVERGENT_AEAD_KEY_CONTEXT,
};
pub use error::AeadError;
pub use frame::{decrypt_chunk, decrypt_frame, encrypt_chunk, encrypt_frame, FrameRef};
pub use key::{ChunkAeadKey, FRAME_KEY_LEN};
pub use nonce::{frame_nonce, FRAME_NONCE_LEN};

/// Reference exports of the layout constants from `ol_chunk`. Available
/// so downstream callers don't have to depend on `ol_chunk` directly to
/// know the frame size.
pub use ol_chunk::{AEAD_FRAME_PLAINTEXT_LEN, AEAD_TAG_LEN};

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
