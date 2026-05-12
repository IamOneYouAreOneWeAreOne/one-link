//! `ol_pair_qr` — pair-by-QR Factor-1 trust establishment.
//!
//! Phase F2 of the Coherence Mesh plan. Two devices that have never
//! met derive a shared chain-key in person, with no third-party
//! infrastructure trusted at any point in the protocol.
//!
//! ## Threat model
//!
//! - **Network attacker (active MITM)**: can drop, modify, inject,
//!   replay anything on the wire. Cannot break Ed25519 or X25519.
//! - **Optical attacker (telephoto / digital relay of the QR)**:
//!   can photograph or live-stream the QR code from a distance, or
//!   relay it to a remote confederate.
//! - **Hardware attacker**: out of scope (covered by hwkey + duress
//!   layers).
//!
//! Defenses provided **without** relying on the network:
//!
//! 1. The QR carries an Ed25519-signed `Invite` whose body binds:
//!    the inviter's identity pubkey, an ephemeral X25519 pubkey, a
//!    one-time nonce, an expiry, and the capability scope being
//!    granted. A network attacker cannot tamper with the bytes the
//!    scanner sees.
//! 2. The scanner replies with its own signed
//!    [`PairResponse`](response::PairResponse) committed to the full
//!    transcript hash; the inviter verifies the transcript before
//!    completing.
//! 3. Both sides derive a [`Sas`](sas::Sas) — a short authentication
//!    string — from the transcript. Users compare the SAS out-of-band
//!    (verbally / visually) to detect any MITM, telephoto, or relay
//!    attack on the network channel.
//! 4. Optional **Factor-2 channel reciprocity** via
//!    [`ol_proximity_pair`] mixes a quantized-channel-bits secret
//!    into the final chain key, defeating remote-relay attacks even
//!    if the SAS check were skipped.
//!
//! ## Determinism
//!
//! Every wire frame is encoded via the strict length-prefixed
//! [`canon`] module. Same struct → same bytes, every platform,
//! every build. Required because the transcript hash is the trust
//! anchor and any encoder ambiguity = security hole.
//!
//! ## End-to-end example
//!
//! ```
//! use ed25519_dalek::SigningKey;
//! use rand_core::OsRng;
//!
//! use ol_pair_qr::invite::CapabilityScope;
//! use ol_pair_qr::{Inviter, Scanner};
//!
//! // Inviter generates a QR-encodable invite.
//! let mut inviter = Inviter::new(
//!     SigningKey::generate(&mut OsRng),
//!     &mut OsRng,
//!     1_900_000_000, // expiry_unix (year 2030+)
//!     CapabilityScope::from_bytes(b"contact:alice").unwrap(),
//! );
//! let qr_bytes = inviter.invite_bytes();
//!
//! // Scanner reads the QR, verifies, builds a response.
//! let scanner_sk = SigningKey::generate(&mut OsRng);
//! let now_unix = 100; // current wall clock
//! let (mut scanner, response_bytes) =
//!     Scanner::scan(scanner_sk, &qr_bytes, now_unix, &mut OsRng).unwrap();
//!
//! // Inviter receives the response, computes SAS for user comparison.
//! let sas_inviter = inviter.receive_response(&response_bytes).unwrap();
//! let sas_scanner = scanner.sas();
//! assert_eq!(sas_inviter, sas_scanner); // identical 5-word string
//!
//! // Users compare SAS verbally. On match, inviter confirms.
//! let (confirm_bytes, chain_key_inviter) = inviter.confirm().unwrap();
//! let chain_key_scanner = scanner.receive_confirm(&confirm_bytes).unwrap();
//!
//! // Both sides derive byte-identical 32-byte chain keys.
//! assert_eq!(chain_key_inviter, chain_key_scanner);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod canon;
pub mod chain_key;
pub mod confirm;
pub mod errors;
pub mod invite;
pub mod inviter;
pub mod response;
pub mod sas;
pub mod sas_words;
pub mod scanner;
pub mod transcript;

pub use chain_key::{derive_chain_key, mix_factor2_recip, ChainKey, CHAIN_KEY_LEN};
pub use confirm::PairConfirm;
pub use errors::PairError;
pub use invite::{CapabilityScope, Invite, INVITE_MAX_BYTES, INVITE_NONCE_LEN, INVITE_VERSION};
pub use inviter::{Inviter, InviterState};
pub use response::PairResponse;
pub use sas::{Sas, SAS_BITS, SAS_WORD_COUNT};
pub use scanner::{Scanner, ScannerState};
pub use transcript::{transcript_hash, TranscriptHash, TRANSCRIPT_LEN};

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Protocol identifier domain-separator. Every BLAKE3 derivation in
/// this crate mixes this string in so that cross-protocol output
/// re-use is computationally impossible.
pub const PROTOCOL_DOMAIN: &[u8] = b"OL-pair-qr-v1";
