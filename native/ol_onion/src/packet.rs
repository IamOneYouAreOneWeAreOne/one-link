//! Onion packet wire format.
//!
//! ## Design choice: shrinking nested-AEAD packets
//!
//! Each peel removes one layer of AEAD wrapping. The packet shrinks
//! by exactly [`PER_LAYER_OVERHEAD`] bytes per hop. The TRANSPORT
//! layer (QUIC datagram or UDP) is expected to pad all onion
//! packets to a uniform size (typically [`TRANSPORT_PAD_HINT`])
//! before sending — that's where the "fixed-size for global
//! passive adversary" property is enforced.
//!
//! Trade-off vs full Sphinx fixed-header design:
//! - PRO: every byte of the wire format is auditable in <300 LOC,
//!   no header-shifting or keystream-XOR loops to get wrong.
//! - PRO: no point-blinding arithmetic — each layer carries its
//!   own ephemeral pubkey directly.
//! - CON: ~96 extra bytes of ephemeral material per 3-hop circuit
//!   vs. Sphinx's single packet-level ephemeral.
//! - CON: relay-to-relay packet size shrinks predictably so the
//!   transport layer MUST pad. If the transport forgets to pad,
//!   hop count leaks. Document this contract; F3 acceptance tests
//!   gate it.
//!
//! ## Wire layout
//!
//! ```text
//!   version           : u8           [= ONION_PACKET_VERSION]
//!   hops_remaining    : u8           [number of further relays after this hop]
//!   ephem_pubkey      : [u8; 32]     [this layer's sender ephemeral X25519]
//!   aead_nonce        : [u8; 12]     [ChaCha20-Poly1305 nonce]
//!   ciphertext_len    : u16 BE       [length of the AEAD ciphertext + tag]
//!   ciphertext        : variable     [AEAD-sealed body for this hop]
//! ```
//!
//! The AEAD-decrypted body is one of:
//!
//! - **Relay layer** (hops_remaining > 0):
//!     `next_hop_id (32 B) || inner_OnionPacket_bytes (variable)`
//! - **Destination layer** (hops_remaining == 0):
//!     `user_payload (variable)`
//!
//! The version + hops_remaining + ephem_pubkey + aead_nonce +
//! ciphertext_len are bound into the AEAD AAD so a relay cannot
//! tamper with packet metadata without breaking the next hop's
//! verify.

use crate::canon::{Reader, Writer};
use crate::errors::{OnionError, OnionResult};

/// Wire protocol version byte.
pub const ONION_PACKET_VERSION: u8 = 1;

/// Length of the X25519 ephemeral pubkey carried in each layer.
pub const EPHEM_PUBKEY_LEN: usize = 32;

/// Length of the ChaCha20-Poly1305 nonce.
pub const AEAD_NONCE_LEN: usize = 12;

/// Length of the Poly1305 authentication tag appended to each
/// AEAD ciphertext.
pub const AEAD_TAG_LEN: usize = 16;

/// Length of a [`crate::hop::HopId`] in bytes.
pub const HOP_ID_LEN: usize = 32;

/// Bytes added per layer of onion wrapping:
/// version (1) + hops_remaining (1) + ephem_pubkey (32) +
/// aead_nonce (12) + ciphertext_len (2) + AEAD tag (16) +
/// hop_id pointing to next hop (32, for relay layers).
pub const PER_LAYER_OVERHEAD: usize = 1 + 1 + EPHEM_PUBKEY_LEN
    + AEAD_NONCE_LEN
    + 2
    + AEAD_TAG_LEN
    + HOP_ID_LEN;

/// Maximum supported circuit length (destination + relays). 5 covers
/// 1-hop ("pinned-contact") + 3-hop ("paranoid") + 1 hop of headroom.
pub const MAX_HOPS: usize = 5;

/// Suggested uniform transport-level packet size. Daemons SHOULD
/// pad onion packets to this length with random bytes before
/// transmitting; that's where the "fixed-size on the wire" property
/// is enforced (this layer's packet structure is variable per peel).
pub const TRANSPORT_PAD_HINT: usize = 1280;

/// Reserved for [`OnionError::PayloadOversize`] checks; payload at
/// the innermost layer is capped so the outermost packet still
/// fits inside [`TRANSPORT_PAD_HINT`] even at MAX_HOPS hops.
pub const MAX_USER_PAYLOAD: usize =
    TRANSPORT_PAD_HINT.saturating_sub(MAX_HOPS * PER_LAYER_OVERHEAD);

/// Length of the per-layer onion header bytes covered by the AEAD
/// AAD (used by both encrypt + decrypt to bind the metadata).
pub const ONION_HEADER_LEN: usize = 1 + 1 + EPHEM_PUBKEY_LEN + AEAD_NONCE_LEN + 2;

/// Total bytes of [`OnionPacket`] when its ciphertext is `n` bytes.
pub fn onion_packet_size(ciphertext_len: usize) -> usize {
    ONION_HEADER_LEN + ciphertext_len
}

/// Convenience constant — the fully-padded packet length used by the
/// transport layer for fixed-size shipping. Equal to
/// [`TRANSPORT_PAD_HINT`].
pub const ONION_PACKET_SIZE: usize = TRANSPORT_PAD_HINT;

/// Per-layer onion packet as it travels between hops.
///
/// Constructed by [`crate::build_onion`]; consumed by
/// [`crate::peel_one_layer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionPacket {
    /// Wire protocol version.
    pub version: u8,
    /// Number of additional relays after the current hop. `0` means
    /// the current hop is the destination.
    pub hops_remaining: u8,
    /// Sender's ephemeral X25519 pubkey for this layer.
    pub ephem_pubkey: [u8; EPHEM_PUBKEY_LEN],
    /// ChaCha20-Poly1305 nonce for this layer.
    pub aead_nonce: [u8; AEAD_NONCE_LEN],
    /// AEAD-sealed body (ciphertext || tag).
    pub ciphertext: Vec<u8>,
}

impl OnionPacket {
    /// Encode to the wire byte form.
    pub fn encode(&self) -> Vec<u8> {
        let total = ONION_HEADER_LEN + self.ciphertext.len();
        let mut w = Writer::with_capacity(total);
        w.write_u8(self.version);
        w.write_u8(self.hops_remaining);
        w.write_fixed(&self.ephem_pubkey);
        w.write_fixed(&self.aead_nonce);
        // u16 BE ciphertext length.
        w.write_u16(self.ciphertext.len() as u16);
        w.write_fixed(&self.ciphertext);
        w.into_bytes()
    }

    /// Decode from the wire byte form.
    pub fn decode(bytes: &[u8]) -> OnionResult<Self> {
        let mut r = Reader::new(bytes);
        let version = r.read_u8()?;
        if version != ONION_PACKET_VERSION {
            return Err(OnionError::UnsupportedVersion {
                got: version,
                supported: ONION_PACKET_VERSION,
            });
        }
        let hops_remaining = r.read_u8()?;
        let ephem_slice = r.read_fixed(EPHEM_PUBKEY_LEN)?;
        let mut ephem_pubkey = [0u8; EPHEM_PUBKEY_LEN];
        ephem_pubkey.copy_from_slice(ephem_slice);
        let nonce_slice = r.read_fixed(AEAD_NONCE_LEN)?;
        let mut aead_nonce = [0u8; AEAD_NONCE_LEN];
        aead_nonce.copy_from_slice(nonce_slice);
        let ciphertext_len = r.read_u16()? as usize;
        // Refuse oversize length before allocating.
        if ciphertext_len > TRANSPORT_PAD_HINT {
            return Err(OnionError::BadFrameSize {
                got: ciphertext_len,
                expected: TRANSPORT_PAD_HINT,
            });
        }
        let ct_slice = r.read_fixed(ciphertext_len)?;
        Ok(Self {
            version,
            hops_remaining,
            ephem_pubkey,
            aead_nonce,
            ciphertext: ct_slice.to_vec(),
        })
    }

    /// Build the AEAD AAD covering everything except the ciphertext
    /// itself. Both sender and relay compute this independently and
    /// the AEAD bind ensures neither can lie about the metadata.
    pub fn aad(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(ONION_HEADER_LEN);
        w.write_u8(self.version);
        w.write_u8(self.hops_remaining);
        w.write_fixed(&self.ephem_pubkey);
        w.write_fixed(&self.aead_nonce);
        w.write_u16(self.ciphertext.len() as u16);
        w.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> OnionPacket {
        OnionPacket {
            version: ONION_PACKET_VERSION,
            hops_remaining: 2,
            ephem_pubkey: [0xAB; EPHEM_PUBKEY_LEN],
            aead_nonce: [0xCD; AEAD_NONCE_LEN],
            ciphertext: vec![0u8; 64],
        }
    }

    #[test]
    fn encode_decode_round_trip() {
        let p = fixture();
        let enc = p.encode();
        let dec = OnionPacket::decode(&enc).unwrap();
        assert_eq!(p, dec);
    }

    #[test]
    fn unsupported_version_rejected() {
        let mut bytes = fixture().encode();
        bytes[0] = 0xFE;
        let err = OnionPacket::decode(&bytes).unwrap_err();
        assert!(matches!(err, OnionError::UnsupportedVersion { got: 0xFE, .. }));
    }

    #[test]
    fn oversize_ciphertext_length_rejected() {
        // Construct a packet whose declared ciphertext length is
        // larger than TRANSPORT_PAD_HINT — refuse before allocating.
        let mut w = Writer::new();
        w.write_u8(ONION_PACKET_VERSION);
        w.write_u8(0);
        w.write_fixed(&[0u8; EPHEM_PUBKEY_LEN]);
        w.write_fixed(&[0u8; AEAD_NONCE_LEN]);
        w.write_u16((TRANSPORT_PAD_HINT + 1) as u16);
        // No actual bytes follow — decode should fail at length check.
        let bytes = w.into_bytes();
        let err = OnionPacket::decode(&bytes).unwrap_err();
        assert!(matches!(
            err,
            OnionError::BadFrameSize { got, expected }
                if got == TRANSPORT_PAD_HINT + 1 && expected == TRANSPORT_PAD_HINT
        ));
    }

    #[test]
    fn truncated_bytes_rejected() {
        let bytes = vec![ONION_PACKET_VERSION, 0, 0xAB];
        let err = OnionPacket::decode(&bytes).unwrap_err();
        assert!(matches!(err, OnionError::Truncated { .. }));
    }

    #[test]
    fn aad_matches_encoded_prefix() {
        let p = fixture();
        let enc = p.encode();
        let aad = p.aad();
        assert_eq!(&enc[..aad.len()], aad.as_slice());
    }

    #[test]
    fn constants_self_consistent() {
        assert!(MAX_USER_PAYLOAD > 0);
        assert!(TRANSPORT_PAD_HINT >= MAX_HOPS * PER_LAYER_OVERHEAD);
    }
}
