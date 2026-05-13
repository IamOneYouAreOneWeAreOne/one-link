//! [`HopDescriptor`] — what the sender knows about each relay in
//! a circuit.
//!
//! Each relay is identified by:
//!
//! - A [`HopId`] — 32 raw bytes the sender pinned during peer
//!   discovery (typically the relay's BLAKE3(identity-pubkey)).
//!   Forwarded in cleartext between hops so the previous hop can
//!   address the packet to the right next-hop.
//! - An [`x25519_dalek::PublicKey`] — the relay's long-term X25519
//!   pubkey used for the ECDH that derives each layer's AEAD key.

use x25519_dalek::PublicKey;
use zeroize::Zeroize;

/// Length of a [`HopId`] in bytes.
pub const HOP_ID_LEN: usize = 32;

/// 32-byte routing identifier for a hop. Typically BLAKE3(identity)
/// from the discovery layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Zeroize)]
pub struct HopId(pub [u8; HOP_ID_LEN]);

impl HopId {
    /// Wrap raw bytes.
    pub fn from_bytes(b: [u8; HOP_ID_LEN]) -> Self {
        Self(b)
    }

    /// View the raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; HOP_ID_LEN] {
        &self.0
    }
}

/// Sender-side view of a relay in the circuit.
///
/// Clone-able because the sender hands a copy to each layer of the
/// onion-construction loop. Drop zeroizes — the long-term pubkey
/// isn't sensitive but consistent handling keeps the audit story
/// simple.
#[derive(Debug, Clone)]
pub struct HopDescriptor {
    /// Routing identifier — used by the previous hop to address
    /// the packet to this relay.
    pub id: HopId,
    /// Long-term X25519 pubkey — used by the sender to derive this
    /// layer's AEAD key via ephemeral ECDH.
    pub pubkey: PublicKey,
}

impl HopDescriptor {
    /// Construct from raw 32-byte id + 32-byte X25519 pubkey bytes.
    pub fn new(id_bytes: [u8; HOP_ID_LEN], pubkey_bytes: [u8; 32]) -> Self {
        Self {
            id: HopId::from_bytes(id_bytes),
            pubkey: PublicKey::from(pubkey_bytes),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::StaticSecret;

    #[test]
    fn hop_id_from_bytes_and_back() {
        let raw = [7u8; HOP_ID_LEN];
        let h = HopId::from_bytes(raw);
        assert_eq!(h.as_bytes(), &raw);
    }

    #[test]
    fn hop_descriptor_roundtrip() {
        let sk = StaticSecret::from([1u8; 32]);
        let pk = PublicKey::from(&sk).to_bytes();
        let id = [42u8; HOP_ID_LEN];
        let d = HopDescriptor::new(id, pk);
        assert_eq!(d.id.as_bytes(), &id);
        assert_eq!(d.pubkey.to_bytes(), pk);
    }

    #[test]
    fn hop_id_equality_constant_time_friendly() {
        let a = HopId::from_bytes([1u8; HOP_ID_LEN]);
        let b = HopId::from_bytes([1u8; HOP_ID_LEN]);
        let c = HopId::from_bytes([2u8; HOP_ID_LEN]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
