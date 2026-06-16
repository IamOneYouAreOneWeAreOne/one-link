//! Relay-side single-layer peel.
//!
//! Each relay receives an [`OnionPacket`], runs ECDH with its
//! long-term X25519 secret + the packet's ephemeral pubkey,
//! derives this layer's AEAD key, decrypts one layer, and either:
//!
//! - **Forwards**: emits `(next_hop_id, inner_packet_bytes)` for the
//!   transport to send to the next relay.
//! - **Delivers**: this relay IS the destination; emits the
//!   plaintext user payload.
//!
//! # Example
//!
//! ```no_run
//! use rand::rngs::OsRng;
//! use x25519_dalek::{PublicKey, StaticSecret};
//! use ol_onion::{
//!     build_onion, peel_one_layer, Circuit, HopDescriptor, HopId,
//!     PeelOutcome, HOP_ID_LEN,
//! };
//!
//! let sk = StaticSecret::from([7u8; 32]);
//! let dest = HopDescriptor {
//!     id: HopId::from_bytes([7u8; HOP_ID_LEN]),
//!     pubkey: PublicKey::from(&sk),
//! };
//! let circuit = Circuit::new(vec![dest]).unwrap();
//! let packet = build_onion(&circuit, b"payload", &mut OsRng).unwrap();
//! match peel_one_layer(&sk, &packet).unwrap() {
//!     PeelOutcome::Deliver { payload } => assert_eq!(payload, b"payload"),
//!     PeelOutcome::Forward { .. } => panic!("expected Deliver"),
//! }
//! ```

use aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::canon::Reader;
use crate::errors::{OnionError, OnionResult};
use crate::hop::{HopId, HOP_ID_LEN};
use crate::keyderiv::derive_layer_key_relay;
use crate::packet::OnionPacket;

/// Outcome of a single peel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeelOutcome {
    /// This relay forwards the inner packet to `next_hop`.
    Forward {
        /// Routing identifier of the next hop the inner packet
        /// should be sent to.
        next_hop: HopId,
        /// Encoded bytes of the inner [`OnionPacket`] ready for
        /// transmission.
        inner_packet_bytes: Vec<u8>,
    },
    /// This relay is the destination. Deliver the payload.
    Deliver {
        /// User payload, as encrypted by the sender.
        payload: Vec<u8>,
    },
}

/// Peel one layer of onion encryption.
///
/// `relay_static_sk` is the relay's long-term X25519 secret.
/// `packet` is the incoming layer.
pub fn peel_one_layer(
    relay_static_sk: &StaticSecret,
    packet: &OnionPacket,
) -> OnionResult<PeelOutcome> {
    // Verify the ephemeral pubkey is not all-zero (small-order
    // defense). x25519-dalek folds small-order to zero downstream
    // so we check explicitly first.
    if packet.ephem_pubkey.iter().all(|&b| b == 0) {
        return Err(OnionError::SmallOrderPubkey);
    }

    let sender_epk = PublicKey::from(packet.ephem_pubkey);
    let layer_key = derive_layer_key_relay(relay_static_sk, &sender_epk);
    let cipher = ChaCha20Poly1305::new_from_slice(layer_key.as_bytes())
        .map_err(|_| OnionError::Internal("ChaCha20Poly1305 key init"))?;

    let aad = packet.aad();
    let plaintext = cipher
        .decrypt(
            (&packet.aead_nonce).into(),
            Payload {
                msg: &packet.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| OnionError::AeadFail)?;

    if packet.hops_remaining == 0 {
        // Destination layer: the whole plaintext is the user payload.
        Ok(PeelOutcome::Deliver { payload: plaintext })
    } else {
        // Relay layer: plaintext is `next_hop_id (32) || inner_packet_bytes`.
        if plaintext.len() < HOP_ID_LEN {
            return Err(OnionError::Internal(
                "relay-layer plaintext shorter than HOP_ID_LEN",
            ));
        }
        let mut r = Reader::new(&plaintext);
        let next_hop_slice = r.read_fixed(HOP_ID_LEN)?;
        let mut id_bytes = [0u8; HOP_ID_LEN];
        id_bytes.copy_from_slice(next_hop_slice);
        let next_hop = HopId::from_bytes(id_bytes);
        // The rest of the plaintext is the inner OnionPacket's
        // encoded bytes — emit as-is for the transport.
        let inner_packet_bytes = plaintext[HOP_ID_LEN..].to_vec();
        Ok(PeelOutcome::Forward {
            next_hop,
            inner_packet_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::build_onion;
    use crate::circuit::Circuit;
    use crate::hop::HopDescriptor;
    use rand::rngs::OsRng;

    fn fake_hop_pair(i: u8) -> (StaticSecret, HopDescriptor) {
        let sk = StaticSecret::from([i; 32]);
        let pk = PublicKey::from(&sk);
        (
            sk,
            HopDescriptor {
                id: HopId::from_bytes([i; HOP_ID_LEN]),
                pubkey: pk,
            },
        )
    }

    #[test]
    fn one_hop_circuit_round_trip() {
        let (dest_sk, dest) = fake_hop_pair(1);
        let circuit = Circuit::new(vec![dest]).unwrap();
        let packet = build_onion(&circuit, b"hello world", &mut OsRng).unwrap();
        let outcome = peel_one_layer(&dest_sk, &packet).unwrap();
        match outcome {
            PeelOutcome::Deliver { payload } => assert_eq!(payload, b"hello world"),
            PeelOutcome::Forward { .. } => panic!("expected Deliver"),
        }
    }

    #[test]
    fn two_hop_circuit_round_trip() {
        let (r1_sk, r1) = fake_hop_pair(10);
        let (r2_sk, r2) = fake_hop_pair(20);
        let circuit = Circuit::new(vec![r1.clone(), r2.clone()]).unwrap();
        let packet = build_onion(&circuit, b"two-hop", &mut OsRng).unwrap();

        // r1 peels first
        let outcome = peel_one_layer(&r1_sk, &packet).unwrap();
        let (next_hop, inner_bytes) = match outcome {
            PeelOutcome::Forward {
                next_hop,
                inner_packet_bytes,
            } => (next_hop, inner_packet_bytes),
            _ => panic!("expected Forward"),
        };
        assert_eq!(next_hop, r2.id);
        // r2 peels next
        let inner = OnionPacket::decode(&inner_bytes).unwrap();
        let outcome = peel_one_layer(&r2_sk, &inner).unwrap();
        match outcome {
            PeelOutcome::Deliver { payload } => assert_eq!(payload, b"two-hop"),
            _ => panic!("expected Deliver"),
        }
    }

    #[test]
    fn three_hop_circuit_round_trip() {
        let (r1_sk, r1) = fake_hop_pair(10);
        let (r2_sk, r2) = fake_hop_pair(20);
        let (r3_sk, r3) = fake_hop_pair(30);
        let (dest_sk, dest) = fake_hop_pair(40);
        let circuit = Circuit::new(vec![r1, r2.clone(), r3.clone(), dest.clone()]).unwrap();
        let packet = build_onion(&circuit, b"three-hop test", &mut OsRng).unwrap();

        // r1 → r2
        let o1 = peel_one_layer(&r1_sk, &packet).unwrap();
        let (nh1, b1) = match o1 {
            PeelOutcome::Forward {
                next_hop,
                inner_packet_bytes,
            } => (next_hop, inner_packet_bytes),
            _ => panic!(),
        };
        assert_eq!(nh1, r2.id);
        // r2 → r3
        let p2 = OnionPacket::decode(&b1).unwrap();
        let o2 = peel_one_layer(&r2_sk, &p2).unwrap();
        let (nh2, b2) = match o2 {
            PeelOutcome::Forward {
                next_hop,
                inner_packet_bytes,
            } => (next_hop, inner_packet_bytes),
            _ => panic!(),
        };
        assert_eq!(nh2, r3.id);
        // r3 → dest
        let p3 = OnionPacket::decode(&b2).unwrap();
        let o3 = peel_one_layer(&r3_sk, &p3).unwrap();
        let (nh3, b3) = match o3 {
            PeelOutcome::Forward {
                next_hop,
                inner_packet_bytes,
            } => (next_hop, inner_packet_bytes),
            _ => panic!(),
        };
        assert_eq!(nh3, dest.id);
        // dest delivers
        let p4 = OnionPacket::decode(&b3).unwrap();
        let o4 = peel_one_layer(&dest_sk, &p4).unwrap();
        match o4 {
            PeelOutcome::Deliver { payload } => assert_eq!(payload, b"three-hop test"),
            _ => panic!(),
        }
    }

    #[test]
    fn wrong_relay_key_fails_aead() {
        let (_, r1) = fake_hop_pair(10);
        let (_, dest) = fake_hop_pair(20);
        let circuit = Circuit::new(vec![r1, dest]).unwrap();
        let packet = build_onion(&circuit, b"x", &mut OsRng).unwrap();
        let wrong_sk = StaticSecret::from([99u8; 32]);
        let err = peel_one_layer(&wrong_sk, &packet).unwrap_err();
        assert_eq!(err, OnionError::AeadFail);
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let (dest_sk, dest) = fake_hop_pair(1);
        let circuit = Circuit::new(vec![dest]).unwrap();
        let mut packet = build_onion(&circuit, b"hello", &mut OsRng).unwrap();
        packet.ciphertext[0] ^= 0x01;
        let err = peel_one_layer(&dest_sk, &packet).unwrap_err();
        assert_eq!(err, OnionError::AeadFail);
    }

    #[test]
    fn tampered_aad_rejected() {
        let (dest_sk, dest) = fake_hop_pair(1);
        let circuit = Circuit::new(vec![dest]).unwrap();
        let mut packet = build_onion(&circuit, b"hello", &mut OsRng).unwrap();
        // Flip hops_remaining — should change AAD and break AEAD.
        packet.hops_remaining ^= 0x01;
        let err = peel_one_layer(&dest_sk, &packet).unwrap_err();
        assert_eq!(err, OnionError::AeadFail);
    }

    #[test]
    fn small_order_pubkey_rejected() {
        let (dest_sk, dest) = fake_hop_pair(1);
        let circuit = Circuit::new(vec![dest]).unwrap();
        let mut packet = build_onion(&circuit, b"hello", &mut OsRng).unwrap();
        packet.ephem_pubkey = [0u8; 32];
        let err = peel_one_layer(&dest_sk, &packet).unwrap_err();
        assert_eq!(err, OnionError::SmallOrderPubkey);
    }
}
