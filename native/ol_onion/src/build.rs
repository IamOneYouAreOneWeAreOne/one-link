//! Sender-side onion construction.
//!
//! Wraps a user payload in N layers of ChaCha20-Poly1305 AEAD, one
//! per hop in the chosen [`Circuit`]. The result is the
//! [`OnionPacket`] that the sender hands to the FIRST hop; each
//! relay along the path peels exactly one layer via
//! [`crate::peel_one_layer`] before forwarding.
//!
//! # Example
//!
//! ```no_run
//! use rand::rngs::OsRng;
//! use x25519_dalek::{PublicKey, StaticSecret};
//! use ol_onion::{
//!     build_onion, Circuit, HopDescriptor, HopId, HOP_ID_LEN,
//! };
//!
//! let sk = StaticSecret::from([1u8; 32]);
//! let dest = HopDescriptor {
//!     id: HopId::from_bytes([1u8; HOP_ID_LEN]),
//!     pubkey: PublicKey::from(&sk),
//! };
//! let circuit = Circuit::new(vec![dest]).unwrap();
//! let packet = build_onion(&circuit, b"payload", &mut OsRng).unwrap();
//! assert_eq!(packet.hops_remaining, 0);
//! ```

use aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::canon::Writer;
use crate::circuit::Circuit;
use crate::errors::{OnionError, OnionResult};
use crate::keyderiv::derive_layer_key_sender;
use crate::packet::{
    onion_packet_size, OnionPacket, AEAD_NONCE_LEN, HOP_ID_LEN, MAX_USER_PAYLOAD,
    ONION_PACKET_VERSION,
};

/// Build an onion packet wrapping `payload` for delivery along
/// `circuit`. The sender hands the returned [`OnionPacket`] to the
/// first hop (`circuit.hops()[0]`); each subsequent hop is reached
/// by peeling one layer at a time.
///
/// `rng` provides the per-layer ephemeral X25519 secrets +
/// per-layer AEAD nonces. Must be cryptographically secure.
///
/// Refuses `payload` longer than [`MAX_USER_PAYLOAD`] so the final
/// outermost packet still fits inside [`TRANSPORT_PAD_HINT`].
pub fn build_onion<R: RngCore + CryptoRng>(
    circuit: &Circuit,
    payload: &[u8],
    rng: &mut R,
) -> OnionResult<OnionPacket> {
    if payload.len() > MAX_USER_PAYLOAD {
        return Err(OnionError::PayloadOversize {
            got: payload.len(),
            max: MAX_USER_PAYLOAD,
        });
    }
    let hops = circuit.hops();
    if hops.is_empty() {
        return Err(OnionError::EmptyCircuit);
    }

    // Build from the INNERMOST layer outward. The innermost layer
    // (destination) wraps just the user payload; each subsequent
    // outer layer wraps `next_hop_id || previous_OnionPacket_bytes`.
    let mut current_plaintext: Vec<u8> = payload.to_vec();
    let mut current_packet: Option<OnionPacket> = None;

    // Iterate hops from last (destination) to first (entry relay).
    let n = hops.len();
    for i in (0..n).rev() {
        let hop = &hops[i];

        // Per-layer ephemeral keypair for the sender.
        let mut esk_bytes = [0u8; 32];
        rng.fill_bytes(&mut esk_bytes);
        let esk = StaticSecret::from(esk_bytes);
        let epk: PublicKey = (&esk).into();
        // Zeroize the seed bytes — `esk` retains its own copy via
        // StaticSecret's clamping.
        let _ = esk_bytes;

        // Per-layer AEAD nonce.
        let mut aead_nonce = [0u8; AEAD_NONCE_LEN];
        rng.fill_bytes(&mut aead_nonce);

        // hops_remaining is the count of relays AFTER this one.
        // For the destination (i == n-1), it's 0. For the first
        // relay (i == 0) in an n-hop circuit, it's n-1.
        // n ≤ MAX_HOPS = 5, so (n - 1 - i) fits in u8 trivially.
        debug_assert!(n <= crate::packet::MAX_HOPS);
        let hops_remaining = u8::try_from(n - 1 - i)
            .map_err(|_| OnionError::Internal("validated hop count exceeds u8"))?;

        // Layer key.
        let layer_key = derive_layer_key_sender(&esk, &hop.pubkey);
        let cipher = ChaCha20Poly1305::new_from_slice(layer_key.as_bytes())
            .map_err(|_| OnionError::Internal("ChaCha20Poly1305 key init"))?;

        // Construct AAD: the would-be packet's header bytes.
        // We need to know ciphertext_len in advance because it's
        // bound in the AAD — compute plaintext_len + 16 (Poly1305
        // tag).
        let plaintext_len = current_plaintext.len();
        let ciphertext_len = plaintext_len + 16;
        let mut aad = Writer::with_capacity(crate::packet::ONION_HEADER_LEN);
        aad.write_u8(ONION_PACKET_VERSION);
        aad.write_u8(hops_remaining);
        aad.write_fixed(epk.as_bytes());
        aad.write_fixed(&aead_nonce);
        // ciphertext_len ≤ TRANSPORT_PAD_HINT = 1280, bounded by the
        // payload-size check at function entry; fits in u16 trivially.
        debug_assert!(u16::try_from(ciphertext_len).is_ok());
        let ciphertext_len_u16 = u16::try_from(ciphertext_len)
            .map_err(|_| OnionError::Internal("onion ciphertext length exceeds u16"))?;
        aad.write_u16(ciphertext_len_u16);
        let aad_bytes = aad.into_bytes();

        let ciphertext = cipher
            .encrypt(
                (&aead_nonce).into(),
                Payload {
                    msg: &current_plaintext,
                    aad: &aad_bytes,
                },
            )
            .map_err(|_| OnionError::Internal("AEAD encrypt"))?;

        let packet = OnionPacket {
            version: ONION_PACKET_VERSION,
            hops_remaining,
            ephem_pubkey: *epk.as_bytes(),
            aead_nonce,
            ciphertext,
        };

        // For the NEXT iteration (one layer outward), the plaintext
        // becomes: this hop's id (so the previous relay knows where
        // to forward) || this layer's encoded packet.
        if i > 0 {
            let mut next_plain =
                Vec::with_capacity(HOP_ID_LEN + onion_packet_size(packet.ciphertext.len()));
            next_plain.extend_from_slice(hop.id.as_bytes());
            next_plain.extend_from_slice(&packet.encode());
            current_plaintext = next_plain;
        } else {
            // Top-level: nothing wraps this packet. Sender hands it
            // to hops[0].
        }
        current_packet = Some(packet);
    }

    let outer = current_packet.ok_or(OnionError::Internal("no layers built"))?;
    Ok(outer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hop::{HopDescriptor, HopId};
    use rand::rngs::OsRng;
    use x25519_dalek::StaticSecret;

    fn fake_hop(i: u8) -> (StaticSecret, HopDescriptor) {
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
    fn one_hop_circuit_builds() {
        let (_, dest) = fake_hop(1);
        let circuit = Circuit::new(vec![dest]).unwrap();
        let packet = build_onion(&circuit, b"hello", &mut OsRng).unwrap();
        assert_eq!(packet.hops_remaining, 0);
        assert!(packet.ciphertext.len() >= 5 + 16); // payload + tag
    }

    #[test]
    fn three_hop_circuit_builds() {
        let (_, r1) = fake_hop(1);
        let (_, r2) = fake_hop(2);
        let (_, r3) = fake_hop(3);
        let (_, dest) = fake_hop(4);
        let circuit = Circuit::new(vec![r1, r2, r3, dest]).unwrap();
        let packet = build_onion(&circuit, b"hi", &mut OsRng).unwrap();
        // Outermost packet has hops_remaining = 3 (relays after the
        // first hop, which is the destination at index 3).
        assert_eq!(packet.hops_remaining, 3);
    }

    #[test]
    fn payload_oversize_rejected() {
        let (_, dest) = fake_hop(1);
        let circuit = Circuit::new(vec![dest]).unwrap();
        let huge = vec![0u8; MAX_USER_PAYLOAD + 1];
        let err = build_onion(&circuit, &huge, &mut OsRng).unwrap_err();
        assert!(matches!(err, OnionError::PayloadOversize { .. }));
    }

    #[test]
    fn outer_packet_size_under_transport_pad() {
        use crate::packet::TRANSPORT_PAD_HINT;
        let (_, r1) = fake_hop(1);
        let (_, r2) = fake_hop(2);
        let (_, r3) = fake_hop(3);
        let (_, dest) = fake_hop(4);
        let circuit = Circuit::new(vec![r1, r2, r3, dest]).unwrap();
        let payload = vec![0u8; MAX_USER_PAYLOAD / 2];
        let packet = build_onion(&circuit, &payload, &mut OsRng).unwrap();
        assert!(packet.encode().len() <= TRANSPORT_PAD_HINT);
    }
}
