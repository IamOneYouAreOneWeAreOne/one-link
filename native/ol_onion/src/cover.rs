//! Cover-traffic helpers — D05 from the integration map.
//!
//! Generates onion cover packets with the same encoded layout and length
//! as an equally shaped real packet. Their innermost plaintext starts
//! with a magic marker the destination uses to drop them. Layout/length
//! equality is not a claim of traffic indistinguishability: timing,
//! volume, route, and caller behavior are outside this module.
//!
//! ## Why a marker (vs purely-random payload)
//!
//! A purely-random innermost payload survives the destination's
//! AEAD verification (an attacker can't forge it without the
//! destination's secret key — only the SENDER can build it), but
//! the destination has no protocol-level way to distinguish a
//! cover packet from a real one. We need a way for the destination
//! to silently drop cover, otherwise:
//!
//!   1. The destination's app layer would surface garbage payloads.
//!   2. Cover and real traffic would compete for receive-side queue
//!      slots, defeating the energy advantage we're going for.
//!
//! Solution: prepend a 4-byte magic identifier (`COVER_MAGIC`).
//! Real-protocol payloads NEVER start with this sequence (the wire
//! protocol uses `make_msg` outputs which are length-prefixed JSON;
//! the first four bytes are always a frame length, which has the
//! high bits zero for valid frames < 256 MiB, never the 0xC0 0xCC
//! 0xE3 0xAF cover prefix).
//!
//! ## Encoded-layout equality
//!
//! After AEAD wrapping the cover marker + random body is exactly the
//! same length as wrapping a real payload of the same body length.
//! The marker is not visible without the innermost layer's secret key.
//! This does not establish that a global observer sees identical traffic
//! distributions or cannot classify cover using other metadata.
//!
//! ## Determinism for testing
//!
//! `build_cover_packet` takes a caller-supplied `RngCore + CryptoRng`,
//! so tests can drive it with a seeded RNG for byte-stable output.
//! The marker bytes are constants.

use rand_core::{CryptoRng, RngCore};

use crate::build::build_onion;
use crate::circuit::Circuit;
use crate::errors::{OnionError, OnionResult};
use crate::packet::{OnionPacket, MAX_USER_PAYLOAD};

/// The 4-byte magic identifier prepended to cover-traffic payloads.
/// Chosen so it cannot appear at offset 0 of any real wire frame
/// (whose first 4 bytes are a length prefix — high bit always 0
/// for valid frames under 2 GiB).
pub const COVER_MAGIC: [u8; 4] = [0xC0, 0xCC, 0xE3, 0xAF];

/// Default body length for a cover packet. Picked to look like
/// "typical small chat message" on the wire. Real packets are
/// padded to fixed `ONION_PACKET_SIZE` regardless, so this only
/// affects intermediate-layer ciphertext lengths.
pub const DEFAULT_COVER_BODY_LEN: usize = 256;

/// Construct a cover-traffic onion packet for `circuit`.
///
/// The innermost plaintext is `COVER_MAGIC || random_bytes(body_len)`.
/// The packet's outer layout and encoded length match a real packet of
/// the same shape: same circuit length, fixed transport size after
/// padding, and AEAD tag/header sequence. No timing/volume/route
/// indistinguishability claim is made.
///
/// # Errors
/// Returns [`OnionError::PayloadOversize`] if `body_len + 4` exceeds
/// `MAX_USER_PAYLOAD`. Any cryptographic failure in `build_onion`
/// propagates.
pub fn build_cover_packet<R: RngCore + CryptoRng>(
    circuit: &Circuit,
    body_len: usize,
    rng: &mut R,
) -> OnionResult<OnionPacket> {
    let total = body_len.saturating_add(COVER_MAGIC.len());
    if total > MAX_USER_PAYLOAD {
        return Err(OnionError::PayloadOversize {
            got: total,
            max: MAX_USER_PAYLOAD,
        });
    }
    let mut payload = Vec::with_capacity(total);
    payload.extend_from_slice(&COVER_MAGIC);
    let mut body = vec![0u8; body_len];
    rng.fill_bytes(&mut body);
    payload.extend_from_slice(&body);
    build_onion(circuit, &payload, rng)
}

/// Construct a cover-traffic onion packet with the default body length.
///
/// Convenience wrapper around [`build_cover_packet`] for the common
/// case where the caller doesn't have a specific length to mimic.
///
/// # Errors
/// Same as [`build_cover_packet`].
pub fn build_default_cover_packet<R: RngCore + CryptoRng>(
    circuit: &Circuit,
    rng: &mut R,
) -> OnionResult<OnionPacket> {
    build_cover_packet(circuit, DEFAULT_COVER_BODY_LEN, rng)
}

/// True iff the (decrypted, innermost) `payload` starts with
/// [`COVER_MAGIC`]. Destinations should call this on the result of
/// peeling the final layer and drop the packet if it returns true,
/// silently and before any application-layer processing.
#[must_use]
pub fn is_cover_payload(payload: &[u8]) -> bool {
    payload.len() >= COVER_MAGIC.len() && payload[..COVER_MAGIC.len()] == COVER_MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hop::{HopDescriptor, HopId};
    use crate::packet::HOP_ID_LEN;
    use crate::peel::peel_one_layer;
    use rand_core::SeedableRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn hop_n(seed: u8) -> (HopDescriptor, StaticSecret) {
        let sk = StaticSecret::from([seed; 32]);
        let pk = PublicKey::from(&sk);
        let h = HopDescriptor {
            id: HopId::from_bytes([seed; HOP_ID_LEN]),
            pubkey: pk,
        };
        (h, sk)
    }

    fn make_circuit(n: usize) -> (Circuit, Vec<StaticSecret>) {
        let mut hops = Vec::with_capacity(n);
        let mut secrets = Vec::with_capacity(n);
        for i in 0..n {
            let (h, s) = hop_n(u8::try_from(i + 1).unwrap());
            hops.push(h);
            secrets.push(s);
        }
        (Circuit::new(hops).unwrap(), secrets)
    }

    #[test]
    fn cover_magic_is_4_bytes() {
        assert_eq!(COVER_MAGIC.len(), 4);
    }

    #[test]
    fn is_cover_recognizes_magic() {
        let mut payload = COVER_MAGIC.to_vec();
        payload.extend_from_slice(b"random body");
        assert!(is_cover_payload(&payload));
    }

    #[test]
    fn is_cover_rejects_real_payload() {
        // Real wire frames start with a 4-byte big-endian length.
        // For frames <= 256 MiB the high byte is < 0x10. COVER_MAGIC
        // starts with 0xC0; no valid real frame collides.
        let real = b"\x00\x00\x00\x10{\"t\":\"TEXT\"}";
        assert!(!is_cover_payload(real));
    }

    #[test]
    fn is_cover_handles_short() {
        assert!(!is_cover_payload(b""));
        assert!(!is_cover_payload(&[0xC0]));
        assert!(!is_cover_payload(&[0xC0, 0xCC, 0xE3])); // 3 bytes
    }

    #[test]
    fn cover_packet_decrypts_through_all_hops_and_marker_visible() {
        // Construct a 3-hop circuit + 1-hop destination = 4 entries.
        let (circuit, secrets) = make_circuit(4);
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xABCD_EF12);
        let packet = build_cover_packet(&circuit, 200, &mut rng).unwrap();
        // Peel each layer in order — the final result should be the
        // cover marker followed by random body.
        let mut current = packet;
        for (i, sk) in secrets.iter().enumerate() {
            let peel = peel_one_layer(sk, &current).unwrap();
            match peel {
                crate::peel::PeelOutcome::Forward {
                    inner_packet_bytes, ..
                } => {
                    assert!(i < secrets.len() - 1, "Forward at destination hop");
                    current = crate::packet::OnionPacket::decode(&inner_packet_bytes).unwrap();
                }
                crate::peel::PeelOutcome::Deliver { payload } => {
                    assert_eq!(i, secrets.len() - 1, "Deliver before destination");
                    assert!(is_cover_payload(&payload));
                    assert_eq!(payload.len(), COVER_MAGIC.len() + 200);
                    return;
                }
            }
        }
        panic!("never reached destination delivery");
    }

    #[test]
    fn cover_packet_oversize_body_rejected() {
        let (circuit, _) = make_circuit(2);
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        let oversize = MAX_USER_PAYLOAD; // body_len + 4 > MAX
        let r = build_cover_packet(&circuit, oversize, &mut rng);
        assert!(matches!(r, Err(OnionError::PayloadOversize { .. })));
    }

    #[test]
    fn default_cover_body_len_works() {
        let (circuit, _) = make_circuit(2);
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(2);
        let _ = build_default_cover_packet(&circuit, &mut rng).unwrap();
    }

    #[test]
    fn cover_packet_has_same_encoded_length_as_real() {
        // This assertion is intentionally limited to encoded length.
        let (circuit, _) = make_circuit(3);
        let mut rng_c = rand_chacha::ChaCha20Rng::seed_from_u64(11);
        let mut rng_r = rand_chacha::ChaCha20Rng::seed_from_u64(12);

        let cover = build_cover_packet(&circuit, 100, &mut rng_c).unwrap();
        let real_payload = vec![7u8; 104]; // same total length
        let real = crate::build::build_onion(&circuit, &real_payload, &mut rng_r).unwrap();

        let cover_bytes = cover.encode();
        let real_bytes = real.encode();
        assert_eq!(cover_bytes.len(), real_bytes.len());
    }
}
