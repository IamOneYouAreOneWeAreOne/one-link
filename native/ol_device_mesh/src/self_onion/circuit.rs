//! Self-mesh circuit builder + peeler.
//!
//! Composes a Layer-6 [`crate::self_routing::Route`] with the
//! shipped F3 [`ol_onion::sphinx`] Sphinx Coherence primitive to
//! produce a fully-built [`ol_onion::sphinx::SphinxPacket`] aimed at
//! the destination device. The peeler wraps the shipped Sphinx
//! peel call so callers can drive the personal-mesh circuit without
//! re-deriving Ristretto scalars themselves.

use curve25519_dalek::ristretto::CompressedRistretto;
use ol_onion::sphinx::core::{
    build_sphinx_onion, generate_static_keypair, peel_sphinx_layer, SphinxHop,
    SphinxPacket, SphinxPeelOutcome, SPHINX_MAX_USER_PAYLOAD,
};
use ol_onion::HopId;
use rand_core::{CryptoRng, RngCore};

use crate::errors::{DeviceMeshError, DeviceMeshResult};
use crate::self_routing::Route;
use crate::subkey::DEVICE_ID_LEN;

use super::identity::OnionIdentity;
use super::registry::OnionKeyRegistry;

/// Domain-separation prefix the sender prepends to the payload
/// before handing it to Sphinx. The destination strips it on
/// receive; foreign packets that don't carry the prefix are dropped.
pub const SELF_ONION_DOMAIN_PAYLOAD: &[u8] = b"OL-mesh-self-onion-v1\0";

/// Peel outcome from a self-onion layer. Wraps the underlying
/// Sphinx outcome with self-mesh-specific semantics.
///
/// `SphinxPacket` is ~1.3 KiB, so the `Forward` payload is boxed —
/// the enum stays cheap on the stack (matches against this enum live
/// in the per-hop forwarding hot loop).
#[derive(Debug)]
pub enum SelfOnionPeelOutcome {
    /// Forward the packet onward to `next_hop_device_id`.
    Forward {
        /// Device id of the next hop (decoded from the Sphinx
        /// header).
        next_hop_device_id: [u8; DEVICE_ID_LEN],
        /// The packet to forward (with one layer removed).
        next_packet: Box<SphinxPacket>,
    },
    /// This device is the destination; here's the payload.
    Deliver {
        /// User payload bytes (with the self-onion domain prefix
        /// stripped).
        payload: Vec<u8>,
    },
    /// The packet's outer payload didn't carry the self-onion
    /// domain prefix — it's not a self-mesh packet. The daemon
    /// drops it.
    NotSelfOnion,
}

/// Build a self-onion circuit for `route` carrying `payload`.
///
/// `route` is the output of [`crate::self_routing::pick_best_route`].
/// `registry` provides each hop's master-attested Ristretto255
/// pubkey. `day_index` selects the validity window in the registry
/// (typically the receiver's `subkey.day_index()`).
pub fn build_self_onion_circuit<R: RngCore + CryptoRng>(
    route: &Route,
    registry: &OnionKeyRegistry,
    day_index: u64,
    payload: &[u8],
    rng: &mut R,
) -> DeviceMeshResult<SphinxPacket> {
    if route.hops.len() < 2 {
        return Err(DeviceMeshError::SelfOnionRouteTooShort {
            got: route.hops.len(),
        });
    }
    // The destination is the LAST hop. The first hop is `src` — we
    // don't include it in the Sphinx circuit (Sphinx walks
    // intermediate + final; the source's job is just to send the
    // built packet to the first intermediate, which is `hops[1]`).
    let sphinx_targets: &[[u8; DEVICE_ID_LEN]] = &route.hops[1..];

    let mut sphinx_circuit: Vec<SphinxHop> = Vec::with_capacity(sphinx_targets.len());
    for device_id in sphinx_targets {
        let pk_bytes = registry.pubkey_for(device_id, day_index)?;
        // Pad device_id to SLOT_ID_LEN (32 bytes) by prefixing with
        // zeros — the Sphinx hop id is opaque to the protocol, we
        // just need it to be unique + recoverable.
        let mut slot_id = [0u8; 32];
        slot_id[16..].copy_from_slice(device_id);
        let hop = SphinxHop::new(slot_id, pk_bytes)
            .map_err(|_| DeviceMeshError::SelfOnionBadHopPubkey {
                device_id: *device_id,
            })?;
        sphinx_circuit.push(hop);
    }

    // Domain-prefix the payload.
    let mut wrapped = Vec::with_capacity(SELF_ONION_DOMAIN_PAYLOAD.len() + payload.len());
    wrapped.extend_from_slice(SELF_ONION_DOMAIN_PAYLOAD);
    wrapped.extend_from_slice(payload);
    if wrapped.len() > SPHINX_MAX_USER_PAYLOAD {
        return Err(DeviceMeshError::SelfOnionPayloadOversize {
            got: payload.len(),
            max: SPHINX_MAX_USER_PAYLOAD.saturating_sub(SELF_ONION_DOMAIN_PAYLOAD.len()),
        });
    }

    let (eph_sk, _eph_pk) = generate_static_keypair(rng);
    let packet =
        build_sphinx_onion(&eph_sk, &sphinx_circuit, &wrapped, rng).map_err(|e| {
            DeviceMeshError::SelfOnionSphinxBuildFailed(format!("{e}"))
        })?;
    Ok(packet)
}

/// Peel one layer of a self-onion packet using the local device's
/// onion identity. Returns the next hop or the delivered payload.
pub fn peel_self_onion_layer(
    local_identity: &OnionIdentity,
    packet: &SphinxPacket,
) -> DeviceMeshResult<SelfOnionPeelOutcome> {
    let scalar = local_identity.peel_scalar();
    let outcome = peel_sphinx_layer(&scalar, packet)
        .map_err(|e| DeviceMeshError::SelfOnionSphinxPeelFailed(format!("{e}")))?;
    match outcome {
        SphinxPeelOutcome::Forward { next_hop, next_packet } => {
            // The Sphinx hop id is the SLOT_ID_LEN-padded device id.
            // Recover the trailing DEVICE_ID_LEN bytes.
            let slot_bytes = *next_hop.as_bytes();
            let mut device_id = [0u8; DEVICE_ID_LEN];
            device_id.copy_from_slice(&slot_bytes[16..]);
            Ok(SelfOnionPeelOutcome::Forward {
                next_hop_device_id: device_id,
                next_packet: Box::new(next_packet),
            })
        }
        SphinxPeelOutcome::Deliver { payload } => {
            // Strip the self-onion domain prefix.
            if payload.len() < SELF_ONION_DOMAIN_PAYLOAD.len()
                || &payload[..SELF_ONION_DOMAIN_PAYLOAD.len()] != SELF_ONION_DOMAIN_PAYLOAD
            {
                return Ok(SelfOnionPeelOutcome::NotSelfOnion);
            }
            let body = payload[SELF_ONION_DOMAIN_PAYLOAD.len()..].to_vec();
            Ok(SelfOnionPeelOutcome::Deliver { payload: body })
        }
    }
}

// `CompressedRistretto` and `HopId` are referenced for type-
// completeness in future tests; suppress unused-import warnings.
#[allow(dead_code)]
fn ref_compressed_ristretto(b: [u8; 32]) -> Option<()> {
    let _ = CompressedRistretto::from_slice(&b);
    None
}
#[allow(dead_code)]
const fn hop_id_phantom(_x: HopId) {}

#[cfg(test)]
mod tests {
    use super::super::attestation::sign_onion_attestation;
    use super::super::identity::derive_onion_identity;
    use super::super::registry::OnionKeyRegistry;
    use super::*;
    use crate::master::MasterIdentity;
    use crate::self_routing::Route;
    use rand::rngs::OsRng;

    fn build_registry_and_identities(
        n: usize,
    ) -> (
        MasterIdentity,
        Vec<[u8; DEVICE_ID_LEN]>,
        Vec<OnionIdentity>,
        OnionKeyRegistry,
    ) {
        let master = MasterIdentity::generate(&mut OsRng);
        let mut ids = Vec::new();
        let mut identities = Vec::new();
        let mut reg = OnionKeyRegistry::empty();
        for i in 1u8..=(n as u8) {
            let id = [i; DEVICE_ID_LEN];
            let identity = derive_onion_identity(&master, &id);
            let att = sign_onion_attestation(
                &master,
                id,
                identity.public_bytes(),
                0,
                365,
            )
            .unwrap();
            reg.ingest(att, &master.verifying_key()).unwrap();
            ids.push(id);
            identities.push(identity);
        }
        (master, ids, identities, reg)
    }

    #[test]
    fn round_trip_two_hop_circuit() {
        let (_master, ids, identities, reg) =
            build_registry_and_identities(2);
        let route = Route {
            hops: vec![ids[0], ids[1]],
            bottleneck_tau: 100,
            min_last_seen_unix: 1,
        };
        let packet = build_self_onion_circuit(
            &route,
            &reg,
            0,
            b"hello world",
            &mut OsRng,
        )
        .unwrap();
        // Destination is ids[1]; peeling with its identity should
        // yield Deliver.
        let outcome = peel_self_onion_layer(&identities[1], &packet).unwrap();
        match outcome {
            SelfOnionPeelOutcome::Deliver { payload } => {
                assert_eq!(payload, b"hello world");
            }
            other => panic!("expected Deliver, got {other:?}"),
        }
        let _ = packet.as_bytes();
    }

    #[test]
    fn round_trip_three_hop_circuit() {
        let (_master, ids, identities, reg) =
            build_registry_and_identities(4);
        let route = Route {
            hops: vec![ids[0], ids[1], ids[2], ids[3]],
            bottleneck_tau: 100,
            min_last_seen_unix: 1,
        };
        let packet = build_self_onion_circuit(
            &route,
            &reg,
            0,
            b"hello",
            &mut OsRng,
        )
        .unwrap();
        // hops[0] is src (sender); circuit is [hops[1], hops[2], hops[3]].
        let outcome_1 = peel_self_onion_layer(&identities[1], &packet).unwrap();
        let next_packet = match outcome_1 {
            SelfOnionPeelOutcome::Forward { next_hop_device_id, next_packet } => {
                let next_packet = *next_packet;
                assert_eq!(next_hop_device_id, ids[2]);
                next_packet
            }
            other => panic!("expected Forward, got {other:?}"),
        };
        let outcome_2 = peel_self_onion_layer(&identities[2], &next_packet).unwrap();
        let next_packet_2 = match outcome_2 {
            SelfOnionPeelOutcome::Forward { next_hop_device_id, next_packet } => {
                let next_packet = *next_packet;
                assert_eq!(next_hop_device_id, ids[3]);
                next_packet
            }
            other => panic!("expected Forward, got {other:?}"),
        };
        let outcome_3 = peel_self_onion_layer(&identities[3], &next_packet_2).unwrap();
        match outcome_3 {
            SelfOnionPeelOutcome::Deliver { payload } => {
                assert_eq!(payload, b"hello");
            }
            other => panic!("expected Deliver, got {other:?}"),
        }
    }

    #[test]
    fn route_too_short_rejected() {
        let (_master, ids, _identities, reg) =
            build_registry_and_identities(1);
        let route = Route {
            hops: vec![ids[0]],
            bottleneck_tau: 100,
            min_last_seen_unix: 1,
        };
        let err = build_self_onion_circuit(
            &route,
            &reg,
            0,
            b"hi",
            &mut OsRng,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            DeviceMeshError::SelfOnionRouteTooShort { .. }
        ));
    }

    #[test]
    fn payload_oversize_rejected() {
        let (_master, ids, _identities, reg) =
            build_registry_and_identities(2);
        let route = Route {
            hops: vec![ids[0], ids[1]],
            bottleneck_tau: 100,
            min_last_seen_unix: 1,
        };
        let big = vec![0xCDu8; SPHINX_MAX_USER_PAYLOAD + 1];
        let err = build_self_onion_circuit(
            &route,
            &reg,
            0,
            &big,
            &mut OsRng,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            DeviceMeshError::SelfOnionPayloadOversize { .. }
        ));
    }

    #[test]
    fn peel_with_wrong_identity_yields_garbage() {
        // Standard Sphinx: an unintended peer's peel succeeds in
        // bytes but the MAC verify fails. We treat this as a
        // Sphinx-level peel error.
        let (_master, ids, identities, reg) =
            build_registry_and_identities(3);
        let route = Route {
            hops: vec![ids[0], ids[1]],
            bottleneck_tau: 100,
            min_last_seen_unix: 1,
        };
        let packet = build_self_onion_circuit(
            &route,
            &reg,
            0,
            b"intended for ids[1]",
            &mut OsRng,
        )
        .unwrap();
        let err = peel_self_onion_layer(&identities[2], &packet).unwrap_err();
        assert!(matches!(
            err,
            DeviceMeshError::SelfOnionSphinxPeelFailed(_)
        ));
    }
}
