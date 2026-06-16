//! Adversarial vectors for Row 8 Layer 7 self-onion.

use ol_device_mesh::self_onion::{
    build_self_onion_circuit, derive_onion_identity, peel_self_onion_layer, sign_onion_attestation,
    OnionIdentity, OnionKeyRegistry, SelfOnionPeelOutcome,
};
use ol_device_mesh::self_routing::Route;
use ol_device_mesh::{DeviceMeshError, MasterIdentity, DEVICE_ID_LEN};
use ol_onion::sphinx::core::SphinxPacket;
use rand::rngs::OsRng;

fn registry_for(
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
        let att = sign_onion_attestation(&master, id, identity.public_bytes(), 0, 365).unwrap();
        reg.ingest(att, &master.verifying_key()).unwrap();
        ids.push(id);
        identities.push(identity);
    }
    (master, ids, identities, reg)
}

// ── Identity / attestation adversarial ────────────────────────────

#[test]
fn adversarial_attestation_under_different_master_rejected() {
    let master_a = MasterIdentity::generate(&mut OsRng);
    let master_b = MasterIdentity::generate(&mut OsRng);
    let id = [0xAA; DEVICE_ID_LEN];
    let identity = derive_onion_identity(&master_a, &id);
    let att = sign_onion_attestation(&master_a, id, identity.public_bytes(), 0, 365).unwrap();
    let err = att.verify(&master_b.verifying_key()).unwrap_err();
    assert!(matches!(err, DeviceMeshError::OnionAttestationVerifyFail));
}

#[test]
fn adversarial_attestation_tampered_pubkey_rejected() {
    let master = MasterIdentity::generate(&mut OsRng);
    let id = [0xAA; DEVICE_ID_LEN];
    let identity = derive_onion_identity(&master, &id);
    let mut att = sign_onion_attestation(&master, id, identity.public_bytes(), 0, 365).unwrap();
    att.onion_pubkey[7] ^= 0x01;
    let err = att.verify(&master.verifying_key()).unwrap_err();
    assert!(matches!(err, DeviceMeshError::OnionAttestationVerifyFail));
}

#[test]
fn adversarial_attestation_bad_validity_window_rejected_at_sign() {
    let master = MasterIdentity::generate(&mut OsRng);
    let err = sign_onion_attestation(&master, [0xAA; DEVICE_ID_LEN], [0; 32], 100, 50).unwrap_err();
    assert!(matches!(
        err,
        DeviceMeshError::OnionAttestationBadValidityWindow { .. }
    ));
}

// ── Registry adversarial ──────────────────────────────────────────

#[test]
fn adversarial_registry_missing_device_lookup_rejected() {
    let reg = OnionKeyRegistry::empty();
    let err = reg.pubkey_for(&[0xCC; DEVICE_ID_LEN], 0).unwrap_err();
    assert!(matches!(
        err,
        DeviceMeshError::OnionRegistryDeviceMissing { .. }
    ));
}

#[test]
fn adversarial_registry_day_out_of_window_rejected() {
    let master = MasterIdentity::generate(&mut OsRng);
    let id = [0xAA; DEVICE_ID_LEN];
    let identity = derive_onion_identity(&master, &id);
    let att = sign_onion_attestation(&master, id, identity.public_bytes(), 10, 100).unwrap();
    let mut reg = OnionKeyRegistry::empty();
    reg.ingest(att, &master.verifying_key()).unwrap();
    let err = reg.pubkey_for(&id, 200).unwrap_err();
    assert!(matches!(
        err,
        DeviceMeshError::OnionRegistryDayOutOfWindow { .. }
    ));
}

// ── Circuit / peel adversarial ────────────────────────────────────

#[test]
fn adversarial_circuit_single_hop_rejected() {
    let (_master, ids, _identities, reg) = registry_for(1);
    let route = Route {
        hops: vec![ids[0]],
        bottleneck_tau: 1,
        min_last_seen_unix: 1,
    };
    let err = build_self_onion_circuit(&route, &reg, 0, b"hi", &mut OsRng).unwrap_err();
    assert!(matches!(
        err,
        DeviceMeshError::SelfOnionRouteTooShort { .. }
    ));
}

#[test]
fn adversarial_circuit_unknown_hop_rejected() {
    // Route names a device that isn't in the registry.
    let (master, ids, _identities, _reg_unused) = registry_for(2);
    let mut reg = OnionKeyRegistry::empty();
    let identity_known = derive_onion_identity(&master, &ids[0]);
    let att =
        sign_onion_attestation(&master, ids[0], identity_known.public_bytes(), 0, 365).unwrap();
    reg.ingest(att, &master.verifying_key()).unwrap();
    // ids[1] is in the route but NOT in the registry.
    let route = Route {
        hops: vec![ids[0], ids[1]],
        bottleneck_tau: 1,
        min_last_seen_unix: 1,
    };
    let err = build_self_onion_circuit(&route, &reg, 0, b"hi", &mut OsRng).unwrap_err();
    assert!(matches!(
        err,
        DeviceMeshError::OnionRegistryDeviceMissing { .. }
    ));
}

#[test]
fn adversarial_peel_with_wrong_identity_rejected() {
    let (_master, ids, identities, reg) = registry_for(3);
    let route = Route {
        hops: vec![ids[0], ids[1]],
        bottleneck_tau: 1,
        min_last_seen_unix: 1,
    };
    let packet = build_self_onion_circuit(&route, &reg, 0, b"target ids[1]", &mut OsRng).unwrap();
    // Peel with ids[2]'s identity, which isn't the destination.
    let err = peel_self_onion_layer(&identities[2], &packet).unwrap_err();
    assert!(matches!(err, DeviceMeshError::SelfOnionSphinxPeelFailed(_)));
}

#[test]
fn adversarial_packet_carrying_non_self_onion_payload_dropped() {
    // Build a Sphinx packet directly with a payload that DOESN'T
    // carry the OL-mesh-self-onion-v1 prefix. peel_self_onion_layer
    // should classify it as NotSelfOnion (and the daemon will drop).
    use ol_onion::sphinx::core::{build_sphinx_onion, generate_static_keypair, SphinxHop};
    let (master, ids, identities, _reg) = registry_for(1);
    let identity = derive_onion_identity(&master, &ids[0]);
    let pk_bytes = identity.public_bytes();
    let mut slot_id = [0u8; 32];
    slot_id[16..].copy_from_slice(&ids[0]);
    let hop = SphinxHop::new(slot_id, pk_bytes).unwrap();
    let (eph_sk, _eph_pk) = generate_static_keypair(&mut OsRng);
    let packet =
        build_sphinx_onion(&eph_sk, &[hop], b"this is NOT self-onion", &mut OsRng).unwrap();
    let outcome = peel_self_onion_layer(&identities[0], &packet).unwrap();
    assert!(matches!(outcome, SelfOnionPeelOutcome::NotSelfOnion));
}

#[test]
fn adversarial_truncated_packet_rejected() {
    use ol_onion::sphinx::core::SPHINX_PACKET_LEN;
    let short = vec![3u8; SPHINX_PACKET_LEN - 1];
    let err = SphinxPacket::from_bytes(&short).unwrap_err();
    let _ = err; // typed Sphinx error; not a DeviceMeshError directly
}

#[test]
fn adversarial_circuit_payload_oversize_rejected() {
    use ol_onion::sphinx::core::SPHINX_MAX_USER_PAYLOAD;
    let (_master, ids, _identities, reg) = registry_for(2);
    let route = Route {
        hops: vec![ids[0], ids[1]],
        bottleneck_tau: 1,
        min_last_seen_unix: 1,
    };
    let big = vec![0u8; SPHINX_MAX_USER_PAYLOAD + 1];
    let err = build_self_onion_circuit(&route, &reg, 0, &big, &mut OsRng).unwrap_err();
    assert!(matches!(
        err,
        DeviceMeshError::SelfOnionPayloadOversize { .. }
    ));
}
