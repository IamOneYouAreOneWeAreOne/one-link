//! Property tests for Row 8 Layer 7 self-onion.

use proptest::prelude::*;
use rand::rngs::OsRng;

use ol_device_mesh::self_onion::{
    build_self_onion_circuit, derive_onion_identity, peel_self_onion_layer,
    sign_onion_attestation, OnionAttestation, OnionIdentity, OnionKeyRegistry,
    SelfOnionContext, SelfOnionPeelOutcome,
};
use ol_device_mesh::self_routing::Route;
use ol_device_mesh::{MasterIdentity, DEVICE_ID_LEN};

fn cheap_cases() -> u32 {
    if std::env::var("ONE_LINK_F1_GATE").as_deref() == Ok("1") {
        5_000_000
    } else {
        1_000_000
    }
}

fn keygen_cases() -> u32 {
    if std::env::var("ONE_LINK_F1_GATE").as_deref() == Ok("1") {
        10_000
    } else {
        500
    }
}

// ── 1M-iter properties on the canonical transcript ──────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cheap_cases(),
        max_global_rejects: cheap_cases() * 4,
        .. ProptestConfig::default()
    })]

    /// OnionAttestation transcript is a pure function of its inputs.
    #[test]
    fn onion_attestation_transcript_deterministic(
        device_id in any::<[u8; DEVICE_ID_LEN]>(),
        onion_pk in any::<[u8; 32]>(),
        mint in any::<u64>(),
        expiry in any::<u64>(),
    ) {
        let a = OnionAttestation::canonical_transcript(&device_id, &onion_pk, mint, expiry);
        let b = OnionAttestation::canonical_transcript(&device_id, &onion_pk, mint, expiry);
        prop_assert_eq!(a, b);
    }
}

// ── Keygen-bound properties ─────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: keygen_cases(),
        max_global_rejects: keygen_cases() * 4,
        .. ProptestConfig::default()
    })]

    /// Onion identity derivation is deterministic per (master, device).
    #[test]
    fn onion_identity_derivation_deterministic(
        device_id in any::<[u8; DEVICE_ID_LEN]>(),
    ) {
        let master = MasterIdentity::generate(&mut OsRng);
        let a = derive_onion_identity(&master, &device_id);
        let b = derive_onion_identity(&master, &device_id);
        prop_assert_eq!(a.public_bytes(), b.public_bytes());
    }

    /// Sign + verify round-trip for arbitrary validity windows.
    #[test]
    fn onion_attestation_sign_verify(
        device_id in any::<[u8; DEVICE_ID_LEN]>(),
        mint in 0u64..1_000_000,
        ttl in 1u64..1_000,
    ) {
        let master = MasterIdentity::generate(&mut OsRng);
        let identity = derive_onion_identity(&master, &device_id);
        let att = sign_onion_attestation(
            &master, device_id, identity.public_bytes(), mint, mint + ttl,
        ).unwrap();
        att.verify(&master.verifying_key()).unwrap();
    }

    /// Two-hop round-trip: build at src, peel at dst, payload survives.
    #[test]
    fn two_hop_round_trip_preserves_payload(
        payload in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let master = MasterIdentity::generate(&mut OsRng);
        let src_id = [0x11; DEVICE_ID_LEN];
        let dst_id = [0x22; DEVICE_ID_LEN];
        let dst_identity = derive_onion_identity(&master, &dst_id);
        let mut reg = OnionKeyRegistry::empty();
        for id in &[src_id, dst_id] {
            let ident = derive_onion_identity(&master, id);
            let att = sign_onion_attestation(
                &master, *id, ident.public_bytes(), 0, 365,
            ).unwrap();
            reg.ingest(att, &master.verifying_key()).unwrap();
        }
        let route = Route {
            hops: vec![src_id, dst_id],
            bottleneck_tau: 100,
            min_last_seen_unix: 1,
        };
        let packet = build_self_onion_circuit(
            &route, &reg, 0, &payload, &mut OsRng,
        ).unwrap();
        let outcome = peel_self_onion_layer(&dst_identity, &packet).unwrap();
        match outcome {
            SelfOnionPeelOutcome::Deliver { payload: got } => {
                prop_assert_eq!(got, payload);
            }
            other => prop_assert!(
                false,
                "expected Deliver, got {other:?}"
            ),
        }
    }
}

// ── Policy sanity ───────────────────────────────────────────────

#[test]
fn policy_trusted_home_vs_hostile() {
    let trusted = SelfOnionContext::trusted_home();
    let hostile = SelfOnionContext::hostile_network();
    assert!(!trusted.requires_self_onion());
    assert!(hostile.requires_self_onion());
    assert!(hostile.min_hops >= trusted.min_hops);
}
