//! Adversarial vectors v2 — second-round red-team additions across
//! all 10 layers. The shipped per-layer adversarial_vectors_*.rs
//! files cover the obvious attack surface; this file adds vectors
//! against subtler invariants (boundary timestamps, empty inputs,
//! reused tags, decode-time DoS shapes) that didn't make the first
//! cut.

use rand::rngs::OsRng;
use std::collections::BTreeSet;

use ol_device_mesh::active_routing::{DeviceActionRecord, RoutingContext};
use ol_device_mesh::compute::{
    pick_executor, sign_capability_attestation, CapabilityRegistry, DeviceCapability,
};
use ol_device_mesh::distributed_fs::{
    sign_storage_attestation, ErasurePolicy, FileManifest,
};
use ol_device_mesh::duress::{
    create_duress_envelope, sign_duress_alert, PairingChannel, PairingCommitment,
};
use ol_device_mesh::fan_out::{
    fan_out_plan, sign_fetch_request, SourceCapacity, FETCH_NONCE_LEN,
};
use ol_device_mesh::mesh_state::{
    LwwRegister, MeshState, OrSet, PnCounter, SubtreePolicyKind,
};
use ol_device_mesh::quorum::{
    mint_policy, propose_operation, sign_approval, QuorumCertificate,
};
use ol_device_mesh::self_routing::{sign_route_announcement, PeerLink};
use ol_device_mesh::subkey::{fresh_device_id, mint_subkey};
use ol_device_mesh::{DeviceClass, MasterIdentity, DEVICE_ID_LEN};

// ── Layer 1: subkey ────────────────────────────────────────────────

#[test]
fn adversarial_v2_attestation_with_mint_day_equal_expiry_rejected() {
    // A 1-day attestation is theoretically valid (mint == expiry
    // means valid only on `mint_day_index`). But mint_day_index > 0
    // with the same expiry day should NOT cover later days — the
    // covers_day check must be strict.
    let master = MasterIdentity::generate(&mut OsRng);
    let id = fresh_device_id(&mut OsRng);
    let (_sk, att) = mint_subkey(&master, DeviceClass::Phone, id, 10, 10).unwrap();
    assert!(att.covers_day(10));
    assert!(!att.covers_day(11));
    assert!(!att.covers_day(9));
}

#[test]
fn adversarial_v2_subkey_minted_for_future_day() {
    // Mint a subkey for a far-future day (clock skew or attacker
    // future-dating). The attestation should still verify (day
    // index is just an integer), but covers_day(today) is false.
    let master = MasterIdentity::generate(&mut OsRng);
    let id = fresh_device_id(&mut OsRng);
    let (_sk, att) =
        mint_subkey(&master, DeviceClass::Phone, id, 100_000, 100_365).unwrap();
    att.verify(&master.verifying_key()).unwrap();
    assert!(!att.covers_day(0));
    assert!(att.covers_day(100_000));
}

// ── Layer 2: quorum ────────────────────────────────────────────────

#[test]
fn adversarial_v2_proposal_deadline_equal_issue_rejected() {
    let master = MasterIdentity::generate(&mut OsRng);
    let id1 = [0x01; 16];
    let id2 = [0x02; 16];
    let (sk1, _) = mint_subkey(&master, DeviceClass::Phone, id1, 0, 365).unwrap();
    let _ = mint_subkey(&master, DeviceClass::Laptop, id2, 0, 365).unwrap();
    let policy = mint_policy(&master, [0x42; 16], b"x", 1, vec![id1, id2]).unwrap();
    // deadline == issued: must reject.
    let r = propose_operation(&sk1, &policy, [0xEE; 32], [0xDA; 16], 100, 100);
    assert!(r.is_err(), "proposal with deadline == issued must reject");
}

#[test]
fn adversarial_v2_empty_approver_sig_rejected() {
    let master = MasterIdentity::generate(&mut OsRng);
    let id1 = [0x01; 16];
    let id2 = [0x02; 16];
    let (sk1, a1) = mint_subkey(&master, DeviceClass::Phone, id1, 0, 365).unwrap();
    let (sk2, a2) = mint_subkey(&master, DeviceClass::Laptop, id2, 0, 365).unwrap();
    let policy = mint_policy(&master, [0x42; 16], b"x", 1, vec![id1, id2]).unwrap();
    let proposal =
        propose_operation(&sk1, &policy, [0xEE; 32], [0xDA; 16], 100, 2000).unwrap();
    let mut approval = sign_approval(&sk2, &proposal, 110).unwrap();
    approval.approver_sig.clear();
    let cert = QuorumCertificate {
        proposal,
        approvals: vec![approval],
        policy,
        subkey_attestations: vec![a1, a2],
    };
    assert!(cert.verify(&master.verifying_key(), 150).is_err());
}

// ── Layer 3: mesh state ────────────────────────────────────────────

#[test]
fn adversarial_v2_lww_register_empty_value_set() {
    let mut r = LwwRegister::empty();
    r.set(Vec::new(), 1, &[0xAA; 16]);
    // Empty value is valid bytes; should still register.
    assert_eq!(r.value(), Some(&[][..]));
    assert_eq!(r.ts(), 1);
}

#[test]
fn adversarial_v2_or_set_add_remove_same_tag_visible_then_gone() {
    let mut s = OrSet::empty();
    let tag = [0x11; 16];
    s.add(b"elem".to_vec(), tag);
    assert!(s.contains(b"elem"));
    s.remove(b"elem", &tag);
    assert!(!s.contains(b"elem"));
    // Re-add with SAME tag: tombstone wins, element stays invisible.
    s.add(b"elem".to_vec(), tag);
    assert!(!s.contains(b"elem"), "tombstone for same tag must win");
    // Add with a FRESH tag re-introduces.
    s.add(b"elem".to_vec(), [0x22; 16]);
    assert!(s.contains(b"elem"));
}

#[test]
fn adversarial_v2_pn_counter_saturation_does_not_panic() {
    let mut c = PnCounter::default();
    c.adjust([0xAA; 16], i64::MAX / 2);
    c.adjust([0xAA; 16], i64::MAX / 2);
    // One more should saturate, not panic.
    c.adjust([0xAA; 16], 1);
    let _ = c.value();
}

#[test]
fn adversarial_v2_subtree_kind_collision_rejected() {
    let mut state = MeshState::empty();
    state
        .ensure_subtree(b"folder.x".to_vec(), SubtreePolicyKind::LwwRegister)
        .unwrap();
    let r = state.ensure_subtree(b"folder.x".to_vec(), SubtreePolicyKind::OrSet);
    assert!(r.is_err(), "subtree kind collision must reject");
}

// ── Layer 4: distributed FS ────────────────────────────────────────

#[test]
fn adversarial_v2_manifest_chunks_not_stripe_multiple_rejected() {
    // Policy (k=2, m=1) → stripe = 3. Provide 4 chunks (not a
    // multiple). shape_check must reject.
    let policy = ErasurePolicy::new(2, 1, 1).unwrap();
    let manifest = FileManifest {
        file_size: 4 * 1024,
        chunk_size: 1024,
        chunks: vec![[1u8; 32], [2; 32], [3; 32], [4; 32]],
        mime: b"text/plain".to_vec(),
        created_unix: 100,
        policy,
    };
    assert!(manifest.shape_check().is_err());
}

#[test]
fn adversarial_v2_storage_attestation_empty_chunks_rejected_or_signed() {
    let master = MasterIdentity::generate(&mut OsRng);
    let id = fresh_device_id(&mut OsRng);
    let (sk, _) = mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
    // Empty chunks vector: implementation is allowed to either
    // reject early or sign a valid empty-set attestation. Either
    // way, no panic.
    let _ = sign_storage_attestation(&sk, 100, Vec::new());
}

// ── Layer 5: fan-out ───────────────────────────────────────────────

#[test]
fn adversarial_v2_fan_out_overrequest_zero_rejected() {
    let policy = ErasurePolicy::new(2, 1, 1).unwrap();
    let manifest = FileManifest {
        file_size: 6 * 1024,
        chunk_size: 1024,
        chunks: (0..6u8).map(|i| [i; 32]).collect(),
        mime: b"text/plain".to_vec(),
        created_unix: 100,
        policy,
    };
    let sources = vec![SourceCapacity {
        device_id: [0xAA; DEVICE_ID_LEN],
        estimated_bps: 100,
        current_load_bytes: 0,
    }];
    let r = fan_out_plan(&manifest, &[], &sources, 0.0);
    assert!(r.is_err(), "overrequest=0 must reject");
}

#[test]
fn adversarial_v2_fan_out_no_sources_rejected() {
    let policy = ErasurePolicy::new(2, 1, 1).unwrap();
    let manifest = FileManifest {
        file_size: 3 * 1024,
        chunk_size: 1024,
        chunks: vec![[1u8; 32], [2; 32], [3; 32]],
        mime: b"text/plain".to_vec(),
        created_unix: 100,
        policy,
    };
    let r = fan_out_plan(&manifest, &[], &[], 1.0);
    assert!(r.is_err());
}

#[test]
fn adversarial_v2_fetch_request_empty_chunks_rejected() {
    let master = MasterIdentity::generate(&mut OsRng);
    let id = fresh_device_id(&mut OsRng);
    let (sk, _) = mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
    let r = sign_fetch_request(
        &sk,
        [0xFF; DEVICE_ID_LEN],
        [0xAB; 32],
        Vec::new(),
        1024,
        100,
        2000,
        [0x99; FETCH_NONCE_LEN],
    );
    assert!(r.is_err(), "empty chunk list must reject");
}

// ── Layer 6: self-routing ──────────────────────────────────────────

#[test]
fn adversarial_v2_announcement_with_self_loop_silently_dropped() {
    let master = MasterIdentity::generate(&mut OsRng);
    let id = [0x77; DEVICE_ID_LEN];
    let (sk, _) = mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
    // Sign-time should strip self-loop links rather than error.
    let ann = sign_route_announcement(
        &sk,
        100,
        vec![
            PeerLink {
                peer_device_id: id, // SELF
                tau_score: 100,
                last_seen_unix: 50,
                direct: true,
            },
            PeerLink {
                peer_device_id: [0xAA; DEVICE_ID_LEN],
                tau_score: 50,
                last_seen_unix: 50,
                direct: true,
            },
        ],
    )
    .unwrap();
    assert_eq!(ann.links.len(), 1, "self-loop must be stripped at sign");
    assert_eq!(ann.links[0].peer_device_id, [0xAA; DEVICE_ID_LEN]);
}

#[test]
fn adversarial_v2_announcement_duplicate_peer_keeps_higher_tau() {
    let master = MasterIdentity::generate(&mut OsRng);
    let id = [0x77; DEVICE_ID_LEN];
    let (sk, _) = mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
    // Two links to the same peer: sign-time dedup must keep the
    // higher tau_score.
    let ann = sign_route_announcement(
        &sk,
        100,
        vec![
            PeerLink {
                peer_device_id: [0xAA; DEVICE_ID_LEN],
                tau_score: 10,
                last_seen_unix: 50,
                direct: true,
            },
            PeerLink {
                peer_device_id: [0xAA; DEVICE_ID_LEN],
                tau_score: 100,
                last_seen_unix: 60,
                direct: true,
            },
        ],
    )
    .unwrap();
    assert_eq!(ann.links.len(), 1);
    assert_eq!(ann.links[0].tau_score, 100);
}

// ── Layer 7: self-onion ────────────────────────────────────────────
// (Covered well in property_self_onion + adversarial_vectors_self_onion.)

// ── Layer 8: compute ───────────────────────────────────────────────

#[test]
fn adversarial_v2_executor_pick_returns_none_when_no_capacity_profile() {
    let master = MasterIdentity::generate(&mut OsRng);
    let id = [0xD1; DEVICE_ID_LEN];
    let mut reg = CapabilityRegistry::empty();
    reg.ingest(
        sign_capability_attestation(&master, id, vec![DeviceCapability::Gpu], 0, 365)
            .unwrap(),
        &master.verifying_key(),
    )
    .unwrap();
    // Device has the capability but no SourceCapacity profile →
    // pick must return None (we can't score it).
    let pick = pick_executor(&[DeviceCapability::Gpu], &reg, &[], 100);
    assert!(pick.is_none());
}

#[test]
fn adversarial_v2_executor_pick_ignores_load_loaded_device() {
    let master = MasterIdentity::generate(&mut OsRng);
    let fast_id = [0xD1; DEVICE_ID_LEN];
    let slow_id = [0xD2; DEVICE_ID_LEN];
    let mut reg = CapabilityRegistry::empty();
    reg.ingest(
        sign_capability_attestation(&master, fast_id, vec![DeviceCapability::Gpu], 0, 365)
            .unwrap(),
        &master.verifying_key(),
    )
    .unwrap();
    reg.ingest(
        sign_capability_attestation(&master, slow_id, vec![DeviceCapability::Gpu], 0, 365)
            .unwrap(),
        &master.verifying_key(),
    )
    .unwrap();
    // fast_id is much more loaded → slow_id should win.
    let caps = vec![
        SourceCapacity {
            device_id: fast_id,
            estimated_bps: 1_000_000_000,
            current_load_bytes: 1_000_000_000_000,
        },
        SourceCapacity {
            device_id: slow_id,
            estimated_bps: 100_000,
            current_load_bytes: 0,
        },
    ];
    let pick = pick_executor(&[DeviceCapability::Gpu], &reg, &caps, 100);
    assert_eq!(pick, Some(slow_id));
}

// ── Layer 9: active routing ────────────────────────────────────────

#[test]
fn adversarial_v2_decay_with_zero_half_life_noop() {
    let mut r = DeviceActionRecord {
        context_hash: [0; 32],
        device_id: [0; 16],
        alpha: 100,
        beta: 50,
        last_updated_unix: 0,
    };
    r.decay(1_000_000, 0);
    assert_eq!(r.alpha, 100);
    assert_eq!(r.beta, 50);
}

#[test]
fn adversarial_v2_observe_with_clock_skew_doesnt_panic() {
    // last_updated_unix > now_unix is the clock-skew case. observe
    // must not panic on this path.
    let mut r = DeviceActionRecord {
        context_hash: [0; 32],
        device_id: [0; 16],
        alpha: 10,
        beta: 10,
        last_updated_unix: 1_000_000,
    };
    r.observe(true, 0); // now < last_updated
    // Decay path should be similarly resilient.
    r.decay(0, 3600);
    assert!(r.alpha >= 1 && r.beta >= 1);
}

#[test]
fn adversarial_v2_context_hash_changes_with_every_field() {
    let base = RoutingContext {
        contact_pin: [0; 32],
        hour_bucket: 0,
        day_of_week: 0,
        message_class: [0; 4],
        urgency: 0,
    };
    let h0 = base.canonical_hash();
    let mut variations: BTreeSet<[u8; 32]> = BTreeSet::new();
    variations.insert(h0);
    let mut v = base;
    v.contact_pin[0] = 1;
    variations.insert(v.canonical_hash());
    let mut v = base;
    v.hour_bucket = 1;
    variations.insert(v.canonical_hash());
    let mut v = base;
    v.day_of_week = 1;
    variations.insert(v.canonical_hash());
    let mut v = base;
    v.message_class[0] = 1;
    variations.insert(v.canonical_hash());
    let mut v = base;
    v.urgency = 1;
    variations.insert(v.canonical_hash());
    // 6 distinct contexts → 6 distinct hashes.
    assert_eq!(variations.len(), 6, "every field must affect the hash");
}

// ── Layer 10: duress ───────────────────────────────────────────────

#[test]
fn adversarial_v2_duress_envelope_real_equals_decoy_rejected() {
    let mut rng = OsRng;
    let r = create_duress_envelope(
        b"real",
        b"decoy",
        b"same",
        b"same",
        &[0u8; 32],
        &mut rng,
    );
    assert!(r.is_err(), "real_code == decoy_code must reject");
}

#[test]
fn adversarial_v2_duress_alert_resigned_with_different_nonce_diverges() {
    let master = MasterIdentity::generate(&mut OsRng);
    let id = [0xAA; DEVICE_ID_LEN];
    let (sk, _) = mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
    let a = sign_duress_alert(&sk, 1, [0x11; 16]).unwrap();
    let b = sign_duress_alert(&sk, 1, [0x22; 16]).unwrap();
    // Different nonce → different transcript → different sig.
    assert_ne!(a.subkey_sig, b.subkey_sig);
    assert_ne!(a.nonce, b.nonce);
}

#[test]
fn adversarial_v2_pair_commitment_different_channels_diverge() {
    let secret = b"shared-pair-secret";
    let nonce = [0x42; 16];
    let qr = PairingCommitment::build(PairingChannel::Qr, secret, nonce, 100);
    let audio = PairingCommitment::build(PairingChannel::Audio, secret, nonce, 100);
    let motion = PairingCommitment::build(PairingChannel::Motion, secret, nonce, 100);
    // All three same (secret, nonce, ts) but different channels →
    // ALL three commitments must be distinct.
    assert_ne!(qr.commitment, audio.commitment);
    assert_ne!(qr.commitment, motion.commitment);
    assert_ne!(audio.commitment, motion.commitment);
}

// ── Cross-layer: replay across layers ──────────────────────────────

#[test]
fn adversarial_v2_quorum_approval_sig_cannot_be_reused_for_route_announce() {
    // A signature is bound to its domain-separation tag. An
    // approval signature from Layer 2 must not validate as a route
    // announcement signature on Layer 6, even if structurally
    // shoehorned.
    let master = MasterIdentity::generate(&mut OsRng);
    let id1 = [0x01; 16];
    let id2 = [0x02; 16];
    let (sk1, _a1) = mint_subkey(&master, DeviceClass::Phone, id1, 0, 365).unwrap();
    let (sk2, _a2) = mint_subkey(&master, DeviceClass::Laptop, id2, 0, 365).unwrap();
    let policy = mint_policy(&master, [0x42; 16], b"x", 1, vec![id1, id2]).unwrap();
    let proposal =
        propose_operation(&sk1, &policy, [0xEE; 32], [0xDA; 16], 100, 2000).unwrap();
    let approval = sign_approval(&sk2, &proposal, 110).unwrap();
    // Now build a route announcement structurally with the approval
    // sig grafted onto it. Verify must fail (different transcript).
    let ann = sign_route_announcement(
        &sk2,
        100,
        vec![PeerLink {
            peer_device_id: [0xAA; DEVICE_ID_LEN],
            tau_score: 100,
            last_seen_unix: 50,
            direct: true,
        }],
    )
    .unwrap();
    let mut tampered = ann;
    tampered.announcer_sig = approval.approver_sig;
    let vk = ol_pqsig::HybridVerifyingKey::from_bytes(
        &mint_subkey(&master, DeviceClass::Laptop, id2, 0, 365)
            .unwrap()
            .1
            .subkey_vk_bytes,
    )
    .unwrap();
    assert!(tampered.verify(&vk).is_err());
}
