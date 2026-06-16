//! Adversarial vectors for Row 8 Layer 6 self-routing.

use ol_device_mesh::self_routing::{
    dtn_couriers, multi_path_plan, pick_best_route, sign_route_announcement, PeerLink,
    RouteAnnouncement, RouteTable, TauScore, MAX_LINKS_PER_ANNOUNCEMENT,
};
use ol_device_mesh::{mint_subkey, DeviceClass, DeviceMeshError, MasterIdentity, DEVICE_ID_LEN};
use ol_pqsig::HybridVerifyingKey;
use rand::rngs::OsRng;

fn link(peer: [u8; DEVICE_ID_LEN], tau: TauScore, seen: u64) -> PeerLink {
    PeerLink {
        peer_device_id: peer,
        tau_score: tau,
        last_seen_unix: seen,
        direct: true,
    }
}

fn make_subkey() -> (ol_device_mesh::DeviceSubkey, HybridVerifyingKey) {
    let master = MasterIdentity::generate(&mut OsRng);
    let id = [0x55; DEVICE_ID_LEN];
    let (sk, att) = mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
    let vk = HybridVerifyingKey::from_bytes(&att.subkey_vk_bytes).unwrap();
    (sk, vk)
}

// ── Announcement adversarial ──────────────────────────────────────

#[test]
fn adversarial_announcement_cross_subkey_rejected() {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk_a, _) =
        mint_subkey(&master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365).unwrap();
    let (_sk_b, att_b) =
        mint_subkey(&master, DeviceClass::Laptop, [0xBB; DEVICE_ID_LEN], 0, 365).unwrap();
    let vk_b = HybridVerifyingKey::from_bytes(&att_b.subkey_vk_bytes).unwrap();
    let ann = sign_route_announcement(&sk_a, 1, vec![link([0xCC; 16], 100, 1)]).unwrap();
    let err = ann.verify(&vk_b).unwrap_err();
    assert!(matches!(err, DeviceMeshError::RouteAnnouncementVerifyFail));
}

#[test]
fn adversarial_announcement_oversize_rejected() {
    let (sk, _vk) = make_subkey();
    let mut links = Vec::new();
    for i in 0..(MAX_LINKS_PER_ANNOUNCEMENT + 1) {
        let mut peer = [0u8; DEVICE_ID_LEN];
        peer[..4].copy_from_slice(&((i as u32) + 1).to_be_bytes());
        if peer != *sk.device_id() {
            links.push(link(peer, 1, 1));
        }
    }
    let err = sign_route_announcement(&sk, 1, links).unwrap_err();
    assert!(matches!(
        err,
        DeviceMeshError::RouteAnnouncementTooManyLinks { .. }
    ));
}

#[test]
fn adversarial_announcement_manual_unsort_rejected() {
    let (sk, vk) = make_subkey();
    let mut ann = sign_route_announcement(
        &sk,
        1,
        vec![
            link([0x11; 16], 1, 1),
            link([0x22; 16], 1, 1),
            link([0x33; 16], 1, 1),
        ],
    )
    .unwrap();
    ann.links.swap(0, 2);
    let err = ann.verify(&vk).unwrap_err();
    assert!(matches!(
        err,
        DeviceMeshError::RouteAnnouncementLinksNotSorted
    ));
}

#[test]
fn adversarial_announcement_manual_self_loop_rejected() {
    let (sk, vk) = make_subkey();
    let own = *sk.device_id();
    let mut ann = sign_route_announcement(&sk, 1, vec![link([0x11; 16], 1, 1)]).unwrap();
    // Manually inject a self-loop entry post-sign.
    ann.links.insert(0, link(own, 1, 1));
    // Need to re-sort by peer_device_id for sort check to pass.
    ann.links.sort_by_key(|l| l.peer_device_id);
    let err = ann.verify(&vk).unwrap_err();
    assert!(matches!(err, DeviceMeshError::RouteAnnouncementSelfLoop));
}

#[test]
fn adversarial_announcement_tampered_tau_score_rejected() {
    let (sk, vk) = make_subkey();
    let mut ann = sign_route_announcement(&sk, 1, vec![link([0x11; 16], 100, 1)]).unwrap();
    ann.links[0].tau_score = 1;
    let err = ann.verify(&vk).unwrap_err();
    assert!(matches!(err, DeviceMeshError::RouteAnnouncementVerifyFail));
}

// ── Route picker adversarial ──────────────────────────────────────

#[test]
fn adversarial_route_disconnected_returns_none() {
    let (ids, _sks, _vks) = make_three();
    let r = pick_best_route(&RouteTable::empty(), &ids[0], &ids[1]);
    assert!(r.is_none());
}

#[test]
fn adversarial_route_isolated_dst_returns_none() {
    let (ids, sks, vks) = make_three();
    let mut table = RouteTable::empty();
    // src announces; dst announces nothing → no inbound path.
    let ann = sign_route_announcement(&sks[0], 1, vec![link(ids[2], 100, 1)]).unwrap();
    table.ingest(ann, &vks[0]).unwrap();
    let r = pick_best_route(&table, &ids[0], &ids[1]);
    assert!(r.is_none());
}

#[test]
fn adversarial_indirect_link_skipped_for_routing() {
    // Even if an announcement lists peer P with direct=false, the
    // route picker must NOT use that edge.
    let (ids, sks, vks) = make_three();
    let mut table = RouteTable::empty();
    let ann = RouteAnnouncement {
        announcer_device_id: ids[0],
        announcer_day_index: 0,
        announced_at_unix: 1,
        links: vec![PeerLink {
            peer_device_id: ids[1],
            tau_score: 100,
            last_seen_unix: 1,
            direct: false,
        }],
        announcer_sig: vec![],
    };
    // Sign it properly.
    let real_ann = sign_route_announcement(&sks[0], 1, ann.links.clone()).unwrap();
    table.ingest(real_ann, &vks[0]).unwrap();
    let r = pick_best_route(&table, &ids[0], &ids[1]);
    assert!(r.is_none(), "indirect-only path must not be usable");
}

// ── Multi-path adversarial ────────────────────────────────────────

#[test]
fn adversarial_multi_path_zero_k_returns_empty() {
    let (ids, _sks, _vks) = make_three();
    let paths = multi_path_plan(&RouteTable::empty(), &ids[0], &ids[1], 0);
    assert!(paths.is_empty());
}

// ── DTN courier adversarial ───────────────────────────────────────

#[test]
fn adversarial_dtn_no_courier_if_only_one_endpoint_seen() {
    let (ids, sks, vks) = make_three();
    let mut table = RouteTable::empty();
    // src announces seeing courier; nothing about dst.
    let ann = sign_route_announcement(&sks[0], 100, vec![link(ids[2], 50, 100)]).unwrap();
    table.ingest(ann, &vks[0]).unwrap();
    let c = dtn_couriers(&table, &ids[0], &ids[1], 1_000_000);
    assert!(c.is_empty());
}

#[test]
fn adversarial_dtn_filter_by_gap() {
    let (ids, sks, vks) = make_three();
    let mut table = RouteTable::empty();
    let ann = sign_route_announcement(
        &sks[2],
        500,
        vec![link(ids[0], 50, 100), link(ids[1], 50, 500)],
    )
    .unwrap();
    table.ingest(ann, &vks[2]).unwrap();
    // Gap is 400. With max_gap = 100 → no couriers.
    assert!(dtn_couriers(&table, &ids[0], &ids[1], 100).is_empty());
    // With max_gap = 500 → 1 courier.
    assert_eq!(dtn_couriers(&table, &ids[0], &ids[1], 500).len(), 1);
}

// ── Helpers ────────────────────────────────────────────────────────

fn make_three() -> (
    Vec<[u8; DEVICE_ID_LEN]>,
    Vec<ol_device_mesh::DeviceSubkey>,
    Vec<HybridVerifyingKey>,
) {
    let master = MasterIdentity::generate(&mut OsRng);
    let mut ids = Vec::new();
    let mut sks = Vec::new();
    let mut vks = Vec::new();
    for i in 1u8..=3 {
        let id = [i; DEVICE_ID_LEN];
        let (sk, att) = mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
        let vk = HybridVerifyingKey::from_bytes(&att.subkey_vk_bytes).unwrap();
        ids.push(id);
        sks.push(sk);
        vks.push(vk);
    }
    (ids, sks, vks)
}
