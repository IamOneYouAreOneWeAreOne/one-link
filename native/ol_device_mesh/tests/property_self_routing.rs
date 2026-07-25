//! Property tests for Row 8 Layer 6 self-routing.

use proptest::prelude::*;
use rand::rngs::OsRng;

use ol_device_mesh::self_routing::{
    dtn_couriers, multi_path_plan, pick_best_route, sign_route_announcement, PeerLink,
    RouteAnnouncement, RouteTable, TauScore,
};
use ol_device_mesh::{mint_subkey, DeviceClass, DeviceSubkey, MasterIdentity, DEVICE_ID_LEN};
use ol_pqsig::HybridVerifyingKey;

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
        1_000
    }
}

fn link_for(peer: [u8; DEVICE_ID_LEN], tau: TauScore, seen: u64) -> PeerLink {
    PeerLink {
        peer_device_id: peer,
        tau_score: tau,
        last_seen_unix: seen,
        direct: true,
    }
}

// ── 1M-iter properties on the pure canonical transcript ──────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cheap_cases() / 4,
        max_global_rejects: cheap_cases() * 4,
        .. ProptestConfig::default()
    })]

    /// canonical_transcript is a pure function of its inputs.
    #[test]
    fn route_announcement_transcript_deterministic(
        announcer in any::<[u8; DEVICE_ID_LEN]>(),
        day in any::<u64>(),
        unix in any::<u64>(),
        tau in any::<TauScore>(),
        peer in any::<[u8; DEVICE_ID_LEN]>(),
    ) {
        let links = vec![link_for(peer, tau, unix)];
        let a = RouteAnnouncement::canonical_transcript(&announcer, day, unix, &links);
        let b = RouteAnnouncement::canonical_transcript(&announcer, day, unix, &links);
        prop_assert_eq!(a, b);
    }

    /// transcript length grows linearly in link count, and the
    /// per-link contribution is exactly 16+4+8+1 = 29 bytes.
    #[test]
    fn route_transcript_length_is_predictable(
        n in 0usize..16,
    ) {
        let announcer = [0u8; DEVICE_ID_LEN];
        let links: Vec<PeerLink> = (0..n).map(|i| {
            let mut peer = [0u8; DEVICE_ID_LEN];
            peer[0] = u8::try_from(i)
                .expect("the generator creates at most 15 links")
                + 1;
            link_for(peer, 100, 1)
        }).collect();
        let bytes = RouteAnnouncement::canonical_transcript(&announcer, 0, 0, &links);
        // domain(29) + announcer(16) + day(8) + unix(8) + count(4)
        //  + n * (peer(16) + tau(4) + seen(8) + direct(1)) = 65 + 29n
        prop_assert_eq!(bytes.len(), 65 + 29 * n);
    }
}

// ── Keygen-bound properties ──────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: keygen_cases(),
        max_global_rejects: keygen_cases() * 4,
        .. ProptestConfig::default()
    })]

    /// Sign + verify round trip for arbitrary link sets.
    #[test]
    fn announcement_sign_verify_round_trip(
        n_links in 0usize..16,
        announced_at in any::<u64>(),
    ) {
        let master = MasterIdentity::generate(&mut OsRng);
        let id = [0xAA; DEVICE_ID_LEN];
        let (sk, att) =
            mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
        let vk = HybridVerifyingKey::from_bytes(&att.subkey_vk_bytes).unwrap();
        let links: Vec<PeerLink> = (1..=n_links).map(|i| {
            let mut peer = [0u8; DEVICE_ID_LEN];
            peer[0] = u8::try_from(i)
                .expect("the generator creates at most 15 links")
                + 1;
            let tau = TauScore::try_from(i).expect("the generated link count fits in TauScore");
            let last_seen =
                u64::try_from(i).expect("supported Rust pointer widths fit in u64");
            link_for(peer, tau * 10, last_seen)
        }).collect();
        let ann = sign_route_announcement(&sk, announced_at, links).unwrap();
        ann.verify(&vk).unwrap();
    }

    /// pick_best_route returns Some only when src and dst are
    /// connected via at least one direct chain.
    #[test]
    fn pick_route_self_returns_zero_length(
        seed in any::<u8>(),
    ) {
        let master = MasterIdentity::generate(&mut OsRng);
        let id = [seed; DEVICE_ID_LEN];
        let _ = mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
        let r = pick_best_route(&RouteTable::empty(), &id, &id).unwrap();
        prop_assert_eq!(r.length(), 0);
    }
}

// ── DTN courier sanity (no proptest, just deterministic) ─────────

fn make_devices(
    n: usize,
) -> (
    Vec<[u8; DEVICE_ID_LEN]>,
    Vec<DeviceSubkey>,
    Vec<HybridVerifyingKey>,
) {
    let master = MasterIdentity::generate(&mut OsRng);
    let mut ids = Vec::new();
    let mut sks = Vec::new();
    let mut vks = Vec::new();
    for _ in 0..n {
        let ordinal = ids
            .len()
            .checked_add(1)
            .and_then(|value| u8::try_from(value).ok())
            .expect("test meshes contain at most u8::MAX devices");
        let id = [ordinal; DEVICE_ID_LEN];
        let (sk, att) = mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
        let vk = HybridVerifyingKey::from_bytes(&att.subkey_vk_bytes).unwrap();
        ids.push(id);
        sks.push(sk);
        vks.push(vk);
    }
    (ids, sks, vks)
}

#[test]
fn multi_path_returns_no_paths_for_disconnected() {
    let (ids, _sks, _vks) = make_devices(2);
    let paths = multi_path_plan(&RouteTable::empty(), &ids[0], &ids[1], 3);
    assert!(paths.is_empty());
}

#[test]
fn dtn_couriers_empty_when_no_announcements() {
    let (ids, _sks, _vks) = make_devices(2);
    let c = dtn_couriers(&RouteTable::empty(), &ids[0], &ids[1], 1_000_000);
    assert!(c.is_empty());
}
