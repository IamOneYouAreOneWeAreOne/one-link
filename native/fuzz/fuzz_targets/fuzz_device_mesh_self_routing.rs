#![no_main]
//! Fuzz the Layer 6 self-routing announcement + table surface.

use libfuzzer_sys::fuzz_target;
use ol_device_mesh::self_routing::{
    dtn_couriers, multi_path_plan, pick_best_route, sign_route_announcement, PeerLink,
    RouteTable, TauScore,
};
use ol_device_mesh::{
    mint_subkey, DeviceClass, MasterIdentity, DEVICE_ID_LEN,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fuzz_target!(|data: &[u8]| {
    let mut rng = ChaCha20Rng::from_seed([0xA6u8; 32]);
    let master = MasterIdentity::generate(&mut rng);
    let (sk, att_l1) = mint_subkey(
        &master, DeviceClass::Phone, [0x55; DEVICE_ID_LEN], 0, 365,
    )
    .unwrap();
    let vk = ol_pqsig::HybridVerifyingKey::from_bytes(&att_l1.subkey_vk_bytes).unwrap();

    // 1. Build a fuzz-derived link list and sign an announcement.
    let n = ((data.first().copied().unwrap_or(0) as usize) % 16) + 1;
    let mut links: Vec<PeerLink> = Vec::new();
    for i in 0..n {
        let mut peer = [0u8; DEVICE_ID_LEN];
        peer[0] = (i + 1) as u8;
        peer[1] = data.get(i + 1).copied().unwrap_or(0);
        links.push(PeerLink {
            peer_device_id: peer,
            tau_score: u32::from(data.get(i + 2).copied().unwrap_or(0)) * 100,
            last_seen_unix: 1,
            direct: data.get(i + 3).copied().unwrap_or(1) != 0,
        });
    }
    if let Ok(ann) = sign_route_announcement(&sk, 1, links) {
        let _ = ann.verify(&vk);
        // 2. Ingest into a fresh table + run queries.
        let mut table = RouteTable::empty();
        let _ = table.ingest(ann, &vk);
        let src = [0x01; DEVICE_ID_LEN];
        let dst = [0xFF; DEVICE_ID_LEN];
        let _ = pick_best_route(&table, &src, &dst);
        let _ = multi_path_plan(&table, &src, &dst, 3);
        let _ = dtn_couriers(&table, &src, &dst, 1_000_000);
        let _ = table.prune_stale(2, 0);
    }

    // 3. Mutate a signed announcement and try re-verify.
    let _ = sign_route_announcement(&sk, 1, vec![PeerLink {
        peer_device_id: [0xAA; DEVICE_ID_LEN],
        tau_score: 100,
        last_seen_unix: 1,
        direct: true,
    }]).map(|mut a| {
        if let Some(&b) = data.first() {
            if !a.links.is_empty() {
                a.links[0].tau_score = u32::from(b) * 1000;
            }
        }
        let _ = a.verify(&vk);
    });
});
