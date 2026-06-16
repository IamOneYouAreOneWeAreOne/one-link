//! Route + `τ_c` score types.

use crate::subkey::DEVICE_ID_LEN;

use super::table::RouteTable;

/// Discrete `τ_c` estimate. Higher = better (lower loss + lower
/// latency). Stored as a u32 so the canonical wire format is
/// deterministic and ordering is total.
pub type TauScore = u32;

/// Worst-case "no edge known" sentinel — distinct from `TauScore = 0`
/// which means "we know about this edge but it's degraded."
pub const TAU_UNKNOWN: TauScore = 0;

/// A resolved route from src to dst.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// Hops in order: `hops[0] == src`, `hops.last() == dst`. For a
    /// direct route, `hops == [src, dst]` (length 2).
    pub hops: Vec<[u8; DEVICE_ID_LEN]>,
    /// The minimum `τ_c` across all hops on this path — the
    /// bottleneck score. Higher = better.
    pub bottleneck_tau: TauScore,
    /// Latest of the per-edge `last_seen_unix` values along the
    /// path. Receivers use this to age out stale routes.
    pub min_last_seen_unix: u64,
}

impl Route {
    /// Number of hops minus one (the path length).
    #[must_use]
    pub const fn length(&self) -> usize {
        self.hops.len().saturating_sub(1)
    }
    /// `true` iff this is a direct `src → dst` route.
    #[must_use]
    pub fn is_direct(&self) -> bool {
        self.length() == 1
    }
}

/// Find the maximum-bottleneck-τ path from `src` to `dst` in the
/// given route table.
///
/// Algorithm: variant of Dijkstra where "distance" is replaced with
/// "smallest τ on the path so far," and we MAXIMIZE that quantity.
/// Equivalent to the widest-path / bottleneck-routing problem,
/// runs in `O((V + E) log V)`.
///
/// Returns `None` if no path exists.
#[must_use]
pub fn pick_best_route(
    table: &RouteTable,
    src: &[u8; DEVICE_ID_LEN],
    dst: &[u8; DEVICE_ID_LEN],
) -> Option<Route> {
    use std::collections::{BTreeMap, BinaryHeap};

    if src == dst {
        return Some(Route {
            hops: vec![*src],
            bottleneck_tau: TauScore::MAX,
            min_last_seen_unix: u64::MAX,
        });
    }

    // best_tau[v] = highest bottleneck-tau seen reaching v.
    let mut best_tau: BTreeMap<[u8; DEVICE_ID_LEN], TauScore> = BTreeMap::new();
    let mut best_seen: BTreeMap<[u8; DEVICE_ID_LEN], u64> = BTreeMap::new();
    let mut prev: BTreeMap<[u8; DEVICE_ID_LEN], [u8; DEVICE_ID_LEN]> = BTreeMap::new();

    // Max-heap by bottleneck-tau; tie-break on freshness; final
    // tie-break on lex device id so the algorithm is deterministic.
    let mut heap: BinaryHeap<(TauScore, u64, [u8; DEVICE_ID_LEN])> = BinaryHeap::new();
    best_tau.insert(*src, TauScore::MAX);
    best_seen.insert(*src, u64::MAX);
    heap.push((TauScore::MAX, u64::MAX, *src));

    while let Some((cur_tau, cur_seen, node)) = heap.pop() {
        if cur_tau < *best_tau.get(&node).unwrap_or(&TAU_UNKNOWN) {
            continue;
        }
        if node == *dst {
            break;
        }
        // Find all announcements that mention `node` as the
        // announcer; their links describe `node`'s view of its
        // peers.
        let Some(ann) = table.announcement_for(&node) else {
            continue;
        };
        for link in &ann.links {
            if !link.direct {
                continue;
            }
            let edge_tau = link.tau_score;
            let edge_seen = link.last_seen_unix;
            let new_bottleneck = cur_tau.min(edge_tau);
            let new_seen = cur_seen.min(edge_seen);
            let prior = best_tau
                .get(&link.peer_device_id)
                .copied()
                .unwrap_or(TAU_UNKNOWN);
            let prior_seen = best_seen.get(&link.peer_device_id).copied().unwrap_or(0);
            let dominates =
                new_bottleneck > prior || (new_bottleneck == prior && new_seen > prior_seen);
            if dominates {
                best_tau.insert(link.peer_device_id, new_bottleneck);
                best_seen.insert(link.peer_device_id, new_seen);
                prev.insert(link.peer_device_id, node);
                heap.push((new_bottleneck, new_seen, link.peer_device_id));
            }
        }
    }

    let final_tau = best_tau.get(dst).copied()?;
    let final_seen = best_seen.get(dst).copied().unwrap_or(0);
    let mut hops = vec![*dst];
    let mut cursor = *dst;
    while let Some(p) = prev.get(&cursor) {
        hops.push(*p);
        cursor = *p;
        if cursor == *src {
            break;
        }
    }
    if cursor != *src {
        return None;
    }
    hops.reverse();
    Some(Route {
        hops,
        bottleneck_tau: final_tau,
        min_last_seen_unix: final_seen,
    })
}

#[cfg(test)]
mod tests {
    use super::super::announcement::{sign_route_announcement, PeerLink};
    use super::super::table::RouteTable;
    use super::*;
    use crate::master::MasterIdentity;
    use crate::subkey::{fresh_device_id, mint_subkey, SubkeyAttestation};
    use crate::DeviceClass;
    use ol_pqsig::HybridVerifyingKey;
    use rand::rngs::OsRng;

    fn setup(
        n: usize,
    ) -> (
        Vec<[u8; DEVICE_ID_LEN]>,
        Vec<crate::subkey::DeviceSubkey>,
        Vec<SubkeyAttestation>,
        MasterIdentity,
    ) {
        let master = MasterIdentity::generate(&mut OsRng);
        let mut ids = Vec::new();
        let mut sks = Vec::new();
        let mut atts = Vec::new();
        for _ in 0..n {
            let id = fresh_device_id(&mut OsRng);
            let (sk, a) = mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
            ids.push(id);
            sks.push(sk);
            atts.push(a);
        }
        (ids, sks, atts, master)
    }

    fn link(peer: [u8; DEVICE_ID_LEN], tau: TauScore, seen: u64) -> PeerLink {
        PeerLink {
            peer_device_id: peer,
            tau_score: tau,
            last_seen_unix: seen,
            direct: true,
        }
    }

    fn vk(att: &SubkeyAttestation) -> HybridVerifyingKey {
        HybridVerifyingKey::from_bytes(&att.subkey_vk_bytes).unwrap()
    }

    #[test]
    fn picks_direct_route_when_available() {
        let (ids, sks, atts, _m) = setup(2);
        let ann_0 = sign_route_announcement(
            &sks[0],
            1_700_000_000,
            vec![link(ids[1], 100, 1_700_000_000)],
        )
        .unwrap();
        let ann_1 = sign_route_announcement(
            &sks[1],
            1_700_000_000,
            vec![link(ids[0], 100, 1_700_000_000)],
        )
        .unwrap();
        let mut table = RouteTable::empty();
        table.ingest(ann_0, &vk(&atts[0])).unwrap();
        table.ingest(ann_1, &vk(&atts[1])).unwrap();
        let r = pick_best_route(&table, &ids[0], &ids[1]).unwrap();
        assert!(r.is_direct());
        assert_eq!(r.bottleneck_tau, 100);
    }

    #[test]
    fn no_route_returns_none() {
        let (ids, _sks, _atts, _m) = setup(2);
        let table = RouteTable::empty();
        assert!(pick_best_route(&table, &ids[0], &ids[1]).is_none());
    }

    #[test]
    fn prefers_higher_bottleneck_tau() {
        // src → a (tau 100) → dst    vs    src → b (tau 50) → dst
        // src → dst direct (tau 30)
        // Best: through `a` with bottleneck 100.
        let (ids, sks, atts, _m) = setup(4);
        let src = ids[0];
        let dst = ids[1];
        let via_a = ids[2];
        let via_b = ids[3];
        let mut table = RouteTable::empty();
        // src reaches a (100), b (50), dst direct (30).
        table
            .ingest(
                sign_route_announcement(
                    &sks[0],
                    1,
                    vec![link(via_a, 100, 1), link(via_b, 50, 1), link(dst, 30, 1)],
                )
                .unwrap(),
                &vk(&atts[0]),
            )
            .unwrap();
        // a reaches dst (100).
        table
            .ingest(
                sign_route_announcement(&sks[2], 1, vec![link(dst, 100, 1), link(src, 100, 1)])
                    .unwrap(),
                &vk(&atts[2]),
            )
            .unwrap();
        // b reaches dst (50).
        table
            .ingest(
                sign_route_announcement(&sks[3], 1, vec![link(dst, 50, 1), link(src, 50, 1)])
                    .unwrap(),
                &vk(&atts[3]),
            )
            .unwrap();
        // dst announces its own reachability.
        table
            .ingest(
                sign_route_announcement(
                    &sks[1],
                    1,
                    vec![link(src, 30, 1), link(via_a, 100, 1), link(via_b, 50, 1)],
                )
                .unwrap(),
                &vk(&atts[1]),
            )
            .unwrap();
        let r = pick_best_route(&table, &src, &dst).unwrap();
        // Bottleneck on path src → a → dst is min(100, 100) = 100.
        // Direct src → dst is 30. Through b is min(50, 50) = 50.
        // So best should be the via_a path.
        assert_eq!(r.bottleneck_tau, 100);
        assert_eq!(r.hops.len(), 3);
        assert_eq!(r.hops[1], via_a);
    }

    #[test]
    fn src_eq_dst_yields_zero_length_route() {
        let (ids, _sks, _atts, _m) = setup(1);
        let r = pick_best_route(&RouteTable::empty(), &ids[0], &ids[0]).unwrap();
        assert_eq!(r.length(), 0);
        assert_eq!(r.bottleneck_tau, TauScore::MAX);
    }
}
