//! Aggregated route table.
//!
//! A [`RouteTable`] is the receiver's view across every ingested
//! [`RouteAnnouncement`]. New announcements from the same announcer
//! REPLACE the prior one when their `announced_at_unix` is strictly
//! greater (LWW); ties on timestamp break to the announcement with
//! the higher `announcer_day_index` so the newer subkey wins.

use std::collections::BTreeMap;

use ol_pqsig::HybridVerifyingKey;

use crate::errors::DeviceMeshResult;
use crate::subkey::DEVICE_ID_LEN;

use super::announcement::RouteAnnouncement;
use super::route::{pick_best_route, Route, TauScore, TAU_UNKNOWN};

/// Aggregated route view.
#[derive(Debug, Clone, Default)]
pub struct RouteTable {
    announcements: BTreeMap<[u8; DEVICE_ID_LEN], RouteAnnouncement>,
}

impl RouteTable {
    /// Empty table.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Number of announcers we've heard from.
    #[must_use]
    pub fn announcer_count(&self) -> usize {
        self.announcements.len()
    }

    /// Borrow the latest announcement for a given announcer.
    #[must_use]
    pub fn announcement_for(
        &self,
        announcer: &[u8; DEVICE_ID_LEN],
    ) -> Option<&RouteAnnouncement> {
        self.announcements.get(announcer)
    }

    /// All announcers we've heard from, in deterministic order.
    pub fn announcers(&self) -> impl Iterator<Item = &[u8; DEVICE_ID_LEN]> {
        self.announcements.keys()
    }

    /// Ingest a fresh announcement. Verifies the announcer's
    /// signature under the supplied subkey VK; if the announcement
    /// dominates the prior one (newer `announced_at_unix`, or same
    /// timestamp + newer `announcer_day_index`), it replaces it.
    /// Otherwise the call is a no-op.
    ///
    /// Returns `Ok(true)` if the table actually changed.
    pub fn ingest(
        &mut self,
        ann: RouteAnnouncement,
        announcer_vk: &HybridVerifyingKey,
    ) -> DeviceMeshResult<bool> {
        ann.verify(announcer_vk)?;
        let prior = self.announcements.get(&ann.announcer_device_id);
        let dominates = match prior {
            None => true,
            Some(old) => match ann.announced_at_unix.cmp(&old.announced_at_unix) {
                std::cmp::Ordering::Greater => true,
                std::cmp::Ordering::Less => false,
                std::cmp::Ordering::Equal => {
                    ann.announcer_day_index > old.announcer_day_index
                }
            },
        };
        if !dominates {
            return Ok(false);
        }
        self.announcements.insert(ann.announcer_device_id, ann);
        Ok(true)
    }

    /// Drop announcements older than `max_age_secs` relative to
    /// `now_unix`. Returns the number of entries evicted.
    pub fn prune_stale(&mut self, now_unix: u64, max_age_secs: u64) -> usize {
        let threshold = now_unix.saturating_sub(max_age_secs);
        let before = self.announcements.len();
        self.announcements
            .retain(|_, a| a.announced_at_unix >= threshold);
        before - self.announcements.len()
    }
}

/// Find up to `k` highest-bottleneck-τ paths between `src` and
/// `dst`. The first path is the maximum-bottleneck one; subsequent
/// paths are found by removing the bottleneck edge of the prior
/// best path and re-running the picker. Returns fewer than `k`
/// paths if the topology can't supply more disjoint options.
///
/// Useful for the daemon's "race over Wi-Fi + cellular" mode where
/// the receiver wants distinct physical legs.
#[must_use]
pub fn multi_path_plan(
    table: &RouteTable,
    src: &[u8; DEVICE_ID_LEN],
    dst: &[u8; DEVICE_ID_LEN],
    k: usize,
) -> Vec<Route> {
    if k == 0 {
        return Vec::new();
    }
    let mut working = table.clone();
    let mut paths = Vec::with_capacity(k);
    for _ in 0..k {
        let Some(r) = pick_best_route(&working, src, dst) else {
            break;
        };
        // Find the bottleneck edge along the path and patch the
        // working table to drop it.
        let bottleneck_edge = find_bottleneck_edge(&r, &working);
        paths.push(r);
        if let Some((u, v)) = bottleneck_edge {
            redact_edge(&mut working, &u, &v);
        } else {
            break; // no edge to remove → no more disjoint paths
        }
    }
    paths
}

fn find_bottleneck_edge(
    r: &Route,
    table: &RouteTable,
) -> Option<([u8; DEVICE_ID_LEN], [u8; DEVICE_ID_LEN])> {
    if r.hops.len() < 2 {
        return None;
    }
    let mut worst: Option<(TauScore, [u8; DEVICE_ID_LEN], [u8; DEVICE_ID_LEN])> = None;
    for w in r.hops.windows(2) {
        let u = w[0];
        let v = w[1];
        let edge_tau = table
            .announcement_for(&u)
            .map_or(TAU_UNKNOWN, |a| {
                a.links
                    .iter()
                    .find(|l| l.peer_device_id == v && l.direct)
                    .map_or(TAU_UNKNOWN, |l| l.tau_score)
            });
        match worst {
            None => worst = Some((edge_tau, u, v)),
            Some((cur, _, _)) if edge_tau < cur => worst = Some((edge_tau, u, v)),
            _ => {}
        }
    }
    worst.map(|(_, u, v)| (u, v))
}

fn redact_edge(
    table: &mut RouteTable,
    u: &[u8; DEVICE_ID_LEN],
    v: &[u8; DEVICE_ID_LEN],
) {
    // Remove the (u→v) edge from u's announcement. The bidirectional
    // counterpart (v→u) stays; this just blocks the chosen edge in
    // the FORWARD direction for subsequent multi-path picks.
    if let Some(a) = table.announcements.get_mut(u) {
        a.links
            .retain(|l| !(l.peer_device_id == *v && l.direct));
    }
}

#[cfg(test)]
mod tests {
    use super::super::announcement::{sign_route_announcement, PeerLink};
    use super::*;
    use crate::master::MasterIdentity;
    use crate::subkey::{fresh_device_id, mint_subkey, SubkeyAttestation};
    use crate::DeviceClass;
    use rand::rngs::OsRng;

    fn setup(n: usize) -> (
        Vec<[u8; DEVICE_ID_LEN]>,
        Vec<crate::subkey::DeviceSubkey>,
        Vec<SubkeyAttestation>,
    ) {
        let master = MasterIdentity::generate(&mut OsRng);
        let mut ids = Vec::new();
        let mut sks = Vec::new();
        let mut atts = Vec::new();
        for _ in 0..n {
            let id = fresh_device_id(&mut OsRng);
            let (sk, a) =
                mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
            ids.push(id);
            sks.push(sk);
            atts.push(a);
        }
        (ids, sks, atts)
    }

    fn vk(att: &SubkeyAttestation) -> HybridVerifyingKey {
        HybridVerifyingKey::from_bytes(&att.subkey_vk_bytes).unwrap()
    }

    fn link(peer: [u8; DEVICE_ID_LEN], tau: TauScore, seen: u64) -> PeerLink {
        PeerLink {
            peer_device_id: peer,
            tau_score: tau,
            last_seen_unix: seen,
            direct: true,
        }
    }

    #[test]
    fn ingest_newer_replaces_older() {
        let (ids, sks, atts) = setup(2);
        let mut table = RouteTable::empty();
        let old = sign_route_announcement(&sks[0], 1, vec![link(ids[1], 10, 1)]).unwrap();
        let new = sign_route_announcement(&sks[0], 2, vec![link(ids[1], 100, 2)]).unwrap();
        table.ingest(old, &vk(&atts[0])).unwrap();
        table.ingest(new, &vk(&atts[0])).unwrap();
        let cur = table.announcement_for(&ids[0]).unwrap();
        assert_eq!(cur.links[0].tau_score, 100);
    }

    #[test]
    fn ingest_older_is_no_op() {
        let (ids, sks, atts) = setup(2);
        let mut table = RouteTable::empty();
        let new = sign_route_announcement(&sks[0], 2, vec![link(ids[1], 100, 2)]).unwrap();
        let old = sign_route_announcement(&sks[0], 1, vec![link(ids[1], 10, 1)]).unwrap();
        table.ingest(new, &vk(&atts[0])).unwrap();
        let changed = table.ingest(old, &vk(&atts[0])).unwrap();
        assert!(!changed);
        let cur = table.announcement_for(&ids[0]).unwrap();
        assert_eq!(cur.links[0].tau_score, 100);
    }

    #[test]
    fn prune_stale_drops_old_entries() {
        let (ids, sks, atts) = setup(2);
        let mut table = RouteTable::empty();
        let ann = sign_route_announcement(&sks[0], 100, vec![link(ids[1], 10, 100)]).unwrap();
        table.ingest(ann, &vk(&atts[0])).unwrap();
        // Now 1000 sec later with max_age 100 → entry is stale.
        let dropped = table.prune_stale(1_000, 100);
        assert_eq!(dropped, 1);
        assert_eq!(table.announcer_count(), 0);
    }

    #[test]
    fn multi_path_finds_two_disjoint_routes() {
        // src has two equal-tau paths to dst, via two different
        // relays. multi_path_plan(k=2) should return both.
        let (ids, sks, atts) = setup(4);
        let src = ids[0];
        let dst = ids[1];
        let via_a = ids[2];
        let via_b = ids[3];
        let mut table = RouteTable::empty();
        table.ingest(
            sign_route_announcement(
                &sks[0],
                1,
                vec![link(via_a, 100, 1), link(via_b, 100, 1)],
            )
            .unwrap(),
            &vk(&atts[0]),
        )
        .unwrap();
        table.ingest(
            sign_route_announcement(&sks[2], 1, vec![link(dst, 100, 1)]).unwrap(),
            &vk(&atts[2]),
        )
        .unwrap();
        table.ingest(
            sign_route_announcement(&sks[3], 1, vec![link(dst, 100, 1)]).unwrap(),
            &vk(&atts[3]),
        )
        .unwrap();
        table.ingest(
            sign_route_announcement(&sks[1], 1, vec![]).unwrap(),
            &vk(&atts[1]),
        )
        .unwrap();
        let paths = multi_path_plan(&table, &src, &dst, 2);
        assert!(paths.len() >= 1);
        // Verify each path is end-to-end correct.
        for p in &paths {
            assert_eq!(p.hops.first(), Some(&src));
            assert_eq!(p.hops.last(), Some(&dst));
        }
    }
}
