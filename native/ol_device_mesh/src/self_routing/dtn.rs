//! DTN (delay-tolerant networking) courier detection.
//!
//! When two devices (`src`, `dst`) can't reach each other directly
//! OR through any currently-online intermediate, a "courier" device
//! may still carry state between them — picture a tablet that
//! visits home (sees the desktop) then flies elsewhere (sees the
//! phone) and acts as a physical sneakernet between the two.
//!
//! [`dtn_couriers`] returns devices that have been seen reachable
//! to BOTH endpoints within the configured time window, even if
//! they aren't currently online at both at the same time.

use std::collections::BTreeMap;

use crate::subkey::DEVICE_ID_LEN;

use super::table::RouteTable;

/// One per-courier observation record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CourierObservation {
    /// Courier device id.
    pub device_id: [u8; DEVICE_ID_LEN],
    /// Last time the courier was seen reachable to `src`.
    pub src_seen_unix: u64,
    /// Last time the courier was seen reachable to `dst`.
    pub dst_seen_unix: u64,
}

impl CourierObservation {
    /// Time gap between the two reachability sightings. Smaller is
    /// better (less latency in the courier's round trip).
    #[must_use]
    pub const fn gap_secs(&self) -> u64 {
        self.src_seen_unix.abs_diff(self.dst_seen_unix)
    }
}

/// Return devices that have been reachable to both `src` and `dst`
/// within `max_gap_secs` of each other.
///
/// A device `D` qualifies as a courier iff:
/// 1. Some announcement reports `D` reaching `src`.
/// 2. Some announcement reports `D` reaching `dst`.
/// 3. The two `last_seen_unix` values are within `max_gap_secs`.
///
/// The two sightings may come from `D`'s own announcement (`D`
/// claims it reached `src` and `dst`) or from announcements by `src`
/// and `dst` themselves (each said it saw `D`).
///
/// Returns observations sorted by smallest `gap_secs` first.
#[must_use]
pub fn dtn_couriers(
    table: &RouteTable,
    src: &[u8; DEVICE_ID_LEN],
    dst: &[u8; DEVICE_ID_LEN],
    max_gap_secs: u64,
) -> Vec<CourierObservation> {
    // Map: courier_device → (best src_seen, best dst_seen).
    let mut sightings: BTreeMap<[u8; DEVICE_ID_LEN], (u64, u64)> = BTreeMap::new();

    // For each announcement A authored by D:
    //   - A.links contains an entry for `src` → D saw src at time T.
    //   - A.links contains an entry for `dst` → D saw dst at time T.
    // For each announcement A authored by src:
    //   - A.links has D → src saw D at T (so D is reachable to src then).
    // For each announcement A authored by dst:
    //   - A.links has D → dst saw D at T.
    for announcer in table.announcers() {
        let Some(ann) = table.announcement_for(announcer) else { continue };
        for link in &ann.links {
            // src's announcement of D → D was reachable to src at link.last_seen_unix.
            if announcer == src && link.peer_device_id != *src && link.peer_device_id != *dst {
                let entry = sightings.entry(link.peer_device_id).or_insert((0, 0));
                if link.last_seen_unix > entry.0 {
                    entry.0 = link.last_seen_unix;
                }
            }
            // dst's announcement of D.
            if announcer == dst && link.peer_device_id != *src && link.peer_device_id != *dst {
                let entry = sightings.entry(link.peer_device_id).or_insert((0, 0));
                if link.last_seen_unix > entry.1 {
                    entry.1 = link.last_seen_unix;
                }
            }
            // D's announcement of src or dst.
            if announcer != src && announcer != dst {
                if link.peer_device_id == *src {
                    let entry = sightings.entry(*announcer).or_insert((0, 0));
                    if link.last_seen_unix > entry.0 {
                        entry.0 = link.last_seen_unix;
                    }
                } else if link.peer_device_id == *dst {
                    let entry = sightings.entry(*announcer).or_insert((0, 0));
                    if link.last_seen_unix > entry.1 {
                        entry.1 = link.last_seen_unix;
                    }
                }
            }
        }
    }

    let mut out: Vec<CourierObservation> = sightings
        .into_iter()
        .filter_map(|(device_id, (a, b))| {
            if a > 0 && b > 0 {
                let obs = CourierObservation {
                    device_id,
                    src_seen_unix: a,
                    dst_seen_unix: b,
                };
                if obs.gap_secs() <= max_gap_secs {
                    Some(obs)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();
    out.sort_by(|a, b| a.gap_secs().cmp(&b.gap_secs()).then(a.device_id.cmp(&b.device_id)));
    out
}

#[cfg(test)]
mod tests {
    use super::super::announcement::{sign_route_announcement, PeerLink};
    use super::super::route::TauScore;
    use super::*;
    use crate::master::MasterIdentity;
    use crate::subkey::{fresh_device_id, mint_subkey, SubkeyAttestation};
    use crate::DeviceClass;
    use ol_pqsig::HybridVerifyingKey;
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
    fn courier_detected_from_its_own_announcement() {
        // Tablet (T) saw desktop (S) at t=100 and phone (D) at
        // t=120 → courier with gap 20.
        let (ids, sks, atts) = setup(3);
        let src = ids[0]; // desktop
        let dst = ids[1]; // phone
        let courier = ids[2]; // tablet
        let mut table = RouteTable::empty();
        // Courier announces seeing both.
        table.ingest(
            sign_route_announcement(
                &sks[2],
                120,
                vec![link(src, 50, 100), link(dst, 50, 120)],
            )
            .unwrap(),
            &vk(&atts[2]),
        )
        .unwrap();
        let couriers = dtn_couriers(&table, &src, &dst, 60);
        assert_eq!(couriers.len(), 1);
        assert_eq!(couriers[0].device_id, courier);
        assert_eq!(couriers[0].gap_secs(), 20);
    }

    #[test]
    fn courier_filtered_by_max_gap() {
        let (ids, sks, atts) = setup(3);
        let src = ids[0];
        let dst = ids[1];
        let mut table = RouteTable::empty();
        // Courier saw src at t=100 and dst at t=300 (gap 200).
        table.ingest(
            sign_route_announcement(
                &sks[2],
                300,
                vec![link(src, 50, 100), link(dst, 50, 300)],
            )
            .unwrap(),
            &vk(&atts[2]),
        )
        .unwrap();
        // Gap is 200, max is 60 → no couriers.
        let couriers = dtn_couriers(&table, &src, &dst, 60);
        assert!(couriers.is_empty());
        // Gap is 200, max is 300 → 1 courier.
        let couriers = dtn_couriers(&table, &src, &dst, 300);
        assert_eq!(couriers.len(), 1);
    }

    #[test]
    fn sightings_assembled_from_endpoints() {
        // src announces seeing courier; dst announces seeing courier.
        let (ids, sks, atts) = setup(3);
        let src = ids[0];
        let dst = ids[1];
        let courier = ids[2];
        let mut table = RouteTable::empty();
        // src says "I saw courier at t=100"
        table.ingest(
            sign_route_announcement(&sks[0], 100, vec![link(courier, 50, 100)]).unwrap(),
            &vk(&atts[0]),
        )
        .unwrap();
        // dst says "I saw courier at t=120"
        table.ingest(
            sign_route_announcement(&sks[1], 120, vec![link(courier, 50, 120)]).unwrap(),
            &vk(&atts[1]),
        )
        .unwrap();
        let couriers = dtn_couriers(&table, &src, &dst, 60);
        assert_eq!(couriers.len(), 1);
        assert_eq!(couriers[0].device_id, courier);
    }

    #[test]
    fn no_courier_when_only_one_endpoint_seen() {
        let (ids, sks, atts) = setup(3);
        let src = ids[0];
        let dst = ids[1];
        let courier = ids[2];
        let mut table = RouteTable::empty();
        // src saw courier but dst hasn't.
        table.ingest(
            sign_route_announcement(&sks[0], 100, vec![link(courier, 50, 100)]).unwrap(),
            &vk(&atts[0]),
        )
        .unwrap();
        let couriers = dtn_couriers(&table, &src, &dst, 1_000);
        assert!(couriers.is_empty());
    }
}
