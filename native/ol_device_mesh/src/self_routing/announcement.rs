//! Signed route announcement.
//!
//! A [`RouteAnnouncement`] is "I, device A, can reach these peers
//! with these τ_c scores as of time T." Devices sign their own
//! announcements; replicas verify under the master-attested subkey
//! VK before merging into the route table.

use ol_pqsig::{HybridVerifyingKey, HYBRID_SIG_LEN};

use crate::errors::{DeviceMeshError, DeviceMeshResult};
use crate::subkey::{DeviceSubkey, DEVICE_ID_LEN};

use super::route::TauScore;

/// Max links one announcement can carry. Bounds wire size + verify
/// cost. At 32 devices per personal mesh, this is plenty.
pub const MAX_LINKS_PER_ANNOUNCEMENT: usize = 64;

/// Domain-separation tag for route-announcement signing.
pub const ROUTE_ANNOUNCEMENT_DOMAIN: &[u8] = b"OL-mesh-route-announcement-v1";

/// One reachability claim within an announcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerLink {
    /// The peer device.
    pub peer_device_id: [u8; DEVICE_ID_LEN],
    /// τ_c score the announcer estimates for this peer. Higher =
    /// better. See [`super::route::TauScore`].
    pub tau_score: TauScore,
    /// Wall-clock seconds when the announcer last actually observed
    /// the peer (last successful probe / packet exchange).
    pub last_seen_unix: u64,
    /// `true` iff the announcer is offering itself as a direct relay
    /// for this peer. `false` means "I observed the peer but won't
    /// forward traffic" (used by passive presence reports).
    pub direct: bool,
}

/// Signed claim covering every link the announcer is willing to
/// vouch for at this moment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteAnnouncement {
    /// Which device authored the announcement.
    pub announcer_device_id: [u8; DEVICE_ID_LEN],
    /// Announcer subkey's day-index at sign time.
    pub announcer_day_index: u64,
    /// Wall-clock seconds at sign time.
    pub announced_at_unix: u64,
    /// Reachability claims. Sorted ascending by `peer_device_id` so
    /// canonical bytes are deterministic.
    pub links: Vec<PeerLink>,
    /// Announcer's subkey signature over the canonical transcript.
    pub announcer_sig: Vec<u8>,
}

impl RouteAnnouncement {
    /// Canonical bytes the announcer's subkey signs.
    pub fn canonical_transcript(
        announcer_device_id: &[u8; DEVICE_ID_LEN],
        announcer_day_index: u64,
        announced_at_unix: u64,
        links: &[PeerLink],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            ROUTE_ANNOUNCEMENT_DOMAIN.len()
                + DEVICE_ID_LEN
                + 8
                + 8
                + 4
                + links.len() * (DEVICE_ID_LEN + 4 + 8 + 1),
        );
        out.extend_from_slice(ROUTE_ANNOUNCEMENT_DOMAIN);
        out.extend_from_slice(announcer_device_id);
        out.extend_from_slice(&announcer_day_index.to_be_bytes());
        out.extend_from_slice(&announced_at_unix.to_be_bytes());
        let count = u32::try_from(links.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&count.to_be_bytes());
        for l in links {
            out.extend_from_slice(&l.peer_device_id);
            out.extend_from_slice(&l.tau_score.to_be_bytes());
            out.extend_from_slice(&l.last_seen_unix.to_be_bytes());
            out.push(u8::from(l.direct));
        }
        out
    }

    /// Validate the shape (sorted links, no duplicates, bounded).
    pub fn shape_check(&self) -> DeviceMeshResult<()> {
        if self.links.len() > MAX_LINKS_PER_ANNOUNCEMENT {
            return Err(DeviceMeshError::RouteAnnouncementTooManyLinks {
                got: self.links.len(),
                max: MAX_LINKS_PER_ANNOUNCEMENT,
            });
        }
        let mut prev: Option<&[u8; DEVICE_ID_LEN]> = None;
        for l in &self.links {
            if let Some(p) = prev {
                if &l.peer_device_id <= p {
                    return Err(DeviceMeshError::RouteAnnouncementLinksNotSorted);
                }
            }
            // No device should announce itself as its own peer.
            if l.peer_device_id == self.announcer_device_id {
                return Err(DeviceMeshError::RouteAnnouncementSelfLoop);
            }
            prev = Some(&l.peer_device_id);
        }
        if self.announcer_sig.len() != HYBRID_SIG_LEN {
            return Err(DeviceMeshError::BadLength {
                expected: HYBRID_SIG_LEN,
                got: self.announcer_sig.len(),
            });
        }
        Ok(())
    }

    /// Verify the announcer's signature against the supplied subkey VK.
    pub fn verify(&self, vk: &HybridVerifyingKey) -> DeviceMeshResult<()> {
        self.shape_check()?;
        let transcript = Self::canonical_transcript(
            &self.announcer_device_id,
            self.announcer_day_index,
            self.announced_at_unix,
            &self.links,
        );
        vk.verify(&transcript, &self.announcer_sig)
            .map_err(|_| DeviceMeshError::RouteAnnouncementVerifyFail)
    }
}

/// Sign an announcement. The `links` list is sorted + de-duplicated
/// at sign time so two devices announcing the same set of peers
/// produce identical transcripts (caches benefit).
pub fn sign_route_announcement(
    announcer: &DeviceSubkey,
    announced_at_unix: u64,
    mut links: Vec<PeerLink>,
) -> DeviceMeshResult<RouteAnnouncement> {
    if links.len() > MAX_LINKS_PER_ANNOUNCEMENT {
        return Err(DeviceMeshError::RouteAnnouncementTooManyLinks {
            got: links.len(),
            max: MAX_LINKS_PER_ANNOUNCEMENT,
        });
    }
    // Sort + dedup by peer_device_id. We keep the highest-tau entry
    // when duplicates are supplied (so a slightly-stale lower-tau
    // sample doesn't override a fresher higher-tau one).
    links.sort_by_key(|l| (l.peer_device_id, std::cmp::Reverse(l.tau_score)));
    links.dedup_by_key(|l| l.peer_device_id);
    // Drop any self-loop entries.
    links.retain(|l| l.peer_device_id != *announcer.device_id());
    let transcript = RouteAnnouncement::canonical_transcript(
        announcer.device_id(),
        announcer.day_index(),
        announced_at_unix,
        &links,
    );
    let sig = announcer.sign(&transcript)?;
    Ok(RouteAnnouncement {
        announcer_device_id: *announcer.device_id(),
        announcer_day_index: announcer.day_index(),
        announced_at_unix,
        links,
        announcer_sig: sig.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::master::MasterIdentity;
    use crate::subkey::{fresh_device_id, mint_subkey};
    use crate::DeviceClass;
    use rand::rngs::OsRng;

    fn make() -> (DeviceSubkey, HybridVerifyingKey) {
        let master = MasterIdentity::generate(&mut OsRng);
        let id = fresh_device_id(&mut OsRng);
        let (sk, att) =
            mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
        let vk = HybridVerifyingKey::from_bytes(&att.subkey_vk_bytes).unwrap();
        (sk, vk)
    }

    fn link(peer: u8, tau: TauScore, seen: u64) -> PeerLink {
        PeerLink {
            peer_device_id: [peer; DEVICE_ID_LEN],
            tau_score: tau,
            last_seen_unix: seen,
            direct: true,
        }
    }

    #[test]
    fn sign_verify_round_trip() {
        let (sk, vk) = make();
        let ann = sign_route_announcement(
            &sk,
            1,
            vec![link(0xAA, 100, 1), link(0xBB, 50, 1)],
        )
        .unwrap();
        ann.verify(&vk).unwrap();
    }

    #[test]
    fn duplicate_peer_keeps_highest_tau() {
        let (sk, _vk) = make();
        let ann = sign_route_announcement(
            &sk,
            1,
            vec![
                link(0xAA, 50, 1),
                link(0xAA, 100, 1),
                link(0xAA, 25, 1),
            ],
        )
        .unwrap();
        assert_eq!(ann.links.len(), 1);
        assert_eq!(ann.links[0].tau_score, 100);
    }

    #[test]
    fn self_loop_dropped_at_sign() {
        let (sk, _vk) = make();
        let own = *sk.device_id();
        let ann = sign_route_announcement(
            &sk,
            1,
            vec![PeerLink {
                peer_device_id: own,
                tau_score: 100,
                last_seen_unix: 1,
                direct: true,
            }],
        )
        .unwrap();
        assert!(ann.links.is_empty());
    }

    #[test]
    fn manual_unsort_rejected_at_verify() {
        let (sk, vk) = make();
        let mut ann = sign_route_announcement(
            &sk,
            1,
            vec![link(0xAA, 100, 1), link(0xBB, 50, 1), link(0xCC, 25, 1)],
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
    fn cross_subkey_verify_fails() {
        let (sk_a, _vk_a) = make();
        let (_sk_b, vk_b) = make();
        let ann =
            sign_route_announcement(&sk_a, 1, vec![link(0xAA, 100, 1)]).unwrap();
        let err = ann.verify(&vk_b).unwrap_err();
        assert!(matches!(
            err,
            DeviceMeshError::RouteAnnouncementVerifyFail
        ));
    }

    #[test]
    fn oversize_links_rejected_at_sign() {
        let (sk, _vk) = make();
        let mut links = Vec::new();
        for i in 0..(MAX_LINKS_PER_ANNOUNCEMENT + 1) {
            let mut peer = [0u8; DEVICE_ID_LEN];
            peer[..4].copy_from_slice(&(i as u32 + 1).to_be_bytes());
            // Avoid the announcer's own id.
            if peer != *sk.device_id() {
                links.push(PeerLink {
                    peer_device_id: peer,
                    tau_score: 1,
                    last_seen_unix: 1,
                    direct: true,
                });
            }
        }
        let err = sign_route_announcement(&sk, 1, links).unwrap_err();
        assert!(matches!(
            err,
            DeviceMeshError::RouteAnnouncementTooManyLinks { .. }
        ));
    }
}
