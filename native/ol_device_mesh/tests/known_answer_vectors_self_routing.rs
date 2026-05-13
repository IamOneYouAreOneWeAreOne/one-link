//! Pinned KAT vectors for Row 8 Layer 6 self-routing.

use ol_device_mesh::self_routing::{
    PeerLink, RouteAnnouncement, MAX_LINKS_PER_ANNOUNCEMENT,
    ROUTE_ANNOUNCEMENT_DOMAIN,
};
use ol_device_mesh::DEVICE_ID_LEN;

fn check_regen<F: FnOnce()>(label: &str, dump: F) {
    if std::env::var("OL_SELF_ROUTING_KAT_REGEN").as_deref() == Ok("1") {
        eprintln!("[KAT REGEN] {label}");
        dump();
    }
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn kat_domain_tag_pinned() {
    assert_eq!(ROUTE_ANNOUNCEMENT_DOMAIN, b"OL-mesh-route-announcement-v1");
}

#[test]
fn kat_bound_constants_pinned() {
    assert_eq!(MAX_LINKS_PER_ANNOUNCEMENT, 64);
}

#[test]
fn kat_announcement_canonical_transcript_pinned() {
    let announcer = [0xAA; DEVICE_ID_LEN];
    let day: u64 = 3;
    let announced_at: u64 = 1_700_000_000;
    let links = vec![
        PeerLink {
            peer_device_id: [0x11; DEVICE_ID_LEN],
            tau_score: 100,
            last_seen_unix: 1_700_000_000,
            direct: true,
        },
        PeerLink {
            peer_device_id: [0x22; DEVICE_ID_LEN],
            tau_score: 50,
            last_seen_unix: 1_699_999_900,
            direct: false,
        },
    ];
    let bytes =
        RouteAnnouncement::canonical_transcript(&announcer, day, announced_at, &links);
    let hex = to_hex(&bytes);
    let domain_hex = to_hex(ROUTE_ANNOUNCEMENT_DOMAIN);
    assert!(hex.starts_with(&domain_hex));
    check_regen("route-announcement canonical_transcript", || {
        eprintln!("    EXPECTED_HEX = \"{hex}\"");
    });
    const EXPECTED_HEX: &str = concat!(
        "4f4c2d6d6573682d726f7574652d616e6e6f756e63656d656e742d7631", // "OL-mesh-route-announcement-v1"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  // announcer
        "0000000000000003",                  // day
        "000000006553f100",                  // announced_at
        "00000002",                          // link count = 2
        // link 1: peer, tau, seen, direct
        "11111111111111111111111111111111",
        "00000064",                          // tau = 100
        "000000006553f100",                  // last_seen
        "01",                                // direct
        // link 2
        "22222222222222222222222222222222",
        "00000032",                          // tau = 50
        "000000006553f09c",                  // last_seen
        "00",                                // direct = false
    );
    assert_eq!(hex, EXPECTED_HEX, "route-announcement transcript drift");
}

#[test]
fn kat_per_link_byte_overhead_pinned() {
    // Each PeerLink contributes 16 (peer) + 4 (tau) + 8 (seen) + 1
    // (direct) = 29 bytes. Pinned so a future wire-format change
    // (e.g., bumping tau to u64) is a deliberate decision.
    let bytes_zero = RouteAnnouncement::canonical_transcript(
        &[0; DEVICE_ID_LEN],
        0,
        0,
        &[],
    );
    let bytes_one = RouteAnnouncement::canonical_transcript(
        &[0; DEVICE_ID_LEN],
        0,
        0,
        &[PeerLink {
            peer_device_id: [0; DEVICE_ID_LEN],
            tau_score: 0,
            last_seen_unix: 0,
            direct: false,
        }],
    );
    assert_eq!(bytes_one.len() - bytes_zero.len(), 29);
}
