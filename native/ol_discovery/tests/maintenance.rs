//! Row 3 maintenance-loop integration tests.
//!
//! Verifies:
//! - `refresh_stale_buckets` actually marks buckets as refreshed.
//! - `republish_records` re-fires `store_at` against the closest peers
//!   for records older than the threshold.
//! - `tick_maintenance` is the single-call wrapper.

use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;

use ol_discovery::dht_node::DhtNode;
use ol_discovery::node_id::NodeId;
use ol_discovery::record::{PeerRecord, SignedRecord, RECORD_DEFAULT_TTL_SECS};

struct Peer {
    #[allow(dead_code)]
    sk: SigningKey,
    id: NodeId,
    node: DhtNode,
    #[allow(dead_code)]
    record: SignedRecord,
}

fn make_peer(seed_peers: Vec<(NodeId, std::net::SocketAddr)>) -> Peer {
    let sk = SigningKey::generate(&mut OsRng);
    let id = NodeId::from_pubkey(&sk.verifying_key().to_bytes());
    let node = DhtNode::new("127.0.0.1:0".parse().unwrap(), id, seed_peers).unwrap();
    let addr = node.local_addr();
    let rec = PeerRecord {
        publisher_pubkey: sk.verifying_key().to_bytes(),
        endpoints: vec![format!("udp://{addr}")],
        publish_time_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs()),
        ttl_secs: RECORD_DEFAULT_TTL_SECS,
    };
    let signed = SignedRecord::sign(rec, &sk).unwrap();
    node.publish_self_record(signed.clone()).unwrap();
    Peer {
        sk,
        id,
        node,
        record: signed,
    }
}

#[test]
fn tick_maintenance_runs_clean_on_empty_node() {
    // A node with no peers and no records: tick should succeed with
    // (0, 0). Catches accidental panics on empty state.
    let sk = SigningKey::generate(&mut OsRng);
    let id = NodeId::from_pubkey(&sk.verifying_key().to_bytes());
    let node = DhtNode::new("127.0.0.1:0".parse().unwrap(), id, vec![]).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (refreshed, republished) = node.tick_maintenance(now, 3600, 3600);
    assert_eq!(refreshed, 0);
    assert_eq!(republished, 0);
    node.shutdown();
}

#[test]
fn refresh_stale_buckets_marks_buckets_fresh() {
    // 3 peers; node[0] is seeded with the others, so its routing
    // has entries → those buckets initially have last_refresh_unix=0
    // → ALL non-empty buckets count as stale.
    let mut peers: Vec<Peer> = Vec::new();
    for _ in 0..3 {
        let seeds = peers
            .iter()
            .map(|p| (p.id, p.node.local_addr()))
            .collect::<Vec<_>>();
        peers.push(make_peer(seeds));
    }
    std::thread::sleep(Duration::from_millis(50));

    // peer[2] was seeded with peers[0] + peers[1], so its routing
    // has entries → those buckets are non-empty.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 10; // future timestamp so existing last_refresh_unix counts as stale
              // First call: stale buckets should exist + get refreshed.
    let refreshed = peers[2].node.refresh_stale_buckets(now, 0);
    assert!(refreshed > 0, "expected at least one bucket to refresh");

    // Second call IMMEDIATELY after with the same `now`: buckets just
    // got marked refreshed to `now` → none are stale under a max_age >= 1.
    let refreshed_again = peers[2].node.refresh_stale_buckets(now, 1);
    assert_eq!(refreshed_again, 0);

    for p in peers {
        p.node.shutdown();
    }
}

#[test]
fn republish_without_peers_reports_no_acknowledgement() {
    // The record is eligible at max_age=0 but no peer can acknowledge it.
    let sk = SigningKey::generate(&mut OsRng);
    let id = NodeId::from_pubkey(&sk.verifying_key().to_bytes());
    let node = DhtNode::new("127.0.0.1:0".parse().unwrap(), id, vec![]).unwrap();
    let addr = node.local_addr();
    let rec = PeerRecord {
        publisher_pubkey: sk.verifying_key().to_bytes(),
        endpoints: vec![format!("udp://{addr}")],
        publish_time_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        ttl_secs: RECORD_DEFAULT_TTL_SECS,
    };
    let signed = SignedRecord::sign(rec, &sk).unwrap();
    node.cache_verified_record(signed).unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // No peers are known, so no peer can acknowledge this record.
    let republished = node.republish_records(now, 0);
    assert_eq!(republished, 0);

    // With max_age very large, the record is still young → 0.
    let republished_young = node.republish_records(now, 10_000);
    assert_eq!(republished_young, 0);

    node.shutdown();
}

#[test]
fn republish_counts_record_acknowledged_by_reachable_peer() {
    let peer_a = make_peer(vec![]);
    let peer_b = make_peer(vec![(peer_a.id, peer_a.node.local_addr())]);
    peer_a
        .node
        .add_seed_peer(peer_b.id, peer_b.node.local_addr())
        .unwrap();
    std::thread::sleep(Duration::from_millis(50));

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 10;
    assert_eq!(peer_b.node.republish_records(now, 0), 1);
    assert_eq!(
        peer_a.node.lookup_record(peer_b.id).unwrap(),
        Some(peer_b.record.clone())
    );

    peer_a.node.shutdown();
    peer_b.node.shutdown();
}

#[test]
fn tick_maintenance_combines_both_passes() {
    let sk = SigningKey::generate(&mut OsRng);
    let id = NodeId::from_pubkey(&sk.verifying_key().to_bytes());
    let node = DhtNode::new("127.0.0.1:0".parse().unwrap(), id, vec![]).unwrap();
    let addr = node.local_addr();
    let rec = PeerRecord {
        publisher_pubkey: sk.verifying_key().to_bytes(),
        endpoints: vec![format!("udp://{addr}")],
        publish_time_unix: 0, // ancient recovery-cache entry
        ttl_secs: RECORD_DEFAULT_TTL_SECS,
    };
    let signed = SignedRecord::sign(rec, &sk).unwrap();
    node.cache_verified_record(signed).unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (refreshed, republished) = node.tick_maintenance(now, 0, 0);
    assert_eq!(refreshed, 0); // no peers → 0 stale buckets
    assert_eq!(republished, 0); // expired cache entry is pruned, never republished

    node.shutdown();
}
