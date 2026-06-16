//! Property tests for the DHT maintenance loop.
//!
//! `tick_maintenance` is what every long-running daemon calls on a
//! periodic timer to keep the routing table + record store from going
//! stale. These properties pin the invariants that must hold across
//! arbitrary call sequences:
//!
//!   1. `tick_maintenance` is total — it never panics for any inputs.
//!   2. After `mark_bucket_refreshed(i, now)`, `stale_buckets(now, 0)`
//!      no longer includes `i` (well, depending on the freshness gate).
//!   3. `republish_records` count == number of records older than
//!      threshold.
//!   4. `stale_buckets` indices are always in-range and unique.
//!
//! Gate ladder: CI default 5k iters (DhtNode build is socket-bound);
//! nightly 50k iters via `ONE_LINK_F1_GATE=1`.

use std::net::SocketAddr;

use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use rand_core::OsRng;

use ol_discovery::dht_node::DhtNode;
use ol_discovery::node_id::NodeId;
use ol_discovery::record::{PeerRecord, SignedRecord, RECORD_DEFAULT_TTL_SECS};
use ol_discovery::routing::{InsertOutcome, RoutingTable, MAX_BUCKETS};

fn cases() -> u32 {
    if std::env::var("ONE_LINK_F1_GATE").as_deref() == Ok("1") {
        50_000
    } else {
        5_000
    }
}

fn make_node() -> DhtNode {
    let sk = SigningKey::generate(&mut OsRng);
    let id = NodeId::from_pubkey(&sk.verifying_key().to_bytes());
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    DhtNode::new(addr, id, vec![]).unwrap()
}

fn make_record(now_unix: u64) -> SignedRecord {
    let sk = SigningKey::generate(&mut OsRng);
    let rec = PeerRecord {
        publisher_pubkey: sk.verifying_key().to_bytes(),
        endpoints: vec!["udp://127.0.0.1:1".into()],
        publish_time_unix: now_unix,
        ttl_secs: RECORD_DEFAULT_TTL_SECS,
    };
    SignedRecord::sign(rec, &sk).unwrap()
}

// ── Routing-table-only properties (no socket) — cheap, run at high iters

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases() * 20, // table-only is cheap; bump
        max_global_rejects: cases() * 50,
        .. ProptestConfig::default()
    })]

    /// stale_buckets never returns indices out of range.
    #[test]
    fn stale_buckets_indices_in_range(
        own in any::<[u8; 32]>(),
        peers in prop::collection::vec(any::<[u8; 32]>(), 0..50),
        now in any::<u64>(),
        max_age in any::<u64>(),
    ) {
        let own_id = NodeId::from_bytes(own);
        let mut t = RoutingTable::new(own_id);
        for (i, p) in peers.iter().enumerate() {
            let _ = t.insert(NodeId::from_bytes(*p), i as u64);
        }
        let stale = t.stale_buckets(now, max_age);
        for idx in &stale {
            prop_assert!(*idx < MAX_BUCKETS);
        }
        // Indices unique.
        let mut sorted = stale.clone();
        sorted.sort();
        sorted.dedup();
        prop_assert_eq!(sorted.len(), stale.len());
    }

    /// stale_buckets only returns indices for non-empty buckets.
    #[test]
    fn stale_buckets_only_for_non_empty(
        own in any::<[u8; 32]>(),
        peers in prop::collection::vec(any::<[u8; 32]>(), 0..50),
        now in any::<u64>(),
        max_age in any::<u64>(),
    ) {
        let own_id = NodeId::from_bytes(own);
        let mut t = RoutingTable::new(own_id);
        for (i, p) in peers.iter().enumerate() {
            let _ = t.insert(NodeId::from_bytes(*p), i as u64);
        }
        let stale = t.stale_buckets(now, max_age);
        let sizes = t.bucket_sizes();
        for idx in &stale {
            prop_assert!(sizes[*idx] > 0);
        }
    }

    /// After mark_bucket_refreshed(i, now), stale_buckets(now, 1) no
    /// longer includes i — proves the timestamp actually advanced.
    #[test]
    fn mark_refreshed_clears_stale(
        own in any::<[u8; 32]>(),
        peer in any::<[u8; 32]>(),
        now in 1u64..u64::MAX / 2,
    ) {
        let own_id = NodeId::from_bytes(own);
        let peer_id = NodeId::from_bytes(peer);
        prop_assume!(own_id != peer_id);
        let mut t = RoutingTable::new(own_id);
        let outcome = t.insert(peer_id, 0);
        prop_assume!(matches!(outcome, InsertOutcome::Inserted));
        // Find the bucket the peer went into.
        let bucket_idx = own_id.bucket_index(&peer_id).unwrap();
        t.mark_bucket_refreshed(bucket_idx, now);
        let stale = t.stale_buckets(now, 1);
        prop_assert!(
            !stale.contains(&bucket_idx),
            "bucket {bucket_idx} should be fresh after mark_bucket_refreshed"
        );
    }

    /// synthetic_id_for_bucket(i) lands in bucket i (round-trip).
    #[test]
    fn synthetic_id_round_trip(
        own in any::<[u8; 32]>(),
        bucket_idx in 0usize..MAX_BUCKETS,
    ) {
        let own_id = NodeId::from_bytes(own);
        let t = RoutingTable::new(own_id);
        let synth = t.synthetic_id_for_bucket(bucket_idx).unwrap();
        prop_assert_eq!(own_id.bucket_index(&synth), Some(bucket_idx));
    }
}

// ── DhtNode integration properties — socket-bound, lower iters

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases(),
        max_global_rejects: cases() * 10,
        .. ProptestConfig::default()
    })]

    /// tick_maintenance is total — never panics across arbitrary inputs.
    /// Catches future "off-by-one in saturating_sub" / unwrap regressions.
    #[test]
    fn tick_maintenance_never_panics(
        now in any::<u64>(),
        bucket_max_age in any::<u64>(),
        record_max_age in any::<u64>(),
    ) {
        let node = make_node();
        let (_b, _r) = node.tick_maintenance(now, bucket_max_age, record_max_age);
        node.shutdown();
    }

    /// republish_records count == records older than threshold.
    #[test]
    fn republish_count_matches_aged_records(
        now in 1_000_000u64..2_000_000u64,
        ages in prop::collection::vec(0u64..1_000_000, 0..5),
    ) {
        let node = make_node();
        for age in &ages {
            let pub_time = now.saturating_sub(*age);
            let rec = make_record(pub_time);
            node.publish_self_record(rec);
        }
        // With max_age = 0, every record older than `now` counts.
        let count = node.republish_records(now, 0);
        let expected = ages.len();
        // make_node() publishes nothing; ages.len() records inserted; all
        // have publish_time <= now → all count.
        prop_assert_eq!(count, expected);
        node.shutdown();
    }

    /// republish_records with max_age = u64::MAX returns 0 (no record
    /// is older than now - u64::MAX = 0).
    #[test]
    fn republish_zero_when_max_age_huge(
        ages in prop::collection::vec(0u64..1000, 0..3),
    ) {
        let now: u64 = 1_700_000_000;
        let node = make_node();
        for age in &ages {
            let pub_time = now.saturating_sub(*age);
            let rec = make_record(pub_time);
            node.publish_self_record(rec);
        }
        let count = node.republish_records(now, u64::MAX);
        prop_assert_eq!(count, 0);
        node.shutdown();
    }
}
