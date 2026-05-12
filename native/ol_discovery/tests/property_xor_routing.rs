//! Property tests for NodeId XOR-distance + routing-table invariants.
//!
//! Gate ladder matching Phase C / F1 conventions:
//!   - CI default: 50k iters per property
//!   - Nightly (ONE_LINK_F1_GATE=1): 500k iters

use proptest::prelude::*;

use ol_discovery::node_id::{closer_to, NodeId, NODE_ID_BITS};
use ol_discovery::routing::{InsertOutcome, RoutingTable, K_BUCKET_DEFAULT};

fn cases() -> u32 {
    // CI default: 1M to match F1.1 bar. Nightly: 5M.
    if std::env::var("ONE_LINK_F1_GATE").as_deref() == Ok("1") {
        5_000_000
    } else {
        1_000_000
    }
}

// ── XOR distance properties ────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases(),
        max_global_rejects: cases() * 4,
        .. ProptestConfig::default()
    })]

    /// XOR is symmetric: d(a, b) == d(b, a).
    #[test]
    fn xor_symmetric(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
        let na = NodeId::from_bytes(a);
        let nb = NodeId::from_bytes(b);
        prop_assert_eq!(na.distance(&nb), nb.distance(&na));
    }

    /// XOR is zero iff a == b.
    #[test]
    fn xor_zero_iff_eq(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
        let na = NodeId::from_bytes(a);
        let nb = NodeId::from_bytes(b);
        let d = na.distance(&nb);
        prop_assert_eq!(d == [0u8; 32], a == b);
    }

    /// XOR satisfies the triangle inequality: d(a, c) <= d(a, b) ^ d(b, c)
    /// where ^ is component-wise OR (an upper bound on XOR-as-integer).
    /// This is a weaker form than strict integer triangle but holds in
    /// the metric space and catches accidental sign flips.
    #[test]
    fn xor_metric_no_bigger_than_or(
        a in any::<[u8; 32]>(),
        b in any::<[u8; 32]>(),
        c in any::<[u8; 32]>(),
    ) {
        let na = NodeId::from_bytes(a);
        let nb = NodeId::from_bytes(b);
        let nc = NodeId::from_bytes(c);
        let ac = na.distance(&nc);
        let ab = na.distance(&nb);
        let bc = nb.distance(&nc);
        // For every byte position: ac[i] = a[i] ^ c[i] = (a[i]^b[i]) ^ (b[i]^c[i])
        // = ab[i] ^ bc[i]. So ac is component-wise XOR of ab + bc; it's
        // bounded above by their OR (a useful weaker invariant).
        for i in 0..32 {
            prop_assert!(ac[i] <= ab[i] | bc[i]);
        }
    }

    /// closer_to gives a consistent total order — if a < b and b < c
    /// for target t, then a < c.
    #[test]
    fn closer_to_transitive(
        a in any::<[u8; 32]>(),
        b in any::<[u8; 32]>(),
        c in any::<[u8; 32]>(),
        t in any::<[u8; 32]>(),
    ) {
        let na = NodeId::from_bytes(a);
        let nb = NodeId::from_bytes(b);
        let nc = NodeId::from_bytes(c);
        let nt = NodeId::from_bytes(t);
        let ab = closer_to(&na, &nb, &nt);
        let bc = closer_to(&nb, &nc, &nt);
        if ab == std::cmp::Ordering::Less && bc == std::cmp::Ordering::Less {
            prop_assert_eq!(closer_to(&na, &nc, &nt), std::cmp::Ordering::Less);
        }
    }

    /// xor_leading_zeros agrees with the manual bit count.
    #[test]
    fn lz_matches_manual_count(
        a in any::<[u8; 32]>(),
        b in any::<[u8; 32]>(),
    ) {
        let na = NodeId::from_bytes(a);
        let nb = NodeId::from_bytes(b);
        let lz_via_function = na.xor_leading_zeros(&nb);
        let mut lz_manual: u32 = 0;
        for i in 0..32 {
            let x = a[i] ^ b[i];
            if x == 0 {
                lz_manual += 8;
            } else {
                lz_manual += x.leading_zeros();
                break;
            }
        }
        prop_assert_eq!(lz_via_function, lz_manual);
    }

    /// bucket_index is None iff a == b, else in 0..NODE_ID_BITS.
    #[test]
    fn bucket_index_bounds(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
        let na = NodeId::from_bytes(a);
        let nb = NodeId::from_bytes(b);
        let idx = na.bucket_index(&nb);
        if a == b {
            prop_assert_eq!(idx, None);
        } else {
            let i = idx.unwrap();
            prop_assert!(i < NODE_ID_BITS);
        }
    }
}

// ── Routing table invariants ───────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases() / 5, // routing ops are heavier; reduce
        max_global_rejects: cases() * 2,
        .. ProptestConfig::default()
    })]

    /// Inserting any peer either Inserts, BumpsToTail, or returns
    /// BucketFull or SelfInsertIgnored — never panics.
    #[test]
    fn insert_never_panics(
        own in any::<[u8; 32]>(),
        peer in any::<[u8; 32]>(),
        ts in any::<u64>(),
    ) {
        let mut t = RoutingTable::new(NodeId::from_bytes(own));
        let _ = t.insert(NodeId::from_bytes(peer), ts);
    }

    /// closest_to returns at most K entries.
    #[test]
    fn closest_to_size_bounded(
        own in any::<[u8; 32]>(),
        peers in prop::collection::vec(any::<[u8; 32]>(), 0..200),
        target in any::<[u8; 32]>(),
    ) {
        let mut t = RoutingTable::new(NodeId::from_bytes(own));
        for (i, p) in peers.iter().enumerate() {
            let _ = t.insert(NodeId::from_bytes(*p), i as u64);
        }
        let closest = t.closest_to(&NodeId::from_bytes(target));
        prop_assert!(closest.len() <= K_BUCKET_DEFAULT);
    }

    /// closest_to is sorted ascending by XOR distance.
    #[test]
    fn closest_to_sorted_ascending(
        own in any::<[u8; 32]>(),
        peers in prop::collection::vec(any::<[u8; 32]>(), 0..100),
        target in any::<[u8; 32]>(),
    ) {
        let mut t = RoutingTable::new(NodeId::from_bytes(own));
        for (i, p) in peers.iter().enumerate() {
            let _ = t.insert(NodeId::from_bytes(*p), i as u64);
        }
        let nt = NodeId::from_bytes(target);
        let closest = t.closest_to(&nt);
        for w in closest.windows(2) {
            let d0 = w[0].id.distance(&nt);
            let d1 = w[1].id.distance(&nt);
            prop_assert!(d0 <= d1);
        }
    }

    /// Reinserting an existing peer doesn't grow the table.
    #[test]
    fn reinsert_doesnt_grow(
        own in any::<[u8; 32]>(),
        peer in any::<[u8; 32]>(),
        ts1 in any::<u64>(),
        ts2 in any::<u64>(),
    ) {
        let own_id = NodeId::from_bytes(own);
        let peer_id = NodeId::from_bytes(peer);
        prop_assume!(own_id != peer_id);
        let mut t = RoutingTable::new(own_id);
        let _ = t.insert(peer_id, ts1);
        let len_after_first = t.len();
        let outcome = t.insert(peer_id, ts2);
        prop_assert_eq!(outcome, InsertOutcome::BumpedToTail);
        prop_assert_eq!(t.len(), len_after_first);
    }

    /// remove + contains agree.
    #[test]
    fn remove_then_not_contains(
        own in any::<[u8; 32]>(),
        peer in any::<[u8; 32]>(),
    ) {
        let own_id = NodeId::from_bytes(own);
        let peer_id = NodeId::from_bytes(peer);
        prop_assume!(own_id != peer_id);
        let mut t = RoutingTable::new(own_id);
        let _ = t.insert(peer_id, 1);
        prop_assert!(t.contains(&peer_id));
        prop_assert!(t.remove(&peer_id));
        prop_assert!(!t.contains(&peer_id));
    }
}
