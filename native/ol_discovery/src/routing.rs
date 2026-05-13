//! K-bucket routing table.
//!
//! Vanilla Kademlia: 256 buckets (one per bit of the NodeId), each
//! holding up to K most-recently-seen peers. New peers go to the
//! tail of their bucket; existing peers move to the tail when seen
//! again ("recently-seen-most-recent" replacement policy).
//!
//! When a bucket is full and a new peer wants in, we ping the head
//! (least-recently-seen). If the head responds, the new peer is
//! discarded (existing peers preferred — defeats eclipse via flooding).
//! If the head times out, it's replaced by the new peer. This
//! "least-recently-seen replacement" is the Kademlia stability
//! property: long-lived nodes that respond stay in the table.
//!
//! This module provides the routing-table data structure ONLY. The
//! liveness check (PING-on-bucket-full) is a higher-level concern
//! that the daemon's maintenance loop handles via the `Transport`
//! trait; the table itself just exposes
//!   - [`RoutingTable::insert`]: tentatively add a peer; returns
//!     [`InsertOutcome::Inserted`] / `BumpedToTail` / `BucketFull`
//!     so the caller can issue a PING when needed.
//!   - [`RoutingTable::closest_to`]: get the K closest peers to a
//!     target, sorted by XOR distance (lookup primitive).
//!   - [`RoutingTable::stale_buckets`]: which buckets haven't been
//!     touched in `now - max_age_secs`, so the maintenance loop can
//!     run bucket-refresh lookups against them.

use std::cmp::Ordering;
use std::collections::VecDeque;

use crate::node_id::{closer_to, NodeId, NODE_ID_BITS};

/// Default K (replication factor / bucket size). Kademlia paper uses
/// K=20 as the standard; we match.
pub const K_BUCKET_DEFAULT: usize = 20;

/// Number of buckets in the table. One per bit of the NodeId.
pub const MAX_BUCKETS: usize = NODE_ID_BITS; // 256

/// One bucket entry: a peer the local node has heard from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BucketEntry {
    /// The peer's NodeId.
    pub id: NodeId,
    /// Unix-seconds timestamp the entry was last touched (last seen).
    /// Used for least-recently-seen eviction.
    pub last_seen_unix: u64,
}

impl BucketEntry {
    /// Construct an entry.
    #[must_use]
    pub const fn new(id: NodeId, last_seen_unix: u64) -> Self {
        Self { id, last_seen_unix }
    }
}

/// Outcome of attempting to insert a peer into the routing table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InsertOutcome {
    /// Peer was new to the bucket; added.
    Inserted,
    /// Peer already existed; bumped to tail (most-recently-seen).
    BumpedToTail,
    /// Peer is the local node itself — never inserted.
    SelfInsertIgnored,
    /// Bucket is full. Caller should PING the head (least-recently-
    /// seen) and call [`RoutingTable::replace_head_on_timeout`] if
    /// the PING times out. Carries the head entry for the PING.
    BucketFull {
        /// The head (least-recently-seen) of the full bucket.
        head: BucketEntry,
    },
}

/// One K-bucket. Wraps a VecDeque so head-removal + tail-push are O(1).
#[derive(Clone, Debug, Default)]
struct Bucket {
    entries: VecDeque<BucketEntry>,
    last_refresh_unix: u64,
}

/// Kademlia K-bucket routing table.
#[derive(Clone, Debug)]
pub struct RoutingTable {
    own_id: NodeId,
    k: usize,
    buckets: Vec<Bucket>,
}

impl RoutingTable {
    /// Construct a new table for the given local NodeId.
    /// Uses the default K (= [`K_BUCKET_DEFAULT`]).
    #[must_use]
    pub fn new(own_id: NodeId) -> Self {
        Self::with_k(own_id, K_BUCKET_DEFAULT)
    }

    /// Construct with a custom K.
    #[must_use]
    pub fn with_k(own_id: NodeId, k: usize) -> Self {
        let mut buckets = Vec::with_capacity(MAX_BUCKETS);
        for _ in 0..MAX_BUCKETS {
            buckets.push(Bucket::default());
        }
        Self { own_id, k, buckets }
    }

    /// Borrow the local NodeId.
    #[must_use]
    pub const fn own_id(&self) -> &NodeId {
        &self.own_id
    }

    /// K (bucket size) parameter.
    #[must_use]
    pub const fn k(&self) -> usize {
        self.k
    }

    /// Total number of peers currently in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.entries.len()).sum()
    }

    /// True when no peers are in the table.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buckets.iter().all(|b| b.entries.is_empty())
    }

    /// Insert (or update) a peer.
    ///
    /// - New peer → tail of bucket → [`InsertOutcome::Inserted`].
    /// - Existing peer → bumped to tail → [`InsertOutcome::BumpedToTail`].
    /// - Self → ignored → [`InsertOutcome::SelfInsertIgnored`].
    /// - Bucket full + new peer → returns
    ///   [`InsertOutcome::BucketFull`] carrying the head entry. Caller
    ///   pings the head; if head replies, the new peer is discarded;
    ///   if head times out, caller invokes
    ///   [`Self::replace_head_on_timeout`].
    pub fn insert(
        &mut self,
        id: NodeId,
        last_seen_unix: u64,
    ) -> InsertOutcome {
        let Some(idx) = self.own_id.bucket_index(&id) else {
            return InsertOutcome::SelfInsertIgnored;
        };
        let bucket = &mut self.buckets[idx];
        // Existing peer? Move to tail with updated timestamp.
        if let Some(pos) = bucket.entries.iter().position(|e| e.id == id) {
            let mut existing = bucket.entries.remove(pos).expect("position valid");
            existing.last_seen_unix = last_seen_unix;
            bucket.entries.push_back(existing);
            bucket.last_refresh_unix = last_seen_unix;
            return InsertOutcome::BumpedToTail;
        }
        // New peer; bucket has room?
        if bucket.entries.len() < self.k {
            bucket.entries.push_back(BucketEntry::new(id, last_seen_unix));
            bucket.last_refresh_unix = last_seen_unix;
            return InsertOutcome::Inserted;
        }
        // Bucket full. Caller decides what to do via PING.
        let head = *bucket.entries.front().expect("non-empty (k > 0)");
        InsertOutcome::BucketFull { head }
    }

    /// Called by the maintenance loop when a PING-on-bucket-full
    /// targets the head and the head times out. Removes the head
    /// and inserts the new peer at the tail.
    ///
    /// Returns `true` iff the head was actually replaced. Returns
    /// `false` if the head no longer exists (someone else evicted
    /// it in the meantime, or the new peer happened to land in a
    /// different bucket — defensive).
    pub fn replace_head_on_timeout(
        &mut self,
        timed_out_head: NodeId,
        new_peer: NodeId,
        last_seen_unix: u64,
    ) -> bool {
        let Some(idx) = self.own_id.bucket_index(&new_peer) else {
            return false;
        };
        let bucket = &mut self.buckets[idx];
        match bucket.entries.front() {
            Some(head) if head.id == timed_out_head => {
                bucket.entries.pop_front();
                bucket.entries.push_back(BucketEntry::new(
                    new_peer,
                    last_seen_unix,
                ));
                bucket.last_refresh_unix = last_seen_unix;
                true
            }
            _ => false,
        }
    }

    /// Get the K closest peers to `target`, sorted by XOR distance
    /// ascending. Returns at most K entries.
    ///
    /// This is the Kademlia lookup primitive: callers query these
    /// K peers, then iteratively refine via responses. Pure read.
    #[must_use]
    pub fn closest_to(&self, target: &NodeId) -> Vec<BucketEntry> {
        let mut all: Vec<BucketEntry> = self
            .buckets
            .iter()
            .flat_map(|b| b.entries.iter().copied())
            .collect();
        all.sort_by(|a, b| closer_to(&a.id, &b.id, target));
        all.truncate(self.k);
        all
    }

    /// Variant of `closest_to` that returns at most `n` entries
    /// rather than K. Useful when a lookup needs α candidates to
    /// query in parallel where α < K.
    #[must_use]
    pub fn closest_n_to(
        &self,
        target: &NodeId,
        n: usize,
    ) -> Vec<BucketEntry> {
        let mut all: Vec<BucketEntry> = self
            .buckets
            .iter()
            .flat_map(|b| b.entries.iter().copied())
            .collect();
        all.sort_by(|a, b| closer_to(&a.id, &b.id, target));
        all.truncate(n);
        all
    }

    /// Bucket indices whose `last_refresh_unix` is older than
    /// `now_unix - max_age_secs`. Returns indices sorted ascending.
    ///
    /// The maintenance loop runs a `FIND_NODE` lookup against each
    /// stale bucket using a randomly-chosen NodeId in that bucket's
    /// distance range, which has the effect of populating + refreshing
    /// the bucket.
    #[must_use]
    pub fn stale_buckets(
        &self,
        now_unix: u64,
        max_age_secs: u64,
    ) -> Vec<usize> {
        let threshold = now_unix.saturating_sub(max_age_secs);
        let mut out = Vec::new();
        for (i, b) in self.buckets.iter().enumerate() {
            if !b.entries.is_empty() && b.last_refresh_unix <= threshold {
                out.push(i);
            }
        }
        out
    }

    /// Remove a peer (e.g. because they failed too many PINGs).
    /// Returns `true` iff the peer was present.
    pub fn remove(&mut self, id: &NodeId) -> bool {
        let Some(idx) = self.own_id.bucket_index(id) else {
            return false;
        };
        let bucket = &mut self.buckets[idx];
        if let Some(pos) = bucket.entries.iter().position(|e| e.id == *id) {
            bucket.entries.remove(pos);
            true
        } else {
            false
        }
    }

    /// True iff `id` is present in the table.
    #[must_use]
    pub fn contains(&self, id: &NodeId) -> bool {
        let Some(idx) = self.own_id.bucket_index(id) else {
            return false;
        };
        self.buckets[idx].entries.iter().any(|e| e.id == *id)
    }

    /// Diagnostic: number of peers in each bucket index. Index 0 is
    /// the farthest bucket; index 255 is closest-to-self.
    #[must_use]
    pub fn bucket_sizes(&self) -> Vec<usize> {
        self.buckets.iter().map(|b| b.entries.len()).collect()
    }

    /// Mark a bucket as just-refreshed. Maintenance loops call this
    /// after issuing a FIND_NODE refresh lookup against the bucket
    /// so subsequent `stale_buckets()` queries don't immediately
    /// re-flag it.
    pub fn mark_bucket_refreshed(&mut self, bucket_idx: usize, now_unix: u64) {
        if let Some(b) = self.buckets.get_mut(bucket_idx) {
            b.last_refresh_unix = now_unix;
        }
    }

    /// Generate a NodeId that lives in bucket `bucket_idx` (relative
    /// to `own_id`). Used by maintenance to issue refresh lookups
    /// targeting the right distance range.
    ///
    /// Returns `None` if `bucket_idx >= NODE_ID_BITS`.
    #[must_use]
    pub fn synthetic_id_for_bucket(&self, bucket_idx: usize) -> Option<NodeId> {
        if bucket_idx >= crate::node_id::NODE_ID_BITS {
            return None;
        }
        // Construct an ID that XOR-differs from own_id in EXACTLY
        // bit position `bucket_idx`: leading (256-1-bucket_idx) bits
        // of XOR are zero, then a 1 at position bucket_idx, then
        // arbitrary trailing bits. NodeId::bucket_index uses
        // `xor_leading_zeros == bucket_idx` semantics — meaning the
        // first differing bit is the (NODE_ID_BITS-1-bucket_idx)-th
        // MSB. Mirror that: flip the (NODE_ID_BITS-1-bucket_idx)-th
        // MSB of own_id.
        let bit_from_msb = crate::node_id::NODE_ID_BITS - 1 - bucket_idx;
        let byte_idx = bit_from_msb / 8;
        let bit_in_byte = 7 - (bit_from_msb % 8);
        let mut out = *self.own_id.as_bytes();
        out[byte_idx] ^= 1u8 << bit_in_byte;
        Some(NodeId::from_bytes(out))
    }
}

/// Sort utility: stable-sort a list of NodeIds by XOR distance to
/// `target`, ascending. Used by the lookup algorithm.
pub fn sort_by_distance(ids: &mut Vec<NodeId>, target: &NodeId) {
    ids.sort_by(|a, b| {
        let cmp = closer_to(a, b, target);
        if cmp == Ordering::Equal {
            a.cmp(b)
        } else {
            cmp
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> NodeId {
        NodeId([byte; 32])
    }

    #[test]
    fn empty_table_has_no_peers() {
        let t = RoutingTable::new(id(0x42));
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn insert_self_ignored() {
        let mut t = RoutingTable::new(id(0x42));
        let outcome = t.insert(id(0x42), 0);
        assert_eq!(outcome, InsertOutcome::SelfInsertIgnored);
        assert!(t.is_empty());
    }

    #[test]
    fn insert_one_then_lookup_self_returns_it() {
        let mut t = RoutingTable::new(id(0x00));
        let peer = id(0xFF);
        assert_eq!(t.insert(peer, 1), InsertOutcome::Inserted);
        let closest = t.closest_to(&id(0x00));
        assert_eq!(closest.len(), 1);
        assert_eq!(closest[0].id, peer);
    }

    #[test]
    fn reinsert_bumps_to_tail() {
        let mut t = RoutingTable::with_k(id(0x00), 4);
        // Two peers in the same bucket (top bit set).
        let a = NodeId({
            let mut x = [0u8; 32];
            x[0] = 0x80;
            x
        });
        let b = NodeId({
            let mut x = [0u8; 32];
            x[0] = 0xC0;
            x
        });
        assert_eq!(t.insert(a, 1), InsertOutcome::Inserted);
        assert_eq!(t.insert(b, 2), InsertOutcome::Inserted);
        // Re-insert a; should bump to tail.
        assert_eq!(t.insert(a, 3), InsertOutcome::BumpedToTail);
        // Both still in table.
        assert!(t.contains(&a));
        assert!(t.contains(&b));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn bucket_full_returns_head() {
        let mut t = RoutingTable::with_k(id(0x00), 2);
        // Two peers with the same top-bit prefix (same bucket).
        let p1 = NodeId({
            let mut x = [0u8; 32];
            x[0] = 0x80;
            x[1] = 0x01;
            x
        });
        let p2 = NodeId({
            let mut x = [0u8; 32];
            x[0] = 0x80;
            x[1] = 0x02;
            x
        });
        let p3 = NodeId({
            let mut x = [0u8; 32];
            x[0] = 0x80;
            x[1] = 0x03;
            x
        });
        // Sanity: all three must be in the same bucket (bucket 0,
        // since top bit differs from own_id=0).
        assert_eq!(id(0x00).bucket_index(&p1), Some(0));
        assert_eq!(id(0x00).bucket_index(&p2), Some(0));
        assert_eq!(id(0x00).bucket_index(&p3), Some(0));
        assert_eq!(t.insert(p1, 1), InsertOutcome::Inserted);
        assert_eq!(t.insert(p2, 2), InsertOutcome::Inserted);
        // Bucket of size 2 now full.
        let outcome = t.insert(p3, 3);
        match outcome {
            InsertOutcome::BucketFull { head } => {
                assert_eq!(head.id, p1, "head is least-recently-seen");
            }
            other => panic!("expected BucketFull, got {other:?}"),
        }
        // p3 NOT inserted (caller must PING head first).
        assert!(!t.contains(&p3));
    }

    #[test]
    fn replace_head_on_timeout_swaps() {
        let mut t = RoutingTable::with_k(id(0x00), 2);
        let p1 = NodeId({
            let mut x = [0u8; 32];
            x[0] = 0x80;
            x[1] = 0x01;
            x
        });
        let p2 = NodeId({
            let mut x = [0u8; 32];
            x[0] = 0x80;
            x[1] = 0x02;
            x
        });
        let p3 = NodeId({
            let mut x = [0u8; 32];
            x[0] = 0x80;
            x[1] = 0x03;
            x
        });
        t.insert(p1, 1);
        t.insert(p2, 2);
        let _ = t.insert(p3, 3); // BucketFull
        // Simulate head PING timeout — caller invokes replacement.
        assert!(t.replace_head_on_timeout(p1, p3, 4));
        assert!(!t.contains(&p1)); // evicted
        assert!(t.contains(&p3));
        assert!(t.contains(&p2));
    }

    #[test]
    fn closest_to_returns_sorted_ascending() {
        let own = id(0x00);
        let mut t = RoutingTable::new(own);
        // Insert peers across many buckets.
        for byte in 1u8..16 {
            t.insert(id(byte), byte as u64);
        }
        let target = id(0xFF);
        let sorted = t.closest_to(&target);
        assert!(sorted.len() <= K_BUCKET_DEFAULT);
        // Distances are monotonically non-decreasing.
        for w in sorted.windows(2) {
            let d0 = w[0].id.distance(&target);
            let d1 = w[1].id.distance(&target);
            assert!(d0 <= d1, "not sorted: {d0:?} vs {d1:?}");
        }
    }

    #[test]
    fn closest_n_caps_count() {
        let own = id(0x00);
        let mut t = RoutingTable::new(own);
        for byte in 1u8..16 {
            t.insert(id(byte), byte as u64);
        }
        let target = id(0xFF);
        let three = t.closest_n_to(&target, 3);
        assert_eq!(three.len(), 3);
    }

    #[test]
    fn remove_peer() {
        let mut t = RoutingTable::new(id(0x00));
        let p = id(0xAA);
        t.insert(p, 1);
        assert!(t.contains(&p));
        assert!(t.remove(&p));
        assert!(!t.contains(&p));
        // Removing again returns false.
        assert!(!t.remove(&p));
    }

    #[test]
    fn stale_buckets_picks_old_only() {
        let mut t = RoutingTable::new(id(0x00));
        t.insert(id(0x10), 100);
        t.insert(id(0x20), 200);
        let stale = t.stale_buckets(500, 200);
        // both buckets had last_refresh <= 300; both should be stale.
        // But 200 > 300? No: 500 - 200 = 300; entries refreshed at
        // 100 and 200 are both <= 300, so both stale.
        assert!(!stale.is_empty());
        let fresh = t.stale_buckets(250, 200);
        // Threshold = 50; only entries refreshed at <= 50 are stale.
        // Both at 100 and 200 are fresher than 50; none stale.
        assert!(fresh.is_empty());
    }

    #[test]
    fn bucket_sizes_consistent_with_len() {
        let mut t = RoutingTable::new(id(0x00));
        for byte in 1u8..32 {
            t.insert(id(byte), byte as u64);
        }
        let sizes: usize = t.bucket_sizes().iter().sum();
        assert_eq!(sizes, t.len());
    }

    #[test]
    fn sort_by_distance_stable_on_ties() {
        let target = id(0x00);
        let mut ids = vec![id(0x01), id(0x01), id(0x02), id(0x03)];
        sort_by_distance(&mut ids, &target);
        // 01, 01, 02, 03 — ascending.
        assert_eq!(ids, vec![id(0x01), id(0x01), id(0x02), id(0x03)]);
    }
}
