//! Iterative α-parallel Kademlia lookup.
//!
//! The algorithm:
//!
//! 1. Start with the K closest peers we already know from the routing
//!    table (or the bootstrap set on first lookup).
//! 2. Query the α most-promising not-yet-queried peers in parallel,
//!    asking each "give me the K closest peers you know to `target`."
//! 3. Each response returns up to K closer peers. Add them to the
//!    "known" pool, re-sort by XOR distance to target.
//! 4. Repeat: pick the α most-promising not-yet-queried, query.
//! 5. Terminate when no closer peers were discovered in the last
//!    round — we've converged on the K closest.
//!
//! For FIND_VALUE: the same shape, except every query is FIND_VALUE.
//! If any response carries `FindValueOutcome::Found`, return the
//! record immediately (verify signature first).
//!
//! The algorithm is abstracted over a [`Transport`] trait so the
//! daemon can plug UDP / WebRTC / over-mesh-relay without changing
//! the algorithm. Pure-async; the executor (tokio) lives in the
//! daemon, not in this crate.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use thiserror::Error;

use crate::node_id::{closer_to, NodeId};
use crate::record::SignedRecord;
use crate::routing::sort_by_distance;

/// Default α (concurrency parameter) — number of in-flight queries.
/// Kademlia paper uses α = 3 as the standard; matches.
pub const ALPHA_DEFAULT: usize = 3;

/// Default lookup convergence threshold: how many K closest peers to
/// settle on before terminating. Kademlia standard: K = 20.
pub const LOOKUP_K_DEFAULT: usize = 20;

/// Hard cap on iterations per lookup to bound worst-case latency on
/// pathological topologies. log2(2^256) is 256, but realistic networks
/// converge in O(log n) iterations; 64 is a generous cap.
pub const MAX_LOOKUP_ITERS: usize = 64;

/// The result of a single peer query in a lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LookupQueryResult {
    /// Peer answered with closer peers it knows.
    CloserPeers(Vec<NodeId>),
    /// Peer answered with the looked-up record (FIND_VALUE only).
    /// Caller verifies the signature before trusting.
    Found(SignedRecord),
    /// Peer timed out / failed. Caller continues with other peers.
    Failed,
}

/// Lookup outcomes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LookupResult {
    /// FIND_NODE: returns the K closest peers found.
    Closest(Vec<NodeId>),
    /// FIND_VALUE: returns the record (already verified by caller's
    /// transport layer; this just delivers the bytes).
    Value(SignedRecord),
}

/// Errors during lookup.
#[derive(Debug, Error, PartialEq)]
pub enum LookupError {
    /// No peers at all to start with (routing table empty + no bootstrap).
    #[error("no peers known to start lookup")]
    NoBootstrap,
    /// Lookup hit the [`MAX_LOOKUP_ITERS`] cap without converging.
    #[error("lookup did not converge in {0} iterations")]
    DidNotConverge(usize),
}

/// Abstract transport for issuing one FIND_NODE / FIND_VALUE query
/// to a peer and receiving its response.
///
/// The daemon implements this against UDP / WebRTC / over-mesh-relay.
/// Pure-async; returns a boxed future so the trait stays object-safe
/// + works with any executor.
pub trait Transport: Send + Sync {
    /// Send a FIND_NODE or FIND_VALUE query to `peer` asking for
    /// `target`. If `want_value` is true, the receiver should return
    /// `Found(record)` if it has the record; otherwise return closer
    /// peers either way.
    fn query<'a>(
        &'a self,
        peer: NodeId,
        target: NodeId,
        want_value: bool,
    ) -> Pin<Box<dyn Future<Output = LookupQueryResult> + Send + 'a>>;
}

/// One iterative lookup driver. Owns the lookup state machine; the
/// transport provides the actual network.
#[allow(missing_debug_implementations)]
pub struct Lookup<'a> {
    target: NodeId,
    want_value: bool,
    alpha: usize,
    k: usize,
    /// Peers we've heard of but not yet queried, sorted ascending
    /// by XOR distance to target.
    pending: Vec<NodeId>,
    /// NodeIds we've already queried (success, failure, or in-flight).
    /// Prevents duplicate queries.
    queried: HashMap<NodeId, ()>,
    /// Closest peers seen so far (the converging result). Sorted
    /// ascending by XOR distance to target.
    closest: Vec<NodeId>,
    transport: &'a dyn Transport,
}

impl<'a> Lookup<'a> {
    /// Construct a new lookup with default α / K parameters.
    #[must_use]
    pub fn new(
        target: NodeId,
        bootstrap: Vec<NodeId>,
        transport: &'a dyn Transport,
        want_value: bool,
    ) -> Self {
        Self::with_params(
            target,
            bootstrap,
            transport,
            want_value,
            ALPHA_DEFAULT,
            LOOKUP_K_DEFAULT,
        )
    }

    /// Construct with custom α + K. Used by tests + tuning.
    #[must_use]
    pub fn with_params(
        target: NodeId,
        bootstrap: Vec<NodeId>,
        transport: &'a dyn Transport,
        want_value: bool,
        alpha: usize,
        k: usize,
    ) -> Self {
        let mut pending = bootstrap;
        sort_by_distance(&mut pending, &target);
        // Dedup (a bootstrap with duplicates would otherwise waste queries).
        pending.dedup();
        let closest = pending.clone();
        Self {
            target,
            want_value,
            alpha,
            k,
            pending,
            queried: HashMap::new(),
            closest,
            transport,
        }
    }

    /// Run the lookup to convergence (or to the iteration cap).
    ///
    /// # Errors
    /// - [`LookupError::NoBootstrap`] when started with an empty
    ///   bootstrap and an empty routing-table-driven seed.
    /// - [`LookupError::DidNotConverge`] when more than
    ///   [`MAX_LOOKUP_ITERS`] iterations elapse without progress.
    pub async fn run(mut self) -> Result<LookupResult, LookupError> {
        if self.pending.is_empty() {
            return Err(LookupError::NoBootstrap);
        }
        for _iter in 0..MAX_LOOKUP_ITERS {
            // Pick up to α not-yet-queried peers from the front of pending.
            let to_query: Vec<NodeId> = self
                .pending
                .iter()
                .filter(|p| !self.queried.contains_key(*p))
                .take(self.alpha)
                .copied()
                .collect();
            if to_query.is_empty() {
                // No more peers to query — we've converged on what
                // we have. Return the K closest.
                self.closest.truncate(self.k);
                return Ok(LookupResult::Closest(self.closest));
            }
            for p in &to_query {
                self.queried.insert(*p, ());
            }
            // Issue α queries in parallel by polling each future
            // sequentially. The Transport's caller (the daemon) can
            // do real parallelism via the underlying I/O; this
            // sequential await loop preserves correctness either way.
            // A future optimization: poll all futures simultaneously
            // via futures::future::join_all; punted to wiring time.
            let mut any_new_closer = false;
            for peer in to_query {
                match self.transport.query(peer, self.target, self.want_value).await {
                    LookupQueryResult::Found(record) => {
                        return Ok(LookupResult::Value(record));
                    }
                    LookupQueryResult::CloserPeers(closer) => {
                        for c in closer {
                            if c == peer {
                                continue; // peer returning itself: ignore
                            }
                            if !self.queried.contains_key(&c)
                                && !self.pending.contains(&c)
                            {
                                self.pending.push(c);
                                any_new_closer = self.maybe_add_to_closest(c)
                                    || any_new_closer;
                            }
                        }
                    }
                    LookupQueryResult::Failed => {
                        // Peer didn't respond. Don't add anything;
                        // they stay in queried so we don't re-try.
                    }
                }
            }
            // Re-sort pending by distance to target.
            sort_by_distance(&mut self.pending, &self.target);
            // Re-sort closest, cap at K.
            sort_by_distance(&mut self.closest, &self.target);
            self.closest.truncate(self.k);
            // Convergence: if this round didn't add any new closer
            // peers AND the K-closest set is filled, we're done.
            if !any_new_closer && self.closest.len() >= self.k {
                return Ok(LookupResult::Closest(self.closest));
            }
            // Otherwise loop and pick the next α to query.
        }
        Err(LookupError::DidNotConverge(MAX_LOOKUP_ITERS))
    }

    /// Insert `c` into closest if it's nearer to target than the
    /// current K-th. Returns true iff inserted.
    fn maybe_add_to_closest(&mut self, c: NodeId) -> bool {
        if self.closest.len() < self.k {
            self.closest.push(c);
            return true;
        }
        // closest is sorted ascending; the last entry is the
        // farthest K-th. If c is closer than that, swap in.
        let kth = self.closest.last().copied();
        let Some(kth) = kth else {
            return false;
        };
        let c_closer = closer_to(&c, &kth, &self.target);
        if c_closer == std::cmp::Ordering::Less {
            self.closest.push(c);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn id(b: u8) -> NodeId {
        let mut x = [0u8; 32];
        x[0] = b;
        NodeId(x)
    }

    /// Test transport: each peer answers with a pre-configured set of
    /// "closer peers" (or returns Found / Failed). Records every
    /// query for assertions.
    struct StubTransport {
        responses: HashMap<NodeId, LookupQueryResult>,
        queries_seen: Mutex<Vec<(NodeId, NodeId)>>,
    }

    impl StubTransport {
        fn new() -> Self {
            Self {
                responses: HashMap::new(),
                queries_seen: Mutex::new(Vec::new()),
            }
        }
        fn set_response(&mut self, peer: NodeId, resp: LookupQueryResult) {
            self.responses.insert(peer, resp);
        }
    }

    impl Transport for StubTransport {
        fn query<'a>(
            &'a self,
            peer: NodeId,
            target: NodeId,
            _want_value: bool,
        ) -> Pin<Box<dyn Future<Output = LookupQueryResult> + Send + 'a>> {
            self.queries_seen.lock().unwrap().push((peer, target));
            let r = self
                .responses
                .get(&peer)
                .cloned()
                .unwrap_or(LookupQueryResult::Failed);
            Box::pin(async move { r })
        }
    }

    fn block_on<F: Future>(f: F) -> F::Output {
        use std::task::{Context, Poll, Wake, Waker};
        use std::sync::Arc;
        struct N;
        impl Wake for N {
            fn wake(self: Arc<Self>) {}
        }
        let waker = Waker::from(Arc::new(N));
        let mut cx = Context::from_waker(&waker);
        let mut fut = Box::pin(f);
        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(r) => return r,
                Poll::Pending => continue,
            }
        }
    }

    #[test]
    fn no_bootstrap_errors() {
        let t = StubTransport::new();
        let lookup = Lookup::new(id(0xFF), vec![], &t, false);
        assert_eq!(
            block_on(lookup.run()).unwrap_err(),
            LookupError::NoBootstrap
        );
    }

    #[test]
    fn single_peer_no_closer_returns_it() {
        let mut t = StubTransport::new();
        let peer = id(0x42);
        t.set_response(peer, LookupQueryResult::CloserPeers(vec![]));
        let lookup =
            Lookup::with_params(id(0xFF), vec![peer], &t, false, 3, 1);
        let result = block_on(lookup.run()).unwrap();
        match result {
            LookupResult::Closest(c) => {
                assert_eq!(c, vec![peer]);
            }
            other => panic!("expected Closest, got {other:?}"),
        }
    }

    #[test]
    fn find_value_short_circuits_on_found() {
        let mut t = StubTransport::new();
        use crate::record::PeerRecord;
        let dummy_record = SignedRecord {
            record: PeerRecord {
                publisher_pubkey: [0u8; 32],
                endpoints: vec!["udp://1.2.3.4:5".into()],
                publish_time_unix: 100,
                ttl_secs: 1000,
            },
            signature: [0u8; 64],
        };
        let peer = id(0x42);
        t.set_response(peer, LookupQueryResult::Found(dummy_record.clone()));
        let lookup = Lookup::new(id(0xFF), vec![peer], &t, true);
        let result = block_on(lookup.run()).unwrap();
        match result {
            LookupResult::Value(r) => assert_eq!(r, dummy_record),
            other => panic!("expected Value, got {other:?}"),
        }
    }

    #[test]
    fn iterative_descent_via_closer_responses() {
        // Peer A knows B; B knows the target. Lookup starting from A
        // should find B and then converge.
        let mut t = StubTransport::new();
        let a = id(0x40);
        let b = id(0xF0);
        t.set_response(a, LookupQueryResult::CloserPeers(vec![b]));
        t.set_response(b, LookupQueryResult::CloserPeers(vec![]));
        let lookup =
            Lookup::with_params(id(0xFF), vec![a], &t, false, 3, 2);
        let result = block_on(lookup.run()).unwrap();
        match result {
            LookupResult::Closest(c) => {
                // b is closer to target=0xFF than a.
                assert!(c.contains(&a));
                assert!(c.contains(&b));
                // First entry must be b (closer).
                assert_eq!(c[0], b);
            }
            other => panic!("expected Closest, got {other:?}"),
        }
        let queries = t.queries_seen.lock().unwrap();
        // Both a and b were queried.
        let queried_peers: Vec<NodeId> =
            queries.iter().map(|(p, _)| *p).collect();
        assert!(queried_peers.contains(&a));
        assert!(queried_peers.contains(&b));
    }

    #[test]
    fn failed_peers_dont_retry() {
        let mut t = StubTransport::new();
        let a = id(0x42);
        t.set_response(a, LookupQueryResult::Failed);
        let lookup =
            Lookup::with_params(id(0xFF), vec![a], &t, false, 3, 1);
        let _ = block_on(lookup.run()).unwrap();
        // Should only have queried a once despite failure.
        let queries = t.queries_seen.lock().unwrap();
        assert_eq!(queries.iter().filter(|(p, _)| *p == a).count(), 1);
    }

    #[test]
    fn deduplicates_bootstrap() {
        let mut t = StubTransport::new();
        let a = id(0x42);
        t.set_response(a, LookupQueryResult::CloserPeers(vec![]));
        let lookup =
            Lookup::with_params(id(0xFF), vec![a, a, a], &t, false, 3, 1);
        let _ = block_on(lookup.run()).unwrap();
        let queries = t.queries_seen.lock().unwrap();
        // Despite 3x bootstrap, queried only once.
        assert_eq!(queries.iter().filter(|(p, _)| *p == a).count(), 1);
    }

    #[test]
    fn peer_returning_self_is_ignored() {
        // Anti-attack: a malicious peer returns ITSELF as a closer
        // peer in response, trying to make us re-query indefinitely.
        // Must be ignored.
        let mut t = StubTransport::new();
        let a = id(0x42);
        t.set_response(a, LookupQueryResult::CloserPeers(vec![a, a, a]));
        let lookup =
            Lookup::with_params(id(0xFF), vec![a], &t, false, 3, 5);
        let _ = block_on(lookup.run()).unwrap();
        let queries = t.queries_seen.lock().unwrap();
        // Queried a exactly once; self-loop ignored.
        assert_eq!(queries.iter().filter(|(p, _)| *p == a).count(), 1);
    }
}
