//! High-level Kademlia DHT node — the production primitive.
//!
//! Composes everything below it into one object the Python daemon
//! constructs once + drives synchronously:
//!
//! ```text
//!  DhtNode
//!  ├── tokio::Runtime  (owned, multi-thread)
//!  ├── UdpSocket       (bound on caller's chosen addr)
//!  ├── UdpTransport    (impl of Transport trait)
//!  ├── RoutingTable    (K-bucket, populated by inbound RPCs)
//!  ├── records: Map<NodeId, SignedRecord>
//!  ├── seeds:   Map<NodeId, SocketAddr>  (bootstrap endpoints)
//!  ├── receiver-task  (background: decode + dispatch + respond)
//!  └── maintenance-task (background: bucket refresh, record republish)
//! ```
//!
//! Python daemon side:
//!
//! ```python
//!     node = DhtNode("0.0.0.0:7117", my_id, seed_peers)
//!     node.publish_record(my_signed_record)
//!     closest = node.lookup(target_id)            # blocking
//!     record  = node.lookup_record(target_id)     # blocking
//!     node.shutdown()
//! ```
//!
//! Methods are sync from Python's POV. Internally they `block_on`
//! the embedded tokio runtime. Background tasks (receiver,
//! maintenance) run on the same runtime, outlive any single call.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};

use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::lookup::{Lookup, LookupError, LookupResult};
use crate::node_id::NodeId;
use crate::record::SignedRecord;
use crate::routing::RoutingTable;
use crate::rpc::{FindValueOutcome, Request, Response, RpcEnvelope, StoreOutcome};
use crate::udp_transport::{EndpointResolver, RequestHandler, UdpTransport};

/// Maximum signed records retained in memory by one node.
pub const MAX_STORED_RECORDS: usize = 4_096;
/// Maximum configured seed endpoints.
pub const MAX_SEED_PEERS: usize = 4_096;
/// Maximum amount a publisher timestamp may lead the local clock.
pub const MAX_RECORD_FUTURE_SKEW_SECS: u64 = 300;
/// Maximum records selected for one maintenance tick.
pub const MAX_REPUBLISH_RECORDS_PER_TICK: usize = 256;
/// Maximum total peer STORE requests emitted by one maintenance tick.
pub const MAX_REPUBLISH_REQUESTS_PER_TICK: usize = 4_096;
/// Bounded concurrent STORE exchanges during maintenance.
pub const MAX_REPUBLISH_IN_FLIGHT: usize = 32;

/// Default record TTL for outbound republish (24h). Republish cadence
/// is 1 hour by default, well below TTL.
pub const DEFAULT_REPUBLISH_INTERVAL_SECS: u64 = 60 * 60;

/// Default bucket-refresh cadence (1 hour).
pub const DEFAULT_BUCKET_REFRESH_INTERVAL_SECS: u64 = 60 * 60;

/// Errors at the `DhtNode` level.
#[derive(Debug, Error)]
pub enum DhtError {
    /// Failed to bind the UDP socket.
    #[error("bind failed: {0}")]
    Bind(#[from] std::io::Error),
    /// Tokio runtime construction failed.
    #[error("runtime build failed: {0}")]
    Runtime(String),
    /// Lookup driver returned an error.
    #[error("lookup error: {0}")]
    Lookup(LookupError),

    /// A bounded in-memory registry is full or an input list is excessive.
    #[error("resource limit exceeded: {0}")]
    ResourceLimit(&'static str),

    /// A signed record failed validation.
    #[error("invalid signed record: {0}")]
    InvalidRecord(String),

    /// A self-record does not identify this DHT node.
    #[error("self-record publisher does not match node id")]
    SelfRecordIdentityMismatch,

    /// A concrete UDP request failed.
    #[error("UDP request failed: {0}")]
    Request(String),
}

impl From<LookupError> for DhtError {
    fn from(e: LookupError) -> Self {
        Self::Lookup(e)
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Shared inner state — held by the receiver, maintenance, and
/// query paths via `Arc`.
struct Inner {
    own_id: NodeId,
    transport: Arc<UdpTransport>,
    routing: Mutex<RoutingTable>,
    records: Mutex<HashMap<NodeId, SignedRecord>>,
    seeds: Mutex<HashMap<NodeId, SocketAddr>>,
    own_record: Mutex<Option<SignedRecord>>,
}

impl Inner {
    fn now_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
    }
}

/// Resolver that holds a Weak reference to `Inner` so the Arc cycle
/// stays breakable. Inner owns the transport; the transport's resolver
/// only weakly references Inner.
struct WeakResolver {
    weak: std::sync::Weak<Inner>,
}

impl EndpointResolver for WeakResolver {
    fn resolve(&self, peer: NodeId) -> Option<SocketAddr> {
        let inner = self.weak.upgrade()?;
        let seeds = lock_unpoisoned(&inner.seeds);
        if let Some(addr) = seeds.get(&peer).copied() {
            return Some(addr);
        }
        drop(seeds);
        let records = lock_unpoisoned(&inner.records);
        if let Some(rec) = records.get(&peer) {
            for ep in &rec.record.endpoints {
                if let Some(s) = parse_udp_endpoint(ep) {
                    return Some(s);
                }
            }
        }
        None
    }
}

/// `RequestHandler` that closes over `Inner`.
struct InnerHandler {
    inner: Arc<Inner>,
}

impl RequestHandler for InnerHandler {
    fn handle<'a>(
        &'a self,
        env: RpcEnvelope<Request>,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + 'a>> {
        Box::pin(async move {
            // The wire header's sender id is not signed.  Never admit it to
            // the routing table merely because a datagram arrived: doing so
            // lets one spoofed UDP packet poison routing state.  STORE is the
            // only request carrying an identity proof, so admission happens
            // below after its record signature has been verified.
            match env.body {
                Request::Ping => Response::Pong,
                Request::Store(rec) => {
                    if rec.verify().is_ok() {
                        let now = Inner::now_unix();
                        if rec.record.is_fresh(now) {
                            if rec.record.publish_time_unix
                                > now.saturating_add(MAX_RECORD_FUTURE_SKEW_SECS)
                            {
                                return Response::StoreResult(StoreOutcome::Expired);
                            }
                            let mut recs = lock_unpoisoned(&self.inner.records);
                            recs.retain(|_, stored| stored.record.is_fresh(now));
                            let id = rec.node_id();
                            if recs.len() >= MAX_STORED_RECORDS && !recs.contains_key(&id) {
                                Response::StoreResult(StoreOutcome::RateLimited)
                            } else {
                                recs.insert(id, rec);
                                drop(recs);
                                let mut routing = lock_unpoisoned(&self.inner.routing);
                                let _ = routing.insert(id, now);
                                Response::StoreResult(StoreOutcome::Accepted)
                            }
                        } else {
                            Response::StoreResult(StoreOutcome::Expired)
                        }
                    } else {
                        Response::StoreResult(StoreOutcome::BadSignature)
                    }
                }
                Request::FindNode { target } => {
                    let routing = lock_unpoisoned(&self.inner.routing);
                    let closest = routing
                        .closest_to(&target)
                        .into_iter()
                        .map(|b| b.id)
                        .collect();
                    Response::FindNodeResult { closest }
                }
                Request::FindValue { target } => {
                    let now = Inner::now_unix();
                    let mut records = lock_unpoisoned(&self.inner.records);
                    let found = records.get(&target).cloned().filter(|rec| {
                        rec.record.is_fresh(now)
                            && rec.record.publish_time_unix
                                <= now.saturating_add(MAX_RECORD_FUTURE_SKEW_SECS)
                    });
                    if let Some(rec) = found {
                        drop(records);
                        Response::FindValueResult(FindValueOutcome::Found(rec))
                    } else {
                        records.remove(&target);
                        drop(records);
                        let routing = lock_unpoisoned(&self.inner.routing);
                        let closer = routing
                            .closest_to(&target)
                            .into_iter()
                            .map(|b| b.id)
                            .collect();
                        Response::FindValueResult(FindValueOutcome::Closer(closer))
                    }
                }
            }
        })
    }
}

/// Top-level DHT node.
#[allow(missing_debug_implementations)]
pub struct DhtNode {
    runtime: Runtime,
    inner: Arc<Inner>,
    bound_addr: SocketAddr,
    bg_handles: Vec<tokio::task::JoinHandle<()>>,
}

impl DhtNode {
    /// Construct a new DHT node bound to `bind_addr`. Spawns the
    /// receiver task immediately so incoming RPCs are processed.
    ///
    /// # Errors
    /// - [`DhtError::Bind`] when the socket can't bind.
    /// - [`DhtError::Runtime`] if tokio runtime build fails.
    pub fn new(
        bind_addr: SocketAddr,
        own_id: NodeId,
        seed_peers: Vec<(NodeId, SocketAddr)>,
    ) -> Result<Self, DhtError> {
        if seed_peers.len() > MAX_SEED_PEERS {
            return Err(DhtError::ResourceLimit("seed peer count exceeds maximum"));
        }
        let runtime = Runtime::new().map_err(|e| DhtError::Runtime(e.to_string()))?;
        let socket = runtime.block_on(async { UdpSocket::bind(bind_addr).await })?;
        let bound_addr = socket.local_addr()?;
        let socket = Arc::new(socket);
        let routing = RoutingTable::new(own_id);
        // Pre-build a placeholder Inner missing the transport; we'll
        // construct the transport (which needs an EndpointResolver
        // that closes over Inner) and then swap the Arc.
        // Easier: build the transport first with a self-referencing
        // resolver via Arc::new_cyclic.
        let inner = Arc::new_cyclic(|weak_inner: &std::sync::Weak<Inner>| {
            let weak_for_resolver = weak_inner.clone();
            let resolver: Arc<dyn EndpointResolver> = Arc::new(WeakResolver {
                weak: weak_for_resolver,
            });
            let transport = Arc::new(UdpTransport::new(socket.clone(), own_id, resolver));
            Inner {
                own_id,
                transport,
                routing: Mutex::new(routing),
                records: Mutex::new(HashMap::new()),
                seeds: Mutex::new(seed_peers.into_iter().collect()),
                own_record: Mutex::new(None),
            }
        });
        // Seed the routing table with the bootstrap peers' NodeIds.
        {
            let mut routing = lock_unpoisoned(&inner.routing);
            let seeds = lock_unpoisoned(&inner.seeds);
            for &peer_id in seeds.keys() {
                let _ = routing.insert(peer_id, Inner::now_unix());
            }
        }
        // Spawn the receiver on the SHARED transport so responses
        // route back to lookup callers via that same pending-map.
        let handler: Arc<dyn RequestHandler> = Arc::new(InnerHandler {
            inner: inner.clone(),
        });
        // `spawn_receiver` is synchronous but calls `tokio::spawn`
        // internally, so it needs a runtime context. Enter the runtime
        // (rather than block_on) and KEEP the returned JoinHandle alive
        // in `bg_handles` — we must not await it (that would block on
        // the receiver loop ending).
        let recv_handle = {
            let _rt_guard = runtime.enter();
            inner.transport.spawn_receiver(handler)
        };
        Ok(Self {
            runtime,
            inner,
            bound_addr,
            bg_handles: vec![recv_handle],
        })
    }

    /// Local socket address (post-bind, with resolved ephemeral port).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.bound_addr
    }

    /// The node's own `NodeId`.
    #[must_use]
    pub fn own_id(&self) -> NodeId {
        self.inner.own_id
    }

    /// Publish this node's own self-record. The record gets stored
    /// locally + (in production) republished periodically by the
    /// maintenance loop. For the minimal MVP we just stash it.
    pub fn publish_self_record(&self, record: SignedRecord) -> Result<(), DhtError> {
        record
            .verify()
            .map_err(|error| DhtError::InvalidRecord(error.to_string()))?;
        if record.node_id() != self.inner.own_id {
            return Err(DhtError::SelfRecordIdentityMismatch);
        }
        let now = Inner::now_unix();
        if !record.record.is_fresh(now)
            || record.record.publish_time_unix > now.saturating_add(MAX_RECORD_FUTURE_SKEW_SECS)
        {
            return Err(DhtError::InvalidRecord(
                "self-record is expired or future-dated".to_string(),
            ));
        }
        self.runtime.block_on(async {
            let nid = record.node_id();
            let mut rec_lock = lock_unpoisoned(&self.inner.records);
            rec_lock.insert(nid, record.clone());
            drop(rec_lock);
            let mut own = lock_unpoisoned(&self.inner.own_record);
            *own = Some(record);
        });
        Ok(())
    }

    /// Cache a signature-valid record learned through a trusted recovery or
    /// migration path.  Expired records may be loaded so maintenance can
    /// prune them, but lookup paths never serve them.
    pub fn cache_verified_record(&self, record: SignedRecord) -> Result<(), DhtError> {
        record
            .verify()
            .map_err(|error| DhtError::InvalidRecord(error.to_string()))?;
        let mut records = lock_unpoisoned(&self.inner.records);
        let id = record.node_id();
        if records.len() >= MAX_STORED_RECORDS && !records.contains_key(&id) {
            return Err(DhtError::ResourceLimit("record store is full"));
        }
        records.insert(id, record);
        Ok(())
    }

    /// Register a new seed peer (`NodeId` + address). Updates the
    /// resolver so the transport can dial.
    pub fn add_seed_peer(&self, id: NodeId, addr: SocketAddr) -> Result<(), DhtError> {
        self.runtime.block_on(async {
            let mut seeds = lock_unpoisoned(&self.inner.seeds);
            if seeds.len() >= MAX_SEED_PEERS && !seeds.contains_key(&id) {
                return Err(DhtError::ResourceLimit("seed peer registry is full"));
            }
            seeds.insert(id, addr);
            let mut routing = lock_unpoisoned(&self.inner.routing);
            let _ = routing.insert(id, Inner::now_unix());
            Ok(())
        })
    }

    /// Iterative `FIND_NODE` lookup. Returns the K closest peers the
    /// network knows for `target`. Blocking from the caller's POV.
    pub fn lookup(&self, target: NodeId) -> Result<Vec<NodeId>, DhtError> {
        let inner = self.inner.clone();
        let result = self.runtime.block_on(async move {
            let bootstrap = {
                let routing = lock_unpoisoned(&inner.routing);
                routing
                    .closest_to(&target)
                    .into_iter()
                    .map(|b| b.id)
                    .collect::<Vec<_>>()
            };
            if bootstrap.is_empty() {
                return Err(LookupError::NoBootstrap);
            }
            // Use the SHARED transport so response routing via the
            // receiver task lands back in the correct pending map.
            let transport_ref: &UdpTransport = &inner.transport;
            let l = Lookup::new(target, bootstrap, transport_ref, false);
            l.run().await
        })?;
        match result {
            LookupResult::Closest(c) => Ok(c),
            LookupResult::Value(_) => Ok(Vec::new()),
        }
    }

    /// Iterative `FIND_VALUE` lookup. Returns the record if found;
    /// `None` if convergence didn't find it.
    pub fn lookup_record(&self, target: NodeId) -> Result<Option<SignedRecord>, DhtError> {
        // Try local first.
        let now = Inner::now_unix();
        let local = self.runtime.block_on(async {
            let mut records = lock_unpoisoned(&self.inner.records);
            let found = records.get(&target).cloned().filter(|rec| {
                rec.record.is_fresh(now)
                    && rec.record.publish_time_unix
                        <= now.saturating_add(MAX_RECORD_FUTURE_SKEW_SECS)
                    && rec.verify().is_ok()
            });
            if found.is_none() {
                records.remove(&target);
            }
            found
        });
        if let Some(rec) = local {
            return Ok(Some(rec));
        }
        let inner = self.inner.clone();
        let result = self.runtime.block_on(async move {
            let bootstrap = {
                let routing = lock_unpoisoned(&inner.routing);
                routing
                    .closest_to(&target)
                    .into_iter()
                    .map(|b| b.id)
                    .collect::<Vec<_>>()
            };
            if bootstrap.is_empty() {
                return Err(LookupError::NoBootstrap);
            }
            let transport_ref: &UdpTransport = &inner.transport;
            let l = Lookup::new(target, bootstrap, transport_ref, true);
            l.run().await
        })?;
        match result {
            LookupResult::Value(rec) => Ok(Some(rec)),
            LookupResult::Closest(_) => Ok(None),
        }
    }

    /// Send a STORE to a specific peer (synchronous). The peer's
    /// response (`Accepted` / `BadSignature` / ...) is returned.
    pub fn store_at(&self, peer: NodeId, record: SignedRecord) -> Result<StoreOutcome, DhtError> {
        record
            .verify()
            .map_err(|error| DhtError::InvalidRecord(error.to_string()))?;
        let inner = self.inner.clone();
        self.runtime.block_on(async move {
            match inner.transport.request(peer, Request::Store(record)).await {
                Ok(Response::StoreResult(outcome)) => Ok(outcome),
                Ok(_) => Err(DhtError::Request(
                    "peer returned a non-STORE response".to_string(),
                )),
                Err(error) => Err(DhtError::Request(error.to_string())),
            }
        })
    }

    /// Snapshot of the current routing table size (for telemetry).
    #[must_use]
    pub fn routing_table_len(&self) -> usize {
        self.runtime
            .block_on(async { lock_unpoisoned(&self.inner.routing).len() })
    }

    /// Row 3 maintenance: issue a `FIND_NODE` refresh lookup for every
    /// bucket whose `last_refresh_unix` is older than `max_age_secs`.
    ///
    /// Without this, idle buckets accumulate stale peer info and
    /// lookups degrade. Standard Kademlia recommendation: 1 hour.
    ///
    /// Returns the number of buckets refreshed.
    pub fn refresh_stale_buckets(&self, now_unix: u64, max_age_secs: u64) -> usize {
        let stale_indices: Vec<usize> = {
            let routing = lock_unpoisoned(&self.inner.routing);
            routing.stale_buckets(now_unix, max_age_secs)
        };
        if stale_indices.is_empty() {
            return 0;
        }
        let mut refreshed = 0;
        for idx in stale_indices {
            let target_opt = {
                let routing = lock_unpoisoned(&self.inner.routing);
                routing.synthetic_id_for_bucket(idx)
            };
            let Some(target) = target_opt else {
                continue;
            };
            // Issue the lookup — errors here are non-fatal (e.g.,
            // NoBootstrap if routing is genuinely empty). Mark the
            // bucket refreshed regardless so we don't busy-loop.
            let _ = self.lookup(target);
            {
                let mut routing = lock_unpoisoned(&self.inner.routing);
                routing.mark_bucket_refreshed(idx, now_unix);
            }
            refreshed += 1;
        }
        refreshed
    }

    /// Row 3 maintenance: re-publish every record whose stored copy
    /// is older than `max_age_secs`. Calls `store_at` against the
    /// K closest peers per record so they don't expire under the
    /// default record TTL.
    ///
    /// Returns the number of distinct records acknowledged as accepted by at
    /// least one peer. Work is bounded and peer requests run concurrently.
    pub fn republish_records(&self, now_unix: u64, max_age_secs: u64) -> usize {
        let threshold_unix = now_unix.saturating_sub(max_age_secs);
        // Snapshot eligible records under lock so we don't hold the
        // mutex during the network calls.
        let to_republish: Vec<(NodeId, SignedRecord)> = {
            let mut records = lock_unpoisoned(&self.inner.records);
            records.retain(|_, record| record.record.is_fresh(now_unix));
            records
                .iter()
                .filter(|(_id, rec)| {
                    rec.record.publish_time_unix <= threshold_unix
                        && rec.record.publish_time_unix
                            <= now_unix.saturating_add(MAX_RECORD_FUTURE_SKEW_SECS)
                })
                .take(MAX_REPUBLISH_RECORDS_PER_TICK)
                .map(|(id, rec)| (*id, rec.clone()))
                .collect()
        };
        let mut jobs = Vec::new();
        for (rec_id, signed) in to_republish {
            // K closest known peers for this record's id.
            let closest: Vec<NodeId> = {
                let routing = lock_unpoisoned(&self.inner.routing);
                routing
                    .closest_to(&rec_id)
                    .into_iter()
                    .map(|b| b.id)
                    .collect()
            };
            for peer in closest {
                if jobs.len() >= MAX_REPUBLISH_REQUESTS_PER_TICK {
                    break;
                }
                jobs.push((rec_id, peer, signed.clone()));
            }
        }
        let transport = self.inner.transport.clone();
        self.runtime.block_on(async move {
            let semaphore = Arc::new(Semaphore::new(MAX_REPUBLISH_IN_FLIGHT));
            let mut tasks = JoinSet::new();
            for (record_id, peer, record) in jobs {
                let transport = transport.clone();
                let semaphore = semaphore.clone();
                tasks.spawn(async move {
                    let Ok(permit) = semaphore.acquire_owned().await else {
                        return (record_id, false);
                    };
                    let _permit = permit;
                    let accepted = matches!(
                        transport.request(peer, Request::Store(record)).await,
                        Ok(Response::StoreResult(StoreOutcome::Accepted))
                    );
                    (record_id, accepted)
                });
            }
            let mut accepted = HashSet::new();
            while let Some(result) = tasks.join_next().await {
                if let Ok((record_id, true)) = result {
                    accepted.insert(record_id);
                }
            }
            accepted.len()
        })
    }

    /// Row 3 maintenance: single-call wrapper that runs BOTH
    /// stale-bucket refresh AND record republish. Daemons call this
    /// from a periodic timer (e.g., every 60 seconds).
    ///
    /// Returns `(buckets_refreshed, records_republished)`.
    pub fn tick_maintenance(
        &self,
        now_unix: u64,
        bucket_max_age_secs: u64,
        record_max_age_secs: u64,
    ) -> (usize, usize) {
        let bucket_refreshed = self.refresh_stale_buckets(now_unix, bucket_max_age_secs);
        let records_republished = self.republish_records(now_unix, record_max_age_secs);
        (bucket_refreshed, records_republished)
    }

    /// Snapshot of how many records this node currently stores.
    #[must_use]
    pub fn records_len(&self) -> usize {
        self.runtime
            .block_on(async { lock_unpoisoned(&self.inner.records).len() })
    }

    /// Graceful shutdown. Cancels background tasks; runtime drops
    /// at end of the function.
    pub fn shutdown(self) {
        for handle in self.bg_handles {
            handle.abort();
        }
        // Runtime drops here.
    }
}

/// Parse an endpoint string of the form `udp://host:port` into a
/// `SocketAddr`. Returns `None` for non-UDP endpoints or parse
/// failure. Resolves DNS lazily — `host` must already be an IP
/// literal or this returns None (DNS lookup is the daemon's job).
fn parse_udp_endpoint(ep: &str) -> Option<SocketAddr> {
    let rest = ep.strip_prefix("udp://")?;
    rest.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_udp_endpoint_valid() {
        assert!(parse_udp_endpoint("udp://127.0.0.1:5678").is_some());
        assert!(parse_udp_endpoint("udp://[::1]:1234").is_some());
    }

    #[test]
    fn parse_udp_endpoint_invalid() {
        assert!(parse_udp_endpoint("quic://127.0.0.1:5678").is_none());
        assert!(parse_udp_endpoint("udp://bad-not-ip:5").is_none());
        assert!(parse_udp_endpoint("garbage").is_none());
    }
}
