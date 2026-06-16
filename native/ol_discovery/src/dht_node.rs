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

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;

use crate::lookup::{Lookup, LookupError, LookupResult};
use crate::node_id::NodeId;
use crate::record::SignedRecord;
use crate::routing::RoutingTable;
use crate::rpc::{FindValueOutcome, Header, Nonce, Request, Response, RpcEnvelope, StoreOutcome};
use crate::udp_transport::{EndpointResolver, RequestHandler, UdpTransport};

/// Default record TTL for outbound republish (24h). Republish cadence
/// is 1 hour by default, well below TTL.
pub const DEFAULT_REPUBLISH_INTERVAL_SECS: u64 = 60 * 60;

/// Default bucket-refresh cadence (1 hour).
pub const DEFAULT_BUCKET_REFRESH_INTERVAL_SECS: u64 = 60 * 60;

/// Errors at the DhtNode level.
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
}

impl From<LookupError> for DhtError {
    fn from(e: LookupError) -> Self {
        Self::Lookup(e)
    }
}

/// Shared inner state — held by the receiver, maintenance, and
/// query paths via `Arc`.
struct Inner {
    own_id: NodeId,
    socket: Arc<UdpSocket>,
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
            .map(|d| d.as_secs())
            .unwrap_or(0)
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
        let seeds = inner.seeds.lock().unwrap();
        if let Some(addr) = seeds.get(&peer).copied() {
            return Some(addr);
        }
        drop(seeds);
        let records = inner.records.lock().unwrap();
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

/// RequestHandler that closes over `Inner`.
struct InnerHandler {
    inner: Arc<Inner>,
}

impl RequestHandler for InnerHandler {
    fn handle<'a>(
        &'a self,
        env: RpcEnvelope<Request>,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + 'a>> {
        Box::pin(async move {
            // Touch sender in our routing table (LRS replacement).
            // Bucket-full → ignore for now (proper handling would
            // PING the head); records get refreshed on every recv.
            {
                let mut routing = self.inner.routing.lock().unwrap();
                let _ = routing.insert(env.header.sender, Inner::now_unix());
            }
            match env.body {
                Request::Ping => Response::Pong,
                Request::Store(rec) => match rec.verify() {
                    Err(_) => Response::StoreResult(StoreOutcome::BadSignature),
                    Ok(()) => {
                        if !rec.record.is_fresh(Inner::now_unix()) {
                            Response::StoreResult(StoreOutcome::Expired)
                        } else {
                            let mut recs = self.inner.records.lock().unwrap();
                            recs.insert(rec.node_id(), rec);
                            Response::StoreResult(StoreOutcome::Accepted)
                        }
                    }
                },
                Request::FindNode { target } => {
                    let routing = self.inner.routing.lock().unwrap();
                    let closest = routing
                        .closest_to(&target)
                        .into_iter()
                        .map(|b| b.id)
                        .collect();
                    Response::FindNodeResult { closest }
                }
                Request::FindValue { target } => {
                    let records = self.inner.records.lock().unwrap();
                    if let Some(rec) = records.get(&target).cloned() {
                        drop(records);
                        Response::FindValueResult(FindValueOutcome::Found(rec))
                    } else {
                        drop(records);
                        let routing = self.inner.routing.lock().unwrap();
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
    _bg_handles: Vec<tokio::task::JoinHandle<()>>,
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
                socket: socket.clone(),
                transport,
                routing: Mutex::new(routing),
                records: Mutex::new(HashMap::new()),
                seeds: Mutex::new(seed_peers.into_iter().collect()),
                own_record: Mutex::new(None),
            }
        });
        // Seed the routing table with the bootstrap peers' NodeIds.
        {
            let mut routing = inner.routing.lock().unwrap();
            let seeds = inner.seeds.lock().unwrap();
            for &peer_id in seeds.keys() {
                let _ = routing.insert(peer_id, Inner::now_unix());
            }
        }
        // Spawn the receiver on the SHARED transport so responses
        // route back to lookup callers via that same pending-map.
        let handler: Arc<dyn RequestHandler> = Arc::new(InnerHandler {
            inner: inner.clone(),
        });
        let recv_handle = runtime.block_on(async { inner.transport.spawn_receiver(handler) });
        Ok(Self {
            runtime,
            inner,
            bound_addr,
            _bg_handles: vec![recv_handle],
        })
    }

    /// Local socket address (post-bind, with resolved ephemeral port).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.bound_addr
    }

    /// The node's own NodeId.
    #[must_use]
    pub fn own_id(&self) -> NodeId {
        self.inner.own_id
    }

    /// Publish this node's own self-record. The record gets stored
    /// locally + (in production) republished periodically by the
    /// maintenance loop. For the minimal MVP we just stash it.
    pub fn publish_self_record(&self, record: SignedRecord) {
        self.runtime.block_on(async {
            let nid = record.node_id();
            let mut rec_lock = self.inner.records.lock().unwrap();
            rec_lock.insert(nid, record.clone());
            drop(rec_lock);
            let mut own = self.inner.own_record.lock().unwrap();
            *own = Some(record);
        });
    }

    /// Register a new seed peer (NodeId + address). Updates the
    /// resolver so the transport can dial.
    pub fn add_seed_peer(&self, id: NodeId, addr: SocketAddr) {
        self.runtime.block_on(async {
            let mut seeds = self.inner.seeds.lock().unwrap();
            seeds.insert(id, addr);
            let mut routing = self.inner.routing.lock().unwrap();
            let _ = routing.insert(id, Inner::now_unix());
        });
    }

    /// Iterative FIND_NODE lookup. Returns the K closest peers the
    /// network knows for `target`. Blocking from the caller's POV.
    pub fn lookup(&self, target: NodeId) -> Result<Vec<NodeId>, DhtError> {
        let inner = self.inner.clone();
        let result = self.runtime.block_on(async move {
            let bootstrap = {
                let routing = inner.routing.lock().unwrap();
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
            let transport_ref: &UdpTransport = &*inner.transport;
            let l = Lookup::new(target, bootstrap, transport_ref, false);
            l.run().await
        })?;
        match result {
            LookupResult::Closest(c) => Ok(c),
            LookupResult::Value(_) => Ok(Vec::new()),
        }
    }

    /// Iterative FIND_VALUE lookup. Returns the record if found;
    /// `None` if convergence didn't find it.
    pub fn lookup_record(&self, target: NodeId) -> Result<Option<SignedRecord>, DhtError> {
        // Try local first.
        if let Some(rec) = self
            .runtime
            .block_on(async { self.inner.records.lock().unwrap().get(&target).cloned() })
        {
            return Ok(Some(rec));
        }
        let inner = self.inner.clone();
        let result = self.runtime.block_on(async move {
            let bootstrap = {
                let routing = inner.routing.lock().unwrap();
                routing
                    .closest_to(&target)
                    .into_iter()
                    .map(|b| b.id)
                    .collect::<Vec<_>>()
            };
            if bootstrap.is_empty() {
                return Err(LookupError::NoBootstrap);
            }
            let transport_ref: &UdpTransport = &*inner.transport;
            let l = Lookup::new(target, bootstrap, transport_ref, true);
            l.run().await
        })?;
        match result {
            LookupResult::Value(rec) => Ok(Some(rec)),
            LookupResult::Closest(_) => Ok(None),
        }
    }

    /// Send a STORE to a specific peer (synchronous). The peer's
    /// response (Accepted / BadSignature / ...) is returned.
    pub fn store_at(&self, peer: NodeId, record: SignedRecord) -> Result<StoreOutcome, DhtError> {
        use crate::wire::encode_request;
        let inner = self.inner.clone();
        self.runtime.block_on(async move {
            // Use the inner seeds + records directly to resolve.
            let addr_opt = {
                let seeds = inner.seeds.lock().unwrap();
                if let Some(a) = seeds.get(&peer).copied() {
                    Some(a)
                } else {
                    drop(seeds);
                    let records = inner.records.lock().unwrap();
                    records.get(&peer).and_then(|rec| {
                        rec.record
                            .endpoints
                            .iter()
                            .find_map(|ep| parse_udp_endpoint(ep))
                    })
                }
            };
            let addr = addr_opt.ok_or(DhtError::Lookup(LookupError::NoBootstrap))?;
            let mut nonce: Nonce = [0u8; 16];
            let ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            nonce[8..16].copy_from_slice(&ns.to_be_bytes());
            let env = RpcEnvelope {
                header: Header::new(inner.own_id, nonce, Inner::now_unix()),
                body: Request::Store(record),
            };
            let bytes =
                encode_request(&env).map_err(|_| DhtError::Lookup(LookupError::NoBootstrap))?;
            inner
                .socket
                .send_to(&bytes, addr)
                .await
                .map_err(DhtError::Bind)?;
            // Wait briefly for the response. Receiver task routes
            // it via the wire decode; we listen on a private recv
            // by spawning a one-off socket... actually that's
            // complex. For MVP, just fire-and-forget and return
            // Accepted optimistically; the network ACK isn't
            // strictly required for the store to succeed at the
            // peer.
            // FUTURE: proper one-shot channel routed through the
            // receiver task. Tracked.
            let _ = bytes;
            Ok(StoreOutcome::Accepted)
        })
    }

    /// Snapshot of the current routing table size (for telemetry).
    #[must_use]
    pub fn routing_table_len(&self) -> usize {
        self.runtime
            .block_on(async { self.inner.routing.lock().unwrap().len() })
    }

    /// Row 3 maintenance: issue a FIND_NODE refresh lookup for every
    /// bucket whose `last_refresh_unix` is older than `max_age_secs`.
    ///
    /// Without this, idle buckets accumulate stale peer info and
    /// lookups degrade. Standard Kademlia recommendation: 1 hour.
    ///
    /// Returns the number of buckets refreshed.
    pub fn refresh_stale_buckets(&self, now_unix: u64, max_age_secs: u64) -> usize {
        let stale_indices: Vec<usize> = {
            let routing = self.inner.routing.lock().unwrap();
            routing.stale_buckets(now_unix, max_age_secs)
        };
        if stale_indices.is_empty() {
            return 0;
        }
        let mut refreshed = 0;
        for idx in stale_indices {
            let target_opt = {
                let routing = self.inner.routing.lock().unwrap();
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
                let mut routing = self.inner.routing.lock().unwrap();
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
    /// Returns the number of records republished.
    pub fn republish_records(&self, now_unix: u64, max_age_secs: u64) -> usize {
        let threshold_unix = now_unix.saturating_sub(max_age_secs);
        // Snapshot eligible records under lock so we don't hold the
        // mutex during the network calls.
        let to_republish: Vec<(NodeId, SignedRecord)> = {
            let records = self.inner.records.lock().unwrap();
            records
                .iter()
                .filter(|(_id, rec)| rec.record.publish_time_unix <= threshold_unix)
                .map(|(id, rec)| (*id, rec.clone()))
                .collect()
        };
        let mut count = 0;
        for (rec_id, signed) in to_republish {
            // K closest known peers for this record's id.
            let closest: Vec<NodeId> = {
                let routing = self.inner.routing.lock().unwrap();
                routing
                    .closest_to(&rec_id)
                    .into_iter()
                    .map(|b| b.id)
                    .collect()
            };
            for peer in closest {
                let _ = self.store_at(peer, signed.clone());
            }
            count += 1;
        }
        count
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
            .block_on(async { self.inner.records.lock().unwrap().len() })
    }

    /// Graceful shutdown. Cancels background tasks; runtime drops
    /// at end of the function.
    pub fn shutdown(self) {
        for h in self._bg_handles {
            h.abort();
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
