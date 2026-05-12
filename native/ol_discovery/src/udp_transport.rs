//! UDP implementation of the Kademlia [`Transport`] trait.
//!
//! Production DHT lookup over a real UDP socket. Pairs with
//! [`UdpRpcServer`] which receives + dispatches inbound RPCs.
//!
//! Architecture:
//!
//! ```text
//!         Daemon
//!           ↓
//!  ┌─────────────────────┐    UDP socket    ┌─────────────────────┐
//!  │  UdpTransport       │ ←──────────────→ │ Peer's UdpRpcServer │
//!  │  (sends + awaits)   │                  │ (recv + dispatch)   │
//!  └─────────────────────┘                  └─────────────────────┘
//!           ↑
//!         Lookup driver
//! ```
//!
//! The `UdpTransport` is what gets passed to [`crate::lookup::Lookup`]
//! as the `&dyn Transport` argument. Each `query()` call:
//!   1. Builds a FIND_NODE or FIND_VALUE envelope.
//!   2. Picks a peer endpoint by NodeId via the caller-supplied
//!      endpoint resolver.
//!   3. Sends the bytes via UDP.
//!   4. Awaits the response (nonce-matched, timeout-bound).
//!   5. Returns `LookupQueryResult::CloserPeers` /
//!      `LookupQueryResult::Found` / `LookupQueryResult::Failed`.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex};
use tokio::time::timeout;

use crate::lookup::{LookupQueryResult, Transport};
use crate::node_id::NodeId;
use crate::rpc::{Header, Nonce, Request, Response, RpcEnvelope};
use crate::wire::{decode, encode_request, DecodedEnvelope, MAX_WIRE_BYTES};

/// Default per-query timeout: 4 seconds. Wide enough for cross-WAN
/// round-trip + relay routing, tight enough to fail fast.
pub const DEFAULT_QUERY_TIMEOUT_MS: u64 = 4_000;

/// Resolves a NodeId to a UDP `SocketAddr`. The daemon owns this:
/// typically a routing-table lookup → record-store lookup →
/// `endpoints[0]` parse → `SocketAddr`. Returning `None` means we
/// don't know how to reach this peer; the transport treats that as
/// a failed query.
pub trait EndpointResolver: Send + Sync {
    /// Map `peer` to a UDP socket address, if known.
    fn resolve(&self, peer: NodeId) -> Option<SocketAddr>;
}

impl<F> EndpointResolver for F
where
    F: Fn(NodeId) -> Option<SocketAddr> + Send + Sync,
{
    fn resolve(&self, peer: NodeId) -> Option<SocketAddr> {
        (self)(peer)
    }
}

/// In-flight pending queries: nonce → oneshot sender to deliver the
/// matching response when it arrives. Shared between sender and
/// receiver halves.
type PendingMap = Arc<Mutex<HashMap<Nonce, oneshot::Sender<RpcEnvelope<Response>>>>>;

/// UDP transport for Kademlia.
pub struct UdpTransport {
    socket: Arc<UdpSocket>,
    own_id: NodeId,
    pending: PendingMap,
    resolver: Arc<dyn EndpointResolver>,
    timeout_ms: u64,
    nonce_counter: Arc<Mutex<u64>>,
}

impl UdpTransport {
    /// Wire up over an existing UDP socket. The caller (daemon) bound
    /// it on whatever interface + port, and is responsible for
    /// running [`Self::spawn_receiver`] so inbound responses get
    /// routed back to pending queries.
    pub fn new(
        socket: Arc<UdpSocket>,
        own_id: NodeId,
        resolver: Arc<dyn EndpointResolver>,
    ) -> Self {
        Self {
            socket,
            own_id,
            pending: Arc::new(Mutex::new(HashMap::new())),
            resolver,
            timeout_ms: DEFAULT_QUERY_TIMEOUT_MS,
            nonce_counter: Arc::new(Mutex::new(0)),
        }
    }

    /// Override the per-query timeout.
    pub fn with_timeout_ms(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    /// Generate a fresh nonce. Combines a 64-bit counter with random
    /// bytes from the OS so two daemons booting at the same time
    /// don't collide on the counter.
    async fn fresh_nonce(&self) -> Nonce {
        let mut counter = self.nonce_counter.lock().await;
        *counter = counter.wrapping_add(1);
        let c = *counter;
        drop(counter);
        let mut nonce: Nonce = [0u8; 16];
        // First 8 bytes: counter (BE).
        nonce[0..8].copy_from_slice(&c.to_be_bytes());
        // Last 8 bytes: timestamp ns (best-effort uniqueness).
        let ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        nonce[8..16].copy_from_slice(&ns.to_be_bytes());
        nonce
    }

    fn now_unix(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Issue one query + await its response.
    async fn query_impl(
        &self,
        peer: NodeId,
        target: NodeId,
        want_value: bool,
    ) -> LookupQueryResult {
        let Some(addr) = self.resolver.resolve(peer) else {
            return LookupQueryResult::Failed;
        };
        let nonce = self.fresh_nonce().await;
        let env = RpcEnvelope {
            header: Header::new(self.own_id, nonce, self.now_unix()),
            body: if want_value {
                Request::FindValue { target }
            } else {
                Request::FindNode { target }
            },
        };
        let Ok(bytes) = encode_request(&env) else {
            return LookupQueryResult::Failed;
        };
        // Register a oneshot before sending so we can't race the response.
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(nonce, tx);
        // Send. Errors at the network layer → Failed.
        if self.socket.send_to(&bytes, addr).await.is_err() {
            // Clean up the pending entry.
            self.pending.lock().await.remove(&nonce);
            return LookupQueryResult::Failed;
        }
        // Await.
        let outcome = timeout(Duration::from_millis(self.timeout_ms), rx).await;
        match outcome {
            Ok(Ok(resp_env)) => map_response(resp_env.body),
            Ok(Err(_)) | Err(_) => {
                // Drop pending entry on timeout.
                self.pending.lock().await.remove(&nonce);
                LookupQueryResult::Failed
            }
        }
    }

    /// Spawn the receiver background task. Reads inbound UDP
    /// datagrams; routes responses to pending queries, dispatches
    /// requests to the provided handler.
    ///
    /// Caller (daemon) drops the returned handle to terminate.
    pub fn spawn_receiver(
        &self,
        handler: Arc<dyn RequestHandler>,
    ) -> tokio::task::JoinHandle<()> {
        let socket = self.socket.clone();
        let pending = self.pending.clone();
        let own_id = self.own_id;
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_WIRE_BYTES];
            loop {
                let Ok((n, src)) = socket.recv_from(&mut buf).await else {
                    continue;
                };
                let Ok(envelope) = decode(&buf[..n]) else {
                    continue;
                };
                match envelope {
                    DecodedEnvelope::Response(env) => {
                        let nonce = env.header.nonce;
                        if let Some(tx) = pending.lock().await.remove(&nonce) {
                            let _ = tx.send(env);
                        }
                    }
                    DecodedEnvelope::Request(env) => {
                        // Build a response via the user-supplied handler.
                        let nonce = env.header.nonce;
                        let body = handler.handle(env).await;
                        let response_env = RpcEnvelope {
                            header: Header::new(
                                own_id,
                                nonce,
                                std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_secs())
                                    .unwrap_or(0),
                            ),
                            body,
                        };
                        if let Ok(resp_bytes) =
                            crate::wire::encode_response(&response_env)
                        {
                            let _ = socket.send_to(&resp_bytes, src).await;
                        }
                    }
                }
            }
        })
    }
}

impl Transport for UdpTransport {
    fn query<'a>(
        &'a self,
        peer: NodeId,
        target: NodeId,
        want_value: bool,
    ) -> Pin<Box<dyn Future<Output = LookupQueryResult> + Send + 'a>> {
        Box::pin(self.query_impl(peer, target, want_value))
    }
}

/// Handler for inbound RPC requests. The daemon implements this:
/// PING → Pong; STORE → Accepted/BadSignature/...;
/// FIND_NODE → routing-table closest_to; FIND_VALUE → local store
/// lookup falling back to routing-table closest_to.
pub trait RequestHandler: Send + Sync {
    /// Build a response for the given request envelope. Returns the
    /// response BODY only; the framework wraps it with the matching
    /// nonce + sender id + fresh timestamp.
    fn handle<'a>(
        &'a self,
        env: RpcEnvelope<Request>,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + 'a>>;
}

fn map_response(body: Response) -> LookupQueryResult {
    match body {
        Response::Pong | Response::StoreResult(_) => {
            // Surprising responses for a FIND_NODE / FIND_VALUE query.
            // Treat as failure rather than mis-interpreting.
            LookupQueryResult::Failed
        }
        Response::FindNodeResult { closest } => {
            LookupQueryResult::CloserPeers(closest)
        }
        Response::FindValueResult(outcome) => match outcome {
            crate::rpc::FindValueOutcome::Found(rec) => {
                LookupQueryResult::Found(rec)
            }
            crate::rpc::FindValueOutcome::Closer(closer) => {
                LookupQueryResult::CloserPeers(closer)
            }
        },
    }
}
