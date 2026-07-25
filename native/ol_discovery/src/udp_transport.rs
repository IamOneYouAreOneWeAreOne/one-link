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
//!   1. Builds a `FIND_NODE` or `FIND_VALUE` envelope.
//!   2. Picks a peer endpoint by `NodeId` via the caller-supplied
//!      endpoint resolver.
//!   3. Sends the bytes via UDP.
//!   4. Awaits the response (nonce-matched, timeout-bound).
//!   5. Returns `LookupQueryResult::CloserPeers` /
//!      `LookupQueryResult::Found` / `LookupQueryResult::Failed`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use rand_core::{OsRng, RngCore};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex, Semaphore};
use tokio::time::timeout;

use crate::lookup::{LookupQueryResult, Transport};
use crate::node_id::NodeId;
use crate::rpc::{Header, Nonce, Request, Response, RpcEnvelope};
use crate::wire::{decode, encode_request, DecodedEnvelope, WireError, MAX_WIRE_BYTES};

/// Default per-query timeout: 4 seconds. Wide enough for cross-WAN
/// round-trip + relay routing, tight enough to fail fast.
pub const DEFAULT_QUERY_TIMEOUT_MS: u64 = 4_000;

/// Maximum requests concurrently waiting for nonce-matched responses.
pub const MAX_PENDING_QUERIES: usize = 1_024;

/// Maximum request nonces retained for replay detection.
///
/// Entries expire at the RPC clock-skew boundary and the FIFO has a hard
/// ceiling so forged sender ids cannot grow memory without bound.
pub const MAX_REPLAY_WINDOW_ENTRIES: usize = 65_536;

/// Maximum request handlers executing at once.  The receive loop must remain
/// available to deliver nonce-matched responses even when an application
/// handler is slow, but unbounded task spawning would turn that fix into a
/// memory-exhaustion primitive.
pub const MAX_INBOUND_REQUESTS_IN_FLIGHT: usize = 128;

/// Deadline for one application request handler. It matches the outbound
/// query deadline so a stuck handler cannot pin a semaphore slot forever.
pub const INBOUND_REQUEST_HANDLER_TIMEOUT_MS: u64 = DEFAULT_QUERY_TIMEOUT_MS;

/// Per-source request budget in one wall-clock second. UDP source addresses
/// can be spoofed, so this is defense in depth rather than authentication; it
/// still bounds work and reflection traffic from a reachable abusive peer.
pub const MAX_REQUESTS_PER_SOURCE_WINDOW: u32 = 128;

/// Aggregate request budget per wall-clock second. Per-source limiting alone
/// is insufficient for UDP because source IPs can be forged; this ceiling
/// bounds total handler work even during a distributed or spoofed flood.
pub const MAX_REQUESTS_GLOBAL_WINDOW: u32 = 4_096;

/// Hard ceiling for the rate-limiter's source table. New source addresses are
/// rejected while the bounded table is full; expired windows are pruned first.
pub const MAX_RATE_LIMIT_SOURCES: usize = 4_096;

#[derive(Debug, Default)]
struct SourceRateLimiter {
    sources: HashMap<IpAddr, u32>,
    global_window_start_unix: u64,
    global_requests: u32,
}

impl SourceRateLimiter {
    fn accept(&mut self, source: IpAddr, now_unix: u64) -> bool {
        if now_unix != self.global_window_start_unix {
            self.global_window_start_unix = now_unix;
            self.global_requests = 0;
            self.sources.clear();
        }
        if self.global_requests >= MAX_REQUESTS_GLOBAL_WINDOW {
            return false;
        }

        if let Some(requests) = self.sources.get_mut(&source) {
            if *requests >= MAX_REQUESTS_PER_SOURCE_WINDOW {
                return false;
            }
            *requests += 1;
            self.global_requests += 1;
            return true;
        }

        if self.sources.len() >= MAX_RATE_LIMIT_SOURCES {
            return false;
        }
        self.sources.insert(source, 1);
        self.global_requests += 1;
        true
    }
}

#[derive(Debug, Default)]
struct ReplayWindow {
    seen: HashSet<(NodeId, Nonce)>,
    order: VecDeque<(u64, NodeId, Nonce)>,
}

impl ReplayWindow {
    fn accept(&mut self, sender: NodeId, nonce: Nonce, now_unix: u64) -> bool {
        let oldest_allowed = now_unix.saturating_sub(crate::rpc::MAX_CLOCK_SKEW_SECS);
        while self
            .order
            .front()
            .is_some_and(|(received, _, _)| *received < oldest_allowed)
        {
            if let Some((_, old_sender, old_nonce)) = self.order.pop_front() {
                self.seen.remove(&(old_sender, old_nonce));
            }
        }

        let key = (sender, nonce);
        if self.seen.contains(&key) {
            return false;
        }
        while self.order.len() >= MAX_REPLAY_WINDOW_ENTRIES {
            if let Some((_, old_sender, old_nonce)) = self.order.pop_front() {
                self.seen.remove(&(old_sender, old_nonce));
            }
        }
        self.seen.insert(key);
        self.order.push_back((now_unix, sender, nonce));
        true
    }
}

/// Failure from a concrete UDP request/response exchange.
#[derive(Debug, Error)]
pub enum UdpRequestError {
    /// No configured endpoint is known for the peer.
    #[error("no endpoint known for peer")]
    UnknownPeer,
    /// Request serialization failed.
    #[error("wire: {0}")]
    Wire(#[from] WireError),
    /// UDP send failed.
    #[error("send: {0}")]
    Send(#[from] std::io::Error),
    /// Operating-system randomness was unavailable for the anti-spoof nonce.
    #[error("nonce randomness unavailable: {0}")]
    Random(String),
    /// Too many calls are waiting for replies.
    #[error("pending query limit reached ({MAX_PENDING_QUERIES})")]
    PendingLimit,
    /// The peer did not answer before the configured deadline.
    #[error("request timed out")]
    Timeout,
    /// The response delivery channel closed unexpectedly.
    #[error("response channel closed")]
    ResponseChannelClosed,
}

/// Resolves a `NodeId` to a UDP `SocketAddr`. The daemon owns this:
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
struct PendingRequest {
    expected_peer: NodeId,
    expected_addr: SocketAddr,
    response: oneshot::Sender<RpcEnvelope<Response>>,
}

type PendingMap = Arc<Mutex<HashMap<Nonce, PendingRequest>>>;

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

/// UDP transport for Kademlia.
#[allow(missing_debug_implementations)]
pub struct UdpTransport {
    socket: Arc<UdpSocket>,
    own_id: NodeId,
    pending: PendingMap,
    request_replay: Arc<Mutex<ReplayWindow>>,
    request_rates: Arc<Mutex<SourceRateLimiter>>,
    inbound_slots: Arc<Semaphore>,
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
            request_replay: Arc::new(Mutex::new(ReplayWindow::default())),
            request_rates: Arc::new(Mutex::new(SourceRateLimiter::default())),
            inbound_slots: Arc::new(Semaphore::new(MAX_INBOUND_REQUESTS_IN_FLIGHT)),
            resolver,
            timeout_ms: DEFAULT_QUERY_TIMEOUT_MS,
            nonce_counter: Arc::new(Mutex::new(0)),
        }
    }

    /// Override the per-query timeout.
    #[must_use]
    pub fn with_timeout_ms(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    /// Generate an unpredictable nonce and mix in a monotonic local counter.
    async fn fresh_nonce(&self) -> Result<Nonce, UdpRequestError> {
        let mut nonce: Nonce = [0u8; 16];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|error| UdpRequestError::Random(error.to_string()))?;
        let mut counter = self.nonce_counter.lock().await;
        *counter = counter
            .checked_add(1)
            .ok_or_else(|| UdpRequestError::Random("nonce counter exhausted".to_string()))?;
        let c = *counter;
        drop(counter);
        for (byte, counter_byte) in nonce[..8].iter_mut().zip(c.to_be_bytes()) {
            *byte ^= counter_byte;
        }
        Ok(nonce)
    }

    /// Send one typed request and await a nonce-, identity-, and
    /// source-address-matched response.
    pub async fn request(&self, peer: NodeId, body: Request) -> Result<Response, UdpRequestError> {
        let Some(addr) = self.resolver.resolve(peer) else {
            return Err(UdpRequestError::UnknownPeer);
        };
        let nonce = self.fresh_nonce().await?;
        let env = RpcEnvelope {
            header: Header::new(self.own_id, nonce, unix_now()),
            body,
        };
        let bytes = encode_request(&env)?;
        // Register a oneshot before sending so we can't race the response.
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock().await;
            if pending.len() >= MAX_PENDING_QUERIES {
                return Err(UdpRequestError::PendingLimit);
            }
            if pending.contains_key(&nonce) {
                return Err(UdpRequestError::Random(
                    "nonce collision in pending map".to_string(),
                ));
            }
            pending.insert(
                nonce,
                PendingRequest {
                    expected_peer: peer,
                    expected_addr: addr,
                    response: tx,
                },
            );
        }
        if let Err(error) = self.socket.send_to(&bytes, addr).await {
            self.pending.lock().await.remove(&nonce);
            return Err(UdpRequestError::Send(error));
        }
        let outcome = timeout(Duration::from_millis(self.timeout_ms), rx).await;
        match outcome {
            Ok(Ok(resp_env)) => Ok(resp_env.body),
            Ok(Err(_)) => {
                self.pending.lock().await.remove(&nonce);
                Err(UdpRequestError::ResponseChannelClosed)
            }
            Err(_) => {
                self.pending.lock().await.remove(&nonce);
                Err(UdpRequestError::Timeout)
            }
        }
    }

    /// Issue one lookup query + await its response.
    async fn query_impl(
        &self,
        peer: NodeId,
        target: NodeId,
        want_value: bool,
    ) -> LookupQueryResult {
        let body = if want_value {
            Request::FindValue { target }
        } else {
            Request::FindNode { target }
        };
        match self.request(peer, body).await {
            Ok(response) => map_response(response),
            Err(_) => LookupQueryResult::Failed,
        }
    }

    /// Spawn the receiver background task. Reads inbound UDP
    /// datagrams; routes responses to pending queries, dispatches
    /// requests to the provided handler.
    ///
    /// Caller (daemon) drops the returned handle to terminate.
    pub fn spawn_receiver(&self, handler: Arc<dyn RequestHandler>) -> tokio::task::JoinHandle<()> {
        let socket = self.socket.clone();
        let pending = self.pending.clone();
        let request_replay = self.request_replay.clone();
        let request_rates = self.request_rates.clone();
        let inbound_slots = self.inbound_slots.clone();
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
                        if !env.header.is_within_skew(unix_now()) {
                            continue;
                        }
                        let nonce = env.header.nonce;
                        let request = {
                            let mut pending = pending.lock().await;
                            let is_expected = pending.get(&nonce).is_some_and(|request| {
                                request.expected_peer == env.header.sender
                                    && request.expected_addr == src
                            });
                            is_expected.then(|| pending.remove(&nonce)).flatten()
                        };
                        if let Some(request) = request {
                            let _ = request.response.send(env);
                        }
                    }
                    DecodedEnvelope::Request(env) => {
                        let now = unix_now();
                        if !env.header.is_within_skew(now) {
                            continue;
                        }
                        {
                            let mut rates = request_rates.lock().await;
                            if !rates.accept(src.ip(), now) {
                                continue;
                            }
                        }
                        {
                            let mut replay = request_replay.lock().await;
                            if !replay.accept(env.header.sender, env.header.nonce, now) {
                                continue;
                            }
                        }
                        // Keep receiving while application work executes, but
                        // never create more than the fixed number of handler
                        // tasks. `try_acquire_owned` makes overload fail closed
                        // instead of queueing attacker-controlled work.
                        let Ok(permit) = inbound_slots.clone().try_acquire_owned() else {
                            continue;
                        };
                        let nonce = env.header.nonce;
                        let request_handler = handler.clone();
                        let response_socket = socket.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            let Ok(body) = timeout(
                                Duration::from_millis(INBOUND_REQUEST_HANDLER_TIMEOUT_MS),
                                request_handler.handle(env),
                            )
                            .await
                            else {
                                return;
                            };
                            let response_env = RpcEnvelope {
                                header: Header::new(own_id, nonce, unix_now()),
                                body,
                            };
                            if let Ok(resp_bytes) = crate::wire::encode_response(&response_env) {
                                let _ = response_socket.send_to(&resp_bytes, src).await;
                            }
                        });
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
/// `FIND_NODE` → routing-table `closest_to`; `FIND_VALUE` → local store
/// lookup falling back to routing-table `closest_to`.
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
        Response::FindNodeResult { closest } => LookupQueryResult::CloserPeers(closest),
        Response::FindValueResult(outcome) => match outcome {
            crate::rpc::FindValueOutcome::Found(rec) => LookupQueryResult::Found(rec),
            crate::rpc::FindValueOutcome::Closer(closer) => LookupQueryResult::CloserPeers(closer),
        },
    }
}

#[cfg(test)]
mod replay_tests {
    use super::*;

    fn id(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 32])
    }

    #[test]
    fn duplicate_nonce_for_sender_is_rejected() {
        let mut replay = ReplayWindow::default();
        let nonce = [7; 16];
        assert!(replay.accept(id(1), nonce, 1_000));
        assert!(!replay.accept(id(1), nonce, 1_001));
        assert!(replay.accept(id(2), nonce, 1_001));
    }

    #[test]
    fn expired_nonce_leaves_replay_window() {
        let mut replay = ReplayWindow::default();
        let nonce = [9; 16];
        assert!(replay.accept(id(1), nonce, 1_000));
        assert!(replay.accept(id(1), nonce, 1_000 + crate::rpc::MAX_CLOCK_SKEW_SECS + 1));
    }

    #[test]
    fn source_rate_limiter_enforces_budget_and_resets_next_window() {
        let mut rates = SourceRateLimiter::default();
        let source: IpAddr = "192.0.2.10".parse().unwrap();
        for _ in 0..MAX_REQUESTS_PER_SOURCE_WINDOW {
            assert!(rates.accept(source, 1_000));
        }
        assert!(!rates.accept(source, 1_000));
        assert!(rates.accept(source, 1_001));
    }

    #[test]
    fn source_rate_limiter_has_a_hard_source_ceiling() {
        let mut rates = SourceRateLimiter::default();
        for suffix in 0..MAX_RATE_LIMIT_SOURCES {
            let source = IpAddr::from([
                10,
                ((suffix >> 16) & 0xff) as u8,
                ((suffix >> 8) & 0xff) as u8,
                (suffix & 0xff) as u8,
            ]);
            assert!(rates.accept(source, 2_000));
        }
        assert!(!rates.accept(IpAddr::from([192, 0, 2, 99]), 2_000));
        // Expired entries are pruned before admitting a new source.
        assert!(rates.accept(IpAddr::from([192, 0, 2, 99]), 2_002));
    }

    #[test]
    fn source_rate_limiter_enforces_global_budget_against_spoofed_ips() {
        let mut rates = SourceRateLimiter::default();
        for request in 0..MAX_REQUESTS_GLOBAL_WINDOW {
            let source = IpAddr::from([
                198,
                18,
                ((request >> 8) & 0xff) as u8,
                (request & 0xff) as u8,
            ]);
            assert!(rates.accept(source, 3_000));
        }
        assert!(!rates.accept(IpAddr::from([203, 0, 113, 7]), 3_000));
        assert!(rates.accept(IpAddr::from([203, 0, 113, 7]), 3_001));
    }

    #[test]
    fn source_rate_limiter_recovers_from_wall_clock_rewind() {
        let mut rates = SourceRateLimiter::default();
        let source = IpAddr::from([192, 0, 2, 44]);
        for _ in 0..MAX_REQUESTS_PER_SOURCE_WINDOW {
            assert!(rates.accept(source, 5_000));
        }
        assert!(!rates.accept(source, 5_000));
        assert!(rates.accept(source, 4_999));
    }
}
