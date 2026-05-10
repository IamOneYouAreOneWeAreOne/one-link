//! Per-peer state held inside the engine's registry.

use std::net::SocketAddr;
use std::sync::Arc;

use ol_quic::Connection;
use tokio::sync::{Mutex, Semaphore};

use crate::config::TransferConfig;

/// One peer's state inside the engine. The fingerprint key lives in the
/// registry's `HashMap`; this struct is the value.
pub struct PeerEntry {
    /// UDP socket address last reported for this peer. Mutable via
    /// [`crate::TransferEngine::register_peer`].
    pub(crate) addr: Mutex<SocketAddr>,

    /// Cached live connection. Reused across multiple fetches for the
    /// same peer; transparently reconnected on drop.
    ///
    /// `tokio::sync::Mutex` because we may hold it across an `.await`
    /// during the initial `endpoint.connect(...)` call.
    pub(crate) connection: Mutex<Option<Arc<Connection>>>,

    /// Bounds per-peer concurrent in-flight requests per ADR-0013.
    pub(crate) inflight: Arc<Semaphore>,
}

impl std::fmt::Debug for PeerEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerEntry")
            .field("inflight_available", &self.inflight.available_permits())
            .finish_non_exhaustive()
    }
}

impl PeerEntry {
    pub(crate) fn new(addr: SocketAddr, config: &TransferConfig) -> Self {
        Self {
            addr: Mutex::new(addr),
            connection: Mutex::new(None),
            inflight: Arc::new(Semaphore::new(config.max_inflight_per_peer)),
        }
    }
}
