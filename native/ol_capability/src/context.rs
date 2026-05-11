//! Runtime context for capability verification.

/// The runtime environment a capability is checked against. Callers
/// fill in only the fields relevant to their use case; caveats that
/// require a missing field reject.
#[derive(Debug, Clone, Default)]
pub struct Context<'a> {
    /// Current Unix-millisecond timestamp. Required to check
    /// `Caveat::ExpiresAt`.
    pub now_unix_ms: Option<u64>,
    /// Authenticated peer's fingerprint. Required to check
    /// `Caveat::PeerFingerprint`.
    pub peer: Option<[u8; 32]>,
    /// Resource path being accessed. Required for `Caveat::PathPrefix`.
    pub path: Option<&'a str>,
    /// Operation name (e.g., "read", "write"). Required for
    /// `Caveat::OperationIn`.
    pub operation: Option<&'a str>,
}

impl<'a> Context<'a> {
    /// Empty context. Caveats that need any field will reject.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: set `now_unix_ms`.
    #[must_use]
    pub fn with_now(mut self, ms: u64) -> Self {
        self.now_unix_ms = Some(ms);
        self
    }

    /// Builder: set `peer`.
    #[must_use]
    pub fn with_peer(mut self, peer: [u8; 32]) -> Self {
        self.peer = Some(peer);
        self
    }

    /// Builder: set `path`.
    #[must_use]
    pub fn with_path(mut self, path: &'a str) -> Self {
        self.path = Some(path);
        self
    }

    /// Builder: set `operation`.
    #[must_use]
    pub fn with_operation(mut self, op: &'a str) -> Self {
        self.operation = Some(op);
        self
    }
}
