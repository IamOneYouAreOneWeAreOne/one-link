//! RPC envelope types for Kademlia messages.
//!
//! Four RPC pairs:
//!
//!   - **PING / PONG**: liveness probe. Used by routing-table head
//!     replacement (PING on bucket-full) + maintenance refresh.
//!   - **STORE / STORE_ACK**: publish a signed record to the
//!     receiver's local store. Receiver verifies signature before
//!     storing; rejects bad signatures with a typed error code.
//!   - **FIND_NODE / FIND_NODE_RESULT**: ask the receiver for the K
//!     closest peers it knows to `target`. Receiver responds with
//!     its routing-table closest_to(target).
//!   - **FIND_VALUE / FIND_VALUE_RESULT**: ask for the value at
//!     `target` (typically a NodeId being looked up). Receiver
//!     returns the signed record if it has it, OR the K closest
//!     peers otherwise (then the caller iteratively queries them).
//!
//! Every envelope carries a `nonce` (replay-protection within one
//! exchange) and a `timestamp` (replay-protection across exchanges).
//! Stale or duplicate envelopes are rejected by the receiver.
//!
//! Wire format is intentionally not specified at the byte level by
//! this module — the daemon-side transport binding handles encoding
//! (it can use canonical-bytes-of-struct, CBOR, or any encoding
//! consistent across peers). The struct shapes are what's shared.

use thiserror::Error;

use crate::node_id::NodeId;
use crate::record::SignedRecord;

/// Maximum allowed clock skew between sender and receiver. Envelopes
/// dated more than this far in the future or past are rejected.
pub const MAX_CLOCK_SKEW_SECS: u64 = 60 * 5; // 5 minutes

/// Maximum K results in a single FIND_NODE / FIND_VALUE response.
/// Bounded to keep response sizes amplification-resistant.
pub const MAX_FIND_RESULTS: usize = 32;

/// A 128-bit random nonce per envelope. Used together with the
/// envelope's sender NodeId to deduplicate replays within a window.
pub type Nonce = [u8; 16];

/// Common header shared by every RPC envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Header {
    /// NodeId of the sender. The receiver uses this to refresh the
    /// sender's routing-table entry on every received envelope.
    pub sender: NodeId,
    /// 16-byte random nonce. Receiver rejects duplicates in a
    /// recent-window LRU.
    pub nonce: Nonce,
    /// Unix-seconds wall clock from the sender. Rejected if outside
    /// [now - MAX_CLOCK_SKEW, now + MAX_CLOCK_SKEW].
    pub timestamp_unix: u64,
}

impl Header {
    /// Construct a new header.
    #[must_use]
    pub const fn new(sender: NodeId, nonce: Nonce, timestamp_unix: u64) -> Self {
        Self {
            sender,
            nonce,
            timestamp_unix,
        }
    }

    /// Is this header acceptable to a receiver whose clock is `now_unix`?
    /// Checks the timestamp is within [now - MAX_CLOCK_SKEW, now + MAX_CLOCK_SKEW].
    #[must_use]
    pub fn is_within_skew(&self, now_unix: u64) -> bool {
        let lo = now_unix.saturating_sub(MAX_CLOCK_SKEW_SECS);
        let hi = now_unix.saturating_add(MAX_CLOCK_SKEW_SECS);
        self.timestamp_unix >= lo && self.timestamp_unix <= hi
    }
}

/// RPC request kinds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Request {
    /// Liveness probe. No payload beyond the header.
    Ping,
    /// "Store this signed record." Receiver verifies signature
    /// and rejects if invalid.
    Store(SignedRecord),
    /// "Give me the K closest peers you know to `target`."
    FindNode {
        /// NodeId being searched for.
        target: NodeId,
    },
    /// "Give me the value for `target`, or the K closest peers if
    /// you don't have it."
    FindValue {
        /// NodeId being looked up.
        target: NodeId,
    },
}

/// RPC response kinds, paired with their request types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Response {
    /// PING response — alive.
    Pong,
    /// STORE response — accepted or rejected with a typed code.
    StoreResult(StoreOutcome),
    /// FIND_NODE response — closest K peers known to the receiver.
    FindNodeResult {
        /// Up to K peer NodeIds, sorted ascending by XOR distance
        /// to the original `target`.
        closest: Vec<NodeId>,
    },
    /// FIND_VALUE response — either the signed record, or K closest
    /// if the receiver doesn't hold the record.
    FindValueResult(FindValueOutcome),
}

/// STORE outcome: receiver accepted or rejected the record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreOutcome {
    /// Accepted; record is now in the receiver's local store.
    Accepted,
    /// Rejected — record signature failed verification.
    BadSignature,
    /// Rejected — record was already expired at receipt.
    Expired,
    /// Rejected — record's claimed publisher doesn't match the
    /// record's NodeId derivation.
    PublisherMismatch,
    /// Rejected — receiver is rate-limiting this sender.
    RateLimited,
}

/// FIND_VALUE outcome: either we have the record, or we have closer
/// peers to recommend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FindValueOutcome {
    /// Receiver has the record. Returned verbatim; caller still
    /// verifies the signature before trusting.
    Found(SignedRecord),
    /// Receiver doesn't have it but knows these closer peers.
    /// Up to K NodeIds, sorted ascending by XOR distance to target.
    Closer(Vec<NodeId>),
}

/// A complete RPC envelope. `body` is request OR response; senders
/// and receivers distinguish by structural type, not a kind byte.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpcEnvelope<B> {
    /// Common header.
    pub header: Header,
    /// Payload (Request or Response).
    pub body: B,
}

/// Errors during RPC processing.
#[derive(Debug, Error, PartialEq)]
pub enum RpcError {
    /// Sender's clock is outside the acceptable skew window.
    #[error("envelope timestamp outside acceptable skew window")]
    ClockSkew,
    /// Sender is replaying an envelope (nonce + sender already seen).
    #[error("duplicate envelope nonce from this sender")]
    DuplicateNonce,
    /// Response carries more than [`MAX_FIND_RESULTS`] entries.
    #[error("too many results in response: {got} (max {max})")]
    TooManyResults {
        /// Actual count.
        got: usize,
        /// Maximum allowed.
        max: usize,
    },
}

/// Validate a response's result-count bound. Catches malformed peers
/// that try to amplify by returning >K results.
///
/// # Errors
/// Returns [`RpcError::TooManyResults`] if a list-bearing response
/// exceeds [`MAX_FIND_RESULTS`].
pub fn validate_response_size(resp: &Response) -> Result<(), RpcError> {
    match resp {
        Response::FindNodeResult { closest } => {
            if closest.len() > MAX_FIND_RESULTS {
                return Err(RpcError::TooManyResults {
                    got: closest.len(),
                    max: MAX_FIND_RESULTS,
                });
            }
        }
        Response::FindValueResult(FindValueOutcome::Closer(closer)) => {
            if closer.len() > MAX_FIND_RESULTS {
                return Err(RpcError::TooManyResults {
                    got: closer.len(),
                    max: MAX_FIND_RESULTS,
                });
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> NodeId {
        NodeId([b; 32])
    }

    fn nonce() -> Nonce {
        [0x42u8; 16]
    }

    #[test]
    fn skew_window_in_bounds() {
        let h = Header::new(id(1), nonce(), 1_000_000);
        assert!(h.is_within_skew(1_000_000));
        assert!(h.is_within_skew(1_000_000 + MAX_CLOCK_SKEW_SECS));
        assert!(h.is_within_skew(1_000_000 - MAX_CLOCK_SKEW_SECS));
    }

    #[test]
    fn skew_window_out_of_bounds() {
        let h = Header::new(id(1), nonce(), 1_000_000);
        assert!(!h.is_within_skew(1_000_000 + MAX_CLOCK_SKEW_SECS + 1));
        assert!(!h.is_within_skew(1_000_000 - MAX_CLOCK_SKEW_SECS - 1));
    }

    #[test]
    fn validate_response_size_accepts_within_bound() {
        let resp = Response::FindNodeResult {
            closest: vec![id(1); MAX_FIND_RESULTS],
        };
        assert!(validate_response_size(&resp).is_ok());
    }

    #[test]
    fn validate_response_size_rejects_overage() {
        let resp = Response::FindNodeResult {
            closest: vec![id(1); MAX_FIND_RESULTS + 1],
        };
        let err = validate_response_size(&resp).unwrap_err();
        assert!(matches!(err, RpcError::TooManyResults { .. }));
    }

    #[test]
    fn validate_findvalue_closer_size() {
        let resp = Response::FindValueResult(FindValueOutcome::Closer(vec![
            id(1);
            MAX_FIND_RESULTS + 1
        ]));
        let err = validate_response_size(&resp).unwrap_err();
        assert!(matches!(err, RpcError::TooManyResults { .. }));
    }

    #[test]
    fn validate_pong_passes() {
        let resp = Response::Pong;
        assert!(validate_response_size(&resp).is_ok());
    }

    #[test]
    fn validate_store_result_passes() {
        let resp = Response::StoreResult(StoreOutcome::Accepted);
        assert!(validate_response_size(&resp).is_ok());
    }

    #[test]
    fn rpc_envelope_clone_eq() {
        let env = RpcEnvelope {
            header: Header::new(id(1), nonce(), 100),
            body: Request::Ping,
        };
        let env2 = env.clone();
        assert_eq!(env, env2);
    }
}
