//! Coherence Mesh Phase F1.3 — sovereign Kademlia DHT peer discovery.
//!
//! Two daemons that have never met directly find each other WITHOUT
//! any central rendezvous server. Each peer announces a signed record
//! ("peer X is reachable at address Y at time T") to a distributed
//! hash table; lookups traverse XOR-distance-closest peers iteratively
//! until the target's record is found.
//!
//! ## Architecture (Kademlia, with sovereign-mesh additions)
//!
//! - **`node_id`**: 256-bit NodeId derived from the peer's Ed25519
//!   master fingerprint. XOR distance metric. Constant-time bit ops.
//! - **`routing`**: K-bucket routing table. For each prefix-length
//!   bucket, keep the K most-recently-seen peers; refresh stale
//!   buckets periodically.
//! - **`record`**: Signed peer-announcement records. Each carries
//!   reachability info (transport endpoints), a freshness timestamp,
//!   and an Ed25519 signature by the publisher.
//! - **`rpc`**: PING / STORE / FIND_NODE / FIND_VALUE envelope types.
//!   Wire-encoded as length-prefixed canonical bytes, signature-
//!   bound, replay-protected via nonce + timestamp.
//! - **`lookup`**: iterative α-parallel lookup. Queries up to α
//!   nodes concurrently; refines toward the target via responses
//!   that contain closer nodes; terminates when no new closer nodes
//!   are learned.
//! - **`kademlia`**: top-level DHT struct + maintenance loop. Owns
//!   the routing table; runs bucket refresh + record-republish on
//!   a tick.
//!
//! ## Sovereign-mesh additions vs vanilla Kademlia
//!
//! - **Signed records**: every announced value is signed by the
//!   publisher's Ed25519 master key. Lookup verifies signatures
//!   before trusting any record.
//! - **TTL + republish**: records expire (default 24h); publishers
//!   re-announce on a tick (default 1h) so an offline peer's record
//!   falls out of the swarm within the TTL window.
//! - **Coherence-field-aware refresh** (optional): when two nodes
//!   are at the same XOR distance, prefer the one with higher τ_c
//!   (Phase E coupling) — lookups route through more-coherent peers.
//!   Falls back to vanilla Kademlia when no field state is available.
//! - **Sybil resistance via Ed25519 cost**: a NodeId is the BLAKE3
//!   of the Ed25519 master pubkey. Generating an attractive ID
//!   close to a specific target requires generating Ed25519 keys
//!   until one hashes to a useful prefix — a real, GPU-resistant
//!   cost (Ed25519 keygen is CPU-bound, no GPU shortcut).
//!
//! ## Layer status
//!
//! - F1.3-A (this crate): `node_id` + `routing` + `record` + RPC
//!   types + iterative lookup, all pure Rust. **No network.**
//! - F1.3 daemon wiring (separate ship): UDP transport binding,
//!   pyo3 wrapper, Python adapter. The crate's `Transport` trait
//!   lets the daemon swap any wire (UDP / WebRTC / over-mesh-relay).

#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]

pub mod lookup;
pub mod node_id;
pub mod record;
pub mod routing;
pub mod rpc;

pub use lookup::{
    Lookup, LookupError, LookupQueryResult, LookupResult, Transport,
    ALPHA_DEFAULT, LOOKUP_K_DEFAULT, MAX_LOOKUP_ITERS,
};
pub use node_id::{NodeId, NODE_ID_BYTES, NODE_ID_BITS};
pub use record::{
    PeerRecord, RecordError, SignedRecord, RECORD_DEFAULT_TTL_SECS,
};
pub use routing::{
    RoutingTable, K_BUCKET_DEFAULT, MAX_BUCKETS,
};
pub use rpc::{
    Header, Nonce, Request, Response, RpcEnvelope, RpcError,
    FindValueOutcome, StoreOutcome,
    MAX_CLOCK_SKEW_SECS, MAX_FIND_RESULTS,
};
