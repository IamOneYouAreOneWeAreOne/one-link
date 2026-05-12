//! pyo3 wrapper for [`ol_discovery`] — Coherence Mesh Phase F1.3.
//!
//! Exposes the SYNC pieces of the sovereign-discovery layer to the
//! Python daemon: NodeId, SignedRecord, RoutingTable. The async
//! iterative-lookup driver stays in pure Rust for now; the daemon
//! orchestrates lookup at the Python level using these sync primitives
//! + its own async I/O (asyncio + UDP socket). When we want to push
//! lookup into Rust we'll add a pyo3-asyncio binding; not blocking
//! for first production wiring.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use ol_discovery::node_id::{NodeId as InnerNodeId, NODE_ID_BITS, NODE_ID_BYTES};
use ol_discovery::record::{
    PeerRecord as InnerPeerRecord, RecordError,
    SignedRecord as InnerSignedRecord, RECORD_DEFAULT_TTL_SECS,
};
use ol_discovery::routing::{
    BucketEntry as InnerBucketEntry, InsertOutcome as InnerInsertOutcome,
    RoutingTable as InnerRoutingTable, K_BUCKET_DEFAULT, MAX_BUCKETS,
};

// ── NodeId ────────────────────────────────────────────────────────

/// A 256-bit Kademlia NodeId (= BLAKE3 of an Ed25519 master pubkey).
#[pyclass(module = "one_link_native.discovery", frozen, eq, ord, hash)]
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct PyNodeId {
    inner: InnerNodeId,
}

#[pymethods]
impl PyNodeId {
    /// Construct from 32 raw bytes.
    #[new]
    fn new(raw: &[u8]) -> PyResult<Self> {
        if raw.len() != NODE_ID_BYTES {
            return Err(PyValueError::new_err(format!(
                "NodeId must be exactly {NODE_ID_BYTES} bytes, got {}",
                raw.len()
            )));
        }
        let mut b = [0u8; NODE_ID_BYTES];
        b.copy_from_slice(raw);
        Ok(Self {
            inner: InnerNodeId::from_bytes(b),
        })
    }

    /// Derive a NodeId from an Ed25519 master pubkey (32 bytes).
    #[staticmethod]
    fn from_pubkey(pubkey: &[u8]) -> PyResult<Self> {
        if pubkey.len() != 32 {
            return Err(PyValueError::new_err(format!(
                "pubkey must be 32 bytes, got {}",
                pubkey.len()
            )));
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(pubkey);
        Ok(Self {
            inner: InnerNodeId::from_pubkey(&pk),
        })
    }

    /// The underlying 32 bytes.
    fn as_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, self.inner.as_bytes())
    }

    /// XOR distance to another NodeId, as 32 raw bytes.
    fn distance<'py>(
        &self,
        py: Python<'py>,
        other: &Self,
    ) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.distance(&other.inner))
    }

    /// Number of leading zeros in XOR distance (= K-bucket index, or
    /// NODE_ID_BITS=256 when self == other).
    fn xor_leading_zeros(&self, other: &Self) -> u32 {
        self.inner.xor_leading_zeros(&other.inner)
    }

    /// K-bucket index for `other` from this NodeId's perspective.
    /// Returns None for self.
    fn bucket_index(&self, other: &Self) -> Option<usize> {
        self.inner.bucket_index(&other.inner)
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.inner)
    }
}

// ── PeerRecord + SignedRecord ────────────────────────────────────

/// Unsigned peer-announcement payload.
#[pyclass(module = "one_link_native.discovery", frozen)]
#[derive(Clone)]
struct PyPeerRecord {
    inner: InnerPeerRecord,
}

#[pymethods]
impl PyPeerRecord {
    #[new]
    #[pyo3(signature = (publisher_pubkey, endpoints, publish_time_unix, ttl_secs = RECORD_DEFAULT_TTL_SECS))]
    fn new(
        publisher_pubkey: &[u8],
        endpoints: Vec<String>,
        publish_time_unix: u64,
        ttl_secs: u64,
    ) -> PyResult<Self> {
        if publisher_pubkey.len() != 32 {
            return Err(PyValueError::new_err(format!(
                "publisher_pubkey must be 32 bytes, got {}",
                publisher_pubkey.len()
            )));
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(publisher_pubkey);
        Ok(Self {
            inner: InnerPeerRecord {
                publisher_pubkey: pk,
                endpoints,
                publish_time_unix,
                ttl_secs,
            },
        })
    }

    fn publisher_pubkey<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.publisher_pubkey)
    }

    fn endpoints(&self) -> Vec<String> {
        self.inner.endpoints.clone()
    }

    fn publish_time_unix(&self) -> u64 {
        self.inner.publish_time_unix
    }

    fn ttl_secs(&self) -> u64 {
        self.inner.ttl_secs
    }

    fn canonical_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.canonical_bytes())
    }

    fn is_fresh(&self, now_unix: u64) -> bool {
        self.inner.is_fresh(now_unix)
    }

    fn node_id(&self) -> PyNodeId {
        PyNodeId {
            inner: self.inner.node_id(),
        }
    }
}

/// A signed peer record (PeerRecord + Ed25519 signature).
#[pyclass(module = "one_link_native.discovery", frozen)]
#[derive(Clone)]
struct PySignedRecord {
    inner: InnerSignedRecord,
}

#[pymethods]
impl PySignedRecord {
    /// Sign a record with a 32-byte Ed25519 signing-key seed. The
    /// signing key's public component must match record.publisher_pubkey
    /// (defensive; prevents accidentally signing for the wrong identity).
    #[staticmethod]
    fn sign(
        record: &PyPeerRecord,
        signing_key_seed: &[u8],
    ) -> PyResult<Self> {
        if signing_key_seed.len() != 32 {
            return Err(PyValueError::new_err(format!(
                "signing_key_seed must be 32 bytes, got {}",
                signing_key_seed.len()
            )));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(signing_key_seed);
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let signed = InnerSignedRecord::sign(record.inner.clone(), &sk)
            .map_err(map_record_err)?;
        Ok(Self { inner: signed })
    }

    /// Construct from explicit components (e.g., received off the wire).
    #[new]
    fn from_parts(
        record: &PyPeerRecord,
        signature: &[u8],
    ) -> PyResult<Self> {
        if signature.len() != 64 {
            return Err(PyValueError::new_err(format!(
                "signature must be 64 bytes, got {}",
                signature.len()
            )));
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(signature);
        Ok(Self {
            inner: InnerSignedRecord {
                record: record.inner.clone(),
                signature: sig,
            },
        })
    }

    fn record(&self) -> PyPeerRecord {
        PyPeerRecord {
            inner: self.inner.record.clone(),
        }
    }

    fn signature<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.signature)
    }

    /// Verify the Ed25519 signature against the record's canonical
    /// bytes. Returns None on success; raises ValueError on failure.
    fn verify(&self) -> PyResult<()> {
        self.inner.verify().map_err(map_record_err)
    }

    /// Verify + check freshness in one call. Returns True if signed
    /// AND fresh; False if signed but expired; raises ValueError
    /// on signature failure.
    fn verify_and_check_freshness(&self, now_unix: u64) -> PyResult<bool> {
        self.inner
            .verify_and_check_freshness(now_unix)
            .map_err(map_record_err)
    }

    fn node_id(&self) -> PyNodeId {
        PyNodeId {
            inner: self.inner.node_id(),
        }
    }
}

// ── RoutingTable ──────────────────────────────────────────────────

/// Kademlia K-bucket routing table.
#[pyclass(module = "one_link_native.discovery")]
struct PyRoutingTable {
    inner: InnerRoutingTable,
}

/// Insert-outcome enum value as a 0-arg tuple-style Python type.
#[pyclass(module = "one_link_native.discovery", frozen, eq)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum PyInsertOutcome {
    Inserted,
    BumpedToTail,
    SelfInsertIgnored,
    BucketFull,
}

#[pymethods]
impl PyRoutingTable {
    #[new]
    #[pyo3(signature = (own_id, k = K_BUCKET_DEFAULT))]
    fn new(own_id: &PyNodeId, k: usize) -> Self {
        Self {
            inner: InnerRoutingTable::with_k(own_id.inner, k),
        }
    }

    fn own_id(&self) -> PyNodeId {
        PyNodeId {
            inner: *self.inner.own_id(),
        }
    }

    fn k(&self) -> usize {
        self.inner.k()
    }

    fn len(&self) -> usize {
        self.inner.len()
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Insert (or update) a peer. Returns a tuple (outcome,
    /// bucket_full_head). When outcome != BucketFull, the second
    /// element is None; otherwise it's the head NodeId the caller
    /// should PING to test for replacement eligibility.
    fn insert(
        &mut self,
        id: &PyNodeId,
        last_seen_unix: u64,
    ) -> (PyInsertOutcome, Option<PyNodeId>) {
        match self.inner.insert(id.inner, last_seen_unix) {
            InnerInsertOutcome::Inserted => {
                (PyInsertOutcome::Inserted, None)
            }
            InnerInsertOutcome::BumpedToTail => {
                (PyInsertOutcome::BumpedToTail, None)
            }
            InnerInsertOutcome::SelfInsertIgnored => {
                (PyInsertOutcome::SelfInsertIgnored, None)
            }
            InnerInsertOutcome::BucketFull { head } => (
                PyInsertOutcome::BucketFull,
                Some(PyNodeId { inner: head.id }),
            ),
        }
    }

    fn replace_head_on_timeout(
        &mut self,
        timed_out_head: &PyNodeId,
        new_peer: &PyNodeId,
        last_seen_unix: u64,
    ) -> bool {
        self.inner.replace_head_on_timeout(
            timed_out_head.inner,
            new_peer.inner,
            last_seen_unix,
        )
    }

    fn closest_to(&self, target: &PyNodeId) -> Vec<PyNodeId> {
        self.inner
            .closest_to(&target.inner)
            .into_iter()
            .map(|e: InnerBucketEntry| PyNodeId { inner: e.id })
            .collect()
    }

    fn closest_n_to(
        &self,
        target: &PyNodeId,
        n: usize,
    ) -> Vec<PyNodeId> {
        self.inner
            .closest_n_to(&target.inner, n)
            .into_iter()
            .map(|e: InnerBucketEntry| PyNodeId { inner: e.id })
            .collect()
    }

    fn stale_buckets(
        &self,
        now_unix: u64,
        max_age_secs: u64,
    ) -> Vec<usize> {
        self.inner.stale_buckets(now_unix, max_age_secs)
    }

    fn remove(&mut self, id: &PyNodeId) -> bool {
        self.inner.remove(&id.inner)
    }

    fn contains(&self, id: &PyNodeId) -> bool {
        self.inner.contains(&id.inner)
    }

    fn bucket_sizes(&self) -> Vec<usize> {
        self.inner.bucket_sizes()
    }
}

// ── Error mapping ────────────────────────────────────────────────

fn map_record_err(e: RecordError) -> PyErr {
    PyValueError::new_err(e.to_string())
}

// ── Module registration ──────────────────────────────────────────

pub fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyNodeId>()?;
    m.add_class::<PyPeerRecord>()?;
    m.add_class::<PySignedRecord>()?;
    m.add_class::<PyRoutingTable>()?;
    m.add_class::<PyInsertOutcome>()?;
    // Surface Python-friendly aliases.
    let cls = m.getattr("PyNodeId")?;
    m.add("NodeId", cls)?;
    let cls = m.getattr("PyPeerRecord")?;
    m.add("PeerRecord", cls)?;
    let cls = m.getattr("PySignedRecord")?;
    m.add("SignedRecord", cls)?;
    let cls = m.getattr("PyRoutingTable")?;
    m.add("RoutingTable", cls)?;
    let cls = m.getattr("PyInsertOutcome")?;
    m.add("InsertOutcome", cls)?;
    // Constants.
    m.add("NODE_ID_BYTES", NODE_ID_BYTES)?;
    m.add("NODE_ID_BITS", NODE_ID_BITS)?;
    m.add("K_BUCKET_DEFAULT", K_BUCKET_DEFAULT)?;
    m.add("MAX_BUCKETS", MAX_BUCKETS)?;
    m.add("RECORD_DEFAULT_TTL_SECS", RECORD_DEFAULT_TTL_SECS)?;
    Ok(())
}
