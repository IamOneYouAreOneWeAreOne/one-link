//! `one_link_native` — pyo3 binding crate for One Link's hot-path Rust crates.
//!
//! Per [ADR-0008](../../../docs/decisions/0008-ffi-contract.md), this is the
//! single Python-facing surface. Pure-Rust crates in the workspace
//! (`ol_chunk`, eventually `ol_aead`, `ol_chunk_store`, `ol_wal`, ...) are
//! re-exported here as Python submodules:
//!
//! ```python
//! import one_link_native
//! from one_link_native import chunk
//!
//! for boundary in chunk.cdc_iter(buf):
//!     start, end, blake3 = boundary
//!     ...
//! ```
//!
//! The Python daemon imports through this crate; downstream Rust tooling
//! depends on the pure-Rust crates directly.

#![doc(html_root_url = "https://docs.rs/one_link_native/0.21.0")]
// pyo3 macro expansion uses unsafe internals (`ref_from_ptr`,
// `unwrap_required_argument`) that the workspace-level
// `unsafe_op_in_unsafe_fn = "deny"` would flag. The pyo3 maintainers have
// audited those usages; they are sound by construction inside the macro.
// Our hand-written code in this crate keeps the workspace deny semantics
// via local `unsafe { ... }` blocks where actually needed.
#![allow(unsafe_op_in_unsafe_fn)]
// pyo3 wraps every #[pymethods] item in a private module, so explicit
// `pub fn` declarations on those methods become "unreachable pub". This
// is structural — there's no actual visibility leakage. Suppress for
// the whole crate; the macro-generated code is the source.
#![allow(unreachable_pub)]
// pyo3-wrapped types (PyChunkStore, PyAeadCipher, ...) hold non-Debug
// inner state (file handles, ring keys). Adding manual Debug impls
// would leak implementation details into operator logs; instead we
// suppress the missing_debug_implementations workspace lint locally.
#![allow(missing_debug_implementations)]

use pyo3::prelude::*;

mod aead;
mod align;
mod bandit;
mod bloom;
mod capability;
mod chunk;
mod coherence_field;
mod compress;
mod confidential;
mod crdt;
mod discovery;
mod erasure;
mod errors;
mod fec;
mod fountain;
mod fuse;
mod homology;
mod hwkey;
mod obfs;
mod onion;
mod pair_qr;
mod pqkem;
mod pqsig;
mod prefetch;
mod proximity_pair;
mod quic;
mod radio_batcher;
mod ratchet;
mod routing;
mod selector;
mod sphinx;
mod store;
mod threshold_recovery;
mod wal;

/// Top-level Python module entrypoint.
///
/// pyo3 invokes this on `import one_link_native`. We attach each
/// submodule (one per workspace crate) so callers do
/// `from one_link_native import chunk`.
#[pymodule]
fn one_link_native(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Crate version (from one_link_native's Cargo.toml).
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    // Hot-path crate version (ol_chunk, ol_aead, ...). For Phase A1 with
    // only ol_chunk, surface its version as `chunk_version` for telemetry.
    m.add("chunk_version", ol_chunk::VERSION)?;

    // Register all error classes on the top-level module so callers can
    // `except one_link_native.OlError` for catch-all handling.
    errors::register(py, m)?;

    register_storage_modules(py, m)?;
    register_crypto_modules(py, m)?;
    register_field_modules(py, m)?;
    register_identity_modules(py, m)?;
    register_privacy_modules(py, m)?;
    register_policy_modules(py, m)?;
    Ok(())
}

fn register_storage_modules(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Submodules.
    let chunk_mod = PyModule::new(py, "chunk")?;
    chunk::register(py, &chunk_mod)?;
    m.add_submodule(&chunk_mod)?;
    // Make `from one_link_native import chunk` and `import one_link_native.chunk`
    // both work. Without this line, only the dotted form works.
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.chunk", chunk_mod)?;

    let aead_mod = PyModule::new(py, "aead")?;
    aead::register(py, &aead_mod)?;
    m.add_submodule(&aead_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.aead", aead_mod)?;

    let wal_mod = PyModule::new(py, "wal")?;
    wal::register(py, &wal_mod)?;
    m.add_submodule(&wal_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.wal", wal_mod)?;

    let store_mod = PyModule::new(py, "store")?;
    store::register(py, &store_mod)?;
    m.add_submodule(&store_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.store", store_mod)?;

    // Read-only kernel filesystem surface.  The Python ABI is registered on
    // every platform so capability probes are stable, while mount operations
    // become ready only in Linux wheels compiled with `linux-mount`.
    let fuse_mod = PyModule::new(py, "fuse")?;
    fuse::register(py, &fuse_mod)?;
    m.add_submodule(&fuse_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.fuse", fuse_mod)?;

    let quic_mod = PyModule::new(py, "quic")?;
    quic::register(py, &quic_mod)?;
    m.add_submodule(&quic_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.quic", quic_mod)?;

    let bloom_mod = PyModule::new(py, "bloom")?;
    bloom::register(py, &bloom_mod)?;
    m.add_submodule(&bloom_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.bloom", bloom_mod)?;

    let fountain_mod = PyModule::new(py, "fountain")?;
    fountain::register(py, &fountain_mod)?;
    m.add_submodule(&fountain_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.fountain", fountain_mod)?;

    let fec_mod = PyModule::new(py, "fec")?;
    fec::register(py, &fec_mod)?;
    m.add_submodule(&fec_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.fec", fec_mod)?;

    let ratchet_mod = PyModule::new(py, "ratchet")?;
    ratchet::register(py, &ratchet_mod)?;
    m.add_submodule(&ratchet_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.ratchet", ratchet_mod)?;

    Ok(())
}

fn register_crypto_modules(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let pqkem_mod = PyModule::new(py, "pqkem")?;
    pqkem::register(py, &pqkem_mod)?;
    m.add_submodule(&pqkem_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.pqkem", pqkem_mod)?;

    let erasure_mod = PyModule::new(py, "erasure")?;
    erasure::register(py, &erasure_mod)?;
    m.add_submodule(&erasure_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.erasure", erasure_mod)?;

    let bandit_mod = PyModule::new(py, "bandit")?;
    bandit::register(py, &bandit_mod)?;
    m.add_submodule(&bandit_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.bandit", bandit_mod)?;

    let capability_mod = PyModule::new(py, "capability")?;
    capability::register(py, &capability_mod)?;
    m.add_submodule(&capability_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.capability", capability_mod)?;

    let crdt_mod = PyModule::new(py, "crdt")?;
    crdt::register(py, &crdt_mod)?;
    m.add_submodule(&crdt_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.crdt", crdt_mod)?;

    let hwkey_mod = PyModule::new(py, "hwkey")?;
    hwkey::register(py, &hwkey_mod)?;
    m.add_submodule(&hwkey_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.hwkey", hwkey_mod)?;

    Ok(())
}

fn register_field_modules(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Phase D pyo3 bindings.
    let routing_mod = PyModule::new(py, "routing")?;
    routing::register(py, &routing_mod)?;
    m.add_submodule(&routing_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.routing", routing_mod)?;

    let prefetch_mod = PyModule::new(py, "prefetch")?;
    prefetch::register(py, &prefetch_mod)?;
    m.add_submodule(&prefetch_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.prefetch", prefetch_mod)?;

    let homology_mod = PyModule::new(py, "homology")?;
    homology::register(py, &homology_mod)?;
    m.add_submodule(&homology_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.homology", homology_mod)?;

    // Phase E pyo3 bindings — coherence-field substrate (S_One canonical
    // theorem stack). One Rust crate, three calibrations (One Link /
    // OneField / BioMesh) — the unified-field claim made operational.
    let coherence_field_mod = PyModule::new(py, "coherence_field")?;
    coherence_field::register(py, &coherence_field_mod)?;
    m.add_submodule(&coherence_field_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.coherence_field", coherence_field_mod)?;

    Ok(())
}

fn register_identity_modules(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Phase F1.3 — sovereign Kademlia DHT discovery.
    // Two daemons that have never met find each other WITHOUT any
    // rendezvous server. NodeId + RoutingTable + SignedRecord pieces
    // exposed; iterative-lookup driver remains pure Rust for now
    // (daemon orchestrates lookup at the Python level).
    let discovery_mod = PyModule::new(py, "discovery")?;
    discovery::register(py, &discovery_mod)?;
    m.add_submodule(&discovery_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.discovery", discovery_mod)?;

    // Phase F1.4 research surface only. These quantize/parity/hash
    // primitives do not acquire observations, implement real CASCADE,
    // establish entropy, prove proximity, or provide daemon integration.
    let proximity_mod = PyModule::new(py, "proximity_pair")?;
    proximity_pair::register(py, &proximity_mod)?;
    m.add_submodule(&proximity_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.proximity_pair", proximity_mod)?;

    // Phase F1.1 — threshold recovery (Shamir + coherence-field-bound).
    // First crate of the Coherence Mesh track. Identity master-key
    // seeds split across trusted contacts; recovery requires K of N
    // shares AND (optionally) the coherence-field witness at mint time.
    let threshold_mod = PyModule::new(py, "threshold_recovery")?;
    threshold_recovery::register(py, &threshold_mod)?;
    m.add_submodule(&threshold_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.threshold_recovery", threshold_mod)?;

    // Phase F2 — pair-by-QR Factor-1 trust establishment.
    // In-person QR scan + Ed25519-signed invite + transcript hash +
    // human-readable SAS comparison + optional externally supplied
    // Factor-2 candidate with explicit bidirectional key confirmation.
    // Two devices that have never met derive a shared chain key with
    // no third-party trust in the primitive. Daemon wiring is separate and
    // is not present merely because this binding is registered.
    let pair_qr_mod = PyModule::new(py, "pair_qr")?;
    pair_qr::register(py, &pair_qr_mod)?;
    m.add_submodule(&pair_qr_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.pair_qr", pair_qr_mod)?;

    Ok(())
}

fn register_privacy_modules(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Phase F3 — onion-circuit relay (row 5).
    // Nested ChaCha20-Poly1305 encryption with per-layer ephemeral
    // X25519 keys. Each hop only knows its predecessor + successor.
    // build_onion + peel_one_layer are packet primitives. A relay can
    // decrypt only its layer, but it still observes adjacent hops and
    // timing/size/count metadata. Registering this binding does not wire
    // a daemon product route or establish anonymity.
    let onion_mod = PyModule::new(py, "onion")?;
    onion::register(py, &onion_mod)?;
    m.add_submodule(&onion_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.onion", onion_mod)?;

    // Phase F3.5 — Sphinx Coherence (row 5 advanced).
    // Standard Sphinx (Ristretto255 alpha blinding + filler-byte
    // construction) + PQ-hybrid (ML-KEM-768 at entry hop) + field-
    // context binding. The packet-level ephemeral group element changes
    // at each hop and the entry KDF includes ML-KEM-768. Those byte-level
    // properties do not defeat a global observer, prove a post-quantum
    // protocol, or wire Sphinx into daemon traffic.
    let sphinx_mod = PyModule::new(py, "sphinx")?;
    sphinx::register(py, &sphinx_mod)?;
    m.add_submodule(&sphinx_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.sphinx", sphinx_mod)?;

    // Row 1 Ed25519 + ML-DSA-65 signature primitive. Both verifier
    // halves are required; registering the binding does not migrate the
    // daemon's Ed25519 identity or browser/message signatures.
    let pqsig_mod = PyModule::new(py, "pqsig")?;
    pqsig::register(py, &pqsig_mod)?;
    m.add_submodule(&pqsig_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.pqsig", pqsig_mod)?;

    // Row 10 sealed-operation and signed provider-claim primitives.
    // Registering this binding neither places the daemon in an enclave
    // nor proves that live master-sign/attest paths use it.
    let confidential_mod = PyModule::new(py, "confidential")?;
    confidential::register(py, &confidential_mod)?;
    m.add_submodule(&confidential_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.confidential", confidential_mod)?;

    Ok(())
}

fn register_policy_modules(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Row 7 — pluggable transport obfuscation primitive.
    // ChaCha20 stream-cipher wrapper removes obvious plaintext structure
    // under correct nonce/key use. It does not make the complete transport
    // indistinguishable from an allowed protocol or defeat DPI based on
    // handshake, framing, timing, size, endpoint, or active probes.
    let obfs_mod = PyModule::new(py, "obfs")?;
    obfs::register(py, &obfs_mod)?;
    m.add_submodule(&obfs_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.obfs", obfs_mod)?;

    // D02 — Gaussian alignment trust function A(x, t) = exp(-(x^2 +
    // t^2) / L_session). Replaces ad-hoc trust thresholds across
    // _capability_allowed and pair-trust gates with one continuous
    // function from the Equation of ONE.
    let align_mod = PyModule::new(py, "align")?;
    align::register(py, &align_mod)?;
    m.add_submodule(&align_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.align", align_mod)?;

    // D01 — Smart-Rules per-event selector. The 14-rule decision tree
    // from Gap 17; -97% regret vs the daemon's static decision logic.
    // Consumed by send_file at daemon.py:14020. Implements Decide<Decision>
    // from ol_decide; future selector variants (UnifiedMin) plug in
    // through the same trait without changing this surface.
    let selector_mod = PyModule::new(py, "selector")?;
    selector::register(py, &selector_mod)?;
    m.add_submodule(&selector_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.selector", selector_mod)?;

    // D06 — Radio-aware batch scheduler. Coalesces background traffic
    // across the radio's DRX cycle to recover idle energy. 22-44%
    // per-event energy reduction in forge shootouts (Gap 4). 50ms DRX
    // window per Gap 11; foreground urgent bypasses batching entirely
    // per Gap 14. Consumed by broadcast_endpoint_to_paired at
    // daemon.py:12137-12140 + drained on the 20s _prune_loop tick.
    let radio_batcher_mod = PyModule::new(py, "radio_batcher")?;
    radio_batcher::register(py, &radio_batcher_mod)?;
    m.add_submodule(&radio_batcher_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.radio_batcher", radio_batcher_mod)?;

    // D14 — Payload-aware compression dispatcher. lz4 for fast paths,
    // zstd for bulk, none for tiny msgs / already-compressed payloads.
    // Replaces the daemon's static zstd-everywhere with per-(kind, size,
    // hint) routing. ~30% bandwidth target on the test workload mix.
    let compress_mod = PyModule::new(py, "compress")?;
    compress::register(py, &compress_mod)?;
    m.add_submodule(&compress_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("one_link_native.compress", compress_mod)?;

    Ok(())
}
