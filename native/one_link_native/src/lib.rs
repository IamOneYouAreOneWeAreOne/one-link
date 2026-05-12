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
// pyo3 0.22 macros emit `#[cfg(feature = "gil-refs")]` arms which are not
// reachable on our feature set; the unexpected_cfgs lint is therefore a
// false positive. pyo3 0.23 cleans this up; until then we silence it
// uniformly so the release build is warning-clean.
#![allow(unexpected_cfgs)]
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
mod bandit;
mod bloom;
mod capability;
mod chunk;
mod coherence_field;
mod crdt;
mod erasure;
mod errors;
mod fec;
mod fountain;
mod homology;
mod hwkey;
mod pqkem;
mod prefetch;
mod quic;
mod ratchet;
mod routing;
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

    // Submodules.
    let chunk_mod = PyModule::new_bound(py, "chunk")?;
    chunk::register(py, &chunk_mod)?;
    m.add_submodule(&chunk_mod)?;
    // Make `from one_link_native import chunk` and `import one_link_native.chunk`
    // both work. Without this line, only the dotted form works.
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("one_link_native.chunk", chunk_mod)?;

    let aead_mod = PyModule::new_bound(py, "aead")?;
    aead::register(py, &aead_mod)?;
    m.add_submodule(&aead_mod)?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("one_link_native.aead", aead_mod)?;

    let wal_mod = PyModule::new_bound(py, "wal")?;
    wal::register(py, &wal_mod)?;
    m.add_submodule(&wal_mod)?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("one_link_native.wal", wal_mod)?;

    let store_mod = PyModule::new_bound(py, "store")?;
    store::register(py, &store_mod)?;
    m.add_submodule(&store_mod)?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("one_link_native.store", store_mod)?;

    let quic_mod = PyModule::new_bound(py, "quic")?;
    quic::register(py, &quic_mod)?;
    m.add_submodule(&quic_mod)?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("one_link_native.quic", quic_mod)?;

    let bloom_mod = PyModule::new_bound(py, "bloom")?;
    bloom::register(py, &bloom_mod)?;
    m.add_submodule(&bloom_mod)?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("one_link_native.bloom", bloom_mod)?;

    let fountain_mod = PyModule::new_bound(py, "fountain")?;
    fountain::register(py, &fountain_mod)?;
    m.add_submodule(&fountain_mod)?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("one_link_native.fountain", fountain_mod)?;

    let fec_mod = PyModule::new_bound(py, "fec")?;
    fec::register(py, &fec_mod)?;
    m.add_submodule(&fec_mod)?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("one_link_native.fec", fec_mod)?;

    let ratchet_mod = PyModule::new_bound(py, "ratchet")?;
    ratchet::register(py, &ratchet_mod)?;
    m.add_submodule(&ratchet_mod)?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("one_link_native.ratchet", ratchet_mod)?;

    let pqkem_mod = PyModule::new_bound(py, "pqkem")?;
    pqkem::register(py, &pqkem_mod)?;
    m.add_submodule(&pqkem_mod)?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("one_link_native.pqkem", pqkem_mod)?;

    let erasure_mod = PyModule::new_bound(py, "erasure")?;
    erasure::register(py, &erasure_mod)?;
    m.add_submodule(&erasure_mod)?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("one_link_native.erasure", erasure_mod)?;

    let bandit_mod = PyModule::new_bound(py, "bandit")?;
    bandit::register(py, &bandit_mod)?;
    m.add_submodule(&bandit_mod)?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("one_link_native.bandit", bandit_mod)?;

    let capability_mod = PyModule::new_bound(py, "capability")?;
    capability::register(py, &capability_mod)?;
    m.add_submodule(&capability_mod)?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("one_link_native.capability", capability_mod)?;

    let crdt_mod = PyModule::new_bound(py, "crdt")?;
    crdt::register(py, &crdt_mod)?;
    m.add_submodule(&crdt_mod)?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("one_link_native.crdt", crdt_mod)?;

    let hwkey_mod = PyModule::new_bound(py, "hwkey")?;
    hwkey::register(py, &hwkey_mod)?;
    m.add_submodule(&hwkey_mod)?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("one_link_native.hwkey", hwkey_mod)?;

    // Phase D pyo3 bindings.
    let routing_mod = PyModule::new_bound(py, "routing")?;
    routing::register(py, &routing_mod)?;
    m.add_submodule(&routing_mod)?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("one_link_native.routing", routing_mod)?;

    let prefetch_mod = PyModule::new_bound(py, "prefetch")?;
    prefetch::register(py, &prefetch_mod)?;
    m.add_submodule(&prefetch_mod)?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("one_link_native.prefetch", prefetch_mod)?;

    let homology_mod = PyModule::new_bound(py, "homology")?;
    homology::register(py, &homology_mod)?;
    m.add_submodule(&homology_mod)?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("one_link_native.homology", homology_mod)?;

    // Phase E pyo3 bindings — coherence-field substrate (S_One canonical
    // theorem stack). One Rust crate, three calibrations (One Link /
    // OneField / BioMesh) — the unified-field claim made operational.
    let coherence_field_mod = PyModule::new_bound(py, "coherence_field")?;
    coherence_field::register(py, &coherence_field_mod)?;
    m.add_submodule(&coherence_field_mod)?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("one_link_native.coherence_field", coherence_field_mod)?;

    // Phase F1.1 — threshold recovery (Shamir + coherence-field-bound).
    // First crate of the Coherence Mesh track. Identity master-key
    // seeds split across trusted contacts; recovery requires K of N
    // shares AND (optionally) the coherence-field witness at mint time.
    let threshold_mod = PyModule::new_bound(py, "threshold_recovery")?;
    threshold_recovery::register(py, &threshold_mod)?;
    m.add_submodule(&threshold_mod)?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("one_link_native.threshold_recovery", threshold_mod)?;

    Ok(())
}
