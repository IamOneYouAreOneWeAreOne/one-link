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

use pyo3::prelude::*;

mod aead;
mod bandit;
mod bloom;
mod capability;
mod chunk;
mod crdt;
mod erasure;
mod errors;
mod fec;
mod fountain;
mod hwkey;
mod pqkem;
mod quic;
mod ratchet;
mod store;
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

    Ok(())
}
