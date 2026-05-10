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
mod chunk;
mod errors;
mod quic;
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

    Ok(())
}
