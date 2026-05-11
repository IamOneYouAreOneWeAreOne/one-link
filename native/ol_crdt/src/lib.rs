//! CRDT primitives for One Link shared folders.
//!
//! See `docs/decisions/0022-crdt-folders.md`.
//!
//! The plan's Phase C item #4 calls for CRDT shared folders replacing the
//! existing vector-clock manifest in `One_link/src/one_link/foldersync.py`.
//! This crate ships the four lattice types the folder model needs:
//!
//! - `VectorClock` for causal ordering across replicas.
//! - `OrSet` for collaboratively edited file lists (add/remove that don't
//!   resurrect tombstones).
//! - `LwwRegister` for last-writer-wins scalar attributes.
//! - `Folder`: composes the three to model a one-folder-per-replica state.
//!
//! All three sub-lattices satisfy the lattice merge laws (commutativity,
//! associativity, idempotency). The acceptance gate
//! (`tests/lattice_laws.rs`) property-tests this across ≥1M random states.

#![forbid(unsafe_code)]

mod error;
mod folder;
mod lww;
mod or_set;
mod vector_clock;

pub use error::{CrdtError, Result};
pub use folder::{FileEntry, Folder};
pub use lww::LwwRegister;
pub use or_set::OrSet;
pub use vector_clock::{ReplicaId, VectorClock};

/// Lattice element trait: every CRDT type used in a folder must implement
/// commutative + associative + idempotent merge.
pub trait Lattice: Clone {
    fn merge(&mut self, other: &Self);
}
