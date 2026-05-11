//! `ol_homology` — durability detection over the chunk-co-hold graph.
//!
//! Per `FILE_ENGINE_V2_PLAN.md` Phase D item #4:
//!
//! > Persistent homology durability — H1 over the chunk-co-hold
//! > graph; flag closing-loops as fragility events; preemptive
//! > replication. Approximations (witness complexes, sparse
//! > filtrations) needed for production scale; naive O(n³) is
//! > prohibitive.
//!
//! ## Approach
//!
//! Full persistent-homology computation (boundary-matrix reduction)
//! is O(N³) on edge-pair counts — prohibitive at the swarm scales
//! the daemon sees. We ship two cheaper but operationally useful
//! detectors that capture the same intent ("preemptive replication
//! for fragile chunks"):
//!
//! - **H0 component count** via union-find. A connected component
//!   with a single chunk is maximally fragile — no peer redundancy.
//! - **Bridge detection** via DFS lowlink (Tarjan-style). A chunk
//!   whose removal would disconnect the co-hold graph is a "bridge"
//!   and gets replication priority.
//!
//! These approximate the H1 (loops) intent: loops-closing-events
//! corresponds to "previously-bridge edges that gain redundancy."
//! Operators get the actionable signal (which chunks to replicate
//! NOW) without the cubic-time computation.

#![forbid(unsafe_code)]
#![allow(missing_docs)]

mod components;
mod fragility;

pub use components::{components_of, ComponentReport};
pub use fragility::{fragility_score, FragilityReport, FragilityScore};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
