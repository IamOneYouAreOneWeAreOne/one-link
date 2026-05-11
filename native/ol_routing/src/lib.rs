//! `ol_routing` — tau_c-weighted routing primitives for One Link.
//!
//! Per [FILE_ENGINE_V2_PLAN.md] Phase D item #1:
//!
//! > Tau-field routing on swarm graph — harvest OneField
//! > mesh/routing.cl (production τ_c-weighted Dijkstra already
//! > shipping) as starting point. Adapt edge-weight from RF τ_c
//! > gradient → empirical network metrics (RTT, jitter,
//! > observed-throughput). PDE solver runs once per topology
//! > change, not per chunk.
//!
//! This crate ports the pure math from `OneField/onefield/mesh/routing.cl`
//! (~150 lines, production-shipping) and adapts the variable names from
//! RF physics (coherence time, hop distance) to network metrics:
//!
//! ```text
//! tau_c (seconds)   <- network stability proxy (RTT EWMA / jitter-sigma)
//! dist_m (meters)   <- logical hop distance (or RTT itself for 1-hop graphs)
//! loss_rate         <- observed packet-loss fraction
//! ```
//!
//! ## Surface
//!
//! - [`edge_weight`] / [`edge_cost`] / [`loss_penalty`] — pure cost math.
//! - [`prefer_first`] / [`should_swap_hop`] — next-hop selection.
//! - [`shortest_path`] — Dijkstra over an adjacency-list graph.
//!
//! ## Acceptance criteria (Phase D)
//!
//! Per the plan's Phase D acceptance gate:
//!
//! > Tau-field routing beats shortest-path on a fragile-graph
//! > benchmark by stated margin (≥20% reduction in chunks-lost-
//! > on-partition).
//!
//! That benchmark lives in `tests/fragile_graph.rs`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod byzantine;
mod dijkstra;
mod metrics;

pub use byzantine::{
    max_byzantine_count, quorum_safe, rgg_connectivity_radius, rgg_mean_degree,
    tau_claim_corroborated,
};
pub use dijkstra::{shortest_path, AdjacencyGraph, NodeId, PathResult};
pub use metrics::{
    edge_cost, edge_weight, loss_penalty, prefer_first, should_swap_hop,
};

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
