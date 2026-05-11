# ADR-0028: Tau-field routing primitives (Phase D #1)

**Status:** ACCEPTED (Phase D)
**Phase:** D (item #1: tau-field routing on swarm graph)
**Harvest:** `OneField/onefield/mesh/routing.cl` (~150 lines, production-shipping)

---

## Context

The Phase D plan calls for tau-field routing on the swarm graph:

> Tau-field routing on swarm graph — harvest OneField mesh/routing.cl (production τ_c-weighted Dijkstra already shipping) as starting point. Adapt edge-weight from RF τ_c gradient → empirical network metrics (RTT, jitter, observed-throughput). PDE solver runs once per topology change, not per chunk.

OneField's `mesh/routing.cl` is pure math (~150 lines, Coherence Language). The harvest is direct: port the cost functions to Rust as-is, then add a Dijkstra shortest-path algorithm over an adjacency-list graph keyed on string node-ids (peer fingerprints / relay URLs / whatever stable identifier fits the topology).

## Decision

**Ship `native/ol_routing` — a pure-Rust port of OneField's tau-field cost math + a Dijkstra shortest-path solver.**

### Module layout

```
native/ol_routing/
├── Cargo.toml
├── src/
│   ├── lib.rs        # public surface
│   ├── metrics.rs    # edge_weight / loss_penalty / edge_cost / prefer_first / should_swap_hop
│   └── dijkstra.rs   # AdjacencyGraph + shortest_path
├── tests/
│   └── fragile_graph.rs   # Phase D acceptance gate
└── benches/
    └── routing_bench.rs
```

### Cost math (harvested verbatim from OneField)

```rust
edge_weight(tau_c_s, dist_m) = dist_m / (c * tau_c_s)
loss_penalty(loss_rate)     = 1 / (1 - loss)^2     // clamped to [0, 0.99]
edge_cost(...)              = edge_weight(...) * loss_penalty(...)
prefer_first(a, b)          = a < b
should_swap_hop(cur, cand, hysteresis_factor) = cand < cur * hysteresis_factor
```

`c` is the speed of light (299,792,458 m/s) — kept verbatim from the RF-physics ancestry so a daemon meshed with OneField RF nodes shares a single cost surface across both graphs.

Network-context variable interpretation:

```text
tau_c (seconds)   <- network stability proxy (RTT EWMA / jitter-sigma)
dist_m (meters)   <- logical hop distance (or RTT itself for 1-hop graphs)
loss_rate         <- observed packet-loss fraction
```

### Dijkstra solver

`AdjacencyGraph::add_edge(from, to, cost)` builds a directed graph; call twice for undirected. `shortest_path(&g, start, goal) -> Result<PathResult, RoutingError>` returns the path (start → ... → goal) and total cost, or `NoPath` if unreachable. Standard binary-heap-backed Dijkstra; O((V + E) log V).

### Acceptance gate

Phase D gate from `FILE_ENGINE_V2_PLAN.md`:

> Tau-field routing beats shortest-path on a fragile-graph benchmark by stated margin (≥20% reduction in chunks-lost-on-partition).

Test at `native/ol_routing/tests/fragile_graph.rs`:

- Build a graph with two parallel routes source → target:
  - **Short fragile route** (2 hops, naive hop-count picks this; 70% packet loss on the lossy relay).
  - **Long stable route** (4 hops, longer but zero-loss).
- Naive shortest-path picks the fragile route (shorter hop count).
- Tau-field routing picks the long stable route (loss penalty makes the fragile route ~11× more expensive).
- Simulate 1000 chunks down each picked route. Count chunks lost.

**Result on commit `<THIS>`**:

```
naive path: ["source", "relay_lossy", "target"]                          → lost 910 / 1000 chunks
tau path:   ["source", "relay_a", "relay_b", "relay_c", "target"]        → lost 0 / 1000 chunks
chunk-loss reduction: 100.0%
```

**100% chunk-loss reduction**, far exceeding the 20% gate.

## Verification

- **15 unit tests** in `metrics.rs` + `dijkstra.rs` (edge math monotonicity + Dijkstra path + disconnected components + low-loss preference).
- **1 fragile-graph acceptance gate** (100% chunk-loss reduction).
- **16 doc tests** pass (the cost-math docs use `text` code blocks so they don't trigger Rust doctest parsing).
- **0 failures**, **0 unsafe code** (crate-level `#![forbid(unsafe_code)]`).
- Criterion benches at `benches/routing_bench.rs` cover the cost-math primitives + Dijkstra over grids of 8×8 / 16×16 / 32×32 nodes.

## Wiring state

- ✅ `ol_routing` crate live in the workspace.
- ⚠️ Daemon integration is deferred — the daemon doesn't yet have a multi-hop route graph (peer-to-peer over WebRTC / direct sockets has a single path per peer). When the relay layer adds multi-relay routing (Phase D + later), the daemon's relay-selection code calls `ol_routing.shortest_path(...)` to pick the best relay path.
- ⚠️ Python adapter (`one_link.routing_native`) deferred until the daemon has a use case.

## References

- `OneField/onefield/mesh/routing.cl` (verbatim source)
- `FILE_ENGINE_V2_PLAN.md` Phase D item #1 + acceptance gate
- ADR-0019 (bandit — complementary, per-peer-pair signal)
