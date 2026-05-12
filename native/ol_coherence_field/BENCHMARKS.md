# ol_coherence_field — performance baseline

Numbers from `cargo bench -p ol_coherence_field --bench coherence_field_bench`
on the dev workstation (commit `0673aa0`, after CG-loop optimization).

These are the **post-optimization** baselines; subsequent PRs that
regress any line by more than 10% should explain why or get reverted.

## Scalar / per-tick microbenches

| Operation | Time |
|---|---|
| `be_rar(y = 1.0)` | 3.84 ns |
| `be_rar(y = 1e-4)` | 3.92 ns |
| `be_rar(y = 100)` | 4.28 ns |
| `apparent_horizon_anchor(1Gbit, 1% churn)` | 2.49 ns |
| `screening_length(100, 0.01)` | 2.58 ns |
| `one_link_calibration()` | 1.29 ns |

Daemon hot-path implication: BE-RAR adds ~4 ns to each relay-pick
cost evaluation. For a ~5-relay candidate set that's ~20 ns total —
invisible.

## Helmholtz solve (production hot path: PDE per topology change)

| Peers | Time | iters | residual |
|---|---|---|---|
| 100 | 9.19 µs | ~13 | ~1e-7 |
| 1 000 | 134 µs | ~17 | ~1e-7 |
| 5 000 | 822 µs | ~18 | ~1e-7 |
| 10 000 | 1.74 ms | ~18 | ~7e-7 |
| 50 000 | 10.14 ms | ~20 | ~1e-6 |

Plan target was "1 second per solve" — 50k-peer solve has **~100×
headroom**. CG converges in ≤20 iters across all scales (well-
conditioned operator: Γ·I + D·L is SPD with bounded eigenvalues).

## Graph Laplacian matvec (CG inner kernel)

| Peers | Time | per-node |
|---|---|---|
| 1 000 | 1.25 µs | 1.25 ns |
| 10 000 | 15.1 µs | 1.51 ns |
| 50 000 | 118.7 µs | 2.37 ns |

Per-node cost grows mildly with scale due to L2-cache pressure on the
neighbor lists. Within ~2× of memory-bandwidth-limited ideal.

## Source functionals (per element)

| Operation | n = 1 000 | n = 10 000 |
|---|---|---|
| `linear_source` | 107 ns | 1.71 µs |
| `identity_dual_source` | 185 ns | 2.35 µs |

`identity_dual_source` is the production form (S = α·ρ + β·|J|);
`linear_source` is kept as the no-go-theorem baseline.

## Cross-system couplings

| Operation | n = 100 | n = 1 000 | n = 10 000 |
|---|---|---|---|
| `inject_fragility_events` | 28 ns | 232 ns | 3.04 µs |
| `prefetch_priorities` | 381 ns | 2.96 µs | 29.6 µs |
| `rotation_cadence_multiplier` | 1.54 µs | 15.5 µs | 170 µs |

Couplings run "per field-update tick" (~10 Hz). Even at 10k peers all
three combined cost ~200 µs/tick = 0.2% CPU.

## End-to-end (graph build from scratch + solve)

| Peers | Time |
|---|---|
| 1 000 | 186 µs |
| 10 000 | 2.59 ms |

The worst-case "topology change forces full rebuild" cost.

## pyo3 boundary cost (daemon ↔ Rust)

Measured via Python wrapper `one_link.coherence_field_native`:

| Operation | Pure Rust | Via pyo3 | Overhead |
|---|---|---|---|
| `be_rar(1.0)` | 3.8 ns | 51 ns | +47 ns (boundary) |
| `apparent_horizon_anchor` | 2.5 ns | 50 ns | +47 ns |
| `solve_helmholtz` (1k) | 134 µs | 131 µs | ~0 (noise) |
| `rotation_cadence_multiplier` (1k) | 15.5 µs | 48.5 µs | +33 µs (tuple constr) |
| `one_link_calibration` | 1.3 ns | 437 ns | +436 ns (dict constr) |

Scalar calls cost a fixed ~50 ns boundary cross. Bulk calls dominated
by Python-object construction proportional to result size.

## Optimization history

- **CG inner-loop allocation removal + fused axpy + manual dot-product
  unroll** — `0673aa0` follow-up commit. Eliminated per-iter
  `apply_preconditioner` Vec allocations, fused `x += α·p`/`r -= α·ap`
  with running `r·r` accumulation in one pass, manually unrolled the
  dot-product into 4 lanes for better ILP. **−17 % to −27 % on
  `helmholtz_solve` across scales.**
