//! Criterion benchmarks for `ol_coherence_field` (Phase E).
//!
//! Coverage:
//!
//! - **BE-RAR interpolation** — daemon hot path; every relay-pick call
//!   evaluates `nu(y)`. Should be sub-µs.
//! - **Apparent-horizon anchor** — daemon `/api/native_status` surface.
//! - **Helmholtz solve** at 100 / 1k / 5k / 10k / 50k peers — the
//!   per-topology-change cost; budget is "1s per solve" per the plan.
//! - **Graph Laplacian matvec** — the inner kernel of CG. ≥80% of
//!   solve time is matvec calls.
//! - **Couplings**: homology injection / prefetch priorities / ratchet
//!   cadence — these run per "field-update tick" (~10Hz expected).
//! - **Linear-source no-go regression bench** — keep the baseline
//!   reference functional and timed alongside the production source.
//!
//! Run: `cargo bench -p ol_coherence_field`

#![allow(missing_docs)] // criterion_group! emits a fn that we can't doc

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ol_coherence_field::{
    anchor::ApparentHorizonInputs,
    apparent_horizon_anchor, be_rar,
    calibration::one_link_calibration,
    identity_dual_source, inject_fragility_events, linear_source,
    pde::{CgConfig, CgConfigF32},
    prefetch_priorities, rotation_cadence_multiplier, screening_length, solve_helmholtz,
    FragilityEvent, GraphLaplacian, HelmholtzSolver, HelmholtzSolverF32,
};

// ── Scalar / per-tick microbenches ──────────────────────────────────

fn bench_scalar_ops(c: &mut Criterion) {
    c.bench_function("be_rar(y=1.0)", |b| {
        b.iter(|| {
            let v = be_rar(black_box(1.0)).unwrap();
            black_box(v);
        });
    });
    c.bench_function("be_rar(y=1e-4)", |b| {
        b.iter(|| {
            let v = be_rar(black_box(1e-4)).unwrap();
            black_box(v);
        });
    });
    c.bench_function("be_rar(y=100)", |b| {
        b.iter(|| {
            let v = be_rar(black_box(100.0)).unwrap();
            black_box(v);
        });
    });
    c.bench_function("apparent_horizon_anchor(1Gbit, 1% churn)", |b| {
        b.iter(|| {
            let g = apparent_horizon_anchor(black_box(ApparentHorizonInputs {
                c_wire: 1.0e9,
                h_swarm: 0.01,
            }));
            black_box(g);
        });
    });
    c.bench_function("screening_length(100, 0.01)", |b| {
        b.iter(|| {
            let ell = screening_length(black_box(100.0), black_box(0.01));
            black_box(ell);
        });
    });
    c.bench_function("one_link_calibration()", |b| {
        b.iter(|| {
            let cal = one_link_calibration();
            black_box(cal);
        });
    });
}

// ── Graph + matvec + Helmholtz solve at scale ───────────────────────

/// Build a random ring + chord graph with `n` nodes and avg degree ≈ 4.
/// Same topology generator used by the integration tests so timings
/// stay comparable.
fn build_ring_chord(n: usize) -> GraphLaplacian {
    let mut g = GraphLaplacian::new(n);
    for i in 0..n {
        let j = (i + 1) % n;
        let _ = g.add_edge(i, j, 1.0);
    }
    // Chords: every 7th node connects to (i + n/3).
    let step = (n / 3).max(1);
    for i in (0..n).step_by(7) {
        let j = (i + step) % n;
        if i != j {
            let _ = g.add_edge(i, j, 0.5);
        }
    }
    g
}

fn bench_matvec(c: &mut Criterion) {
    let mut group = c.benchmark_group("matvec");
    for &n in &[1_000usize, 10_000, 50_000] {
        let g = build_ring_chord(n);
        g.freeze(); // amortise CSR build out of the timed loop
        let x: Vec<f64> = (0..n).map(|i| (i as f64) * 1e-3).collect();
        let mut y = vec![0.0_f64; n];
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(BenchmarkId::new("L*x", n), |b| {
            b.iter(|| {
                g.matvec(black_box(&x), black_box(&mut y));
                black_box(&y);
            });
        });
        group.bench_function(BenchmarkId::new("L*x_par", n), |b| {
            b.iter(|| {
                g.matvec_par(black_box(&x), black_box(&mut y));
                black_box(&y);
            });
        });
    }
    group.finish();
}

fn bench_helmholtz_solve(c: &mut Criterion) {
    let mut group = c.benchmark_group("helmholtz_solve");
    group.sample_size(20); // long-running solves; default 100 samples = too long
    for &n in &[100usize, 1_000, 5_000, 10_000, 50_000] {
        let g = build_ring_chord(n);
        let mut s = vec![0.0_f64; n];
        s[n / 2] = 1.0; // point source at center
        let cfg = CgConfig {
            max_iter: 2_000,
            tolerance: 1e-6,
        };
        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter(|| {
                let r = solve_helmholtz(
                    black_box(&g),
                    black_box(1.0),
                    black_box(0.1),
                    black_box(&s),
                    cfg,
                )
                .unwrap();
                black_box(r);
            });
        });
    }
    group.finish();
}

// ── Source functionals ──────────────────────────────────────────────

fn bench_sources(c: &mut Criterion) {
    let mut group = c.benchmark_group("source_functionals");
    for &n in &[1_000usize, 10_000] {
        let density: Vec<f64> = (0..n).map(|i| (i as f64).sin().abs()).collect();
        let flux: Vec<f64> = (0..n).map(|i| (i as f64).cos().abs()).collect();
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(BenchmarkId::new("linear_source", n), |b| {
            b.iter(|| {
                let s = linear_source(black_box(&density), black_box(1.0)).unwrap();
                black_box(s);
            });
        });
        group.bench_function(BenchmarkId::new("identity_dual_source", n), |b| {
            b.iter(|| {
                let s = identity_dual_source(
                    black_box(&density),
                    black_box(&flux),
                    black_box(1.0),
                    black_box(0.5),
                )
                .unwrap();
                black_box(s);
            });
        });
    }
    group.finish();
}

// ── Cross-system couplings (per-tick cost) ──────────────────────────

fn bench_couplings(c: &mut Criterion) {
    let mut group = c.benchmark_group("couplings");
    for &n in &[100usize, 1_000, 10_000] {
        // Field array.
        let field: Vec<f64> = (0..n).map(|i| 0.1 + (i as f64) / (n as f64)).collect();
        // Fragility events: 5% of nodes flagged in a single cycle.
        let events: Vec<FragilityEvent> = (0..n / 20)
            .map(|k| FragilityEvent {
                affected_nodes: vec![(k * 17) % n, (k * 31) % n],
                severity: 0.5,
            })
            .collect();
        let mut source = vec![1.0; n];
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(BenchmarkId::new("inject_fragility_events", n), |b| {
            b.iter(|| {
                let applied = inject_fragility_events(
                    black_box(&mut source),
                    black_box(&events),
                    black_box(1.0),
                );
                black_box(applied);
            });
        });
        // Prefetch: requester at 0, holders are every 4th node.
        let holders: Vec<usize> = (1..n).step_by(4).collect();
        group.bench_function(BenchmarkId::new("prefetch_priorities", n), |b| {
            b.iter(|| {
                let p = prefetch_priorities(
                    black_box(&field),
                    black_box(0),
                    black_box(&holders),
                    black_box(1.0),
                );
                black_box(p);
            });
        });
        // Ratchet cadence over the same field.
        group.bench_function(BenchmarkId::new("rotation_cadence_multiplier", n), |b| {
            b.iter(|| {
                let cads = rotation_cadence_multiplier(
                    black_box(&field),
                    black_box(1_000_000),
                    black_box(4.0),
                    black_box(2.0),
                );
                black_box(cads);
            });
        });
    }
    group.finish();
}

// ── End-to-end: build graph + solve from scratch ────────────────────
//
// This is the cost the daemon pays when a topology change forces a
// full rebuild — the worst case for the field path.

fn bench_end_to_end_topology_change(c: &mut Criterion) {
    let mut group = c.benchmark_group("e2e_topology_change");
    group.sample_size(20);
    for &n in &[1_000usize, 10_000] {
        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter(|| {
                let g = build_ring_chord(black_box(n));
                let mut s = vec![0.0; n];
                s[n / 2] = 1.0;
                let r = solve_helmholtz(
                    &g,
                    1.0,
                    0.1,
                    &s,
                    CgConfig {
                        max_iter: 2_000,
                        tolerance: 1e-6,
                    },
                )
                .unwrap();
                black_box(r);
            });
        });
    }
    group.finish();
}

// ── HelmholtzSolver: workspace reuse + warm-start ───────────────────

fn bench_solver_warm_start(c: &mut Criterion) {
    let mut group = c.benchmark_group("helmholtz_solver_warm_start");
    group.sample_size(30);
    for &n in &[1_000usize, 10_000] {
        let g = build_ring_chord(n);
        let mut s = vec![0.0_f64; n];
        s[n / 2] = 1.0;
        let cfg = CgConfig {
            max_iter: 2_000,
            tolerance: 1e-6,
        };

        // Cold: one-shot allocates fresh every call.
        group.bench_function(BenchmarkId::new("one_shot", n), |b| {
            b.iter(|| {
                let r = solve_helmholtz(
                    black_box(&g),
                    black_box(1.0),
                    black_box(0.1),
                    black_box(&s),
                    cfg,
                )
                .unwrap();
                black_box(r);
            });
        });

        // Warm: HelmholtzSolver reuses workspace + warm-start.
        // First call seeds, subsequent calls warm-start from previous.
        group.bench_function(BenchmarkId::new("warm", n), |b| {
            let mut solver = HelmholtzSolver::new(n);
            // Prime: one solve to populate warm-start cache.
            solver.solve(&g, 1.0, 0.1, &s, cfg).unwrap();
            b.iter(|| {
                let r = solver
                    .solve(
                        black_box(&g),
                        black_box(1.0),
                        black_box(0.1),
                        black_box(&s),
                        cfg,
                    )
                    .unwrap();
                black_box(r);
            });
        });

        // Workspace-only (no warm-start): isolates the per-call alloc
        // savings from the warm-start convergence win.
        group.bench_function(BenchmarkId::new("workspace_only", n), |b| {
            let mut solver = HelmholtzSolver::new(n);
            b.iter(|| {
                solver.clear_warm_start();
                let r = solver
                    .solve(
                        black_box(&g),
                        black_box(1.0),
                        black_box(0.1),
                        black_box(&s),
                        cfg,
                    )
                    .unwrap();
                black_box(r);
            });
        });
    }
    group.finish();
}

// ── f32 vs f64 helmholtz solve ──────────────────────────────────────

fn bench_helmholtz_f32_vs_f64(c: &mut Criterion) {
    let mut group = c.benchmark_group("helmholtz_f32_vs_f64");
    group.sample_size(30);
    for &n in &[1_000usize, 10_000] {
        let g = build_ring_chord(n);
        g.freeze();

        // f64 reference
        let mut s64 = vec![0.0_f64; n];
        s64[n / 2] = 1.0;
        let cfg64 = CgConfig {
            max_iter: 2_000,
            tolerance: 1e-6,
        };
        group.bench_function(BenchmarkId::new("f64", n), |b| {
            let mut solver = HelmholtzSolver::new(n);
            b.iter(|| {
                solver.clear_warm_start();
                let r = solver.solve(&g, 1.0, 0.1, &s64, cfg64).unwrap();
                black_box(r);
            });
        });

        // f32 path
        let mut s32 = vec![0.0_f32; n];
        s32[n / 2] = 1.0;
        let cfg32 = CgConfigF32 {
            max_iter: 2_000,
            tolerance: 1e-5,
        };
        group.bench_function(BenchmarkId::new("f32", n), |b| {
            let mut solver = HelmholtzSolverF32::new(n);
            b.iter(|| {
                let r = solver.solve(&g, 1.0, 0.1, &s32, cfg32).unwrap();
                black_box(r);
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_scalar_ops,
    bench_matvec,
    bench_helmholtz_solve,
    bench_sources,
    bench_couplings,
    bench_end_to_end_topology_change,
    bench_solver_warm_start,
    bench_helmholtz_f32_vs_f64,
);
criterion_main!(benches);
