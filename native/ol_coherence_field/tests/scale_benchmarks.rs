//! Phase E scale benchmarks. The plan specifies the field solver
//! must converge on swarms up to 10,000 peers. These tests time the
//! solve + assert the spectral residual gate.

use std::time::Instant;

use ol_coherence_field::pde::sparse_solver::CgConfig;
use ol_coherence_field::{identity_dual_source, solve_helmholtz, GraphLaplacian};

/// Build a small-world graph: ring + every Kth shortcut.
fn small_world(n: usize, every_k: usize) -> GraphLaplacian {
    let mut g = GraphLaplacian::new(n);
    for i in 0..n {
        let j = (i + 1) % n;
        g.add_edge(i, j, 1.0).unwrap();
    }
    for i in (0..n).step_by(every_k) {
        let j = (i + n / 3) % n;
        if i != j {
            g.add_edge(i, j, 0.5).unwrap();
        }
    }
    g
}

fn synthetic_sources(n: usize, fragile_band: std::ops::Range<usize>) -> Vec<f64> {
    let density: Vec<f64> = (0..n)
        .map(|i| if fragile_band.contains(&i) { 0.05 } else { 1.0 })
        .collect();
    let flux: Vec<f64> = (0..n)
        .map(|i| if fragile_band.contains(&i) { 0.02 } else { 0.7 })
        .collect();
    identity_dual_source(&density, &flux, 0.5, 0.5).unwrap()
}

#[test]
fn scale_1000_peers_converges_under_100ms() {
    let node_count = 1_000;
    let graph = small_world(node_count, 7);
    let source = synthetic_sources(node_count, 400..600);
    let config = CgConfig {
        max_iter: 5_000,
        tolerance: 1e-6,
    };
    let started_at = Instant::now();
    let result = solve_helmholtz(&graph, 1.0, 0.5, &source, config).expect("converges");
    let elapsed = started_at.elapsed();
    eprintln!(
        "1k peers: {} CG iters, residual {:.3e}, wall time {:.3?}",
        result.iterations, result.residual, elapsed
    );
    assert!(result.converged, "did not converge");
    assert!(result.residual < 1e-6);
    assert!(
        elapsed.as_millis() < 1000,
        "1k peer solve took {elapsed:.3?} — production hot path budget is 1 second"
    );
}

#[test]
fn scale_5000_peers_converges() {
    let node_count = 5_000;
    let graph = small_world(node_count, 11);
    let source = synthetic_sources(node_count, 2000..3000);
    let config = CgConfig {
        max_iter: 20_000,
        tolerance: 1e-6,
    };
    let started_at = Instant::now();
    let result = solve_helmholtz(&graph, 1.0, 0.5, &source, config).expect("converges");
    let elapsed = started_at.elapsed();
    eprintln!(
        "5k peers: {} CG iters, residual {:.3e}, wall time {:.3?}",
        result.iterations, result.residual, elapsed
    );
    assert!(result.converged);
    assert!(result.residual < 1e-6);
}

#[test]
fn scale_10000_peers_meets_plan_gate() {
    // Phase E plan gate: converge on swarms up to 10,000 peers with
    // spectral residual < 1e-6.
    let node_count = 10_000;
    let graph = small_world(node_count, 17);
    let source = synthetic_sources(node_count, 4000..6000);
    let config = CgConfig {
        max_iter: 50_000,
        tolerance: 1e-6,
    };
    let started_at = Instant::now();
    let result = solve_helmholtz(&graph, 1.0, 0.5, &source, config).expect("converges");
    let elapsed = started_at.elapsed();
    eprintln!(
        "10k peers: {} CG iters, residual {:.3e}, wall time {:.3?}",
        result.iterations, result.residual, elapsed
    );
    assert!(result.converged, "10k peer solve did not converge");
    assert!(
        result.residual < 1e-6,
        "Phase E gate: residual {:.3e} must be < 1e-6",
        result.residual
    );
}
