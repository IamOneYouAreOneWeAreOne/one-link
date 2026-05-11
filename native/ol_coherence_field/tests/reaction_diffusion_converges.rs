//! Phase E acceptance gate: **reaction-diffusion convergence.**
//!
//! Verifies the timestepping form of the reaction-diffusion PDE
//! converges to the same steady-state as the direct Helmholtz solve.
//! Both should agree to within tight numerical tolerance.

use ol_coherence_field::pde::reaction_diffusion::{
    solve_reaction_diffusion_steady, EulerConfig,
};
use ol_coherence_field::pde::sparse_solver::CgConfig;
use ol_coherence_field::{solve_helmholtz, GraphLaplacian};

#[test]
fn euler_steady_state_matches_helmholtz_solve() {
    // Random-ish small graph + source. The two solvers must agree.
    let n = 6;
    let mut g = GraphLaplacian::new(n);
    g.add_edge(0, 1, 1.0).unwrap();
    g.add_edge(1, 2, 1.0).unwrap();
    g.add_edge(2, 3, 2.0).unwrap();
    g.add_edge(3, 4, 1.0).unwrap();
    g.add_edge(4, 5, 1.0).unwrap();
    g.add_edge(0, 5, 0.5).unwrap();

    let source = vec![1.0, 0.0, 2.0, 0.0, -1.0, 0.0];
    let d = 1.0;
    let gamma = 0.3;

    let euler = solve_reaction_diffusion_steady(
        &g,
        d,
        gamma,
        &source,
        EulerConfig::default(),
    )
    .unwrap();
    let helm = solve_helmholtz(&g, d, gamma, &source, CgConfig::default()).unwrap();

    // Compare elementwise.
    for i in 0..n {
        let abs_err = (euler.field[i] - helm.field[i]).abs();
        let rel_err = abs_err / helm.field[i].abs().max(1e-9);
        assert!(
            abs_err < 1e-5 && rel_err < 1e-4,
            "node {i}: euler = {}, helm = {}, abs_err = {abs_err}, rel_err = {rel_err}",
            euler.field[i],
            helm.field[i],
        );
    }
}

#[test]
fn helmholtz_residual_below_1e_minus_6() {
    // The Phase E gate calls for spectral residual < 1e-6.
    let n = 16;
    let mut g = GraphLaplacian::new(n);
    // Build a 4×4 grid.
    for r in 0..4 {
        for c in 0..4 {
            let idx = r * 4 + c;
            if c < 3 {
                g.add_edge(idx, idx + 1, 1.0).unwrap();
            }
            if r < 3 {
                g.add_edge(idx, idx + 4, 1.0).unwrap();
            }
        }
    }
    let mut source = vec![0.0; n];
    source[0] = 1.0;
    source[n - 1] = -1.0;
    let r = solve_helmholtz(&g, 1.0, 0.5, &source, CgConfig::default()).unwrap();
    assert!(
        r.residual < 1e-6,
        "Helmholtz residual {} > 1e-6",
        r.residual
    );
    assert!(r.converged);
}
