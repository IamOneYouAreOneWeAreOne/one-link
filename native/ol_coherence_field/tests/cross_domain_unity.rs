//! Phase E acceptance gate: **cross-domain calibration unity**.
//!
//! The unified-field claim's load-bearing assertion is that the
//! *same algebra* solves the network field, the RF field, and the
//! biological-signal field — only the calibration constants differ.
//! This test exercises all three: same `solve_helmholtz`, same
//! `identity_dual_source`, same `be_rar`, same `apparent_horizon_anchor`,
//! fed the three production calibrations.

use ol_coherence_field::calibration::{
    bio_mesh_calibration, one_field_calibration, one_link_calibration, Calibration, Domain,
};
use ol_coherence_field::pde::sparse_solver::CgConfig;
use ol_coherence_field::{be_rar, identity_dual_source, solve_helmholtz, GraphLaplacian};

/// Solve the field for one domain. Returns the recovered field +
/// the BE-RAR-mapped routing scores.
fn solve_for_domain(cal: &Calibration) -> (Vec<f64>, Vec<f64>) {
    // Small structured swarm: 8 nodes in a ring with one "fragile"
    // band of 2 nodes. Same topology across all three domains so we
    // can verify the math operates consistently.
    let node_count = 8;
    let mut graph = GraphLaplacian::new(node_count);
    for i in 0..node_count {
        let j = (i + 1) % node_count;
        graph.add_edge(i, j, 1.0).unwrap();
    }
    let fragile: Vec<bool> = (0..node_count).map(|i| (3..5).contains(&i)).collect();
    let density: Vec<f64> = fragile
        .iter()
        .map(|&f| if f { 0.05 } else { 1.0 })
        .collect();
    let flux: Vec<f64> = fragile
        .iter()
        .map(|&f| if f { 0.02 } else { 0.6 })
        .collect();
    let source = identity_dual_source(&density, &flux, cal.alpha_density, cal.beta_flux).unwrap();
    let cfg = CgConfig {
        max_iter: 5_000,
        tolerance: 1e-9,
    };
    let result = solve_helmholtz(&graph, cal.d, cal.gamma, &source, cfg).unwrap();
    let field_min = result.field.iter().copied().fold(f64::INFINITY, f64::min);
    let field_max = result
        .field
        .iter()
        .copied()
        .fold(f64::NEG_INFINITY, f64::max);
    let span = (field_max - field_min).max(1e-9);
    let routing_scores: Vec<f64> = result
        .field
        .iter()
        .map(|&v| {
            let normalized = ((v - field_min) / span).max(1e-9);
            be_rar(normalized).unwrap()
        })
        .collect();
    (result.field, routing_scores)
}

#[test]
fn same_algebra_solves_all_three_domains() {
    let one_link = one_link_calibration();
    let one_field = one_field_calibration();
    let bio_mesh = bio_mesh_calibration();

    let (one_link_field, one_link_scores) = solve_for_domain(&one_link);
    let (one_field_values, one_field_scores) = solve_for_domain(&one_field);
    let (bio_mesh_field, bio_mesh_scores) = solve_for_domain(&bio_mesh);

    eprintln!("One Link: domain={:?}", one_link.domain);
    eprintln!("  ell_screen = {:?}", one_link.screening_length());
    eprintln!("  g_A = {:?}", one_link.apparent_horizon_anchor());
    eprintln!(
        "  field range: {:.3e} .. {:.3e}",
        one_link_field.iter().copied().fold(f64::INFINITY, f64::min),
        one_link_field
            .iter()
            .copied()
            .fold(f64::NEG_INFINITY, f64::max)
    );

    eprintln!("OneField:  domain={:?}", one_field.domain);
    eprintln!("  ell_screen = {:?}", one_field.screening_length());
    eprintln!("  g_A = {:?}", one_field.apparent_horizon_anchor());

    eprintln!("BioMesh:   domain={:?}", bio_mesh.domain);
    eprintln!("  ell_screen = {:?}", bio_mesh.screening_length());
    eprintln!("  g_A = {:?}", bio_mesh.apparent_horizon_anchor());

    // 1. All three solves must have produced a numerically-stable
    //    field: finite, real, non-trivial.
    for (name, field) in [
        ("One Link", &one_link_field),
        ("OneField", &one_field_values),
        ("BioMesh", &bio_mesh_field),
    ] {
        for (i, v) in field.iter().enumerate() {
            assert!(v.is_finite(), "{name} field[{i}] is not finite: {v}");
        }
        // Field shouldn't be the zero vector (sources are non-trivial).
        let max_abs = field.iter().map(|v| v.abs()).fold(0.0_f64, f64::max);
        assert!(
            max_abs > 1e-12,
            "{name} field is suspiciously close to zero (max abs = {max_abs})"
        );
    }

    // 2. The same fragile-band structure should produce the same
    //    RELATIVE shape in each domain (mid-band nu is highest, ring
    //    nodes are lowest). The absolute values differ (different
    //    calibrations), but the topology of the field is preserved.
    //    Verify: nu at fragile-band nodes > nu at non-fragile nodes
    //    in all three domains.
    let fragile_indices = [3usize, 4];
    let safe_indices = [0usize, 1, 6, 7];
    for (name, nu) in [
        ("One Link", &one_link_scores),
        ("OneField", &one_field_scores),
        ("BioMesh", &bio_mesh_scores),
    ] {
        let frag_min = fragile_indices
            .iter()
            .map(|&i| nu[i])
            .fold(f64::INFINITY, f64::min);
        let safe_max = safe_indices
            .iter()
            .map(|&i| nu[i])
            .fold(f64::NEG_INFINITY, f64::max);
        assert!(
            frag_min > safe_max,
            "{name}: fragile nu ({frag_min:.4}) should exceed safe nu ({safe_max:.4})"
        );
    }

    // 3. The three domains' anchor scales must legitimately differ
    //    — that's the whole point of separate calibrations.
    let one_link_anchor = one_link.apparent_horizon_anchor().unwrap();
    let one_field_anchor = one_field.apparent_horizon_anchor().unwrap();
    let bio_mesh_anchor = bio_mesh.apparent_horizon_anchor().unwrap();
    let scale_spread = one_link_anchor.max(one_field_anchor).max(bio_mesh_anchor)
        / one_link_anchor.min(one_field_anchor).min(bio_mesh_anchor);
    assert!(
        scale_spread > 100.0,
        "anchor scales should span at least 100× across domains; got {scale_spread:.3}"
    );
    eprintln!("anchor-scale spread across domains: {scale_spread:.3e}×");

    // 4. Domain tags propagate correctly.
    assert_eq!(one_link.domain, Domain::OneLink);
    assert_eq!(one_field.domain, Domain::OneField);
    assert_eq!(bio_mesh.domain, Domain::BioMesh);
}
