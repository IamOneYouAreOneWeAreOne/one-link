//! `BioMesh` biological-signal calibration.
//!
//! Maps the unified field constants to biological-signal observables:
//!
//! | Field-theory variable | BioMesh analog |
//! |---|---|
//! | `D` | biological-signal diffusion (mm² / s) |
//! | `Γ` | metabolic-decay rate (1 / s) |
//! | `c` | max signal propagation rate in tissue (m/s) |
//! | `H_0` | metabolic-turnover rate (1 / s) |

use super::{Calibration, Domain};

/// Default `BioMesh` calibration for typical mammalian-tissue signals.
#[must_use]
pub fn bio_mesh_calibration() -> Calibration {
    Calibration {
        domain: Domain::BioMesh,
        // 1 mm² / s — characteristic biological signal diffusion in
        // tissue.
        d: 1.0e-6,
        // 1 / s — metabolic decay of a typical signaling molecule.
        gamma: 1.0,
        alpha_density: 0.5,
        beta_flux: 0.5,
        support_phase_c0: 0.80,
        support_phase_w: 0.12,
        // 100 m/s — fastest in-tissue signal propagation (myelinated
        // nerve fibers).
        c_propagation: 100.0,
        // 1e-3 / s — slow metabolic-turnover rate at the organism
        // level.
        h_0_equivalent: 1.0e-3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bio_mesh_calibration_finite_and_positive() {
        let c = bio_mesh_calibration();
        assert!(c.d > 0.0);
        assert!(c.gamma > 0.0);
        assert!(c.c_propagation > 0.0);
    }

    #[test]
    fn bio_mesh_screening_length_in_meters() {
        let c = bio_mesh_calibration();
        let ell = c.screening_length().unwrap();
        // ell = √(1e-6 / 1) = 1e-3 m = 1 mm. Matches the
        // physically-plausible diffusion scale in tissue.
        assert!((ell - 1.0e-3).abs() < 1e-9, "ell = {ell}");
    }
}
