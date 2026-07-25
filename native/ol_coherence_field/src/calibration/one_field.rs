//! `OneField` Mesh RF calibration.
//!
//! Same algebra as One Link's network calibration, but the constants
//! describe RF `τ_c` phenomena instead of network ones:
//!
//! | Field-theory variable | OneField analog |
//! |---|---|
//! | `D` | atmospheric RF τ_c diffusion (m² / s) |
//! | `Γ` | atmospheric damping rate (1 / s) |
//! | `c` | speed of light (299,792,458 m/s) |
//! | `H_0` | tropospheric-fade rate per characteristic distance |

use super::{Calibration, Domain};

/// Default `OneField` calibration for typical urban RF environments.
#[must_use]
pub fn one_field_calibration() -> Calibration {
    Calibration {
        domain: Domain::OneField,
        // 100 m² / s — typical RF τ_c diffusion in mid-troposphere.
        d: 100.0,
        // 0.1 / s — characteristic atmospheric coherence decay rate.
        gamma: 0.1,
        alpha_density: 0.5,
        beta_flux: 0.5,
        support_phase_c0: 0.80,
        support_phase_w: 0.12,
        // Speed of light in vacuum.
        c_propagation: 299_792_458.0,
        // Tropospheric-fade rate per characteristic distance (1/s
        // equivalent).
        h_0_equivalent: 1.0e-3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_field_calibration_finite_and_positive() {
        let c = one_field_calibration();
        assert!(c.d > 0.0);
        assert!(c.gamma > 0.0);
        assert!(c.c_propagation > 0.0);
    }

    #[test]
    fn one_field_screening_length_in_meters() {
        let c = one_field_calibration();
        // ell = √(100 / 0.1) = √1000 ≈ 31.6 meters.
        let ell = c.screening_length().unwrap();
        assert!((ell - 31.622_776_601_683_79).abs() < 1e-9, "ell = {ell}");
    }
}
