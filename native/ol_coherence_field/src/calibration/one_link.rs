//! One Link network calibration.
//!
//! Maps the cosmological / RF / biological constants of the unified
//! field to network observables:
//!
//! | Cosmology | One Link analog |
//! |---|---|
//! | `D` (diffusion) | info-mixing rate across swarm neighbors (chunks gossiped per second per peer) |
//! | `Γ` (damping) | peer-churn rate (peers leaving per second per active peer) |
//! | `c` (speed of light) | max physical link bandwidth (bits/sec) |
//! | `H_0` (Hubble rate) | swarm-wide peer-churn fraction per second |
//! | `S` (source) | per-peer (chunks held + chunks moving) — identity-sector dual |
//!
//! Defaults below are typical small-LAN values; production callers
//! should override based on live swarm metrics.

use super::{Calibration, Domain};

/// Default One Link calibration. Numbers are typical small-LAN
/// regime; the daemon should refit them from observed metrics on
/// every topology change.
#[must_use]
pub fn one_link_calibration() -> Calibration {
    Calibration {
        domain: Domain::OneLink,
        // 100 chunks/s gossip rate across swarm neighbors.
        d: 100.0,
        // 1% peer-churn per second.
        gamma: 0.01,
        // Density weight 0.5: chunks-held counts as much as flux.
        alpha_density: 0.5,
        // Flux weight 0.5: chunks-moving counts equally.
        beta_flux: 0.5,
        // Same support-phase fit as the galaxy-side best.
        support_phase_c0: 0.80,
        support_phase_w: 0.12,
        // 1 Gbit/s = 1e9 bits/s.
        c_propagation: 1.0e9,
        // 1% churn / sec at swarm level.
        h_0_equivalent: 0.01,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_link_calibration_finite_and_positive() {
        let c = one_link_calibration();
        assert!(c.d > 0.0);
        assert!(c.gamma > 0.0);
        assert!(c.alpha_density >= 0.0);
        assert!(c.beta_flux >= 0.0);
        assert!(c.c_propagation > 0.0);
        assert!(c.h_0_equivalent > 0.0);
    }

    #[test]
    fn one_link_screening_length_is_finite_hops() {
        let c = one_link_calibration();
        let ell = c.screening_length().unwrap();
        // ell = √(100 / 0.01) = √10000 = 100 hops.
        assert!((ell - 100.0).abs() < 1e-6, "ell = {ell}");
    }
}
