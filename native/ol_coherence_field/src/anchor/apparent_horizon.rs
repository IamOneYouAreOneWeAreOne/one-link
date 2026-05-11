//! Apparent-horizon anchor scale `g_A = c · H_0 / (2π)`.
//!
//! ## Cosmology side
//!
//! On galaxy scales, `g_A = c · H_0 / (2π) ≈ 1.04 × 10⁻¹⁰ m/s²` for
//! Planck `H_0 = 67.36 km/s/Mpc`. This is the present-epoch apparent-
//! horizon acceleration — the absolute scale at which the rotation-
//! curve flat-velocity asymptote is anchored. Every rotation curve
//! in the SPARC sample lives just below this scale; nothing exceeds
//! it.
//!
//! ## Network analog
//!
//! Map the cosmological quantities to network observables:
//!
//! - `c` (speed of light) → `c_wire`: max physical link bandwidth
//!   (bits/sec). The fastest a packet can plausibly move.
//! - `H_0` (Hubble rate) → `H_swarm`: rate of peer churn relative to
//!   swarm size (peer-departures per second per total peer count).
//!
//! Then `g_A_network = c_wire · H_swarm / (2π)` is the absolute
//! per-peer pressure ceiling: no peer can drive routing pressure
//! above this without violating the swarm's mass-energy budget. It
//! becomes the hard upper bound on any source term contribution.
//!
//! This is the mathematical-ceiling guarantee: an adversarial relay
//! that fakes its metrics can't push beyond `g_A` without becoming
//! detectable on the swarm-wide observable.

/// Inputs needed to calibrate the apparent-horizon anchor.
#[derive(Debug, Clone, Copy)]
pub struct ApparentHorizonInputs {
    /// Maximum physical wire speed available in the swarm (bits/sec).
    /// Network analog of the speed of light.
    pub c_wire: f64,
    /// Peer-churn rate normalized by swarm size (peer-departures per
    /// second per total peer). Network analog of `H_0`.
    pub h_swarm: f64,
}

impl Default for ApparentHorizonInputs {
    fn default() -> Self {
        Self {
            // 1 Gbit/s wire (LAN baseline).
            c_wire: 1.0e9,
            // 1 peer departure per 100 peers per second (1% churn/s).
            h_swarm: 0.01,
        }
    }
}

/// Compute `g_A = c · H_0 / (2π)`. Returns `None` for non-physical
/// inputs.
#[must_use]
pub fn apparent_horizon_anchor(inputs: ApparentHorizonInputs) -> Option<f64> {
    if inputs.c_wire <= 0.0
        || inputs.h_swarm <= 0.0
        || !inputs.c_wire.is_finite()
        || !inputs.h_swarm.is_finite()
    {
        return None;
    }
    Some(inputs.c_wire * inputs.h_swarm / (2.0 * std::f64::consts::PI))
}

/// Galaxy-scale `g_A` for Planck `H_0`. Reference constant used by
/// the cross-domain calibration test that verifies the network
/// calculation can reproduce the cosmological number when fed
/// cosmological inputs.
///
/// `c = 299_792_458 m/s`, `H_0 = 67.36 km/s/Mpc = 2.184 × 10⁻¹⁸ /s`,
/// so `g_A = 1.042 × 10⁻¹⁰ m/s²`.
pub const G_A_GALAXY_PLANCK: f64 = 1.0416e-10;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_basic_network_value() {
        // c = 1 Gbit/s, H_swarm = 0.01 /s → g_A ≈ 1.59 × 10⁶
        // bits/s² (routing-pressure ceiling).
        let g_a = apparent_horizon_anchor(ApparentHorizonInputs {
            c_wire: 1.0e9,
            h_swarm: 0.01,
        })
        .unwrap();
        let expected = 1.0e9 * 0.01 / (2.0 * std::f64::consts::PI);
        assert!((g_a - expected).abs() < 1e-6);
    }

    #[test]
    fn anchor_rejects_non_physical() {
        assert!(apparent_horizon_anchor(ApparentHorizonInputs {
            c_wire: -1.0,
            h_swarm: 0.01,
        })
        .is_none());
        assert!(apparent_horizon_anchor(ApparentHorizonInputs {
            c_wire: 1.0e9,
            h_swarm: -0.01,
        })
        .is_none());
        assert!(apparent_horizon_anchor(ApparentHorizonInputs {
            c_wire: 0.0,
            h_swarm: 0.01,
        })
        .is_none());
    }

    #[test]
    fn anchor_reproduces_galaxy_constant_under_cosmological_inputs() {
        // Plug in real cosmological inputs: c = 299,792,458 m/s,
        // H_0 = 67.36 km/s/Mpc → 2.184 × 10⁻¹⁸ /s. The same formula
        // that drives the network anchor should produce the canonical
        // galaxy g_A — that's the cross-domain unity test.
        let c = 299_792_458.0_f64;
        let h_0 = 67.36e3 / (3.0857e22); // km/s/Mpc → /s
        let g_a = apparent_horizon_anchor(ApparentHorizonInputs {
            c_wire: c,
            h_swarm: h_0,
        })
        .unwrap();
        let relative_error = (g_a - G_A_GALAXY_PLANCK).abs() / G_A_GALAXY_PLANCK;
        assert!(
            relative_error < 0.01,
            "g_A from formula = {g_a}; expected ≈ {} (galaxy reference)",
            G_A_GALAXY_PLANCK
        );
    }
}
