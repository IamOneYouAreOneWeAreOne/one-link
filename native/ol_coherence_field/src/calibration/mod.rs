//! Cross-domain calibration.
//!
//! The whole point of `ol_coherence_field` as a shared crate is that
//! the **same Rust code** plus a **per-domain calibration** produces
//! the field for One Link (network), `OneField` Mesh (RF), and `BioMesh`
//! (biological signals). This module supplies the per-domain
//! constants.
//!
//! The algebra is identical: reaction-diffusion → Helmholtz reduction
//! → Green-function nonlocal kernel → BE-RAR interpolation →
//! apparent-horizon anchor. Each domain picks its own
//! `(D, Γ, c_wire_equivalent, H_swarm_equivalent)` from observed
//! local metrics.
//!
//! This is the software expression of the unified-field claim: one
//! crate, three calibrations.

mod bio_mesh;
mod one_field;
mod one_link;

pub use bio_mesh::bio_mesh_calibration;
pub use one_field::one_field_calibration;
pub use one_link::one_link_calibration;

/// Which physical / network domain this calibration represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Domain {
    /// One Link network swarm.
    OneLink,
    /// `OneField` Mesh RF `τ_c` routing.
    OneField,
    /// `BioMesh` biological-signal field.
    BioMesh,
}

/// Per-domain coherence-field calibration.
///
/// Stored as a flat struct (no domain-specific types) so the same
/// solver code consumes any of them without conditional branches.
#[derive(Debug, Clone, Copy)]
pub struct Calibration {
    /// Which domain this calibration is for. Used for diagnostics +
    /// cross-domain dispatch in the daemon.
    pub domain: Domain,
    /// Diffusion coefficient. Units: domain-specific.
    pub d: f64,
    /// Damping / decay rate. Units: 1/(domain time).
    pub gamma: f64,
    /// Density-source weight α.
    pub alpha_density: f64,
    /// Flux-source weight β.
    pub beta_flux: f64,
    /// Support-phase transition midpoint `c0`. Galaxy-side best fit
    /// is 0.80; the other domains can override.
    pub support_phase_c0: f64,
    /// Support-phase transition width `w_phase`. Galaxy-side best
    /// fit is 0.12.
    pub support_phase_w: f64,
    /// `c`-analog: maximum signal propagation speed in the domain.
    /// One Link: max wire bps. `OneField`: c-of-light (RF). `BioMesh`:
    /// max signal-propagation rate.
    pub c_propagation: f64,
    /// `H_0`-analog: domain-equivalent "Hubble rate" (rate of
    /// system-level perturbation per unit system size). One Link:
    /// peer-churn fraction / sec. `OneField`: tropospheric-fade rate.
    /// `BioMesh`: metabolic-turnover rate.
    pub h_0_equivalent: f64,
}

impl Calibration {
    /// Derived: screening length `ell_screen = √(D / Γ)`.
    #[must_use]
    pub fn screening_length(&self) -> Option<f64> {
        crate::anchor::screening_length(self.d, self.gamma)
    }

    /// Derived: apparent-horizon anchor `g_A`.
    #[must_use]
    pub fn apparent_horizon_anchor(&self) -> Option<f64> {
        crate::anchor::apparent_horizon_anchor(crate::anchor::ApparentHorizonInputs {
            c_wire: self.c_propagation,
            h_swarm: self.h_0_equivalent,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_domain_calibrations_yield_sensible_anchors() {
        // Each domain should produce a finite, positive g_A. The
        // ratios should differ by many orders of magnitude (the whole
        // point of cross-domain calibration is that the scales are
        // domain-specific even though the algebra is shared).
        let ol = one_link_calibration();
        let of = one_field_calibration();
        let bm = bio_mesh_calibration();
        let one_link_anchor = ol.apparent_horizon_anchor().unwrap();
        let one_field_anchor = of.apparent_horizon_anchor().unwrap();
        let bio_mesh_anchor = bm.apparent_horizon_anchor().unwrap();
        assert!(one_link_anchor > 0.0 && one_link_anchor.is_finite());
        assert!(one_field_anchor > 0.0 && one_field_anchor.is_finite());
        assert!(bio_mesh_anchor > 0.0 && bio_mesh_anchor.is_finite());
    }

    #[test]
    fn calibrations_distinguish_domains_in_anchor_scale() {
        // Screening lengths are in different unit systems (hops vs
        // meters vs mm) so direct numerical comparison isn't
        // meaningful. The apparent-horizon anchor g_A, built from
        // c_propagation · h_0_equivalent / (2π), IS a physical
        // quantity per domain — the magnitudes should differ
        // substantially.
        let ol = one_link_calibration();
        let of = one_field_calibration();
        let bm = bio_mesh_calibration();
        let one_link_anchor = ol.apparent_horizon_anchor().unwrap();
        let one_field_anchor = of.apparent_horizon_anchor().unwrap();
        let bio_mesh_anchor = bm.apparent_horizon_anchor().unwrap();
        let largest = one_link_anchor.max(one_field_anchor).max(bio_mesh_anchor);
        let smallest = one_link_anchor.min(one_field_anchor).min(bio_mesh_anchor);
        assert!(
            largest / smallest > 100.0,
            "anchors too close across domains: largest = {largest}, smallest = {smallest}",
        );
    }
}
