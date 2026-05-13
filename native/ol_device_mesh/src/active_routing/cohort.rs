//! Cohort-prior cold-start.
//!
//! When a fresh user mints a fresh master, the routing history is
//! empty. Picking purely-uniformly across devices works but is
//! slow to converge. A cohort prior lets the daemon pre-seed the
//! posterior with "typical-user" values per device class so the
//! picker starts with a reasonable bias.

use crate::device_class::DeviceClass;

/// Default `α` for the cohort prior (uniform Beta(1, 1)).
pub const COHORT_DEFAULT_ALPHA: u32 = 1;

/// Default `β` for the cohort prior.
pub const COHORT_DEFAULT_BETA: u32 = 1;

/// Cold-start prior. Defaults to uniform Beta(1, 1); callers can
/// adjust per-class to bias toward "people usually act on phone
/// for DMs" / "people usually act on laptop for work files" /
/// etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CohortPrior {
    /// Default α applied to every (context, device) pair.
    pub default_alpha: u32,
    /// Default β applied to every (context, device) pair.
    pub default_beta: u32,
    /// Extra α applied when the device is a Phone.
    pub phone_alpha_bonus: u32,
    /// Extra α applied when the device is a Laptop.
    pub laptop_alpha_bonus: u32,
    /// Extra α applied when the device is a Desktop.
    pub desktop_alpha_bonus: u32,
}

impl CohortPrior {
    /// Uniform prior (no class-specific bias). Slow to converge
    /// but unbiased.
    #[must_use]
    pub fn uniform() -> Self {
        Self {
            default_alpha: COHORT_DEFAULT_ALPHA,
            default_beta: COHORT_DEFAULT_BETA,
            phone_alpha_bonus: 0,
            laptop_alpha_bonus: 0,
            desktop_alpha_bonus: 0,
        }
    }

    /// Conservative bias: phone gets a small boost (most messages
    /// land there first); laptop gets a moderate boost for work
    /// stuff; desktop gets a small boost. Daemon-tunable.
    #[must_use]
    pub fn typical_user() -> Self {
        Self {
            default_alpha: COHORT_DEFAULT_ALPHA,
            default_beta: COHORT_DEFAULT_BETA,
            phone_alpha_bonus: 3,
            laptop_alpha_bonus: 2,
            desktop_alpha_bonus: 1,
        }
    }

    /// `(α, β)` for `class`. Sums the default + class-specific
    /// bonus.
    #[must_use]
    pub fn for_class(&self, class: DeviceClass) -> (u32, u32) {
        let bonus = match class {
            DeviceClass::Phone => self.phone_alpha_bonus,
            DeviceClass::Laptop => self.laptop_alpha_bonus,
            DeviceClass::Desktop => self.desktop_alpha_bonus,
            _ => 0,
        };
        (self.default_alpha.saturating_add(bonus), self.default_beta)
    }
}

impl Default for CohortPrior {
    fn default() -> Self {
        Self::uniform()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_no_bias() {
        let p = CohortPrior::uniform();
        for c in [
            DeviceClass::Phone,
            DeviceClass::Laptop,
            DeviceClass::Desktop,
            DeviceClass::Generic,
        ] {
            assert_eq!(p.for_class(c), (1, 1));
        }
    }

    #[test]
    fn typical_user_biases_in_order() {
        let p = CohortPrior::typical_user();
        let (phone_a, _) = p.for_class(DeviceClass::Phone);
        let (laptop_a, _) = p.for_class(DeviceClass::Laptop);
        let (desktop_a, _) = p.for_class(DeviceClass::Desktop);
        let (generic_a, _) = p.for_class(DeviceClass::Generic);
        assert!(phone_a > laptop_a);
        assert!(laptop_a > desktop_a);
        assert!(desktop_a > generic_a);
    }
}
