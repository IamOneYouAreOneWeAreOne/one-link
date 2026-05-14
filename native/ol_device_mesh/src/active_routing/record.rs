//! Per-(context, device) Beta-posterior counter record.

/// Hard cap on `α` and `β`. Bounds memory + prevents posterior
/// from getting so peaked that fresh signal is ignored. When the
/// counts hit this cap, we apply a half-decay (divide both by 2)
/// on the next observation so the posterior keeps adapting.
pub const MAX_POSTERIOR_COUNT: u32 = 1024;

/// One `Beta(α, β)` posterior plus bookkeeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceActionRecord {
    /// 32-byte hash of the routing context.
    pub context_hash: [u8; 32],
    /// 16-byte device id.
    pub device_id: [u8; 16],
    /// "Acted on this device" count.
    pub alpha: u32,
    /// "Didn't act" count.
    pub beta: u32,
    /// Wall-clock seconds of the most recent observation. Used by
    /// the higher-layer decay sweep.
    pub last_updated_unix: u64,
}

impl DeviceActionRecord {
    /// Fresh record with neutral counts (`Beta(1, 1)`, the uniform
    /// prior). Caller can pre-seed via the cohort prior instead.
    #[must_use]
    pub const fn empty(context_hash: [u8; 32], device_id: [u8; 16]) -> Self {
        Self {
            context_hash,
            device_id,
            alpha: 1,
            beta: 1,
            last_updated_unix: 0,
        }
    }

    /// Record an observation. `acted` is `true` if the user acted
    /// on a message routed to this device in this context.
    /// Saturates at [`MAX_POSTERIOR_COUNT`] via the
    /// "half-decay-then-increment" rule.
    pub fn observe(&mut self, acted: bool, now_unix: u64) {
        if self.alpha.saturating_add(self.beta) >= MAX_POSTERIOR_COUNT {
            self.alpha = (self.alpha / 2).max(1);
            self.beta = (self.beta / 2).max(1);
        }
        if acted {
            self.alpha = self.alpha.saturating_add(1).min(MAX_POSTERIOR_COUNT);
        } else {
            self.beta = self.beta.saturating_add(1).min(MAX_POSTERIOR_COUNT);
        }
        self.last_updated_unix = now_unix;
    }

    /// Posterior mean — Bayes-optimal point estimate of P(act).
    #[must_use]
    pub fn posterior_mean(&self) -> f64 {
        let a = f64::from(self.alpha);
        let b = f64::from(self.beta);
        a / (a + b)
    }

    /// Apply a half-life decay since `last_updated_unix`. Counts
    /// halve every `half_life_secs`. Used by the daemon's periodic
    /// sweep so old observations fade out and the picker can adapt
    /// to drifting user preferences.
    pub fn decay(&mut self, now_unix: u64, half_life_secs: u64) {
        if half_life_secs == 0 || now_unix <= self.last_updated_unix {
            return;
        }
        let elapsed = now_unix - self.last_updated_unix;
        // Number of half-lives elapsed (integer; we don't bother
        // with fractional decays for predictability).
        let n = elapsed / half_life_secs;
        if n == 0 {
            return;
        }
        let shift = n.min(20) as u32;
        // alpha, beta floor at 1 so the posterior never goes to 0.
        let denom = 1u32 << shift;
        self.alpha = (self.alpha / denom).max(1);
        self.beta = (self.beta / denom).max(1);
        self.last_updated_unix = now_unix;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_record_posterior_is_half() {
        let r = DeviceActionRecord::empty([0; 32], [0; 16]);
        assert!((r.posterior_mean() - 0.5).abs() < 1e-12);
    }

    #[test]
    fn observe_act_increases_alpha() {
        let mut r = DeviceActionRecord::empty([0; 32], [0; 16]);
        r.observe(true, 100);
        assert_eq!(r.alpha, 2);
        assert_eq!(r.beta, 1);
        assert!(r.posterior_mean() > 0.5);
    }

    #[test]
    fn observe_dismiss_increases_beta() {
        let mut r = DeviceActionRecord::empty([0; 32], [0; 16]);
        r.observe(false, 100);
        assert_eq!(r.alpha, 1);
        assert_eq!(r.beta, 2);
        assert!(r.posterior_mean() < 0.5);
    }

    #[test]
    fn saturation_triggers_half_decay() {
        let mut r = DeviceActionRecord {
            context_hash: [0; 32],
            device_id: [0; 16],
            alpha: 500,
            beta: 500,
            last_updated_unix: 0,
        };
        // alpha + beta = 1000 < 1024; one more observation OK.
        r.observe(true, 1);
        assert_eq!(r.alpha, 501);
        // alpha + beta = 1001 + 500 = no, 501 + 500 = 1001 still <1024.
        r.alpha = 1000;
        r.beta = 24; // alpha+beta = 1024 exactly → next observe halves.
        r.observe(true, 2);
        assert!(r.alpha <= 600);
        assert!(r.beta <= 24);
    }

    #[test]
    fn decay_half_life_halves_counts() {
        let mut r = DeviceActionRecord {
            context_hash: [0; 32],
            device_id: [0; 16],
            alpha: 100,
            beta: 200,
            last_updated_unix: 0,
        };
        r.decay(60, 60); // one half-life elapsed
        assert_eq!(r.alpha, 50);
        assert_eq!(r.beta, 100);
    }

    #[test]
    fn decay_floors_at_one() {
        let mut r = DeviceActionRecord {
            context_hash: [0; 32],
            device_id: [0; 16],
            alpha: 1,
            beta: 1,
            last_updated_unix: 0,
        };
        r.decay(10_000, 10);
        assert_eq!(r.alpha, 1);
        assert_eq!(r.beta, 1);
    }

    #[test]
    fn decay_zero_half_life_noop() {
        let mut r = DeviceActionRecord {
            context_hash: [0; 32],
            device_id: [0; 16],
            alpha: 50,
            beta: 50,
            last_updated_unix: 0,
        };
        r.decay(10_000, 0);
        assert_eq!(r.alpha, 50);
        assert_eq!(r.beta, 50);
    }
}
