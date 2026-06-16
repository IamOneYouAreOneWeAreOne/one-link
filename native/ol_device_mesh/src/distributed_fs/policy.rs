//! Erasure-coding policy.
//!
//! `(k, m)` Reed-Solomon: `k` data shards + `m` parity shards.
//! `m` parity is computed by the underlying `ol_erasure` crate.
//! `min_devices` is the minimum number of DISTINCT devices that must
//! each hold a copy of each shard for the file to count as "durable
//! under the policy."

use crate::errors::{DeviceMeshError, DeviceMeshResult};

/// Upper bound on `k + m`. Reed-Solomon over GF(2^8) supports up to
/// 256, but we cap lower for predictable verify cost.
pub const MAX_K_PLUS_M: u8 = 32;

/// Erasure-coding policy parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErasurePolicy {
    /// Number of data shards.
    pub k: u8,
    /// Number of parity shards.
    pub m: u8,
    /// Minimum number of distinct devices that must each hold a
    /// copy of every shard for the file to count as durable.
    pub min_devices_per_shard: u8,
}

impl ErasurePolicy {
    /// Construct a new policy and validate its shape.
    pub const fn new(k: u8, m: u8, min_devices_per_shard: u8) -> DeviceMeshResult<Self> {
        if k == 0 {
            return Err(DeviceMeshError::ErasurePolicyZeroData);
        }
        if (k as u16) + (m as u16) > MAX_K_PLUS_M as u16 {
            return Err(DeviceMeshError::ErasurePolicyOversize {
                k,
                m,
                max: MAX_K_PLUS_M,
            });
        }
        if min_devices_per_shard == 0 {
            return Err(DeviceMeshError::ErasurePolicyZeroMinDevices);
        }
        Ok(Self {
            k,
            m,
            min_devices_per_shard,
        })
    }

    /// Total shard count `k + m`.
    #[must_use]
    pub const fn total_shards(self) -> u16 {
        (self.k as u16) + (self.m as u16)
    }

    /// Redundancy ratio `(k + m) / k`. For (10, 4): 1.4×. For
    /// (3, 2): 1.67×.
    #[must_use]
    pub fn redundancy_ratio(self) -> f64 {
        (self.total_shards() as f64) / (self.k as f64)
    }

    /// Number of additional shard-copies needed to satisfy the
    /// `min_devices_per_shard` rule.
    #[must_use]
    pub const fn needed_for_durability(self, current_holders: usize) -> usize {
        (self.min_devices_per_shard as usize).saturating_sub(current_holders)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_round_trips() {
        let p = ErasurePolicy::new(10, 4, 2).unwrap();
        assert_eq!(p.k, 10);
        assert_eq!(p.m, 4);
        assert_eq!(p.min_devices_per_shard, 2);
        assert_eq!(p.total_shards(), 14);
        assert!((p.redundancy_ratio() - 1.4).abs() < 1e-9);
    }

    #[test]
    fn zero_k_rejected() {
        let err = ErasurePolicy::new(0, 4, 2).unwrap_err();
        assert!(matches!(err, DeviceMeshError::ErasurePolicyZeroData));
    }

    #[test]
    fn oversize_rejected() {
        let err = ErasurePolicy::new(28, 8, 2).unwrap_err();
        assert!(matches!(err, DeviceMeshError::ErasurePolicyOversize { .. }));
    }

    #[test]
    fn zero_min_devices_rejected() {
        let err = ErasurePolicy::new(10, 4, 0).unwrap_err();
        assert!(matches!(err, DeviceMeshError::ErasurePolicyZeroMinDevices));
    }

    #[test]
    fn needed_for_durability_matches_min() {
        let p = ErasurePolicy::new(10, 4, 3).unwrap();
        assert_eq!(p.needed_for_durability(0), 3);
        assert_eq!(p.needed_for_durability(2), 1);
        assert_eq!(p.needed_for_durability(3), 0);
        assert_eq!(p.needed_for_durability(10), 0);
    }
}
