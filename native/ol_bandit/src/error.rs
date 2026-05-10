//! Errors for `ol_bandit`.

use thiserror::Error;

/// Errors from bandit operations.
///
/// Not `Eq` because the `InvalidReward { got: f64 }` variant carries a
/// float (which doesn't impl `Eq` because of NaN). `PartialEq` is fine.
#[derive(Debug, Error, Clone, PartialEq)]
pub enum BanditError {
    /// `Bandit::new` called with `arms.is_empty()`.
    #[error("bandit needs at least one arm")]
    NoArms,

    /// `update` called with arm index out of range.
    #[error("arm index {got} out of range for bandit with {n_arms} arms")]
    ArmIndexOutOfRange {
        /// Provided index.
        got: usize,
        /// Total arms.
        n_arms: usize,
    },

    /// `update` called with reward outside `[0, 1]`.
    #[error("reward must be in [0, 1]; got {got}")]
    InvalidReward {
        /// Provided reward.
        got: f64,
    },
}
