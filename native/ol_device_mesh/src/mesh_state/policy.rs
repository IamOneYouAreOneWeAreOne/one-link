//! Subtree-level policy: which CRDT kind a label uses, and whether
//! mutations to that subtree require a Layer-2 quorum certificate.

use super::state::Subtree;

/// CRDT kind for a subtree. Bound at first-write time and immutable
/// afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubtreePolicyKind {
    /// `LwwRegister` — single LWW value.
    LwwRegister,
    /// `OrSet` — observed-remove set.
    OrSet,
    /// `PnCounter` — per-device positive/negative counter.
    PnCounter,
    /// `LwwMap` — Map<bytes, LWW bytes> with tombstones.
    LwwMap,
}

/// Higher-layer policy for a subtree: kind + whether ops require a
/// quorum certificate. The mesh-state engine reads this at op-apply
/// time; the daemon owns the policy table.
#[derive(Debug, Clone)]
pub struct SubtreePolicy {
    /// CRDT kind for this subtree.
    pub kind: SubtreePolicyKind,
    /// `true` if any op against this subtree requires a Layer-2
    /// [`crate::quorum::QuorumCertificate`].
    pub quorum_gated: bool,
}

impl SubtreePolicy {
    /// A plain (non-quorum-gated) policy of the given kind.
    #[must_use]
    pub const fn plain(kind: SubtreePolicyKind) -> Self {
        Self {
            kind,
            quorum_gated: false,
        }
    }
    /// A quorum-gated policy of the given kind.
    #[must_use]
    pub const fn quorum_gated(kind: SubtreePolicyKind) -> Self {
        Self {
            kind,
            quorum_gated: true,
        }
    }
}

/// What kind is the given subtree?
#[must_use]
pub const fn subtree_kind(subtree: &Subtree) -> SubtreePolicyKind {
    match subtree {
        Subtree::LwwRegister(_) => SubtreePolicyKind::LwwRegister,
        Subtree::OrSet(_) => SubtreePolicyKind::OrSet,
        Subtree::PnCounter(_) => SubtreePolicyKind::PnCounter,
        Subtree::LwwMap(_) => SubtreePolicyKind::LwwMap,
    }
}
