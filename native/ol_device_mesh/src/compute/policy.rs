//! Task class identifier + per-class policy types.

use crate::errors::{DeviceMeshError, DeviceMeshResult};

/// Maximum length of a [`TaskClass`] byte string.
pub const MAX_TASK_CLASS_LEN: usize = 32;

/// Domain-separation tag mixed into request transcripts (referenced
/// by `task.rs`; exported here for symmetry with the rest of the
/// crate's surface).
pub const TASK_CLASS_DOMAIN: &[u8] = b"OL-mesh-task-class-v1";

/// Stable opaque task-class identifier. Higher layers register
/// well-known values (e.g., `transcribe-audio`, `transcode-video`,
/// `llm-inference`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TaskClass {
    bytes: Vec<u8>,
}

impl TaskClass {
    /// Construct from raw bytes. Errors if longer than
    /// [`MAX_TASK_CLASS_LEN`] or empty.
    pub fn new(bytes: &[u8]) -> DeviceMeshResult<Self> {
        if bytes.is_empty() {
            return Err(DeviceMeshError::TaskClassEmpty);
        }
        if bytes.len() > MAX_TASK_CLASS_LEN {
            return Err(DeviceMeshError::TaskClassTooLong {
                got: bytes.len(),
                max: MAX_TASK_CLASS_LEN,
            });
        }
        Ok(Self { bytes: bytes.to_vec() })
    }

    /// Borrow the raw byte representation.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Per-task-class policy controlling executor selection + gating.
#[derive(Debug, Clone)]
pub struct TaskPolicy {
    /// The class this policy applies to.
    pub class: TaskClass,
    /// Minimum battery percentage the executor must have (0..100).
    /// 0 means "no battery threshold."
    pub min_battery_pct: u8,
    /// Max wall-clock seconds the executor may take.
    pub max_wall_secs: u32,
    /// If true, a Layer-2 [`crate::quorum::QuorumCertificate`] is
    /// required before this task class can be dispatched.
    pub requires_quorum: bool,
    /// If true, the executor must hold the
    /// [`super::DeviceCapability::Tee`] capability (confidential
    /// compute).
    pub requires_tee: bool,
}

impl TaskPolicy {
    /// Conservative default for general-purpose tasks.
    pub fn general(class: TaskClass) -> Self {
        Self {
            class,
            min_battery_pct: 20,
            max_wall_secs: 3600,
            requires_quorum: false,
            requires_tee: false,
        }
    }

    /// Hardened policy for high-stakes ops (touches master, dumps
    /// >10 MB, contacts external service). Requires K-of-N + TEE.
    pub fn high_stakes(class: TaskClass) -> Self {
        Self {
            class,
            min_battery_pct: 50,
            max_wall_secs: 600,
            requires_quorum: true,
            requires_tee: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_class_round_trip() {
        let c = TaskClass::new(b"transcribe-audio").unwrap();
        assert_eq!(c.bytes(), b"transcribe-audio");
    }

    #[test]
    fn empty_task_class_rejected() {
        let err = TaskClass::new(b"").unwrap_err();
        assert!(matches!(err, DeviceMeshError::TaskClassEmpty));
    }

    #[test]
    fn oversize_task_class_rejected() {
        let big = vec![b'x'; MAX_TASK_CLASS_LEN + 1];
        let err = TaskClass::new(&big).unwrap_err();
        assert!(matches!(err, DeviceMeshError::TaskClassTooLong { .. }));
    }

    #[test]
    fn general_policy_defaults() {
        let p = TaskPolicy::general(TaskClass::new(b"x").unwrap());
        assert_eq!(p.min_battery_pct, 20);
        assert!(!p.requires_quorum);
        assert!(!p.requires_tee);
    }

    #[test]
    fn high_stakes_policy_requires_quorum_and_tee() {
        let p = TaskPolicy::high_stakes(TaskClass::new(b"rotate-master").unwrap());
        assert!(p.requires_quorum);
        assert!(p.requires_tee);
        assert!(p.min_battery_pct >= 50);
    }
}
