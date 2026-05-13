//! Authenticated CRDT operations.
//!
//! Every state change ([`AuthenticatedOp`]) is signed by the
//! emitting device's Layer-1 subkey. Replicas verify the signature
//! under the master-attested subkey VK before merging.

use ol_pqsig::{HybridVerifyingKey, HYBRID_SIG_LEN};

use crate::errors::{DeviceMeshError, DeviceMeshResult};
use crate::subkey::{DeviceSubkey, DEVICE_ID_LEN};

use super::state::OrSetTag;

/// Domain-separation tag for the op signing transcript.
pub const AUTH_OP_DOMAIN: &[u8] = b"OL-mesh-auth-op-v1";

/// Maximum subtree-label byte length.
pub const MAX_SUBTREE_LABEL_LEN: usize = 64;

/// Maximum byte length of a single LWW value / map value.
pub const MAX_DELTA_VALUE_LEN: usize = 8192;

/// One CRDT delta. Higher layers compose these into batches; the
/// mesh-state engine applies them one at a time to keep canonical
/// hashing deterministic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delta {
    /// Write `(value, ts)` to a [`crate::mesh_state::LwwRegister`].
    LwwSet {
        /// Value bytes.
        value: Vec<u8>,
        /// LWW timestamp.
        ts: u64,
    },
    /// Tagged add to an [`crate::mesh_state::OrSet`].
    OrAdd {
        /// Element bytes.
        element: Vec<u8>,
        /// Tag uniquely identifying this add (typically
        /// `(device_id, seq)`-derived).
        tag: OrSetTag,
    },
    /// Tagged remove from an [`crate::mesh_state::OrSet`].
    OrRemove {
        /// Element bytes.
        element: Vec<u8>,
        /// Tag of the add being removed.
        tag: OrSetTag,
    },
    /// Adjust a [`crate::mesh_state::PnCounter`] slot.
    Counter {
        /// Per-counter device id. Typically the emitter's own id.
        device_id: [u8; DEVICE_ID_LEN],
        /// Signed delta (positive accumulates into pos; negative
        /// into neg).
        delta: i64,
    },
    /// Put `(value, ts)` into an [`crate::mesh_state::LwwMap`].
    MapPut {
        /// Map key.
        key: Vec<u8>,
        /// Map value.
        value: Vec<u8>,
        /// LWW timestamp.
        ts: u64,
    },
    /// Tombstone an [`crate::mesh_state::LwwMap`] entry.
    MapDelete {
        /// Map key.
        key: Vec<u8>,
        /// LWW timestamp.
        ts: u64,
    },
}

impl Delta {
    /// One-byte discriminant used in the canonical transcript.
    #[must_use]
    pub fn kind_tag(&self) -> u8 {
        match self {
            Self::LwwSet { .. } => 1,
            Self::OrAdd { .. } => 2,
            Self::OrRemove { .. } => 3,
            Self::Counter { .. } => 4,
            Self::MapPut { .. } => 5,
            Self::MapDelete { .. } => 6,
        }
    }
    /// True iff this delta requires the subtree to be of the kind
    /// implied by `kind_tag`. Used by upstream policy checks.
    #[must_use]
    pub fn validate_size(&self) -> DeviceMeshResult<()> {
        match self {
            Self::LwwSet { value, .. } | Self::MapPut { value, .. } => {
                if value.len() > MAX_DELTA_VALUE_LEN {
                    return Err(DeviceMeshError::DeltaValueTooLong {
                        got: value.len(),
                        max: MAX_DELTA_VALUE_LEN,
                    });
                }
            }
            _ => {}
        }
        Ok(())
    }
    fn canonical_into(&self, out: &mut Vec<u8>) {
        out.push(self.kind_tag());
        match self {
            Self::LwwSet { value, ts } => {
                push_bytes(out, value);
                out.extend_from_slice(&ts.to_be_bytes());
            }
            Self::OrAdd { element, tag } => {
                push_bytes(out, element);
                out.extend_from_slice(tag);
            }
            Self::OrRemove { element, tag } => {
                push_bytes(out, element);
                out.extend_from_slice(tag);
            }
            Self::Counter { device_id, delta } => {
                out.extend_from_slice(device_id);
                out.extend_from_slice(&delta.to_be_bytes());
            }
            Self::MapPut { key, value, ts } => {
                push_bytes(out, key);
                push_bytes(out, value);
                out.extend_from_slice(&ts.to_be_bytes());
            }
            Self::MapDelete { key, ts } => {
                push_bytes(out, key);
                out.extend_from_slice(&ts.to_be_bytes());
            }
        }
    }
}

fn push_bytes(out: &mut Vec<u8>, b: &[u8]) {
    let len = u32::try_from(b.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&b[..len as usize]);
}

/// An op signed by the emitter's subkey, ready for sibling replicas
/// to verify + merge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedOp {
    /// Target subtree label.
    pub subtree: Vec<u8>,
    /// The CRDT delta.
    pub delta: Delta,
    /// Emitter device id.
    pub device_id: [u8; DEVICE_ID_LEN],
    /// Emitter's subkey day-index.
    pub day_index: u64,
    /// Per-device monotonic sequence number. Replicas drop ops where
    /// `seq <= last_seen[device_id]` to defeat replay.
    pub seq: u64,
    /// Wall-clock seconds at issue time. Layer 3 doesn't enforce a
    /// skew window; higher layers may.
    pub wall_unix: u64,
    /// Subkey signature over the canonical transcript.
    pub subkey_sig: Vec<u8>,
}

impl AuthenticatedOp {
    /// Canonical bytes the subkey signs over.
    pub fn canonical_transcript(
        subtree: &[u8],
        delta: &Delta,
        device_id: &[u8; DEVICE_ID_LEN],
        day_index: u64,
        seq: u64,
        wall_unix: u64,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            AUTH_OP_DOMAIN.len() + 4 + subtree.len() + 1 + 64 + DEVICE_ID_LEN + 8 + 8 + 8,
        );
        out.extend_from_slice(AUTH_OP_DOMAIN);
        push_bytes(&mut out, subtree);
        delta.canonical_into(&mut out);
        out.extend_from_slice(device_id);
        out.extend_from_slice(&day_index.to_be_bytes());
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&wall_unix.to_be_bytes());
        out
    }
    /// Sign a delta into an [`AuthenticatedOp`].
    pub fn sign(
        subkey: &DeviceSubkey,
        subtree: Vec<u8>,
        delta: Delta,
        seq: u64,
        wall_unix: u64,
    ) -> DeviceMeshResult<Self> {
        if subtree.len() > MAX_SUBTREE_LABEL_LEN {
            return Err(DeviceMeshError::SubtreeLabelTooLong {
                got: subtree.len(),
                max: MAX_SUBTREE_LABEL_LEN,
            });
        }
        delta.validate_size()?;
        let transcript = Self::canonical_transcript(
            &subtree,
            &delta,
            subkey.device_id(),
            subkey.day_index(),
            seq,
            wall_unix,
        );
        let sig = subkey.sign(&transcript)?;
        Ok(Self {
            subtree,
            delta,
            device_id: *subkey.device_id(),
            day_index: subkey.day_index(),
            seq,
            wall_unix,
            subkey_sig: sig.to_vec(),
        })
    }
    /// Verify the signature under the supplied subkey VK. Caller is
    /// responsible for proving the VK is the emitter's (via a
    /// master-signed [`crate::SubkeyAttestation`]).
    pub fn verify(&self, subkey_vk: &HybridVerifyingKey) -> DeviceMeshResult<()> {
        if self.subkey_sig.len() != HYBRID_SIG_LEN {
            return Err(DeviceMeshError::BadLength {
                expected: HYBRID_SIG_LEN,
                got: self.subkey_sig.len(),
            });
        }
        if self.subtree.len() > MAX_SUBTREE_LABEL_LEN {
            return Err(DeviceMeshError::SubtreeLabelTooLong {
                got: self.subtree.len(),
                max: MAX_SUBTREE_LABEL_LEN,
            });
        }
        self.delta.validate_size()?;
        let transcript = Self::canonical_transcript(
            &self.subtree,
            &self.delta,
            &self.device_id,
            self.day_index,
            self.seq,
            self.wall_unix,
        );
        subkey_vk
            .verify(&transcript, &self.subkey_sig)
            .map_err(|_| DeviceMeshError::AuthOpVerifyFail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::master::MasterIdentity;
    use crate::subkey::{fresh_device_id, mint_subkey};
    use crate::DeviceClass;
    use rand::rngs::OsRng;

    fn make() -> DeviceSubkey {
        let master = MasterIdentity::generate(&mut OsRng);
        let id = fresh_device_id(&mut OsRng);
        let (sk, _att) =
            mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
        sk
    }

    #[test]
    fn sign_verify_round_trip() {
        let sk = make();
        let op = AuthenticatedOp::sign(
            &sk,
            b"contacts".to_vec(),
            Delta::OrAdd {
                element: b"alice@example".to_vec(),
                tag: [0x01; 16],
            },
            1,
            1_700_000_000,
        )
        .unwrap();
        op.verify(&sk.verifying_key()).unwrap();
    }

    #[test]
    fn cross_subkey_verify_fails() {
        let sk_a = make();
        let sk_b = make();
        let op = AuthenticatedOp::sign(
            &sk_a,
            b"x".to_vec(),
            Delta::LwwSet { value: b"v".to_vec(), ts: 1 },
            1,
            1,
        )
        .unwrap();
        let err = op.verify(&sk_b.verifying_key()).unwrap_err();
        assert!(matches!(err, DeviceMeshError::AuthOpVerifyFail));
    }

    #[test]
    fn tampered_subtree_breaks_verify() {
        let sk = make();
        let mut op = AuthenticatedOp::sign(
            &sk,
            b"x".to_vec(),
            Delta::LwwSet { value: b"v".to_vec(), ts: 1 },
            1,
            1,
        )
        .unwrap();
        op.subtree = b"y".to_vec();
        let err = op.verify(&sk.verifying_key()).unwrap_err();
        assert!(matches!(err, DeviceMeshError::AuthOpVerifyFail));
    }

    #[test]
    fn oversize_subtree_label_rejected_at_sign() {
        let sk = make();
        let big = vec![b'x'; MAX_SUBTREE_LABEL_LEN + 1];
        let err = AuthenticatedOp::sign(
            &sk,
            big,
            Delta::LwwSet { value: b"v".to_vec(), ts: 1 },
            1,
            1,
        )
        .unwrap_err();
        assert!(matches!(err, DeviceMeshError::SubtreeLabelTooLong { .. }));
    }

    #[test]
    fn oversize_lww_value_rejected_at_sign() {
        let sk = make();
        let big = vec![0u8; MAX_DELTA_VALUE_LEN + 1];
        let err = AuthenticatedOp::sign(
            &sk,
            b"x".to_vec(),
            Delta::LwwSet { value: big, ts: 1 },
            1,
            1,
        )
        .unwrap_err();
        assert!(matches!(err, DeviceMeshError::DeltaValueTooLong { .. }));
    }
}
