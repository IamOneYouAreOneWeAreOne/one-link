//! `TaskRequest` + `TaskResult` signed envelopes.

use blake3::Hasher;
use ol_pqsig::{HybridVerifyingKey, HYBRID_SIG_LEN};

use crate::distributed_fs::{FileId, FILE_ID_LEN};
use crate::errors::{DeviceMeshError, DeviceMeshResult};
use crate::subkey::{DeviceSubkey, DEVICE_ID_LEN};

use super::capability::DeviceCapability;
use super::policy::{TaskClass, MAX_TASK_CLASS_LEN};

/// Domain-separation tag for task-request signing.
pub const TASK_REQUEST_DOMAIN: &[u8] = b"OL-mesh-task-request-v1";

/// Domain-separation tag for task-result signing.
pub const TASK_RESULT_DOMAIN: &[u8] = b"OL-mesh-task-result-v1";

/// 32-byte content-addressed handle for a [`TaskRequest`] —
/// BLAKE3 over its canonical transcript.
pub type TaskRequestId = [u8; 32];

/// Length of the per-request nonce.
pub const TASK_NONCE_LEN: usize = 16;

/// Maximum required-capabilities list length on a request.
pub const MAX_REQUIRED_CAPS_PER_TASK: usize = 16;

/// Requester-signed task request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRequest {
    /// Task class identifier (e.g. `b"transcribe-audio"` /
    /// `b"transcode-video"` / `b"llm-inference"`).
    pub task_class: TaskClass,
    /// Requester device.
    pub requester_device_id: [u8; DEVICE_ID_LEN],
    /// Requester subkey day-index at sign.
    pub requester_day_index: u64,
    /// Content-addressed `FileId` of the input bundle.
    pub input_file_id: FileId,
    /// Capabilities the executor MUST hold (sorted ascending).
    pub required_capabilities: Vec<DeviceCapability>,
    /// Max wall-clock seconds the executor may take.
    pub max_wall_secs: u32,
    /// Max byte size of the output.
    pub max_output_bytes: u64,
    /// Wall-clock seconds at request issue.
    pub issued_unix: u64,
    /// Wall-clock seconds the request expires.
    pub deadline_unix: u64,
    /// Per-request nonce. Executors track recently-seen nonces to
    /// drop duplicates.
    pub nonce: [u8; TASK_NONCE_LEN],
    /// Requester's subkey signature.
    pub requester_sig: Vec<u8>,
}

impl TaskRequest {
    /// Canonical bytes the requester signs.
    ///
    /// 10 args reflects the signed-field surface of the protocol;
    /// the transcript is structural, not a logical bundle.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn canonical_transcript(
        task_class: &TaskClass,
        requester_device_id: &[u8; DEVICE_ID_LEN],
        requester_day_index: u64,
        input_file_id: &FileId,
        required_capabilities: &[DeviceCapability],
        max_wall_secs: u32,
        max_output_bytes: u64,
        issued_unix: u64,
        deadline_unix: u64,
        nonce: &[u8; TASK_NONCE_LEN],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            TASK_REQUEST_DOMAIN.len()
                + 2
                + task_class.bytes().len()
                + DEVICE_ID_LEN
                + 8
                + FILE_ID_LEN
                + 2
                + required_capabilities.len() * 8
                + 4
                + 8
                + 8
                + 8
                + TASK_NONCE_LEN,
        );
        out.extend_from_slice(TASK_REQUEST_DOMAIN);
        let cl = task_class.bytes();
        let cl_len = u16::try_from(cl.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&cl_len.to_be_bytes());
        out.extend_from_slice(cl);
        out.extend_from_slice(requester_device_id);
        out.extend_from_slice(&requester_day_index.to_be_bytes());
        out.extend_from_slice(input_file_id);
        let n_caps = u16::try_from(required_capabilities.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&n_caps.to_be_bytes());
        for c in required_capabilities {
            out.extend_from_slice(&c.tag());
        }
        out.extend_from_slice(&max_wall_secs.to_be_bytes());
        out.extend_from_slice(&max_output_bytes.to_be_bytes());
        out.extend_from_slice(&issued_unix.to_be_bytes());
        out.extend_from_slice(&deadline_unix.to_be_bytes());
        out.extend_from_slice(nonce);
        out
    }

    /// Compute the content-addressed [`TaskRequestId`].
    #[must_use]
    pub fn request_id(&self) -> TaskRequestId {
        task_request_id(&self.canonical_transcript_for_id())
    }

    fn canonical_transcript_for_id(&self) -> Vec<u8> {
        Self::canonical_transcript(
            &self.task_class,
            &self.requester_device_id,
            self.requester_day_index,
            &self.input_file_id,
            &self.required_capabilities,
            self.max_wall_secs,
            self.max_output_bytes,
            self.issued_unix,
            self.deadline_unix,
            &self.nonce,
        )
    }

    /// Validate shape (sorted capabilities, bounded sizes).
    pub fn shape_check(&self) -> DeviceMeshResult<()> {
        if self.task_class.bytes().len() > MAX_TASK_CLASS_LEN {
            return Err(DeviceMeshError::TaskClassTooLong {
                got: self.task_class.bytes().len(),
                max: MAX_TASK_CLASS_LEN,
            });
        }
        if self.required_capabilities.len() > MAX_REQUIRED_CAPS_PER_TASK {
            return Err(DeviceMeshError::TaskTooManyCapabilities {
                got: self.required_capabilities.len(),
                max: MAX_REQUIRED_CAPS_PER_TASK,
            });
        }
        let mut prev: Option<DeviceCapability> = None;
        for c in &self.required_capabilities {
            if let Some(p) = prev {
                if *c <= p {
                    return Err(DeviceMeshError::TaskCapabilitiesNotSorted);
                }
            }
            prev = Some(*c);
        }
        if self.deadline_unix <= self.issued_unix {
            return Err(DeviceMeshError::TaskDeadlineNotAfterIssue {
                issued_unix: self.issued_unix,
                deadline_unix: self.deadline_unix,
            });
        }
        if self.requester_sig.len() != HYBRID_SIG_LEN {
            return Err(DeviceMeshError::BadLength {
                expected: HYBRID_SIG_LEN,
                got: self.requester_sig.len(),
            });
        }
        Ok(())
    }

    /// Verify the requester's signature.
    pub fn verify(&self, requester_vk: &HybridVerifyingKey) -> DeviceMeshResult<()> {
        self.shape_check()?;
        let transcript = self.canonical_transcript_for_id();
        requester_vk
            .verify(&transcript, &self.requester_sig)
            .map_err(|_| DeviceMeshError::TaskRequestVerifyFail)
    }
}

/// Sign a task request. Sorts + de-duplicates `required_capabilities`
/// at sign so two requesters asking for the same set produce
/// byte-identical transcripts.
///
/// 9 args reflects the protocol's signed-field surface; bundling
/// them into a builder would obscure the wire-format binding.
#[allow(clippy::too_many_arguments)]
pub fn sign_task_request(
    requester: &DeviceSubkey,
    task_class: TaskClass,
    input_file_id: FileId,
    mut required_capabilities: Vec<DeviceCapability>,
    max_wall_secs: u32,
    max_output_bytes: u64,
    issued_unix: u64,
    deadline_unix: u64,
    nonce: [u8; TASK_NONCE_LEN],
) -> DeviceMeshResult<TaskRequest> {
    if deadline_unix <= issued_unix {
        return Err(DeviceMeshError::TaskDeadlineNotAfterIssue {
            issued_unix,
            deadline_unix,
        });
    }
    if task_class.bytes().len() > MAX_TASK_CLASS_LEN {
        return Err(DeviceMeshError::TaskClassTooLong {
            got: task_class.bytes().len(),
            max: MAX_TASK_CLASS_LEN,
        });
    }
    required_capabilities.sort();
    required_capabilities.dedup();
    if required_capabilities.len() > MAX_REQUIRED_CAPS_PER_TASK {
        return Err(DeviceMeshError::TaskTooManyCapabilities {
            got: required_capabilities.len(),
            max: MAX_REQUIRED_CAPS_PER_TASK,
        });
    }
    let transcript = TaskRequest::canonical_transcript(
        &task_class,
        requester.device_id(),
        requester.day_index(),
        &input_file_id,
        &required_capabilities,
        max_wall_secs,
        max_output_bytes,
        issued_unix,
        deadline_unix,
        &nonce,
    );
    let sig = requester.sign(&transcript)?;
    Ok(TaskRequest {
        task_class,
        requester_device_id: *requester.device_id(),
        requester_day_index: requester.day_index(),
        input_file_id,
        required_capabilities,
        max_wall_secs,
        max_output_bytes,
        issued_unix,
        deadline_unix,
        nonce,
        requester_sig: sig.to_vec(),
    })
}

/// Executor-signed task result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskResult {
    /// Which request this result fulfils.
    pub task_request_id: TaskRequestId,
    /// Executor device.
    pub executor_device_id: [u8; DEVICE_ID_LEN],
    /// Executor subkey day-index.
    pub executor_day_index: u64,
    /// Content-addressed `FileId` of the output bundle.
    pub output_file_id: FileId,
    /// Size of the output in bytes.
    pub output_byte_size: u64,
    /// Wall-clock seconds at completion.
    pub completed_unix: u64,
    /// Executor's subkey signature.
    pub executor_sig: Vec<u8>,
}

impl TaskResult {
    /// Canonical bytes the executor signs.
    #[must_use]
    pub fn canonical_transcript(
        task_request_id: &TaskRequestId,
        executor_device_id: &[u8; DEVICE_ID_LEN],
        executor_day_index: u64,
        output_file_id: &FileId,
        output_byte_size: u64,
        completed_unix: u64,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            TASK_RESULT_DOMAIN.len() + 32 + DEVICE_ID_LEN + 8 + FILE_ID_LEN + 8 + 8,
        );
        out.extend_from_slice(TASK_RESULT_DOMAIN);
        out.extend_from_slice(task_request_id);
        out.extend_from_slice(executor_device_id);
        out.extend_from_slice(&executor_day_index.to_be_bytes());
        out.extend_from_slice(output_file_id);
        out.extend_from_slice(&output_byte_size.to_be_bytes());
        out.extend_from_slice(&completed_unix.to_be_bytes());
        out
    }

    /// Verify the executor's signature.
    pub fn verify(&self, executor_vk: &HybridVerifyingKey) -> DeviceMeshResult<()> {
        if self.executor_sig.len() != HYBRID_SIG_LEN {
            return Err(DeviceMeshError::BadLength {
                expected: HYBRID_SIG_LEN,
                got: self.executor_sig.len(),
            });
        }
        let transcript = Self::canonical_transcript(
            &self.task_request_id,
            &self.executor_device_id,
            self.executor_day_index,
            &self.output_file_id,
            self.output_byte_size,
            self.completed_unix,
        );
        executor_vk
            .verify(&transcript, &self.executor_sig)
            .map_err(|_| DeviceMeshError::TaskResultVerifyFail)
    }
}

/// Sign a task result.
pub fn sign_task_result(
    executor: &DeviceSubkey,
    task_request_id: TaskRequestId,
    output_file_id: FileId,
    output_byte_size: u64,
    completed_unix: u64,
) -> DeviceMeshResult<TaskResult> {
    let transcript = TaskResult::canonical_transcript(
        &task_request_id,
        executor.device_id(),
        executor.day_index(),
        &output_file_id,
        output_byte_size,
        completed_unix,
    );
    let sig = executor.sign(&transcript)?;
    Ok(TaskResult {
        task_request_id,
        executor_device_id: *executor.device_id(),
        executor_day_index: executor.day_index(),
        output_file_id,
        output_byte_size,
        completed_unix,
        executor_sig: sig.to_vec(),
    })
}

/// Compute a [`TaskRequestId`] from raw canonical transcript bytes.
#[must_use]
pub fn task_request_id(transcript: &[u8]) -> TaskRequestId {
    let mut h = Hasher::new();
    h.update(b"OL-mesh-task-request-id-v1");
    h.update(transcript);
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::master::MasterIdentity;
    use crate::subkey::{fresh_device_id, mint_subkey};
    use crate::DeviceClass;
    use rand::rngs::OsRng;

    fn make_subkey() -> DeviceSubkey {
        let master = MasterIdentity::generate(&mut OsRng);
        let id = fresh_device_id(&mut OsRng);
        let (sk, _) = mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
        sk
    }

    #[test]
    fn task_request_sign_verify_round_trip() {
        let sk = make_subkey();
        let req = sign_task_request(
            &sk,
            TaskClass::new(b"transcribe-audio").unwrap(),
            [0xAA; FILE_ID_LEN],
            vec![DeviceCapability::Microphone, DeviceCapability::CpuHeavy],
            300,
            10_000_000,
            1,
            10_000,
            [0xCC; TASK_NONCE_LEN],
        )
        .unwrap();
        req.verify(&sk.verifying_key()).unwrap();
    }

    #[test]
    fn task_request_id_deterministic() {
        let sk = make_subkey();
        let req = sign_task_request(
            &sk,
            TaskClass::new(b"x").unwrap(),
            [0xAA; FILE_ID_LEN],
            vec![],
            1,
            1,
            1,
            10,
            [0xCC; TASK_NONCE_LEN],
        )
        .unwrap();
        assert_eq!(req.request_id(), req.request_id());
    }

    #[test]
    fn task_request_deadline_before_issue_rejected() {
        let sk = make_subkey();
        let err = sign_task_request(
            &sk,
            TaskClass::new(b"x").unwrap(),
            [0xAA; FILE_ID_LEN],
            vec![],
            1,
            1,
            10,
            5,
            [0xCC; TASK_NONCE_LEN],
        )
        .unwrap_err();
        assert!(matches!(
            err,
            DeviceMeshError::TaskDeadlineNotAfterIssue { .. }
        ));
    }

    #[test]
    fn task_request_tampered_breaks_verify() {
        let sk = make_subkey();
        let mut req = sign_task_request(
            &sk,
            TaskClass::new(b"x").unwrap(),
            [0xAA; FILE_ID_LEN],
            vec![DeviceCapability::Gpu],
            1,
            1,
            1,
            10,
            [0xCC; TASK_NONCE_LEN],
        )
        .unwrap();
        req.max_wall_secs = 9_999;
        let err = req.verify(&sk.verifying_key()).unwrap_err();
        assert!(matches!(err, DeviceMeshError::TaskRequestVerifyFail));
    }

    #[test]
    fn task_result_sign_verify_round_trip() {
        let sk = make_subkey();
        let result =
            sign_task_result(&sk, [0xEE; 32], [0xDD; FILE_ID_LEN], 10_000, 1_700_000_000).unwrap();
        result.verify(&sk.verifying_key()).unwrap();
    }

    #[test]
    fn task_result_tampered_breaks_verify() {
        let sk = make_subkey();
        let mut result =
            sign_task_result(&sk, [0xEE; 32], [0xDD; FILE_ID_LEN], 10_000, 1_700_000_000).unwrap();
        result.output_byte_size = 9_999;
        let err = result.verify(&sk.verifying_key()).unwrap_err();
        assert!(matches!(err, DeviceMeshError::TaskResultVerifyFail));
    }
}
