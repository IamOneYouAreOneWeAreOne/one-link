//! Row 8 Layer 8 — cross-device distributed compute.
//!
//! Heavy tasks (ML inference, video transcoding, audio
//! transcription, file thumbnail generation) auto-distribute
//! across your idle, capable devices. The phone says "transcribe
//! this 1h audio"; the desktop in the same house actually does the
//! work; the phone gets the result. Your devices ARE your private
//! supercomputer.
//!
//! ## What this layer ships
//!
//! - [`DeviceCapability`] — what a device CAN do (GPU, `CpuHeavy`,
//!   Mic, Camera, `LargeDisk`, `AlwaysOn`, etc.).
//! - [`CapabilityAttestation`] — master-signed binding from
//!   `device_id` to its capability list. Replicas pin the master VK
//!   and trust the binding.
//! - [`CapabilityRegistry`] — aggregated table the requester
//!   consults to find candidate executors.
//! - [`TaskRequest`] — requester-signed: "I need `task_class` run
//!   with these inputs; output goes back to me; here are the
//!   capabilities the executor must have; deadline is D."
//! - [`TaskResult`] — executor-signed: "I, device E, completed
//!   `task_request_id` with output `FileId` F at time T."
//! - [`pick_executor`] — capability-matching + capacity-weighted
//!   picker. Composes the Layer-5 [`SourceCapacity`] type.
//! - [`TaskPolicy`] — per-task-class policy (allowed executors,
//!   min battery %, max wall-clock, quorum-required flag).
//!
//! ## Composition with the lower layers
//!
//! - **Layer 1**: every request + result is signed by the
//!   originating device's subkey.
//! - **Layer 2**: high-stakes task classes (touches master seed,
//!   exfiltrates >X bytes, contacts external service) require a
//!   K-of-N [`crate::quorum::QuorumCertificate`] before the
//!   executor will accept the request.
//! - **Layer 4**: inputs + outputs are content-addressed
//!   [`crate::distributed_fs::FileId`] handles. The executor
//!   fetches inputs via the shipped Layer-4 placement / Layer-5
//!   fan-out flow.
//! - **Layer 5**: `SourceCapacity` reused in the picker as a load
//!   estimate.
//! - **Layer 6**: requester picks the executor's path via
//!   `pick_best_route` once the executor is chosen.
//!
//! ## What this layer doesn't ship
//!
//! - The actual task runtime (per-task-class invocation; the
//!   daemon plugs in its own handlers).
//! - The heartbeat protocol for long-running tasks (Layer-3
//!   CRDT subtree pattern covers it; the daemon owns the keys).
//! - The Phase D bandit (shipped); this layer just consumes
//!   `SourceCapacity` for picker-load-balancing.

pub mod attestation;
pub mod capability;
pub mod picker;
pub mod policy;
pub mod registry;
pub mod task;

pub use attestation::{
    sign_capability_attestation, CapabilityAttestation,
    CAPABILITY_ATTESTATION_DOMAIN,
};
pub use capability::{DeviceCapability, MAX_CAPABILITIES_PER_DEVICE};
pub use picker::pick_executor;
pub use policy::{
    TaskClass, TaskPolicy, MAX_TASK_CLASS_LEN, TASK_CLASS_DOMAIN,
};
pub use registry::CapabilityRegistry;
pub use task::{
    sign_task_request, sign_task_result, task_request_id, TaskRequest,
    TaskRequestId, TaskResult, TASK_REQUEST_DOMAIN, TASK_RESULT_DOMAIN,
};
