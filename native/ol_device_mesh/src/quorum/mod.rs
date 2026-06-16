//! Row 8 Layer 2 — threshold device quorum.
//!
//! High-stakes operations require K-of-N device approval. Examples
//! the upper layers will tag through Layer 2:
//!
//! - granting a new capability to a friend or app,
//! - sending to a first-time contact,
//! - transferring more than a configurable byte budget,
//! - revoking a sibling device,
//! - rotating the master identity,
//! - factor-resetting the mesh.
//!
//! ## Composition
//!
//! ```text
//! QuorumPolicy        master signs (label, k, eligible_device_ids)
//!     │
//!     │   pinned by every device in the mesh
//!     ▼
//! QuorumProposal      issuer device proposes an operation, signs it
//!     │
//!     │   broadcast to siblings
//!     ▼
//! QuorumApproval(s)   each eligible sibling co-signs the proposal_id
//!     │
//!     │   collected by the issuer (or any device)
//!     ▼
//! QuorumCertificate   proposal + ≥K approvals + subkey attestations
//!     │
//!     │   produced once, persisted, verified by anyone with the
//!     │   master verifying key.
//!     ▼
//!  authorised operation executes
//! ```
//!
//! ## Verification rule
//!
//! [`QuorumCertificate::verify`] checks ALL of the following:
//!
//! 1. The [`QuorumPolicy`] is signed by the master.
//! 2. Every subkey attestation in the cert is signed by the master.
//! 3. The [`QuorumProposal`] is signed by the issuer's subkey AND
//!    the issuer is in the policy's eligible list.
//! 4. Each [`QuorumApproval`] is signed by its claimed approver's
//!    subkey AND the approver is in the policy's eligible list.
//! 5. The certificate carries at least `policy.k` DISTINCT approvers
//!    (the policy author counts as one approval if they signed both
//!    the proposal and an approval — Layer 2 doesn't fold the
//!    proposal signature into the K count; callers must include an
//!    explicit approval if they want the issuer to count).
//! 6. No approval's `approved_unix` is past the proposal's
//!    `deadline_unix`.
//! 7. The proposal's `deadline_unix` itself is not yet past
//!    `now_unix` (verifier checks this; we don't bake the verifier's
//!    clock into the certificate).
//!
//! ## Anti-replay
//!
//! Every proposal carries a 16-byte nonce + the issuer's device id +
//! a wall-clock timestamp. The `proposal_id` is BLAKE3 over the
//! canonical proposal bytes, so two proposals with the same nonce
//! but different issuers / deadlines / operation digests yield
//! distinct ids. Approvals bind to the proposal id, never to the
//! raw operation. Higher layers track seen `proposal_id`s to drop
//! duplicates.
//!
//! ## What this layer doesn't do
//!
//! - Negative votes (a "refuse" record that kills the proposal).
//!   Skipped intentionally; Layer 2 is the positive-quorum path.
//!   Higher layers can build refusal-by-time-out from the deadline.
//! - BLS / FROST threshold signatures. Each device signs
//!   independently and the verifier checks K independent signatures.
//!   That's how Bitcoin multi-sig works; it's simpler, audits
//!   cleanly, and avoids dragging in a new curve.
//! - Per-policy approval rate limits. Higher layers add those.
//!
//! ## Example
//!
//! ```no_run
//! use ol_device_mesh::quorum::{
//!     mint_policy, propose_operation, sign_approval, QuorumCertificate,
//! };
//! use ol_device_mesh::{
//!     mint_subkey, DeviceClass, MasterIdentity,
//! };
//! use rand::rngs::OsRng;
//!
//! let master = MasterIdentity::generate(&mut OsRng);
//!
//! // Three devices on the mesh.
//! let phone_id = [0xAA; 16];
//! let laptop_id = [0xBB; 16];
//! let desktop_id = [0xCC; 16];
//! let (phone_sk, phone_att) =
//!     mint_subkey(&master, DeviceClass::Phone, phone_id, 0, 365).unwrap();
//! let (laptop_sk, laptop_att) =
//!     mint_subkey(&master, DeviceClass::Laptop, laptop_id, 0, 365).unwrap();
//! let (desktop_sk, desktop_att) =
//!     mint_subkey(&master, DeviceClass::Desktop, desktop_id, 0, 365).unwrap();
//!
//! // The master signs a policy: "high-stakes ops require 2 of {phone,
//! // laptop, desktop}."
//! let policy = mint_policy(
//!     &master,
//!     [0x01; 16],
//!     b"high-stakes",
//!     2,
//!     vec![phone_id, laptop_id, desktop_id],
//! ).unwrap();
//!
//! // Phone proposes an operation.
//! let op_digest = [0xEE; 32];
//! let now = 1_700_000_000u64;
//! let proposal = propose_operation(
//!     &phone_sk,
//!     &policy,
//!     op_digest,
//!     [0xDA; 16],
//!     now,
//!     now + 3600,
//! ).unwrap();
//!
//! // Laptop and desktop sign approvals.
//! let a1 = sign_approval(&laptop_sk, &proposal, now + 60).unwrap();
//! let a2 = sign_approval(&desktop_sk, &proposal, now + 120).unwrap();
//!
//! // Build the certificate (anyone can do this).
//! let cert = QuorumCertificate {
//!     proposal,
//!     approvals: vec![a1, a2],
//!     policy: policy.clone(),
//!     subkey_attestations: vec![phone_att, laptop_att, desktop_att],
//! };
//!
//! // Anyone with the master VK can verify the whole thing.
//! cert.verify(&master.verifying_key(), now + 200).unwrap();
//! ```

pub mod approval;
pub mod certificate;
pub mod policy;
pub mod proposal;

pub use approval::{sign_approval, QuorumApproval, APPROVAL_DOMAIN};
pub use certificate::{QuorumCertificate, MAX_APPROVALS, MAX_ELIGIBLE_DEVICES};
pub use policy::{
    mint_policy, QuorumPolicy, QuorumPolicyId, POLICY_DOMAIN, POLICY_ID_LEN, POLICY_LABEL_MAX,
};
pub use proposal::{
    propose_operation, ProposalId, ProposalNonce, QuorumProposal, OPERATION_DIGEST_LEN,
    PROPOSAL_DOMAIN, PROPOSAL_NONCE_LEN,
};
