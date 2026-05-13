//! Row 8 Layer 9 — active-inference device routing.
//!
//! Learns which device the user actually acts on for each kind of
//! incoming message, in each time-of-day context, and routes
//! accordingly. "Message from Alice on a Wednesday afternoon →
//! laptop, because that's where Alex always reads Alice's
//! messages." Outperforms the simple "wake whichever device is
//! online" heuristic.
//!
//! ## Algorithm
//!
//! Per (`context`, `device`) pair we maintain a `Beta(α, β)`
//! posterior over the probability that the user will ACT on a
//! message routed to that device in that context. We update on
//! every observed action (`act` → α += 1; `dismiss` → β += 1).
//!
//! Picking a device uses **Thompson sampling**: for each candidate
//! we sample `p ~ Beta(α, β)` and pick the device with the largest
//! sample. This naturally trades exploitation (high posterior mean)
//! against exploration (high posterior variance) without any
//! manual ε-greedy hack — and it converges to the optimal device
//! at log(N) regret.
//!
//! Cold-start: when we have no personal history for `(context,
//! device)`, the posterior starts at `Beta(α_cohort, β_cohort)`
//! seeded from the cohort prior. Cohort prior can be a flat
//! Beta(1, 1) (uniform) or per-device-class derived from typical-
//! user data.
//!
//! ## Composition with the lower layers
//!
//! - **Layer 1**: device identities + master attestation.
//! - **Layer 5 / Layer 6**: candidate device set comes from
//!   wherever the daemon enumerates "online + reachable" devices.
//! - **Phase D `ol_prefetch` / `ol_bandit`** (shipped): this layer
//!   is the daemon-side glue that wraps the bandit into the
//!   personal-device-mesh routing question.
//!
//! ## What this layer ships
//!
//! - [`RoutingContext`] — canonical structure for "who / when /
//!   what" that conditions the routing decision.
//! - [`DeviceActionRecord`] — Beta-posterior counters (α, β) per
//!   `(context_hash, device_id)`.
//! - [`RoutingHistory`] — observation table.
//! - [`CohortPrior`] — cold-start prior.
//! - [`pick_device_for_context`] — Thompson-sampling picker.
//! - [`RoutingPolicy`] — daemon-side knobs.
//!
//! ## What this layer doesn't ship
//!
//! - The actual "did the user act on this" detector — daemon
//!   surface; we just consume the boolean.
//! - History replication across the mesh — Layer-3 CRDT mirror
//!   pattern handles it; the daemon owns the wiring.

pub mod context;
pub mod cohort;
pub mod history;
pub mod picker;
pub mod policy;
pub mod record;

pub use cohort::{CohortPrior, COHORT_DEFAULT_ALPHA, COHORT_DEFAULT_BETA};
pub use context::{RoutingContext, ROUTING_CONTEXT_DOMAIN};
pub use history::RoutingHistory;
pub use picker::{pick_device_for_context, MAX_CANDIDATES_PER_PICK};
pub use policy::{RoutingPolicy, ROUTING_HISTORY_DECAY_DEFAULT_SECS};
pub use record::{DeviceActionRecord, MAX_POSTERIOR_COUNT};
