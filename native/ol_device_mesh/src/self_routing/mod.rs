//! Row 8 Layer 6 — τ_c-routed self-mesh + DTN courier.
//!
//! Personal-mesh routing: given a source and destination among your
//! OWN devices, pick the highest-coherence (τ_c) path. The path may
//! be direct (`src → dst` over LAN / cellular / Wi-Fi) or multi-hop
//! through another device in the mesh (e.g., phone → desktop →
//! laptop because the phone can't directly reach the laptop on the
//! current Wi-Fi network).
//!
//! ## Self-mesh vs friend-mesh
//!
//! Friend-mesh routing (the Phase D `ol_routing` τ_c PDE) optimises
//! a public swarm graph. Self-mesh routing optimises a small graph
//! of YOUR devices — phone, laptop, tablet, desktop, server — and
//! has tighter trust assumptions:
//!
//! - Every node in the graph is signed by the master via a Layer-1
//!   `SubkeyAttestation`. There are no untrusted intermediates.
//! - Cover traffic + onion routing are SKIPPED on self-traffic (you
//!   talking to yourself; no metadata to hide).
//! - Multi-path racing for critical messages is cheap because the
//!   max fan-out is bounded by your device count.
//!
//! ## Composition with the lower layers
//!
//! - **Layer 1**: every [`RouteAnnouncement`] is signed by the
//!   announcing device's subkey.
//! - **Layer 3 (CRDT mirror)**: route announcements can be stored
//!   as a Layer-3 LWW-Map subtree keyed by announcer device id, so
//!   every device sees the same route view.
//! - **Layer 5 (fan-out)**: the fan-out planner picks sources via
//!   [`RouteTable::pick_best_route`]; multi-source races use
//!   [`RouteTable::multi_path_plan`].
//!
//! ## What this layer ships
//!
//! - [`RouteAnnouncement`] — signed claim "I (announcer) can reach
//!   peers {P → τ_score, last_seen_unix} as of `announced_at_unix`."
//!   Includes a `direct` flag per link so the receiver knows
//!   whether the announcer is offering itself as a relay or just
//!   reporting another device's reachability.
//! - [`RouteTable`] — receiver's aggregated view across all
//!   ingested announcements. Stale announcements get evicted via
//!   the deterministic LWW rule on `announced_at_unix`.
//! - [`pick_best_route`] — max-min-τ_c path finder. Dijkstra-style
//!   variant where the "distance" to a node is the WORST τ on the
//!   path so far; we maximise this floor (equivalent to widest-
//!   path / bottleneck routing).
//! - [`multi_path_plan`] — the K highest-τ_c paths, edge-disjoint
//!   when possible so the receiver can race Wi-Fi vs cellular
//!   vs Ethernet legs.
//! - [`dtn_couriers`] — physical-courier detection: devices that
//!   have been seen near both endpoints within a configurable
//!   time window, even if they're not currently online at the
//!   same time. Sufficient for "tablet flies home and syncs
//!   between desktop and phone."
//!
//! ## What this layer doesn't ship
//!
//! - The actual wire transport (Phase A2 QUIC + the OS networking
//!   stack underneath).
//! - The τ_c estimator (Phase D `ol_routing` + Phase E
//!   `ol_coherence_field` provide it; this layer just consumes the
//!   scalar score).
//! - The reachability prober (it's a daemon-level concern; this
//!   layer accepts whatever the prober reports).

pub mod announcement;
pub mod dtn;
pub mod route;
pub mod table;

pub use announcement::{
    sign_route_announcement, PeerLink, RouteAnnouncement,
    ROUTE_ANNOUNCEMENT_DOMAIN, MAX_LINKS_PER_ANNOUNCEMENT,
};
pub use dtn::{dtn_couriers, CourierObservation};
pub use route::{pick_best_route, Route, TauScore};
pub use table::{multi_path_plan, RouteTable};
