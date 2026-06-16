//! Row 8 Layer 7 — self-onion routing through your own devices when
//! the underlying network is hostile.
//!
//! When you're on an untrusted Wi-Fi (airport, coffee shop, hostile
//! border crossing), direct device-to-device traffic leaks who you
//! talk to even if every packet is encrypted: the destination IP
//! addresses are visible to the on-path observer. Self-onion routing
//! wraps the traffic in a Sphinx Coherence onion (the F3 layer
//! already shipped) where each hop is one of YOUR OWN devices, so
//! the observer sees only an opaque relay sequence among devices
//! they can't link to you.
//!
//! ## What this layer ships
//!
//! - [`OnionIdentity`] — a per-device Ristretto255 keypair, derived
//!   deterministically from the master seed so the master can
//!   re-mint it on any new pairing. The PUBKEY half is the
//!   Sphinx static-pk for that device's hop.
//! - [`OnionAttestation`] — master-signed binding of
//!   `device_id → ristretto_pubkey`. Replicas verify under the
//!   master VK before trusting any device as a hop.
//! - [`OnionKeyRegistry`] — aggregated attestation table; what the
//!   sender consults to materialise [`ol_onion::sphinx::SphinxHop`]
//!   structs for a circuit.
//! - [`build_self_onion_circuit`] — given a Layer-6 route + the
//!   registry + a payload, produce a fully-built
//!   [`ol_onion::sphinx::SphinxPacket`] aimed at the destination
//!   device.
//! - [`peel_self_onion_layer`] — wrapper around the Sphinx peel
//!   that takes a [`OnionIdentity`] and dispatches the result.
//! - [`SelfOnionContext`] — policy: min hop count, hostile-network
//!   flag, cover-traffic rate. Daemons consult this to decide
//!   "direct or self-onion."
//!
//! ## Composition with the lower layers
//!
//! - **Layer 1**: every [`OnionAttestation`] is signed by the
//!   master's hybrid signing key (the same root every other
//!   personal-mesh primitive trusts).
//! - **Layer 3 (CRDT mirror)**: the registry can be stored as a
//!   Layer-3 LWW-Map subtree keyed by `device_id` so every device
//!   sees the same onion-key view.
//! - **Layer 6 (self-routing)**: hop selection consumes a
//!   [`crate::self_routing::Route`] — the routing layer's max-min-τ
//!   picker chooses the path; this layer turns it into a Sphinx
//!   circuit.
//! - **F3 `ol_onion::sphinx`**: the Sphinx machinery itself.
//!   Layer 7 doesn't reimplement Sphinx; it composes the shipped
//!   primitive with personal-mesh identities.
//!
//! ## What this layer doesn't ship
//!
//! - The Sphinx Coherence primitive itself (already shipped as
//!   `ol_onion::sphinx`).
//! - Hostile-network detection (daemon-level concern — Wi-Fi SSID
//!   trust list, captive-portal heuristics, etc.).
//! - Cover-traffic emission (Phase B `ol_onion::sphinx::cover`
//!   shipped; this layer just references the rate policy).

pub mod attestation;
pub mod circuit;
pub mod identity;
pub mod policy;
pub mod registry;

pub use attestation::{sign_onion_attestation, OnionAttestation, ONION_ATTESTATION_DOMAIN};
pub use circuit::{
    build_self_onion_circuit, peel_self_onion_layer, SelfOnionPeelOutcome,
    SELF_ONION_DOMAIN_PAYLOAD,
};
pub use identity::{
    derive_onion_identity, OnionIdentity, ONION_DERIVATION_DOMAIN, ONION_PUBKEY_LEN,
    ONION_SECRET_LEN,
};
pub use policy::{SelfOnionContext, DEFAULT_MIN_HOPS};
pub use registry::OnionKeyRegistry;
