//! `ol_decide` — the universal `Decide` trait + `Context` struct for
//! per-event context-aware decisions across the One Link daemon.
//!
//! ## Why this crate exists
//!
//! The shipping daemon scatters per-event decisions across many sites
//! with their own ad-hoc logic and constants: which transport to use,
//! how many onion hops, whether to lay an anchor, when to batch radio,
//! how aggressive to prefetch, whether to compress, what trust to assign
//! a peer, and ~20 others (see `intergration map.txt`, decision-point
//! catalog).
//!
//! Each of those is currently a hand-tuned constant or a buried `if`
//! statement. The integration map's Design Rule R1 says:
//!
//! > No constants where context exists. Every value that varies by
//! > event/peer/mode MUST be `decide(ctx)`, not a config knob.
//!
//! This crate defines the universal contract: one `Context` struct that
//! every decision consumes, and one `Decide` trait that every decision
//! implements. The selector (`ol_selector`), trust scoring (`ol_align`),
//! transport choice, onion-hop count, batch policy, anchor-lay rule,
//! and 20+ other sites can all be expressed as `impl Decide<T> for X`
//! and tested in isolation.
//!
//! ## Surface
//!
//! - [`Context`] — the 8-signal struct (per Gap 18 ablation).
//! - [`Decide`] — the trait every decision point implements.
//! - The signal enums: [`EventKind`], [`PeerRelationship`], [`Urgency`],
//!   [`RadioState`], [`NetworkType`], [`UserMode`].
//! - [`DecideError`] — for context-building errors.
//!
//! ## The 8 essential signals (Gap 18-verified)
//!
//! | Signal             | Source in daemon                                    |
//! |--------------------|-----------------------------------------------------|
//! | `kind`             | wire.py message-type enum                           |
//! | `size`             | frame length prefix                                 |
//! | `peer`             | `PeerRecord.trust` ('pinned'/'pending'/'rejected')  |
//! | `urgency`          | derived from kind + REST caller                     |
//! | `radio_state`      | platform shim (default: Active)                     |
//! | `network`          | platform shim (default: Wifi)                       |
//! | `user_mode`        | settings table (default: Normal)                    |
//! | `observed_loss`    | relay metrics EWMA                                  |
//! | `pattern_strength` | predictor confidence                                |
//!
//! Five are already in the daemon; three default to safe values until
//! platform shims ship.

#![doc(html_root_url = "https://docs.rs/ol_decide/0.21.0")]

pub mod context;
pub mod decide;
pub mod error;

pub use context::{
    Context, EventKind, NetworkType, PeerRelationship, RadioState, Urgency, UserMode,
};
pub use decide::Decide;
pub use error::DecideError;

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
