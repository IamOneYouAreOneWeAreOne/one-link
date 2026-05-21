//! `ol_radio_batcher` — deterministic radio-aware batch scheduler.
//!
//! ## What it does
//!
//! Background traffic on a mobile device wakes the radio. Every wake
//! costs ~100ms of "tail energy" — the radio stays warm for a tail
//! period after the actual transmit. Many small wakes per second is
//! the most expensive thing One Link can do to a battery.
//!
//! The fix is straightforward: coalesce background traffic into the
//! next scheduled radio cycle. The DRX (Discontinuous Reception) cycle
//! on LTE/5G has well-defined windows — short DRX (~10ms) and long DRX
//! (~100ms+). If we already need to wake the radio at the next cycle
//! boundary, sending one combined transmission costs no more energy
//! than sending nothing.
//!
//! ## What this crate IS
//!
//! - A deterministic queue with age-bounded drain semantics.
//! - Time-injected — the caller supplies `now_ms` to every operation,
//!   so the scheduler is fully testable without wall-clock dependencies.
//! - Priority-aware — urgent entries are drained on every tick;
//!   normal entries wait for the DRX window.
//! - Pure Rust, no allocator surprises, no panics on any input.
//!
//! ## What this crate is NOT
//!
//! - It does NOT decide what's urgent vs background. That's the
//!   selector's job (ol_selector, decision point D06). The batcher
//!   only sees entries the selector tagged as `Batch`.
//! - It does NOT poll the OS for radio state. The daemon may set it
//!   externally via [`Batcher::set_radio_state`] as an observability
//!   signal; the deterministic core ignores it (the daemon decides
//!   how to use it).
//! - It does NOT do any I/O. `drain(now_ms)` returns the entries that
//!   need to be sent; the caller does the actual sending.
//!
//! ## Evidence (Gap 4 / Gap 14 from the forge shootouts)
//!
//! - Gap 4: 22-44% per-event radio energy reduction with batching enabled.
//! - Gap 11: Optimal DRX window is 50ms (NOT the 200ms first guess —
//!   smaller window keeps p99 latency in check without giving up most
//!   of the energy win).
//! - Gap 14: Foreground urgent traffic MUST bypass batching, or p99
//!   doubles. The selector enforces this; the batcher only sees
//!   background entries by contract.
//!
//! ## Design Rules (from `intergration map.txt`)
//!
//! - **R1.** No constants where context exists — DRX window is a
//!   constructor argument, not a hardcoded literal.
//! - **R3.** safe-default semantics: `drain(now_ms)` with `now_ms = u64::MAX`
//!   force-drains everything (the emergency-flush path).

#![doc(html_root_url = "https://docs.rs/ol_radio_batcher/0.21.0")]

pub mod batcher;
pub mod error;
pub mod priority;
pub mod state;

pub use batcher::{Batcher, BatcherStats, DrainOutcome, QueueEntry};
pub use error::BatcherError;
pub use priority::Priority;
pub use state::RadioState;

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default DRX window in milliseconds.
///
/// Per Gap 11 in the forge shootouts: 50ms is the optimum across all
/// tested workloads. Smaller wastes the energy win; larger pumps p99
/// latency without proportional benefit.
pub const DEFAULT_DRX_WINDOW_MS: u32 = 50;

/// Default maximum queue length.
///
/// Hard ceiling on per-process memory pressure. Anything beyond gets
/// [`BatcherError::QueueFull`]. Sized for a daemon broadcasting to a
/// few thousand paired peers at most.
pub const DEFAULT_MAX_QUEUE_SIZE: usize = 4096;

/// Default maximum entry age in milliseconds.
///
/// Force-drains anything older than this even if the DRX window
/// hasn't elapsed. Prevents indefinite delay from clock skew or
/// dropped drain ticks.
pub const DEFAULT_MAX_AGE_MS: u32 = 20_000;
