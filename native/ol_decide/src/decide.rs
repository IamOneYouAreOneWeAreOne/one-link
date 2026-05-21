//! The universal `Decide` trait.

use crate::context::Context;

/// Every per-event decision in the One Link daemon implements this trait.
///
/// Per Design Rules from `intergration map.txt`:
///
/// - **R1.** No constants where context exists. The trait body's whole
///   purpose is to convert `Context` -> action, never a config knob.
/// - **R2.** Single `Context` input, shared across all `Decide` impls.
/// - **R3.** Every impl ships with `safe_default(ctx)` as a fallback
///   for when the smart path errors out or required signals are missing.
/// - **R4.** Every impl is testable in isolation (no I/O, no globals).
///
/// # Example
///
/// ```
/// use ol_decide::{Context, Decide, EventKind};
///
/// struct ToyDecider;
/// impl Decide<&'static str> for ToyDecider {
///     fn decide(&self, ctx: &Context) -> &'static str {
///         if ctx.size < 1024 { "small" } else { "large" }
///     }
///     fn safe_default(&self, _ctx: &Context) -> &'static str {
///         "small"
///     }
///     fn name(&self) -> &'static str { "ToyDecider" }
/// }
///
/// let ctx = Context::safe_default(EventKind::Msg, 512);
/// assert_eq!(ToyDecider.decide(&ctx), "small");
/// ```
pub trait Decide<Action> {
    /// Compute the action for this context.
    ///
    /// This is the "smart" path: full Smart-Rules / UnifiedMin / mode
    /// awareness etc. Should never panic; if logic is undecidable for
    /// some input, fall through to [`safe_default`](Self::safe_default).
    fn decide(&self, ctx: &Context) -> Action;

    /// The conservative fallback action.
    ///
    /// Should be the action that's hardest to regret: maximum onion hops,
    /// cover traffic ON, anchor laid, never batch, etc. Used by the
    /// daemon when a Decide impl panics or returns an error, or when
    /// the Context is incomplete.
    fn safe_default(&self, ctx: &Context) -> Action;

    /// Stable name for telemetry / logging. Should be unique per impl.
    fn name(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{Context, EventKind};

    /// A throwaway Decide impl used to verify the trait shape compiles
    /// and is callable end-to-end.
    struct SizeBucket;

    impl Decide<&'static str> for SizeBucket {
        fn decide(&self, ctx: &Context) -> &'static str {
            if ctx.size < 1024 {
                "small"
            } else if ctx.size < 1_000_000 {
                "medium"
            } else {
                "large"
            }
        }
        fn safe_default(&self, _ctx: &Context) -> &'static str {
            "small"
        }
        fn name(&self) -> &'static str {
            "SizeBucket"
        }
    }

    #[test]
    fn decide_dispatches_per_context() {
        let small = Context::safe_default(EventKind::Msg, 200);
        let medium = Context::safe_default(EventKind::File, 50_000);
        let large = Context::safe_default(EventKind::File, 10_000_000);

        let d = SizeBucket;
        assert_eq!(d.decide(&small), "small");
        assert_eq!(d.decide(&medium), "medium");
        assert_eq!(d.decide(&large), "large");
    }

    #[test]
    fn safe_default_is_callable() {
        let ctx = Context::safe_default(EventKind::Msg, 0);
        assert_eq!(SizeBucket.safe_default(&ctx), "small");
    }

    #[test]
    fn name_is_stable() {
        assert_eq!(SizeBucket.name(), "SizeBucket");
    }
}
