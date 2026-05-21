"""Adapter for the per-event selector (``ol_selector`` via
``one_link_native``).

Smart-Rules implementation of decision point D01 from
`intergration map.txt`. Replaces the daemon's static
QUIC_SMALL_FILE_THRESHOLD branch at daemon.py:14020-14080 with a
context-aware decide(...) call.

The selector takes 9 keyword args (5 required + 4 with safe defaults
for signals the daemon doesn't yet track per-event) and returns a dict
with the 7 decision fields the send path needs to consume.
"""

from __future__ import annotations

import logging
from typing import TypedDict

log = logging.getLogger(__name__)

try:
    from one_link_native import selector as _native_selector  # type: ignore[import-not-found]

    HAS_NATIVE: bool = True
    NATIVE_VERSION: str | None = getattr(_native_selector, "__version__", None)
except ImportError as exc:
    HAS_NATIVE = False
    NATIVE_VERSION = None
    _native_selector = None  # type: ignore[assignment]
    log.info(
        "one_link_native.selector not installed (%s); Smart-Rules selector "
        "unavailable. Build via `cd native && maturin develop --release`.",
        exc,
    )


class Decision(TypedDict):
    """Selector output. See ol_selector::Decision for field semantics."""

    transport: str  # "quic_stream" | "quic_datagram" | "webrtc" | "relay"
    path: str  # "classical" | "coherence"
    onion_hops: int  # 1 | 3 | 5
    cover_traffic: bool
    batch_decision: str  # "emit_now" | "batch" | "urgent_bypass"
    anchor_lay: bool
    predictor_warm: bool


def smart_rules():
    """Construct a SmartRules selector instance.

    Stateless; safe to cache one instance on the daemon and reuse.
    """
    _require_native()
    return _native_selector.SmartRules()


def unified_min(**weights):
    """Construct a UnifiedMin selector — the Phase H continuous
    energy-minimization variant.

    Pass any of the 11 weight kwargs to override defaults:
      alpha_coherence, privacy_weight, cover_penalty, anchor_cost,
      batch_latency_cost, onion_hop_cost, relay_rtt_multiplier,
      lambda_dynamic, dark_base, dark_coherence, dark_cover.

    Returns a selector with the same decide(...) signature as
    SmartRules — daemons can A/B test by constructing one of each
    and routing per-event through whichever they want to compare.
    """
    _require_native()
    if not weights:
        return _native_selector.UnifiedMin()
    return _native_selector.UnifiedMin.with_weights(**weights)


def online_learner(
    learning_rate: float = 0.001,
    regularization: float = 0.01,
    weight_bound_multiplier: float = 10.0,
):
    """Construct a Phase I OnlineLearner — UnifiedMin + observed-regret
    weight adaptation.

    Production usage (gated by ONE_LINK_ONLINE_LEARN=1):
        learner = selector_native.online_learner()
        # decide as normal:
        d = learner.decide(kind=..., size=..., ...)
        # after observing the outcome (latency, leak, etc.) compute regret:
        regret = observed_cost - expected_cost
        learner.observe(regret, d, kind=..., size=..., ...)

    Default rate (0.001) is small enough that ~100 mis-tuned
    observations across a single decision can't materially change
    behavior. Regularization (0.01) keeps weights bounded around
    the factory defaults in steady state.
    """
    _require_native()
    return _native_selector.OnlineLearner(
        learning_rate=float(learning_rate),
        regularization=float(regularization),
        weight_bound_multiplier=float(weight_bound_multiplier),
    )


def safe_default() -> Decision:
    """The conservative fallback decision: 5-hop onion, cover on,
    anchor laid, emit-now, classical path. Used when smart logic errors
    or the Context is incomplete.
    """
    _require_native()
    return _native_selector.SmartRules().safe_default()


def verify_contract(decision: Decision, user_mode: str) -> list[str]:
    """F4 — verify a selector decision respects the user_mode contract.

    Mirrors `ol_selector::Decision::verify_contract` but operates on the
    Python dict shape returned by `SmartRules.decide`. Returns the list
    of violation labels (empty list = pass). Useful for daemon-side
    runtime enforcement / observability without crossing the pyo3
    boundary again.

    Returns labels matching `ContractViolation::as_str`:
      - "paranoid_under_hops"
      - "paranoid_no_cover"
      - "battery_save_cover"
      - "latency_strict_batched"
      - "latency_strict_relay"
    """
    mode = normalize_user_mode(user_mode)
    violations: list[str] = []
    if mode == "paranoid":
        if int(decision.get("onion_hops", 0)) < 3:
            violations.append("paranoid_under_hops")
        if not decision.get("cover_traffic", False):
            violations.append("paranoid_no_cover")
    elif mode == "battery_save":
        if decision.get("cover_traffic", False):
            violations.append("battery_save_cover")
    elif mode == "latency_strict":
        if decision.get("batch_decision") == "batch":
            violations.append("latency_strict_batched")
        if decision.get("transport") == "relay":
            violations.append("latency_strict_relay")
    return violations


VALID_USER_MODES: tuple[str, ...] = (
    "normal",
    "paranoid",
    "battery_save",
    "latency_strict",
)
"""Mode contracts the selector knows about. The daemon persists one of
these in the settings table under the `user_mode` key; the selector
reads it on every event to decide privacy/latency/energy trade-offs.
"""


def normalize_user_mode(raw: str | None) -> str:
    """Validate + normalize a user_mode label. Unknown / missing values
    default to "normal" (Design Rule R3 safe-default).

    Accepts the same aliases the Rust core does (case-insensitive,
    hyphens permitted in compound labels).
    """
    if not raw:
        return "normal"
    s = str(raw).strip().lower().replace("-", "_")
    if s in VALID_USER_MODES:
        return s
    if s == "paranoid":
        return "paranoid"
    if s in ("batterysave", "battery_save"):
        return "battery_save"
    if s in ("latencystrict", "latency_strict"):
        return "latency_strict"
    return "normal"


def _require_native() -> None:
    if not HAS_NATIVE:
        raise RuntimeError(
            "one_link_native.selector required but not installed; "
            "build via `cd native && maturin develop --release`."
        )
