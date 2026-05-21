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


def safe_default() -> Decision:
    """The conservative fallback decision: 5-hop onion, cover on,
    anchor laid, emit-now, classical path. Used when smart logic errors
    or the Context is incomplete.
    """
    _require_native()
    return _native_selector.SmartRules().safe_default()


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
