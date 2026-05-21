"""Adapter for the Gaussian alignment trust function (``ol_align`` via
``one_link_native``).

Per the Equation of ONE: A(x, t) = exp(-(x^2 + t^2) / L_session) computes
a continuous trust score in (0, 1] from (hop_distance, staleness, session
length). Replaces hand-tuned trust thresholds across the daemon.

Decision point D02 in `intergration map.txt`.
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)

try:
    from one_link_native import align as _native_align  # type: ignore[import-not-found]

    HAS_NATIVE: bool = True
    NATIVE_VERSION: str | None = getattr(_native_align, "__version__", None)
except ImportError as exc:
    HAS_NATIVE = False
    NATIVE_VERSION = None
    _native_align = None  # type: ignore[assignment]
    log.info(
        "one_link_native.align not installed (%s); A(x,t) trust unavailable. "
        "Build via `cd native && maturin develop --release`.",
        exc,
    )


def trust_score(hop_distance: float, staleness_seconds: float, l_session: float) -> float:
    """Compute A(x, t) = exp(-(x^2 + t^2) / L_session) directly.

    Use this when the caller already knows L_session. Otherwise prefer
    :func:`trust_for` to pick the tier default.
    """
    _require_native()
    return _native_align.trust_score(
        float(hop_distance), float(staleness_seconds), float(l_session)
    )


def trust_for(
    relationship: str, hop_distance: float, staleness_seconds: float
) -> float:
    """Compute trust using the relationship tier's default L_session.

    `relationship` accepts `"paired"` / `"pinned"`, `"known"` / `"pending"`,
    or `"stranger"` / `"rejected"` / `"unknown"`. Case-insensitive.
    """
    _require_native()
    return _native_align.trust_for(
        relationship, float(hop_distance), float(staleness_seconds)
    )


def l_paired() -> float:
    """Default L_session (days) for paired peers (100)."""
    _require_native()
    return _native_align.l_paired()


def l_known() -> float:
    """Default L_session (days) for known peers (30)."""
    _require_native()
    return _native_align.l_known()


def l_stranger() -> float:
    """Default L_session (days) for stranger peers (5)."""
    _require_native()
    return _native_align.l_stranger()


# ---------- Python-only convenience: fallback if native not built ----------

def trust_score_python(
    hop_distance: float, staleness_seconds: float, l_session: float
) -> float:
    """Pure-Python implementation for use when the native crate is
    unavailable (development, tests, CI builds without maturin).

    Mirrors the Rust implementation. Raises ``ValueError`` on invalid
    inputs. Slower than the native path; use only as fallback.
    """
    import math

    for name, val in (
        ("hop_distance", hop_distance),
        ("staleness_seconds", staleness_seconds),
        ("l_session", l_session),
    ):
        if not math.isfinite(val):
            raise ValueError(f"{name} must be finite (got {val})")
    if hop_distance < 0:
        raise ValueError(f"hop_distance must be >= 0 (got {hop_distance})")
    if staleness_seconds < 0:
        raise ValueError(f"staleness_seconds must be >= 0 (got {staleness_seconds})")
    if l_session <= 0:
        raise ValueError(f"l_session must be > 0 (got {l_session})")

    staleness_days = staleness_seconds / 86_400.0
    exponent = -((hop_distance**2) + (staleness_days**2)) / l_session
    return math.exp(exponent)


def _require_native() -> None:
    if not HAS_NATIVE:
        raise RuntimeError(
            "one_link_native.align required but not installed; "
            "build via `cd native && maturin develop --release`. "
            "For development you can use trust_score_python() as a pure-Python "
            "fallback."
        )
