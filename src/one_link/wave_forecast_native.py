"""Adapter for the wave-equation cascade forecaster
(``ol_coherence_field::wave`` via ``one_link_native``).

Decision point D25 from `intergration map.txt`. The native
``WaveStepper`` implements the leapfrog scheme

    ψ(t+dt) = 2·ψ(t) − ψ(t−dt) + c²·dt²·Δψ − γ·dt·(ψ(t)−ψ(t−dt))

on the per-peer τ_c scalar field, forecasting disturbance
propagation across the mesh. Disturbances exceeding the cascade
threshold tick the warning counter; this is RESEARCH-GRADE per
Gap 25 (high recall, ~21% precision at the tuned threshold).

Daemon-side usage:

    self._wave = wave_forecast_native.wave_stepper()
    self._wave.set_wave_speed(0.5)
    self._wave.set_damping(0.05)
    self._wave.set_clamp_range(0.0, 1.0)   # τ_c is in [0, 1]
    self._wave.seed(self._snapshot_field_state())
    # On every tick:
    neighbors = self._build_field_neighbor_graph()
    warns = self._wave.step(dt, neighbors)

The forecaster is gated by ``ONE_LINK_WAVE_FORECAST=1`` env. Default
off so v0.20 tests see no behavior change.
"""

from __future__ import annotations

import logging
from typing import Optional

log = logging.getLogger(__name__)

try:
    from one_link_native import coherence_field as _native_cf  # type: ignore[import-not-found]

    NATIVE_VERSION: Optional[str] = getattr(_native_cf, "__version__", None)
    _WaveStepper = getattr(_native_cf, "WaveStepper", None)
    # HAS_NATIVE is True only when BOTH the module imports AND the
    # WaveStepper class is present. A coherence_field module without
    # WaveStepper (e.g. an older wheel) signals "not available" so
    # the daemon falls through to the no-op path cleanly.
    HAS_NATIVE: bool = _WaveStepper is not None
    if not HAS_NATIVE:
        log.info(
            "one_link_native.coherence_field.WaveStepper not exposed by "
            "the installed wheel; D25 wave-forecast unavailable. "
            "Rebuild via `cd native && maturin develop --release`.",
        )
except ImportError as exc:
    HAS_NATIVE = False
    NATIVE_VERSION = None
    _native_cf = None  # type: ignore[assignment]
    _WaveStepper = None  # type: ignore[assignment]
    log.info(
        "one_link_native.coherence_field not available (%s); D25 "
        "wave-forecast unavailable. Build via "
        "`cd native && maturin develop --release`.",
        exc,
    )


def wave_stepper():
    """Construct a fresh WaveStepper with default parameters.

    Defaults match the integration map's calibration:
      - wave_speed = 1.0 (normalised τ_c units / second)
      - damping = 0.05 (gives ~20 dt-step useful forecast horizon)
      - cascade_threshold = 0.15 (per Gap 28 calibration)

    Use the ``set_*`` methods on the returned instance to customise.
    """
    _require_native()
    # _require_native() raises unless the native class loaded, so it is
    # non-None here (mypy can't see through the import-fallback assignment).
    assert _WaveStepper is not None
    return _WaveStepper()


def has_native() -> bool:
    """Whether the native WaveStepper is available. Equivalent to
    ``HAS_NATIVE`` constant but importable without the ImportError
    guard."""
    return HAS_NATIVE


def _require_native() -> None:
    if not HAS_NATIVE:
        raise RuntimeError(
            "one_link_native.coherence_field.WaveStepper required "
            "but not available; build via `cd native && maturin develop "
            "--release`."
        )


__all__ = [
    "HAS_NATIVE",
    "NATIVE_VERSION",
    "has_native",
    "wave_stepper",
]
