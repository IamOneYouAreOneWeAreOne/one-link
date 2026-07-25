"""Adapter for `FieldObservations` (``ol_coherence_field`` via
``one_link_native``).

Decision point D23 (field-state writes) + D24 (∇τ_c gradient) in
`intergration map.txt`. The daemon writes per-peer τ_c observations
here from three confirmed sites:

  - _update_transfer       (daemon.py:3367-3376)
  - _observe_prefetch      (daemon.py:9213-9270, write at 9268)
  - record_relay_observation (daemon.py:10307-10335)

Each write is trust-weighted via `_peer_trust_score(peer_fp)` to defend
against field poisoning (Gap 4 evidence: 92% reduction in poisoning
impact at 15% attacker fraction).

The gradient is RESEARCH-GRADE per Gap 25 (high recall, ~21% precision
at the tuned threshold). Surface it as a soft signal in this phase;
selector + relay-picker may consult it for anchor-lay hints but should
not gate decisions on it.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from one_link_native.coherence_field import FieldObservations

log = logging.getLogger(__name__)

_FieldObservations: type[FieldObservations] | None

try:
    from one_link_native import coherence_field as _native_cf  # type: ignore[import-not-found]

    HAS_NATIVE: bool = True
    NATIVE_VERSION: str | None = getattr(_native_cf, "__version__", None)
    _FieldObservations = _native_cf.FieldObservations
except (ImportError, AttributeError) as exc:
    HAS_NATIVE = False
    NATIVE_VERSION = None
    _native_cf = None  # type: ignore[assignment]
    _FieldObservations = None  # type: ignore[assignment]
    log.info(
        "one_link_native.coherence_field.FieldObservations not available "
        "(%s); D23 field-state writes unavailable. Build via "
        "`cd native && maturin develop --release`.",
        exc,
    )


def field_observations(alpha: float = 0.05, initial_value: float = 0.5):
    """Construct a FieldObservations buffer.

    `alpha` is the EWMA learning rate at trust = 1.0 (in (0, 1]).
    Typical: 0.05 — moderate responsiveness, ~20-sample window.

    `initial_value` is the cold-start τ_c for newly-observed peers.
    Default 0.5 means neutral starting trust.

    Daemon-side usage:
        self._field_obs = field_observations_native.field_observations()
        # ... on every transfer / prefetch / relay observation:
        trust = self._peer_trust_score(peer_fp) or 0.5
        self._field_obs.update(peer_fp, observed_tau, trust)
    """
    return _require_native()(alpha, initial_value)


def _require_native() -> type[FieldObservations]:
    factory = _FieldObservations
    if not HAS_NATIVE or factory is None:
        raise RuntimeError(
            "one_link_native.coherence_field.FieldObservations required "
            "but not available; build via `cd native && maturin develop "
            "--release`."
        )
    return factory
