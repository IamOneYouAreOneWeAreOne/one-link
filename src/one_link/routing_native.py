"""Adapter for the file-engine v2 native tau-field routing crate
(``ol_routing`` via ``one_link_native``).

Per ADR-0028: τ_c-weighted Dijkstra + Byzantine-tolerance primitives.
Phase D #1 + #2.
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)

try:
    from one_link_native import routing as _native_routing  # type: ignore[attr-defined]

    HAS_NATIVE: bool = True
    NATIVE_VERSION: str | None = getattr(_native_routing, "__version__", None)
except ImportError as exc:
    HAS_NATIVE = False
    NATIVE_VERSION = None
    _native_routing = None  # type: ignore[assignment]
    log.info(
        "one_link_native.routing not installed (%s); ADR-0028 tau-field "
        "routing unavailable. Build via `cd native && maturin develop --release`.",
        exc,
    )


def adjacency_graph():
    """Build a fresh, empty :class:`AdjacencyGraph`."""
    _require_native()
    return _native_routing.AdjacencyGraph()


def edge_cost(tau_c_s: float, dist_m: float, loss_rate: float) -> float:
    """Combined edge cost = edge_weight × loss_penalty."""
    _require_native()
    return _native_routing.edge_cost(tau_c_s, dist_m, loss_rate)


def edge_weight(tau_c_s: float, dist_m: float) -> float:
    """Raw τ_c-weighted edge weight (no loss penalty applied). Used by
    the Phase E BE-RAR scorer, which composes its own loss-penalty term
    over this weight."""
    _require_native()
    return _native_routing.edge_weight(tau_c_s, dist_m)


def tau_claim_corroborated(
    claimed_tau_c_s: float, observed_success_rate: float, tolerance: float = 0.5
) -> bool:
    """Daemon cross-validation: does a peer's claimed τ_c match observed
    packet success? Returns False if the claim is suspect."""
    _require_native()
    return _native_routing.tau_claim_corroborated(
        claimed_tau_c_s, observed_success_rate, tolerance
    )


def _require_native() -> None:
    if not HAS_NATIVE:
        raise RuntimeError(
            "one_link_native.routing required for ADR-0028 tau-field routing but "
            "not installed; build via `cd native && maturin develop --release`."
        )
