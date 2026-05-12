"""Adapter for the file-engine v2 native coherence-field crate
(``ol_coherence_field`` via ``one_link_native``).

Phase E of `One_link/docs/FILE_ENGINE_V2_PLAN.md`. Surfaces the S_One
canonical theorem stack to the daemon:

1. Reaction-diffusion / Helmholtz solve `(Γ·I + D·L)·δτ_c = S` on a
   graph Laplacian.
2. Green-function nonlocal kernel (one solve, N readouts).
3. BE-RAR interpolation `nu(y) = 1/(1 − exp(−√y))` with α = 1/2.
4. Screening length + apparent-horizon anchor calibration.
5. Identity-sector dual source `S = α·ρ + β·|J|`.
6. Cross-domain calibrations: One Link / OneField / BioMesh.
7. Couplings: homology → field, field → prefetch, field → ratchet.
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)

try:
    from one_link_native import coherence_field as _native_field  # type: ignore[import-not-found]

    HAS_NATIVE: bool = True
    NATIVE_VERSION: str | None = getattr(_native_field, "__version__", None)
except ImportError as exc:
    HAS_NATIVE = False
    NATIVE_VERSION = None
    _native_field = None  # type: ignore[assignment]
    log.info(
        "one_link_native.coherence_field not installed (%s); Phase E "
        "coherence-field routing unavailable. Build via "
        "`cd native && maturin develop --release`.",
        exc,
    )


def graph_laplacian(n_nodes: int) -> Any:
    """Build a fresh, empty :class:`GraphLaplacian` over ``n_nodes``."""
    _require_native()
    return _native_field.GraphLaplacian(n_nodes)


def solve_helmholtz(
    graph: Any,
    d: float,
    gamma: float,
    source: list[float],
    *,
    max_iters: int = 2000,
    tolerance: float = 1e-6,
) -> dict[str, Any]:
    """Solve ``(Γ·I + D·L)·δτ_c = S`` for the field over ``graph``.

    Returns a dict ``{"field", "residual", "iterations", "converged"}``.
    """
    _require_native()
    return _native_field.solve_helmholtz(
        graph, d, gamma, source, max_iters, tolerance
    )


def be_rar(y: float) -> float:
    """BE-RAR interpolation ``nu(y) = 1/(1 − exp(−√y))``. α=1/2 forced
    by Bose statistics — see ``ol_coherence_field/src/interpolation``."""
    _require_native()
    return _native_field.be_rar(y)


def apparent_horizon_anchor(c_wire: float, h_swarm: float) -> float | None:
    """Compute ``g_A = c · H_swarm / (2π)``. ``None`` on non-physical inputs."""
    _require_native()
    return _native_field.apparent_horizon_anchor(c_wire, h_swarm)


def screening_length(d: float, gamma: float) -> float | None:
    """Screening length ``ell_screen = √(D / Γ)``."""
    _require_native()
    return _native_field.screening_length(d, gamma)


def one_link_calibration() -> dict[str, Any]:
    """Production One Link calibration constants (D, Γ, α, β, c, H_0)."""
    _require_native()
    return _native_field.one_link_calibration()


def rotation_cadence_multiplier(
    field: list[float],
    baseline_bytes: int,
    *,
    mu_max: float = 4.0,
    power: float = 2.0,
) -> list[tuple[int, float, int]]:
    """Per-peer ratchet rotation cadence under the coherence field.

    Returns a list of ``(peer_index, multiplier, bytes_between_rotations)``
    tuples. Low-coherence peers rotate faster per byte than high-coherence
    peers — crypto strength as a function of network physics.
    """
    _require_native()
    return _native_field.rotation_cadence_multiplier(
        field, baseline_bytes, mu_max, power
    )


def prefetch_priorities(
    field: list[float],
    requester: int,
    holders: list[int],
    *,
    route_weight: float = 1.0,
) -> list[tuple[int, float, float]]:
    """Rank holders for where to pre-position a chunk along high-coherence
    paths to ``requester``. Returns ``(holder, normalised_field, cost)``
    sorted best-first."""
    _require_native()
    return _native_field.prefetch_priorities(
        field, requester, holders, route_weight
    )


def inject_fragility_events(
    source: list[float],
    events: list[tuple[list[int], float]],
    *,
    coupling_strength: float = 1.0,
) -> tuple[list[float], list[float]]:
    """Modify ``source`` to encode fragility events from `ol_homology`.

    Returns ``(modified_source, applied_penalties)``. Fragility cycles
    detected by persistent homology source negative spikes into ``S``;
    the next field solve re-equilibrates so routes avoid the fragile
    region BEFORE the partition completes.
    """
    _require_native()
    return _native_field.inject_fragility_events(
        source, events, coupling_strength
    )


def _require_native() -> None:
    if not HAS_NATIVE:
        raise RuntimeError(
            "one_link_native.coherence_field required for Phase E field "
            "routing but not installed; build via "
            "`cd native && maturin develop --release`."
        )
