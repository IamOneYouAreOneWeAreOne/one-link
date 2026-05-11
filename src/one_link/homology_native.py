"""Adapter for the file-engine v2 native chunk-co-hold graph durability
detectors (``ol_homology`` via ``one_link_native``).

Per ADR-0033 Phase D #4: H0 components + bridge detection over the
chunk-co-hold graph for operational replication-priority sorting.
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)

try:
    from one_link_native import homology as _native_homology  # type: ignore[import-not-found]

    HAS_NATIVE: bool = True
except ImportError as exc:
    HAS_NATIVE = False
    _native_homology = None  # type: ignore[assignment]
    log.info(
        "one_link_native.homology not installed (%s); ADR-0033 chunk-co-hold "
        "durability unavailable. Build via `cd native && maturin develop --release`.",
        exc,
    )


def components_of(nodes, edges):
    """Compute union-find connected components of a chunk-co-hold graph.

    Returns a :class:`ComponentReport` with ``n_components``, ``sizes``,
    ``singletons``."""
    _require_native()
    return _native_homology.components_of(list(nodes), list(edges))


def fragility_score(nodes, edges, holders):
    """Compute per-chunk fragility scores + replication priority list.

    Returns ``(scores, replication_priority)`` where ``scores`` is a
    list of :class:`FragilityScore` and ``replication_priority`` is a
    list of chunk-ids sorted by descending score."""
    _require_native()
    return _native_homology.fragility_score(
        list(nodes), list(edges), dict(holders)
    )


def _require_native() -> None:
    if not HAS_NATIVE:
        raise RuntimeError(
            "one_link_native.homology required for ADR-0033 chunk-co-hold "
            "durability but not installed; build via `cd native && maturin "
            "develop --release`."
        )
