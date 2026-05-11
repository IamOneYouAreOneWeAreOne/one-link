"""Adapter for the file-engine v2 native CRDT folder type (``ol_crdt``
via ``one_link_native``).

Per ADR-0022: Folder CRDT composing vector clock + OR-set + LWW. Replaces
the daemon's ``foldersync.py`` vector-clock manifest.
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)

try:
    from one_link_native import crdt as _native_crdt  # type: ignore[import-not-found]
    from one_link_native import OlCrdtError  # type: ignore[import-not-found]

    HAS_NATIVE: bool = True
except ImportError as exc:
    HAS_NATIVE = False
    _native_crdt = None  # type: ignore[assignment]
    OlCrdtError = RuntimeError  # type: ignore[assignment, misc]
    log.info(
        "one_link_native.crdt not installed (%s); ADR-0022 CRDT folders "
        "unavailable. Build via `cd native && maturin develop --release`.",
        exc,
    )


def folder():
    """Build a fresh empty Folder CRDT."""
    _require_native()
    return _native_crdt.Folder()


def _require_native() -> None:
    if not HAS_NATIVE:
        raise RuntimeError(
            "one_link_native.crdt required for ADR-0022 CRDT folders "
            "but not installed; build via `cd native && maturin develop --release`."
        )
