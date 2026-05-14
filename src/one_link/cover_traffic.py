"""Row 6 — cover-traffic daemon scheduler.

Wraps the native ``one_link_native.sphinx.CoverScheduler`` Poisson-
rate inter-arrival generator with a Python ``threading.Thread`` that
calls a user-supplied ``emit_cover()`` callback at the scheduled
intervals.

The cover packet itself is a real Sphinx Coherence packet built via
``one_link_native.sphinx.build_cover_packet`` (carries the
``COVER_SENTINEL`` so the destination drops the payload). Indistinguishable
on the wire from a real Sphinx packet of the same size — defeats traffic-
analysis attacks that count how many real messages a peer sends per
unit time.

Daemons that wire this:

    from one_link.cover_traffic import CoverTrafficDaemon

    cover = CoverTrafficDaemon(
        rate_hz=0.5,            # one cover packet per 2 seconds, on average
        emit_cover=daemon._emit_cover_packet,
    )
    cover.start()
    ...
    cover.stop()   # blocks briefly while the worker drains its current sleep

The ``emit_cover`` callback is invoked from a background daemon
thread — keep it short and thread-safe. The callback signature is
``Callable[[], None]``; failures inside it are logged and swallowed
so a transient error doesn't kill the cover-traffic schedule.
"""

from __future__ import annotations

import logging
import secrets
import threading
import time
from typing import Callable, Optional

log = logging.getLogger(__name__)

try:
    from one_link_native import sphinx as _native_sphinx  # type: ignore[import-not-found]

    HAS_NATIVE: bool = True
except ImportError as exc:
    HAS_NATIVE = False
    _native_sphinx = None  # type: ignore[assignment]
    log.info(
        "one_link_native.sphinx not installed (%s); Row 6 cover "
        "traffic scheduler unavailable. Build via "
        "`cd native && maturin develop --release`.",
        exc,
    )


# Default emission rate. 0.5 Hz = one cover packet per ~2 s on
# average. Tier-2 active-inference adaptive rate would set this
# dynamically from observer-entropy minimization; Phase 1 picks a
# conservative constant.
DEFAULT_RATE_HZ: float = 0.5


class CoverTrafficNotInstalled(RuntimeError):
    """Raised when the daemon tries to start cover traffic but the
    native sphinx module isn't built."""


class CoverTrafficDaemon:
    """Background thread emitting cover packets at a Poisson rate.

    Thread-safety: ``start()`` and ``stop()`` are safe to call from
    the daemon's main event loop. ``emit_cover()`` runs in the worker
    thread.

    The scheduler's sleep is interruptible via the internal
    ``_stop_event``; ``stop()`` triggers it so a long sleep doesn't
    delay shutdown.
    """

    __slots__ = (
        "_rate_hz",
        "_emit_cover",
        "_sched",
        "_thread",
        "_stop_event",
        "_emitted",
        "_errors",
    )

    def __init__(
        self,
        rate_hz: float = DEFAULT_RATE_HZ,
        emit_cover: Optional[Callable[[], None]] = None,
        seed: Optional[bytes] = None,
    ) -> None:
        """``rate_hz``: average emission rate. ``emit_cover``: callback
        invoked on each scheduled tick; may be ``None`` to run the
        scheduler in tick-counting mode (useful for tests).
        ``seed``: 32-byte deterministic seed for the Poisson generator;
        defaults to CSPRNG.
        """
        if not HAS_NATIVE:
            raise CoverTrafficNotInstalled(
                "one_link_native.sphinx unavailable. Build with "
                "`cd native && maturin develop --release`."
            )
        if rate_hz <= 0.0:
            raise ValueError(f"rate_hz must be > 0, got {rate_hz}")
        if seed is None:
            seed = secrets.token_bytes(32)
        if len(seed) != 32:
            raise ValueError(f"seed must be 32 bytes, got {len(seed)}")
        self._rate_hz = rate_hz
        self._emit_cover = emit_cover
        self._sched = _native_sphinx.CoverScheduler(rate_hz, seed)  # type: ignore[union-attr]
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._emitted = 0
        self._errors = 0

    @property
    def rate_hz(self) -> float:
        return self._rate_hz

    @property
    def emitted(self) -> int:
        """Total cover packets emitted since ``start()``."""
        return self._emitted

    @property
    def errors(self) -> int:
        """Total exceptions raised by the ``emit_cover`` callback."""
        return self._errors

    @property
    def is_running(self) -> bool:
        t = self._thread
        return t is not None and t.is_alive()

    def start(self) -> None:
        """Start the worker thread. Idempotent: subsequent calls
        while running are no-ops."""
        if self.is_running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="ol-cover-traffic",
            daemon=True,
        )
        self._thread.start()

    def stop(self, join_timeout: float = 5.0) -> None:
        """Signal stop + block on the worker draining (up to
        ``join_timeout`` seconds)."""
        self._stop_event.set()
        t = self._thread
        if t is not None:
            t.join(timeout=join_timeout)
            self._thread = None

    def _run(self) -> None:
        while not self._stop_event.is_set():
            wait_ms = self._sched.next_wait_ms()
            # Cap the sleep so stop() responsiveness doesn't suffer
            # on long Poisson tails. Long tails get rescheduled on
            # the next iteration if the stop_event hasn't fired.
            wait_s = min(wait_ms / 1000.0, 30.0)
            if self._stop_event.wait(timeout=wait_s):
                return
            if self._emit_cover is not None:
                try:
                    self._emit_cover()
                    self._emitted += 1
                except Exception as e:
                    self._errors += 1
                    log.warning("cover-traffic emit_cover raised: %s", e)
            else:
                # No callback: just count ticks (test mode).
                self._emitted += 1


def build_cover_packet(circuit, cover_size: int) -> bytes:
    """Build a Sphinx Coherence cover packet. ``circuit`` is a list
    of `(hop_id_bytes, hop_pubkey_bytes)` pairs (see
    ``one_link_native.sphinx`` docs). Use the result as the wire
    payload of a normal Sphinx packet — destinations identify it via
    ``is_cover_payload(packet.payload)`` and drop the payload."""
    if not HAS_NATIVE:
        raise CoverTrafficNotInstalled(
            "one_link_native.sphinx unavailable. Build with "
            "`cd native && maturin develop --release`."
        )
    return _native_sphinx.build_cover_packet(circuit, cover_size)  # type: ignore[union-attr]


def is_cover_payload(payload: bytes) -> bool:
    """True iff ``payload`` carries the cover-packet sentinel
    prefix. Destinations call this on every delivered Sphinx
    payload."""
    if not HAS_NATIVE:
        return False
    return _native_sphinx.is_cover_payload(payload)  # type: ignore[union-attr]
