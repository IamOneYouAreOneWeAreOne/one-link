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

# F4 mode-contract integration:
#   - paranoid     : cover ALWAYS on (per F4 paranoid_no_cover violation)
#   - battery_save : cover ALWAYS off (per F4 battery_save_cover violation)
#   - normal       : opt-in via env (ONE_LINK_COVER_TRAFFIC=1)
#   - latency_strict: opt-in via env (cover-on permitted but not mandated)
ALWAYS_ON_MODES: tuple[str, ...] = ("paranoid",)
NEVER_ON_MODES: tuple[str, ...] = ("battery_save",)
OPT_IN_MODES: tuple[str, ...] = ("normal", "latency_strict")


def is_cover_mandated(user_mode: str) -> bool:
    """True iff F4 mandates cover traffic for ``user_mode``."""
    return (user_mode or "normal").strip().lower() in ALWAYS_ON_MODES


def is_cover_forbidden(user_mode: str) -> bool:
    """True iff F4 forbids cover traffic for ``user_mode``."""
    return (user_mode or "normal").strip().lower() in NEVER_ON_MODES


def should_run_cover(user_mode: str, env_gate: bool) -> bool:
    """Effective on/off decision combining F4 mode contract with the
    explicit env-gate flag. F4 mandates / forbids override the env
    flag in both directions."""
    if is_cover_forbidden(user_mode):
        return False
    if is_cover_mandated(user_mode):
        return True
    return bool(env_gate)


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
        "_user_mode",
        "_env_gate",
        "_mode_lock",
        "_rate_multiplier",
        "_skipped",
        "_rng",
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
        # F4 mode-contract state. Defaults match the daemon's startup
        # ("normal" mode, env gate off) so the emitter doesn't run
        # until the daemon explicitly opts in or switches to paranoid.
        self._user_mode: str = "normal"
        self._env_gate: bool = False
        self._mode_lock = threading.Lock()
        # Adaptive-rate multiplier in [0, 1]. The Bernoulli-skip
        # in _run() emits with probability ``_rate_multiplier`` on
        # every native-scheduler tick. Equivalent to a Poisson
        # process at effective rate base_rate * multiplier.
        # Default 1.0 = no adaptation (baseline rate).
        self._rate_multiplier: float = 1.0
        self._skipped: int = 0
        # Dedicated RNG seeded from the same source so two daemons
        # with the same seed produce the same skip pattern (testable).
        import random as _random
        self._rng = _random.Random()
        # Derive a deterministic seed from the same bytes the scheduler
        # got — when callers pass a fixed seed, the skip pattern is
        # reproducible for tests.
        self._rng.seed(int.from_bytes(seed, "big", signed=False))

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

    # ---------- F4 mode-contract integration ----------

    def set_user_mode(self, mode: str) -> None:
        """Update the F4 mode. Mandated modes (paranoid) force the
        emitter on; forbidden modes (battery_save) force it off — the
        daemon is responsible for calling ``apply_mode_contract()``
        after this if it wants the lifecycle to react synchronously."""
        with self._mode_lock:
            self._user_mode = (mode or "normal").strip().lower()

    def set_env_gate(self, enabled: bool) -> None:
        """Set the explicit env-gate flag. Honoured for opt-in modes;
        overridden in both directions by mandated/forbidden modes."""
        with self._mode_lock:
            self._env_gate = bool(enabled)

    def set_rate_multiplier(self, multiplier: float) -> None:
        """Set the adaptive-rate multiplier in [0, 1].

        Effective emission rate becomes ``base_rate * multiplier``
        via a Bernoulli-skip in the run loop: every native scheduler
        tick emits with probability ``multiplier``, skips otherwise.
        Mathematically equivalent to a Poisson process at
        ``base_rate * multiplier`` rate (thinning property).

        Use cases:
          - Selector-driven: ``cover_ratio`` from
            ``Daemon.selector_decision_stats()`` scaled to a
            multiplier. High cover_ratio -> high rate; low ->
            baseline floor.
          - Bandwidth-driven: throttle down when the radio is
            constrained.

        Clamped to [0.0, 1.0]. Values outside the range are silently
        snapped to the nearest endpoint."""
        m = max(0.0, min(1.0, float(multiplier)))
        with self._mode_lock:
            self._rate_multiplier = m

    @property
    def rate_multiplier(self) -> float:
        """Current adaptive-rate multiplier."""
        with self._mode_lock:
            return self._rate_multiplier

    @property
    def skipped(self) -> int:
        """Total scheduler ticks skipped by the Bernoulli adapter."""
        return self._skipped

    @property
    def effective_enabled(self) -> bool:
        """Whether the F4 contract + env-gate combination says cover
        traffic should currently be active."""
        with self._mode_lock:
            return should_run_cover(self._user_mode, self._env_gate)

    def apply_mode_contract(self) -> bool:
        """Reconcile the running state with the F4 contract + env-gate.
        Returns True iff a state transition occurred (started or
        stopped). Idempotent; safe to call on every mode-change
        notification. The daemon should call this after
        ``set_user_mode`` / ``set_env_gate`` so a paranoid switch
        instantly turns the emitter on, and a battery_save switch
        instantly turns it off."""
        want = self.effective_enabled
        running = self.is_running
        if want and not running:
            self.start()
            return True
        if not want and running:
            self.stop()
            return True
        return False

    def start(self) -> None:
        """Start the worker thread. Idempotent: subsequent calls
        while running are no-ops. Will refuse to start if the F4
        contract forbids cover traffic (battery_save)."""
        if self.is_running:
            return
        with self._mode_lock:
            if is_cover_forbidden(self._user_mode):
                log.info(
                    "cover-traffic start refused: mode=%s forbids cover",
                    self._user_mode,
                )
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

    def stats(self) -> dict:
        """Inspection snapshot for ops telemetry / operator UI. Pure
        readout — never raises."""
        with self._mode_lock:
            mode = self._user_mode
            gate = self._env_gate
            effective = should_run_cover(mode, gate)
            multiplier = self._rate_multiplier
        return {
            "rate_hz": self._rate_hz,
            "rate_multiplier": multiplier,
            "effective_rate_hz": self._rate_hz * multiplier,
            "user_mode": mode,
            "env_gate": gate,
            "effective_enabled": effective,
            "running": self.is_running,
            "emitted": self._emitted,
            "skipped": self._skipped,
            "errors": self._errors,
            "mandated_by_mode": is_cover_mandated(mode),
            "forbidden_by_mode": is_cover_forbidden(mode),
        }

    def _run(self) -> None:
        while not self._stop_event.is_set():
            wait_ms = self._sched.next_wait_ms()
            # Cap the sleep so stop() responsiveness doesn't suffer
            # on long Poisson tails. Long tails get rescheduled on
            # the next iteration if the stop_event hasn't fired.
            wait_s = min(wait_ms / 1000.0, 30.0)
            if self._stop_event.wait(timeout=wait_s):
                return
            # Adaptive-rate Bernoulli skip. multiplier=1.0 always emits;
            # multiplier=0.0 always skips. The thinning property of
            # Poisson processes guarantees the resulting inter-arrival
            # distribution is still Poisson with rate
            # base_rate * multiplier.
            with self._mode_lock:
                m = self._rate_multiplier
            if m < 1.0 and self._rng.random() >= m:
                self._skipped += 1
                continue
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
