"""Tests for the Row 6 cover-traffic daemon scheduler."""

from __future__ import annotations

import time

import pytest

from one_link.cover_traffic import (
    HAS_NATIVE,
    CoverTrafficDaemon,
    is_cover_payload,
)

pytestmark = pytest.mark.skipif(
    not HAS_NATIVE,
    reason="one_link_native.sphinx not built; run `maturin develop --release`",
)


def test_constructor_rejects_invalid_rate():
    with pytest.raises(ValueError):
        CoverTrafficDaemon(rate_hz=0.0)
    with pytest.raises(ValueError):
        CoverTrafficDaemon(rate_hz=-1.0)


def test_constructor_rejects_wrong_seed_length():
    with pytest.raises(ValueError):
        CoverTrafficDaemon(rate_hz=1.0, seed=bytes([0] * 31))


def test_scheduler_emits_at_rate():
    """20 Hz over 0.6 s should produce > 1 tick. Poisson variance
    is high at small samples — just confirm SOMETHING ticks."""
    ticks = [0]

    def emit() -> None:
        ticks[0] += 1

    c = CoverTrafficDaemon(
        rate_hz=20.0, emit_cover=emit, seed=bytes([0x42] * 32)
    )
    c.start()
    try:
        time.sleep(0.6)
    finally:
        c.stop()
    assert ticks[0] >= 1
    assert c.emitted == ticks[0]


def test_scheduler_is_idempotent_start():
    c = CoverTrafficDaemon(rate_hz=5.0, emit_cover=None, seed=bytes([0x42] * 32))
    c.start()
    try:
        c.start()  # second start is a no-op
        assert c.is_running
    finally:
        c.stop()
    assert not c.is_running


def test_scheduler_stop_responsive_under_long_sleep():
    """Even with rate_hz=0.001 (mean inter-arrival ~1000s), stop()
    returns quickly because the worker caps each sleep at 30s and
    polls _stop_event."""
    c = CoverTrafficDaemon(
        rate_hz=0.001, emit_cover=None, seed=bytes([0x42] * 32)
    )
    c.start()
    t0 = time.time()
    c.stop(join_timeout=5.0)
    elapsed = time.time() - t0
    # Should return well under the 30s sleep cap.
    assert elapsed < 1.5, f"stop took {elapsed:.2f}s"


def test_emit_callback_exception_does_not_kill_worker():
    """A raising emit_cover bumps the error counter but the worker
    keeps emitting."""
    counts = {"ok": 0, "err": 0}

    def emit() -> None:
        counts["ok"] += 1
        if counts["ok"] % 2 == 0:
            raise RuntimeError("simulated emit failure")

    c = CoverTrafficDaemon(
        rate_hz=50.0, emit_cover=emit, seed=bytes([0x44] * 32)
    )
    c.start()
    time.sleep(0.3)
    c.stop()
    assert counts["ok"] >= 2
    # Errors counter tracks at least one raise.
    assert c.errors >= 1


def test_is_cover_payload_recognises_empty_as_non_cover():
    assert is_cover_payload(b"") is False
    assert is_cover_payload(b"not a cover packet") is False
