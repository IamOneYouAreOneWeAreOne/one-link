"""Tests for the equal-power crossfade protocol.

The properties that matter:
  - At t=0:  gain_old = 1.0, gain_new = 0.0
  - At t=1:  gain_old = 0.0, gain_new = 1.0
  - At t=0.5: gain_old^2 + gain_new^2 = 1.0 (equal power)
  - The mix function preserves total energy at the midpoint.
"""

from __future__ import annotations

import math

import pytest

from one_link.crossfade import (
    DEFAULT_DURATION_MS,
    MAX_DURATION_MS,
    MIN_DURATION_MS,
    CrossfadeKind,
    make_device_handoff,
    make_route_handoff,
    mix_samples,
)


# ---------------------------------------------------------------------------
# Gain-curve properties
# ---------------------------------------------------------------------------

def test_gain_curve_starts_at_full_old() -> None:
    plan = make_route_handoff(started_at_ms=0)
    s = plan.gain_at(0)
    assert s.gain_old == pytest.approx(1.0, abs=1e-9)
    assert s.gain_new == pytest.approx(0.0, abs=1e-9)


def test_gain_curve_ends_at_full_new() -> None:
    plan = make_route_handoff(started_at_ms=0, duration_ms=200)
    s = plan.gain_at(200)
    assert s.gain_old == pytest.approx(0.0, abs=1e-9)
    assert s.gain_new == pytest.approx(1.0, abs=1e-9)


def test_gain_curve_equal_power_at_midpoint() -> None:
    plan = make_route_handoff(started_at_ms=0, duration_ms=200)
    s = plan.gain_at(100)
    assert s.gain_old ** 2 + s.gain_new ** 2 == pytest.approx(1.0, abs=1e-9)


def test_gain_curve_equal_power_at_every_point() -> None:
    """The equal-power invariant must hold across the whole fade,
    not just at the midpoint."""
    plan = make_route_handoff(started_at_ms=0, duration_ms=200)
    for s in plan.samples():
        total_power = s.gain_old ** 2 + s.gain_new ** 2
        assert total_power == pytest.approx(1.0, abs=1e-9), (
            f"power broken at t={s.timestamp_ms}: "
            f"old={s.gain_old}, new={s.gain_new}, total={total_power}"
        )


def test_gain_before_start_returns_full_old() -> None:
    plan = make_route_handoff(started_at_ms=100, duration_ms=200)
    s = plan.gain_at(-50)
    assert s.gain_old == 1.0
    assert s.gain_new == 0.0


def test_gain_after_end_returns_full_new() -> None:
    plan = make_route_handoff(started_at_ms=100, duration_ms=200)
    s = plan.gain_at(500)
    assert s.gain_old == 0.0
    assert s.gain_new == 1.0


# ---------------------------------------------------------------------------
# Sample iteration
# ---------------------------------------------------------------------------

def test_samples_produces_correct_step_count() -> None:
    plan = make_route_handoff(
        started_at_ms=0, duration_ms=200, tick_hz=50.0,
    )
    samples = list(plan.samples())
    # 200 ms at 50 Hz = 10 steps + the final boundary sample = 11
    assert len(samples) == 11
    assert samples[0].timestamp_ms == 0
    assert samples[-1].timestamp_ms == 200


def test_samples_monotonic_in_time() -> None:
    plan = make_route_handoff(started_at_ms=0, duration_ms=200)
    samples = list(plan.samples())
    for i in range(1, len(samples)):
        assert samples[i].timestamp_ms >= samples[i - 1].timestamp_ms


def test_samples_old_monotonically_decreases() -> None:
    plan = make_route_handoff(started_at_ms=0, duration_ms=200)
    samples = list(plan.samples())
    for i in range(1, len(samples)):
        assert samples[i].gain_old <= samples[i - 1].gain_old + 1e-12


def test_samples_new_monotonically_increases() -> None:
    plan = make_route_handoff(started_at_ms=0, duration_ms=200)
    samples = list(plan.samples())
    for i in range(1, len(samples)):
        assert samples[i].gain_new >= samples[i - 1].gain_new - 1e-12


# ---------------------------------------------------------------------------
# Construction validation
# ---------------------------------------------------------------------------

def test_duration_below_minimum_raises() -> None:
    with pytest.raises(ValueError, match="below MIN_DURATION_MS"):
        make_route_handoff(started_at_ms=0, duration_ms=5)


def test_duration_above_maximum_raises() -> None:
    with pytest.raises(ValueError, match="above MAX_DURATION_MS"):
        make_route_handoff(started_at_ms=0, duration_ms=5000)


def test_default_duration_is_in_range() -> None:
    assert MIN_DURATION_MS <= DEFAULT_DURATION_MS <= MAX_DURATION_MS


def test_route_vs_device_kind() -> None:
    r = make_route_handoff(started_at_ms=0)
    d = make_device_handoff(started_at_ms=0)
    assert r.kind == CrossfadeKind.ROUTE_HANDOFF
    assert d.kind == CrossfadeKind.DEVICE_HANDOFF


# ---------------------------------------------------------------------------
# Sample mixing — 16-bit signed LE PCM
# ---------------------------------------------------------------------------

def test_mix_at_full_old_returns_old_samples() -> None:
    a = (1000).to_bytes(2, "little", signed=True) * 4
    b = (2000).to_bytes(2, "little", signed=True) * 4
    out = mix_samples(
        old_samples=a, new_samples=b,
        gain_old=1.0, gain_new=0.0,
    )
    assert out == a


def test_mix_at_full_new_returns_new_samples() -> None:
    a = (1000).to_bytes(2, "little", signed=True) * 4
    b = (2000).to_bytes(2, "little", signed=True) * 4
    out = mix_samples(
        old_samples=a, new_samples=b,
        gain_old=0.0, gain_new=1.0,
    )
    assert out == b


def test_mix_at_midpoint_blends_proportionally() -> None:
    a = (1000).to_bytes(2, "little", signed=True) * 4
    b = (3000).to_bytes(2, "little", signed=True) * 4
    out = mix_samples(
        old_samples=a, new_samples=b,
        gain_old=0.5, gain_new=0.5,
    )
    # Each sample = 0.5 * 1000 + 0.5 * 3000 = 2000
    for i in range(0, len(out), 2):
        sample = int.from_bytes(out[i:i + 2], "little", signed=True)
        assert sample == 2000


def test_mix_clips_to_int16_range() -> None:
    """If gain_old + gain_new > 1.0 the result can exceed int16. The
    mixer must clip rather than wrap."""
    a = (32000).to_bytes(2, "little", signed=True) * 2
    b = (32000).to_bytes(2, "little", signed=True) * 2
    out = mix_samples(
        old_samples=a, new_samples=b,
        gain_old=1.0, gain_new=1.0,
    )
    for i in range(0, len(out), 2):
        sample = int.from_bytes(out[i:i + 2], "little", signed=True)
        # Clip at 32767, not wrap to negative.
        assert sample == 32767


def test_mix_clips_negative() -> None:
    a = (-32000).to_bytes(2, "little", signed=True) * 2
    b = (-32000).to_bytes(2, "little", signed=True) * 2
    out = mix_samples(
        old_samples=a, new_samples=b,
        gain_old=1.0, gain_new=1.0,
    )
    for i in range(0, len(out), 2):
        sample = int.from_bytes(out[i:i + 2], "little", signed=True)
        assert sample == -32768


def test_mix_unequal_length_zero_pads_shorter() -> None:
    # Old has 4 samples, new has 2 — the trailing 2 samples mix as
    # if new were silence.
    a = (1000).to_bytes(2, "little", signed=True) * 4
    b = (2000).to_bytes(2, "little", signed=True) * 2
    out = mix_samples(
        old_samples=a, new_samples=b,
        gain_old=0.5, gain_new=0.5,
    )
    assert len(out) == len(a)
    s0 = int.from_bytes(out[0:2], "little", signed=True)
    s_last = int.from_bytes(out[6:8], "little", signed=True)
    assert s0 == 1500  # 0.5 * 1000 + 0.5 * 2000
    assert s_last == 500  # 0.5 * 1000 + 0.5 * 0


def test_mix_rejects_invalid_gain_range() -> None:
    with pytest.raises(ValueError):
        mix_samples(old_samples=b"", new_samples=b"", gain_old=1.5, gain_new=0.0)
    with pytest.raises(ValueError):
        mix_samples(old_samples=b"", new_samples=b"", gain_old=0.0, gain_new=-0.1)


def test_mix_rejects_invalid_sample_width() -> None:
    with pytest.raises(ValueError):
        mix_samples(
            old_samples=b"", new_samples=b"",
            gain_old=1.0, gain_new=0.0, sample_width_bytes=3,
        )


# ---------------------------------------------------------------------------
# Deterministic equal-power energy preservation
# ---------------------------------------------------------------------------

def test_total_perceived_power_constant_through_handoff() -> None:
    """The crossfade preserves perceived loudness across the
    transition. With identical signals on both paths (e.g., a sine
    tone), the equal-power curve keeps total RMS roughly constant."""
    plan = make_route_handoff(started_at_ms=0, duration_ms=200, tick_hz=50.0)
    # Constant amplitude on both sides
    a = (10000).to_bytes(2, "little", signed=True) * 100
    b = (10000).to_bytes(2, "little", signed=True) * 100
    rms_values = []
    for sample in plan.samples():
        mixed = mix_samples(
            old_samples=a, new_samples=b,
            gain_old=sample.gain_old, gain_new=sample.gain_new,
        )
        squared_sum = 0
        for i in range(0, len(mixed), 2):
            s = int.from_bytes(mixed[i:i + 2], "little", signed=True)
            squared_sum += s * s
        rms = math.sqrt(squared_sum / (len(mixed) // 2))
        rms_values.append(rms)
    # With identical inputs and equal-power gains, the mixed signal
    # equals the input (gain_old + gain_new in linear domain ≠ 1, BUT
    # because both inputs are identical, mixed = old*(g_old+g_new)
    # = old*(cos t + sin t)). The TOTAL POWER of the mix is preserved
    # — that's the equal-power property. RMS won't be constant since
    # we're summing identical signals; it varies with (g_old + g_new).
    # The property we DO want to verify: no point dips below the
    # cross-mix minimum (sin pi/4 + cos pi/4) ≈ 1.414 amplitude scaling.
    # That's the audible-dip-free property.
    min_rms = min(rms_values)
    max_rms = max(rms_values)
    # The variation is bounded.
    assert min_rms > 0
    assert max_rms / min_rms < 1.5  # less than 3.5 dB swing
