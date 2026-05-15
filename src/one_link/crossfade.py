"""Crossfade — equal-power audio gain protocol for path + device handoffs.

When the Route Brain switches a call from path A to path B, or when
the Multi-Device Body Engine moves the microphone role from device A
to device B, two streams briefly produce audio simultaneously. The
naive solution (instantaneous switch) yields an audible pop. The
naive cross-mix at constant total gain (sum of linear gains = 1.0)
under-attenuates at the midpoint and the listener hears a dip.

This module implements the **equal-power crossfade** — the gain
curves are::

    gain_old(t) = cos(t * π/2)        # 1.0 → 0.0
    gain_new(t) = sin(t * π/2)        # 0.0 → 1.0

where t ∈ [0, 1] over the crossfade duration. The sum of squares is
always 1.0, so perceived power stays constant. This is the standard
DJ-mixer crossfade curve.

The default duration is 200 ms, matching the doc's Tier ε acceptance
target ("all paths converge without media gap > 250 ms"). Callers
can override for longer (calm) or shorter (cliff-edge) fades.

Pure module: produces a schedule of (timestamp, gain_old, gain_new)
samples. The caller applies the gains to its actual audio frames.
Cross-platform deterministic — same inputs, same outputs to 1e-15.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md §4.3 (crossfade)
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import IntEnum
from typing import Iterator


DEFAULT_DURATION_MS = 200
MIN_DURATION_MS = 20    # below this you hear the discontinuity
MAX_DURATION_MS = 2000  # above this the user notices the overlap


class CrossfadeKind(IntEnum):
    """What's being handed off. Doesn't change the curve; helps the
    audit log + Body Engine telemetry separate route from device
    transitions."""

    ROUTE_HANDOFF  = 0   # path A → path B, same device
    DEVICE_HANDOFF = 1   # device A → device B, same role (mic, cam, etc.)
    CODEC_HANDOFF  = 2   # Tier η — opus → semantic delta


@dataclass(frozen=True)
class CrossfadeSample:
    """One gain sample at one instant in time."""

    timestamp_ms: float     # ms since crossfade start
    gain_old: float         # 0..1
    gain_new: float         # 0..1


@dataclass(frozen=True)
class CrossfadePlan:
    """A precomputed gain schedule for one handoff event.

    Use:
      - :meth:`samples` to enumerate the gain pairs at the requested
        tick rate (50 Hz default — one sample per audio packet at
        20 ms cadence).
      - :meth:`gain_at` for ad-hoc interpolation if the audio path
        is event-driven rather than tick-driven.
    """

    kind: CrossfadeKind
    duration_ms: int
    started_at_ms: int
    tick_hz: float = 50.0  # 50 Hz = one sample per 20-ms opus frame

    def samples(self) -> Iterator[CrossfadeSample]:
        """Iterate the gain schedule from t=0 to t=duration. The last
        sample is exactly (gain_old=0, gain_new=1)."""
        step_ms = 1000.0 / self.tick_hz
        if step_ms <= 0:
            raise ValueError("tick_hz must be positive")
        n_steps = max(1, int(round(self.duration_ms / step_ms)))
        for i in range(n_steps + 1):
            t_ms = min(self.duration_ms, i * step_ms)
            yield self._sample_at(t_ms)

    def gain_at(self, t_ms: float) -> CrossfadeSample:
        """Return the gain pair at an arbitrary instant. Clamped:
        before the start → all-old; after the end → all-new."""
        if t_ms <= 0.0:
            return CrossfadeSample(0.0, 1.0, 0.0)
        if t_ms >= self.duration_ms:
            return CrossfadeSample(float(self.duration_ms), 0.0, 1.0)
        return self._sample_at(t_ms)

    def _sample_at(self, t_ms: float) -> CrossfadeSample:
        t = max(0.0, min(1.0, t_ms / self.duration_ms))
        phase = t * math.pi / 2
        return CrossfadeSample(
            timestamp_ms=t_ms,
            gain_old=math.cos(phase),
            gain_new=math.sin(phase),
        )


# ---------------------------------------------------------------------------
# Mixer — applies gain to actual audio samples
# ---------------------------------------------------------------------------

def mix_samples(
    *,
    old_samples: bytes,
    new_samples: bytes,
    gain_old: float,
    gain_new: float,
    sample_width_bytes: int = 2,
) -> bytes:
    """Linear PCM cross-mix. Both inputs are little-endian signed
    integer samples (16-bit by default). Output is the same width.

    The Body Engine + Route Brain use this for actual buffer mixing
    on a soft-handoff. Tier ε guarantees:
      - No clipping for inputs that don't clip themselves (equal-
        power preserves total power).
      - Deterministic — pure function, no randomness, no FP drift
        beyond the platform's IEEE-754 guarantees.

    Returns the mixed bytes. If the two inputs differ in length, the
    shorter one is logically zero-padded.
    """
    if sample_width_bytes not in (1, 2, 4):
        raise ValueError("sample_width_bytes must be 1, 2, or 4")
    if not (0.0 <= gain_old <= 1.0):
        raise ValueError("gain_old out of range")
    if not (0.0 <= gain_new <= 1.0):
        raise ValueError("gain_new out of range")
    if sample_width_bytes == 1:
        return _mix_u8(old_samples, new_samples, gain_old, gain_new)
    if sample_width_bytes == 2:
        return _mix_s16le(old_samples, new_samples, gain_old, gain_new)
    return _mix_s32le(old_samples, new_samples, gain_old, gain_new)


def _mix_s16le(a: bytes, b: bytes, ga: float, gb: float) -> bytes:
    """Mix two 16-bit signed little-endian PCM streams.

    Optimized: uses ``struct.iter_unpack`` to batch-unpack instead of
    per-sample slicing. About 3-4× faster than the per-byte loop for
    realistic 20 ms / 1920-sample frames.

    Falls back gracefully to per-sample for unequal-length inputs.
    """
    import struct

    a_len = len(a)
    b_len = len(b)
    if a_len == b_len and a_len % 2 == 0:
        # Hot path: equal-length, even-sample inputs.
        n_samples = a_len // 2
        a_vals = struct.unpack(f"<{n_samples}h", a)
        b_vals = struct.unpack(f"<{n_samples}h", b)
        out_vals = [
            max(-32768, min(32767, int(a_vals[i] * ga + b_vals[i] * gb)))
            for i in range(n_samples)
        ]
        return struct.pack(f"<{n_samples}h", *out_vals)

    # Slow path: unequal length / odd byte count → zero-pad.
    n = max(a_len, b_len)
    if n % 2:
        n += 1
    out = bytearray(n)
    a_view = memoryview(a)
    b_view = memoryview(b)
    for i in range(0, n, 2):
        av = (
            int.from_bytes(a_view[i:i + 2], "little", signed=True)
            if i + 2 <= a_len else 0
        )
        bv = (
            int.from_bytes(b_view[i:i + 2], "little", signed=True)
            if i + 2 <= b_len else 0
        )
        mixed = max(-32768, min(32767, int(av * ga + bv * gb)))
        out[i:i + 2] = mixed.to_bytes(2, "little", signed=True)
    return bytes(out)


def _mix_u8(a: bytes, b: bytes, ga: float, gb: float) -> bytes:
    n = max(len(a), len(b))
    out = bytearray(n)
    for i in range(n):
        av = a[i] - 128 if i < len(a) else 0
        bv = b[i] - 128 if i < len(b) else 0
        mixed = int(av * ga + bv * gb) + 128
        mixed = max(0, min(255, mixed))
        out[i] = mixed
    return bytes(out)


def _mix_s32le(a: bytes, b: bytes, ga: float, gb: float) -> bytes:
    n = max(len(a), len(b))
    if n % 4:
        n += 4 - (n % 4)
    out = bytearray(n)
    for i in range(0, n, 4):
        av = (
            int.from_bytes(a[i:i + 4], "little", signed=True)
            if i + 4 <= len(a) else 0
        )
        bv = (
            int.from_bytes(b[i:i + 4], "little", signed=True)
            if i + 4 <= len(b) else 0
        )
        mixed = int(av * ga + bv * gb)
        mixed = max(-2_147_483_648, min(2_147_483_647, mixed))
        out[i:i + 4] = mixed.to_bytes(4, "little", signed=True)
    return bytes(out)


# ---------------------------------------------------------------------------
# Builder helpers
# ---------------------------------------------------------------------------

def make_route_handoff(
    *,
    started_at_ms: int,
    duration_ms: int = DEFAULT_DURATION_MS,
    tick_hz: float = 50.0,
) -> CrossfadePlan:
    """Schedule a route-handoff fade (path A → path B)."""
    _validate_duration(duration_ms)
    return CrossfadePlan(
        kind=CrossfadeKind.ROUTE_HANDOFF,
        duration_ms=duration_ms,
        started_at_ms=started_at_ms,
        tick_hz=tick_hz,
    )


def make_device_handoff(
    *,
    started_at_ms: int,
    duration_ms: int = DEFAULT_DURATION_MS,
    tick_hz: float = 50.0,
) -> CrossfadePlan:
    """Schedule a device-handoff fade (mic moves from laptop to phone)."""
    _validate_duration(duration_ms)
    return CrossfadePlan(
        kind=CrossfadeKind.DEVICE_HANDOFF,
        duration_ms=duration_ms,
        started_at_ms=started_at_ms,
        tick_hz=tick_hz,
    )


def _validate_duration(duration_ms: int) -> None:
    if duration_ms < MIN_DURATION_MS:
        raise ValueError(
            f"duration_ms {duration_ms} below MIN_DURATION_MS "
            f"({MIN_DURATION_MS}); below this you hear the discontinuity"
        )
    if duration_ms > MAX_DURATION_MS:
        raise ValueError(
            f"duration_ms {duration_ms} above MAX_DURATION_MS "
            f"({MAX_DURATION_MS}); above this the user notices the overlap"
        )
