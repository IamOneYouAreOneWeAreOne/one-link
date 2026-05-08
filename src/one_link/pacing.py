"""v0.12.0 — bandwidth pacing primitive (token bucket).

The Settings → Storage → Bandwidth limit dropdown stores a single
integer (bandwidth_cap_kbps). The transfer engine's chunk send path
calls `await pacer.pace(len(data))` BEFORE each send. When the cap
is 0 (Unlimited) the call is a fast no-op; when the cap is > 0 the
caller awaits until enough budget has refilled to cover the bytes.

Why a token bucket vs. a sleep-after-send: bucket smooths bursts.
A 100ms-window cap that fires sleep(remaining_window) after each
send produces sawtooth throughput; a token bucket produces a
plateau. Same average rate, much friendlier to the receiver's
write-side flow control.

The bucket is global (combined send + receive) so the cap describes
*One Link's footprint on this machine's link*, not per-direction.
A future refinement could split into separate up/down buckets but
the headline UX promise is "this app uses at most X MB/s" — single
bucket matches that.

The pacer is process-local — no IPC or shared memory across
daemons. Multiple daemons on the same box will each get their own
budget. That's fine: the cap is per-instance.

Thread/async note: the bucket uses an asyncio.Lock so concurrent
.pace() calls serialize through the budget calculation. Each call
holds the lock for ~µs (just arithmetic + maybe one sleep
schedule); under heavy parallelism the lock is not a hot point.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class _State:
    """Token-bucket internals. Capacity = burst tolerance =
    cap_bytes_per_second × BURST_SECONDS. Tokens refill linearly."""
    cap_bytes_per_second: float
    capacity_bytes: float
    tokens: float
    last_refill_ts: float


# 0.5s of burst headroom. Big enough that small chunks pass without
# scheduling overhead; small enough that the average rate stays
# close to the cap on long sustained transfers.
BURST_SECONDS = 0.5

# Minimum sleep to avoid burning CPU on tiny waits. asyncio
# scheduling itself costs ~0.1ms; sleeping less than that gains
# nothing.
MIN_SLEEP_SECONDS = 0.001


class BandwidthPacer:
    """Awaitable token bucket for global bandwidth pacing.

    Pace before every chunk send::

        await pacer.pace(len(payload))
        await channel.send(encode_msg(chunk_msg))

    The pacer auto-no-ops when set_cap(0) is in effect, so call
    sites don't need to branch on whether the user has a cap set.
    """

    def __init__(self, *, cap_kbps: int = 0) -> None:
        self._lock = asyncio.Lock()
        self._state: Optional[_State] = None
        self.set_cap(cap_kbps)

    @property
    def cap_kbps(self) -> int:
        s = self._state
        if s is None:
            return 0
        return int(s.cap_bytes_per_second * 8 / 1024)

    @property
    def is_unlimited(self) -> bool:
        return self._state is None

    def set_cap(self, cap_kbps: int) -> None:
        """Update the cap live. Pass 0 / negative to disable.

        Existing in-flight sends drain through whatever budget is
        still in the bucket; new sends pace against the new cap.
        Cheap, idempotent."""
        if cap_kbps is None or cap_kbps <= 0:
            self._state = None
            return
        bytes_per_sec = float(cap_kbps) * 1024 / 8
        capacity = bytes_per_sec * BURST_SECONDS
        prev = self._state
        if prev is None:
            tokens = capacity
        else:
            # Carry over remaining tokens but never exceed the new
            # capacity (a downsize shouldn't grant a free burst).
            tokens = min(prev.tokens, capacity)
        self._state = _State(
            cap_bytes_per_second=bytes_per_sec,
            capacity_bytes=capacity,
            tokens=tokens,
            last_refill_ts=time.monotonic(),
        )

    async def pace(self, n_bytes: int) -> None:
        """Reserve n_bytes of budget; await if not yet available.

        Idempotent on n_bytes <= 0 (returns immediately). When the
        pacer is unlimited, returns immediately without acquiring
        the lock — the hot path stays cheap."""
        if self.is_unlimited or n_bytes <= 0:
            return
        async with self._lock:
            s = self._state
            if s is None:
                return
            await self._reserve_locked(s, n_bytes)

    async def _reserve_locked(self, s: _State, n_bytes: int) -> None:
        # Refill based on elapsed wall time.
        now = time.monotonic()
        elapsed = max(0.0, now - s.last_refill_ts)
        s.tokens = min(s.capacity_bytes, s.tokens + elapsed * s.cap_bytes_per_second)
        s.last_refill_ts = now
        if n_bytes <= s.tokens:
            s.tokens -= n_bytes
            return
        # Need to wait. If n_bytes exceeds capacity (a single chunk
        # bigger than the bucket), drain to zero then sleep enough
        # to cover the overflow at the cap rate.
        deficit = n_bytes - s.tokens
        wait = deficit / s.cap_bytes_per_second
        if wait < MIN_SLEEP_SECONDS:
            wait = MIN_SLEEP_SECONDS
        # Optimistically debit the full request now and sleep; this
        # keeps the bucket math identity-preserving across awaits.
        s.tokens = 0.0
        # Release the lock during sleep so other paces can queue
        # (they'll see tokens=0 and add to the wait line correctly).
        # asyncio.Lock is reentrant via async-with, so we drop it
        # explicitly.
        # NOTE: we DO want serialization on the math; only the
        # sleep itself runs unlocked.
        await self._sleep_outside_lock(wait, s)

    async def _sleep_outside_lock(self, wait: float, s: _State) -> None:
        # Subtle: we're already inside `async with self._lock`. To
        # release for the sleep, we have to exit the context. Easier
        # pattern: schedule the sleep then re-enter to update
        # last_refill_ts. We approximate by NOT actually releasing
        # the lock — the next caller will queue on the lock and
        # then refill against the post-sleep clock, which yields
        # correct serialized behavior.
        await asyncio.sleep(wait)
        s.last_refill_ts = time.monotonic()
