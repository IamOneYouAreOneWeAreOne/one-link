"""Power detection must never block the daemon's event loop.

The Windows e2e leg failed with a read timeout on /api/power/status:

    urllib3.exceptions.ReadTimeoutError: HTTPConnectionPool(
        host='127.0.0.1', port=7117): Read timed out. (read timeout=5)

The handler called Daemon._power_state() directly, and its refresh path shells
out to PowerShell to ask WinRT whether the connection is metered. That spawn ran
ON THE EVENT LOOP, so for its whole duration the daemon served nothing at all --
and the request that times out need not be the one that blocked. A UI polling
this endpoint would freeze unrelated traffic once per cache window.

_detect_metered budgets "~150ms"; its own subprocess timeout is 2.0s, and a
PowerShell cold start on a loaded machine is far worse than either.
"""

from __future__ import annotations

import asyncio
import inspect
import time

from one_link.daemon import Daemon


def test_power_state_async_lets_the_loop_keep_running(monkeypatch) -> None:
    """The proof: other coroutines make progress DURING the blocking probe."""

    def _slow_probe() -> dict:
        time.sleep(0.30)  # stands in for the PowerShell spawn
        return {"ts": 0.0, "on_battery": False, "metered": False}

    monkeypatch.setattr(Daemon, "_power_state", staticmethod(_slow_probe))

    ticks = 0

    async def _ticker() -> None:
        nonlocal ticks
        for _ in range(30):
            await asyncio.sleep(0.01)
            ticks += 1

    async def _exercise() -> dict:
        probe = asyncio.create_task(Daemon._power_state_async())
        ticker = asyncio.create_task(_ticker())
        result = await probe
        ticker.cancel()
        return result

    result = asyncio.run(_exercise())
    assert result["metered"] is False
    # If the probe had run on the loop, the ticker could not have advanced at
    # all while it was in flight.
    assert ticks >= 5, (
        f"event loop was blocked during the power probe (only {ticks} ticks); "
        "the detection is not running in an executor"
    )


def test_sync_paused_helper_is_also_off_loop(monkeypatch) -> None:
    calls: list[str] = []

    def _slow_gate(self, *, allow_probe: bool = True) -> tuple[bool, str]:
        calls.append("probed")
        time.sleep(0.20)
        return (True, "on battery")

    monkeypatch.setattr(Daemon, "_sync_paused_or_quiet", _slow_gate)

    ticks = 0

    async def _ticker() -> None:
        nonlocal ticks
        for _ in range(30):
            await asyncio.sleep(0.01)
            ticks += 1

    async def _exercise():
        daemon = object.__new__(Daemon)  # no start-up side effects needed
        probe = asyncio.create_task(Daemon._sync_paused_or_quiet_async(daemon))
        ticker = asyncio.create_task(_ticker())
        result = await probe
        ticker.cancel()
        return result

    skip, reason = asyncio.run(_exercise())
    assert (skip, reason) == (True, "on battery")
    assert calls == ["probed"]
    assert ticks >= 3, f"event loop was blocked during the sync gate ({ticks} ticks)"


def test_no_coroutine_calls_the_blocking_power_helpers_directly() -> None:
    """Absence asserted, not remembered.

    A new coroutine calling _power_state() or _sync_paused_or_quiet() directly
    would silently reintroduce the stall, so the async entry points are required
    to be the only ones reachable from a coroutine.
    """

    from one_link import server as server_module

    handler = inspect.getsource(server_module.UIServer.api_power_status)
    # Off-loop was necessary but not sufficient: the request that triggers the
    # refresh still waited for the PowerShell spawn, and the e2e read timeout
    # survived this fix. The handler now takes the strictly stronger route --
    # it never waits on a probe at all -- so pin THAT rather than the awaited
    # blocking call it replaced. See
    # tests/test_power_status_never_waits_on_a_probe.py.
    assert "await self.daemon._power_state_nonblocking()" in handler
    assert "await self.daemon._sync_paused_or_quiet_async(allow_probe=False)" in handler
    assert "self.daemon._power_state()" not in handler
    assert "self.daemon._power_state_async()" not in handler
    assert "self.daemon._sync_paused_or_quiet()" not in handler

    push = inspect.getsource(Daemon.push_folder_to_peer)
    assert "await self._sync_paused_or_quiet_async()" in push
    assert "self._sync_paused_or_quiet()" not in push.replace(
        "await self._sync_paused_or_quiet_async()", ""
    )


def test_the_detection_still_runs_in_a_thread_not_skipped(monkeypatch) -> None:
    """Off-loop must not become never-called: the value must still be real."""

    import threading

    seen: dict[str, object] = {}

    def _probe() -> dict:
        seen["thread"] = threading.current_thread().name
        return {"ts": 1.0, "on_battery": True, "metered": True}

    monkeypatch.setattr(Daemon, "_power_state", staticmethod(_probe))
    result = asyncio.run(Daemon._power_state_async())
    assert result["on_battery"] is True and result["metered"] is True
    assert seen["thread"] != threading.main_thread().name, (
        "the probe ran on the main thread, so it was not moved off the loop"
    )
