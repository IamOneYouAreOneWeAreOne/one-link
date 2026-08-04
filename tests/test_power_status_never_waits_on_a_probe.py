"""/api/power/status must not pay for its own cache refresh.

`e2e (playwright) / windows-latest` failed on
`test_api_power_status_returns_200` with a 5s read timeout. The obvious fix had
already been applied: `_power_state_async` moved the probe off the event loop,
so it no longer blocked every OTHER request. It kept failing, because that
never addressed the latency of the request that triggers the refresh.

`_detect_metered` shells out to PowerShell to ask WinRT about metered
connections. Its own subprocess timeout is 2.0s, and a kill plus reap lands on
top of that; add executor queueing and a second executor round trip for the
sync-policy read and one poll exceeds a 5s budget on a loaded CI runner.

The endpoint's own docstring says it is "cached server-side for 30s so polling
is cheap". These tests hold it to that: the cached reading is served
immediately and the refresh happens behind the response.

The probe here is deliberately slower than the client budget that failed. A
test using a fast probe would pass against the broken code too.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from one_link.daemon import Daemon

# Comfortably longer than the 5s budget the e2e client used, so a version that
# waits for the probe cannot pass this by being merely quick.
SLOW_PROBE_SECONDS = 6.0
# A served-from-cache answer is a dict copy and a clock read.
IMMEDIATE_SECONDS = 0.5


@pytest.fixture(autouse=True)
def _isolate_power_cache():
    """The cache is class state shared by every test in the process."""
    saved = dict(Daemon._power_cache)
    saved_inflight = Daemon._power_refresh_inflight
    Daemon._power_cache = {"ts": 0.0, "on_battery": False, "metered": False}
    Daemon._power_refresh_inflight = False
    yield
    Daemon._power_cache = saved
    Daemon._power_refresh_inflight = saved_inflight


@pytest.fixture
def slow_probe(monkeypatch):
    """Replace the OS probes with a slow one that records its calls."""
    calls: list[float] = []

    def _slow_metered() -> bool:
        calls.append(time.monotonic())
        time.sleep(SLOW_PROBE_SECONDS)
        return True

    monkeypatch.setattr(Daemon, "_detect_metered", staticmethod(_slow_metered))
    monkeypatch.setattr(Daemon, "_detect_on_battery", staticmethod(lambda: True))
    return calls


@pytest.mark.asyncio
async def test_a_cold_cache_answers_immediately_instead_of_waiting(slow_probe):
    started = time.monotonic()
    state, fresh = await Daemon._power_state_nonblocking()
    elapsed = time.monotonic() - started

    assert elapsed < IMMEDIATE_SECONDS, (
        f"the request waited {elapsed:.2f}s on the probe; it must answer from "
        "cache and refresh behind the response"
    )
    # An empty cache is reported as not-fresh rather than dressed up as a
    # reading. The caller can tell the difference.
    assert fresh is False
    assert state["on_battery"] is False
    assert state["metered"] is False


@pytest.mark.asyncio
async def test_the_refresh_actually_happens_behind_the_response(slow_probe):
    # A version that simply never refreshed would pass the test above.
    await Daemon._power_state_nonblocking()
    deadline = time.monotonic() + SLOW_PROBE_SECONDS + 15.0
    while time.monotonic() < deadline:
        if Daemon._power_state_is_fresh():
            break
        await asyncio.sleep(0.1)

    assert Daemon._power_state_is_fresh(), "the background refresh never landed"
    state, fresh = await Daemon._power_state_nonblocking()
    assert fresh is True
    assert state["metered"] is True, "the refreshed value did not reach the cache"
    assert state["on_battery"] is True
    assert len(slow_probe) == 1


@pytest.mark.asyncio
async def test_a_burst_of_polls_schedules_one_probe_not_one_each(slow_probe):
    # A UI polling this endpoint must not be able to spawn a PowerShell per
    # poll while the first refresh is still running.
    for _ in range(25):
        await Daemon._power_state_nonblocking()
    assert len(slow_probe) <= 1, (
        f"{len(slow_probe)} probes scheduled for 25 polls; refreshes must "
        "coalesce while one is in flight"
    )


@pytest.mark.asyncio
async def test_a_fresh_cache_is_served_without_scheduling_anything(slow_probe):
    Daemon._power_cache = {
        "ts": time.monotonic(), "on_battery": True, "metered": False,
    }
    state, fresh = await Daemon._power_state_nonblocking()
    assert fresh is True
    assert state["on_battery"] is True
    assert slow_probe == [], "a fresh cache must not trigger a probe"


@pytest.mark.asyncio
async def test_control_the_blocking_accessor_really_does_wait(slow_probe):
    # The control for every assertion above. If the slow probe ever stops
    # being slow -- a global stub, a changed fixture, a probe that short
    # circuits off Windows -- the "returns immediately" tests would pass
    # against a version that waits, and would be measuring nothing.
    #
    # `_power_state_async` is the pre-fix path and is still used where waiting
    # is correct, so this pins the contrast rather than dead code.
    started = time.monotonic()
    await Daemon._power_state_async()
    elapsed = time.monotonic() - started
    assert elapsed >= SLOW_PROBE_SECONDS * 0.8, (
        f"the blocking accessor returned in {elapsed:.2f}s, so the probe is "
        "not actually slow and the latency tests above prove nothing"
    )


def test_last_known_never_probes(slow_probe):
    started = time.monotonic()
    state = Daemon._power_state_last_known()
    assert time.monotonic() - started < IMMEDIATE_SECONDS
    assert slow_probe == []
    assert set(state) >= {"on_battery", "metered"}


def test_last_known_hands_back_a_copy_not_the_live_cache():
    # Callers put this straight into a JSON response; a mutation there must not
    # rewrite the cache every other reader shares.
    state = Daemon._power_state_last_known()
    state["on_battery"] = True
    assert Daemon._power_cache["on_battery"] is False


def test_the_sync_path_still_probes_by_default():
    # The endpoint stops probing; the code that decides whether to put bytes on
    # the wire must not. If this ever inverts, a laptop on battery with
    # sync_pause_on_battery set would keep uploading.
    import inspect

    signature = inspect.signature(Daemon._sync_paused_or_quiet)
    assert signature.parameters["allow_probe"].default is True

    async_signature = inspect.signature(Daemon._sync_paused_or_quiet_async)
    assert async_signature.parameters["allow_probe"].default is True
