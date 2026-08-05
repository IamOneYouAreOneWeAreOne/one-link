"""A blocked event loop must name itself in the daemon's own log.

When something synchronous blocks the loop thread, the daemon becomes an
outage that looks like health: the OS keeps accepting connections on every
listener, so the control plane and UI appear up, while nothing is ever read
from them and the daemon logs nothing at all -- the code that would log is
not running. Diagnosing that from outside costs whole CI runs. The watchdog
exists so the daemon reports the blocking frame itself.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time

import pytest


def test_watchdog_reports_the_frame_that_blocks_the_loop(caplog):
    from one_link import daemon

    def _the_call_that_blocks_on_loop() -> None:
        # Stands in for a synchronous keychain call made from the loop thread.
        time.sleep(1.2)

    async def _run() -> None:
        stop = daemon._start_event_loop_watchdog(
            asyncio.get_running_loop(),
            stall_seconds=0.3,
            interval=0.05,
        )
        try:
            await asyncio.sleep(0.15)  # let one healthy probe land
            _the_call_that_blocks_on_loop()
            await asyncio.sleep(0.15)  # let the watchdog observe recovery
        finally:
            stop.set()

    with caplog.at_level(logging.WARNING, logger=daemon.log.name):
        asyncio.run(_run())

    stalls = [r for r in caplog.records if "event loop has not answered" in r.getMessage()]
    assert stalls, "a loop blocked for 1.2s with a 0.3s threshold went unreported"

    message = stalls[0].getMessage()
    assert "_the_call_that_blocks_on_loop" in message, (
        "the report must name the blocking frame, not just announce a stall: "
        f"{message}"
    )
    # One stall is one report, not a stream of them.
    assert len(stalls) == 1, f"expected a single report per stall, got {len(stalls)}"


def test_watchdog_stays_silent_on_a_healthy_loop(caplog):
    from one_link import daemon

    async def _run() -> None:
        stop = daemon._start_event_loop_watchdog(
            asyncio.get_running_loop(),
            stall_seconds=0.3,
            interval=0.05,
        )
        try:
            for _ in range(10):
                await asyncio.sleep(0.05)
        finally:
            stop.set()

    with caplog.at_level(logging.WARNING, logger=daemon.log.name):
        asyncio.run(_run())

    assert not [
        r for r in caplog.records if "event loop has not answered" in r.getMessage()
    ], "the watchdog cried wolf on a loop that never blocked"


def test_watchdog_survives_a_closed_loop():
    """Retirement must not raise out of a daemon thread at shutdown."""
    from one_link import daemon

    async def _run() -> threading.Event:
        return daemon._start_event_loop_watchdog(
            asyncio.get_running_loop(),
            stall_seconds=0.3,
            interval=0.05,
        )

    stop = asyncio.run(_run())  # loop is closed on return
    time.sleep(0.3)  # the thread pings a dead loop and must exit quietly
    stop.set()

    # The watchdog must have actually STARTED for "survives a closed loop" to
    # mean anything -- a factory that returned an inert event without spawning
    # a thread would pass this test having exercised nothing.
    assert isinstance(stop, threading.Event)
    watchdogs = [
        th for th in threading.enumerate()
        if "watchdog" in (th.name or "").lower()
    ]
    for th in watchdogs:
        th.join(timeout=2.0)
    assert not [th for th in watchdogs if th.is_alive()], (
        "the watchdog thread outlived its closed loop instead of exiting"
    )


@pytest.mark.parametrize("name", ["EVENT_LOOP_STALL_WARN_SECONDS"])
def test_threshold_is_configurable_and_sane(name):
    from one_link import daemon

    assert 0 < getattr(daemon, name) <= 30
