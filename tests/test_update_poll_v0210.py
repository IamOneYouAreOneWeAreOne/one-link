"""Tests for the daemon's background update-check poll task.

Phase 2b. The endpoint (Phase 2) only fires when the UI loads;
this loop runs every 6h while the daemon is up, so the banner
appears even on a long-lived tab a user left open last night.

Tests:
    * The loop is a real task, started by the daemon's main entry
      and recognized in the broadcast pipeline.
    * When fetch_latest reports a transition (same -> newer), an
      `update_status` WS event fires with the right fields.
    * No-change ticks DO NOT broadcast (avoid spamming every tab
      every 6h).
    * Errors don't propagate (the loop never raises in a way that
      cancels itself).
    * Interval is hours, not seconds (regression guard against
      someone accidentally changing the constant).
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest


def _poll_stub(daemon_cls, ui_server, *, state=None):
    """Build the smallest faithful stand-in for the live poll daemon.

    The sovereignty hardening added a shared network lock so an update request
    cannot race a transition into Quiet/Off-grid mode.  Bind the production
    lazy-lock method here instead of bypassing that security boundary with an
    unrelated test-only context manager.
    """
    stub = SimpleNamespace(
        state=state,
        ui_server=ui_server,
        UPDATE_CHECK_INTERVAL_S=6 * 60 * 60,
        # The historical background installer must remain unreachable even
        # when the poll observes a newer release.
        _maybe_auto_install=AsyncMock(),
    )
    stub.get_update_check_network_lock = (
        daemon_cls.get_update_check_network_lock.__get__(stub)
    )
    return stub


@pytest.mark.asyncio
async def test_update_poll_broadcasts_on_status_change(monkeypatch):
    """Same -> newer: the loop broadcasts an update_status event with
    the new latest_version. UI listens and refreshes the banner."""
    monkeypatch.setenv("ONE_LINK_UPDATE_CHECK", "1")
    from one_link import update_check as uc_mod

    # Sequence the fetch results: first call same, second call newer.
    results = [
        uc_mod.CheckResult(
            status="same", local_version="0.21.0", latest_version="v0.21.0",
        ),
        uc_mod.CheckResult(
            status="newer", local_version="0.21.0", latest_version="v0.22.0",
        ),
    ]
    iterator = iter(results)

    def fake_fetch_latest(local_version, **kw):
        return next(iterator)

    monkeypatch.setattr(uc_mod, "fetch_latest", fake_fetch_latest)

    # Stub the daemon: only what _update_check_loop touches.
    broadcast_calls: list[dict] = []
    fake_ui_server = MagicMock()
    fake_ui_server.broadcast.side_effect = lambda ev: broadcast_calls.append(ev)

    from one_link.daemon import Daemon
    # We don't actually instantiate Daemon (it has heavy init); we
    # bind the coroutine to a lightweight stand-in that satisfies
    # _update_check_loop's only attribute reads.
    stub = _poll_stub(Daemon, fake_ui_server)
    coro = Daemon._update_check_loop.__get__(stub)

    # Make sleep instantaneous + bounded.
    sleep_calls = []
    real_sleep = asyncio.sleep

    async def fake_sleep(n):
        sleep_calls.append(n)
        # Let the loop run exactly two iterations.
        if len(sleep_calls) >= 3:
            raise asyncio.CancelledError
        await real_sleep(0)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    with pytest.raises(asyncio.CancelledError):
        await coro()

    # Two broadcasts expected: the first time (None -> 'same') AND
    # the transition ('same' -> 'newer'). last_status starts as None
    # so the very first observation is also "changed".
    assert len(broadcast_calls) == 2, broadcast_calls
    events = [c.get("status") for c in broadcast_calls]
    assert events == ["same", "newer"]
    assert broadcast_calls[1]["latest_version"] == "v0.22.0"
    stub._maybe_auto_install.assert_not_awaited()
    # Loop slept for at least one warmup + one inter-tick interval.
    assert sleep_calls[0] == 60.0      # 1-minute warmup
    assert sleep_calls[1] >= 60 * 60   # at least 1h between ticks


@pytest.mark.asyncio
async def test_update_poll_does_not_broadcast_when_unchanged(monkeypatch):
    """If two consecutive ticks return the same status + version, the
    second tick is silent. A daemon running for a week shouldn't
    broadcast 28 'still up to date' events."""
    monkeypatch.setenv("ONE_LINK_UPDATE_CHECK", "1")
    from one_link import update_check as uc_mod

    def fake_fetch_latest(local_version, **kw):
        return uc_mod.CheckResult(
            status="same", local_version="0.21.0", latest_version="v0.21.0",
        )

    monkeypatch.setattr(uc_mod, "fetch_latest", fake_fetch_latest)

    broadcast_calls: list[dict] = []
    fake_ui_server = MagicMock()
    fake_ui_server.broadcast.side_effect = lambda ev: broadcast_calls.append(ev)

    from one_link.daemon import Daemon
    stub = _poll_stub(Daemon, fake_ui_server)
    coro = Daemon._update_check_loop.__get__(stub)

    real_sleep = asyncio.sleep
    sleep_count = [0]

    async def fake_sleep(n):
        sleep_count[0] += 1
        if sleep_count[0] >= 4:  # warmup + 3 ticks
            raise asyncio.CancelledError
        await real_sleep(0)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    with pytest.raises(asyncio.CancelledError):
        await coro()

    # First tick fires (None -> 'same' is a change). Subsequent
    # ticks are no-ops.
    assert len(broadcast_calls) == 1, broadcast_calls
    assert broadcast_calls[0]["status"] == "same"


@pytest.mark.asyncio
async def test_update_poll_tolerates_fetch_exceptions(monkeypatch):
    """fetch_latest is supposed to never raise, but if it ever does
    (bug, surprise import error), the loop must not die. The next
    tick should resume."""
    monkeypatch.setenv("ONE_LINK_UPDATE_CHECK", "1")
    from one_link import update_check as uc_mod

    calls = [0]

    def fake_fetch_latest(local_version, **kw):
        calls[0] += 1
        if calls[0] == 1:
            raise RuntimeError("simulated unexpected failure")
        return uc_mod.CheckResult(
            status="newer",
            local_version="0.21.0",
            latest_version="v0.22.0",
        )

    monkeypatch.setattr(uc_mod, "fetch_latest", fake_fetch_latest)

    broadcast_calls: list[dict] = []
    fake_ui_server = MagicMock()
    fake_ui_server.broadcast.side_effect = lambda ev: broadcast_calls.append(ev)

    from one_link.daemon import Daemon
    stub = _poll_stub(Daemon, fake_ui_server)
    coro = Daemon._update_check_loop.__get__(stub)

    real_sleep = asyncio.sleep
    sleep_count = [0]

    async def fake_sleep(n):
        sleep_count[0] += 1
        if sleep_count[0] >= 3:
            raise asyncio.CancelledError
        await real_sleep(0)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    with pytest.raises(asyncio.CancelledError):
        await coro()

    # Loop survived the first error and produced the second tick's
    # 'newer' broadcast.
    assert any(c.get("status") == "newer" for c in broadcast_calls)


@pytest.mark.asyncio
async def test_update_poll_policy_read_failure_is_fail_closed(monkeypatch):
    """A broken privacy store cannot become permission to contact GitHub.

    This remains closed even with the legacy environment opt-in set: a
    trustworthy active preset is the ceiling for outbound update traffic.
    """
    monkeypatch.setenv("ONE_LINK_UPDATE_CHECK", "1")
    from one_link import update_check as uc_mod
    from one_link.daemon import Daemon

    fetch_calls = 0

    def fake_fetch_latest(local_version, **kw):
        nonlocal fetch_calls
        fetch_calls += 1
        return uc_mod.CheckResult(
            status="same",
            local_version=local_version,
            latest_version=local_version,
        )

    monkeypatch.setattr(uc_mod, "fetch_latest", fake_fetch_latest)

    class BrokenPrivacyState:
        def get_setting(self, key):
            raise RuntimeError(f"unreadable setting: {key}")

    fake_ui_server = MagicMock()
    stub = _poll_stub(Daemon, fake_ui_server, state=BrokenPrivacyState())
    # This would loosen policy if the loop trusted it after the state read
    # failed. The implementation must instead apply the Quiet ceiling.
    stub.runtime_sovereignty_preset_name = lambda: "just_works"
    coro = Daemon._update_check_loop.__get__(stub)

    real_sleep = asyncio.sleep
    sleep_count = 0

    async def fake_sleep(n):
        nonlocal sleep_count
        sleep_count += 1
        if sleep_count >= 2:  # warmup, then one disabled-policy cycle
            raise asyncio.CancelledError
        await real_sleep(0)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    with pytest.raises(asyncio.CancelledError):
        await coro()

    assert fetch_calls == 0
    fake_ui_server.broadcast.assert_not_called()
    stub._maybe_auto_install.assert_not_awaited()


def test_update_check_interval_is_in_hours_not_seconds():
    """Regression guard: if someone changes UPDATE_CHECK_INTERVAL_S
    to e.g. 6 (seconds), GitHub will rate-limit the daemon in five
    minutes and the update path becomes useless. Lock the constant
    in the hour range."""
    from one_link.daemon import Daemon
    interval = Daemon.UPDATE_CHECK_INTERVAL_S
    assert interval >= 3600, (
        f"interval is dangerously short: {interval}s; GitHub will rate-limit"
    )
    assert interval <= 24 * 3600, (
        f"interval is unreasonably long: {interval}s; banner would never appear"
    )


def test_update_status_event_handler_present_in_ui():
    """Regression guard: the WS dispatcher in index.html must have a
    branch for update_status. Without it, the daemon broadcasts into
    the void."""
    html = (
        Path(__file__).resolve().parent.parent
        / "src" / "one_link" / "web" / "index.html"
    ).read_text(encoding="utf-8")
    # The dispatcher's branch matches via the same pattern as other
    # WS events ("m.type === \"update_status\"").
    assert '"update_status"' in html, (
        "UI dispatcher missing update_status branch — daemon broadcasts "
        "would be silently dropped"
    )
    # And the branch calls checkForUpdate so the banner actually
    # refreshes in response.
    idx = html.find('"update_status"')
    body = html[idx:idx + 800]
    assert "checkForUpdate" in body, (
        "update_status branch exists but doesn't refresh the banner"
    )
