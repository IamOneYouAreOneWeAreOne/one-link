"""The harness must not authenticate a new daemon with an old daemon's secret.

windows-latest/py3.12 failed on 85146f4 with:

    ControlAuthenticationError: daemon did not authenticate the response
    AssertionError: send threads raised: [ControlAuthenticationError(...)]

Root cause: the harness caches control secrets keyed by control PORT, and the
OS recycles ephemeral ports between tests. Teardown popped the entry only when
it could still read the daemon's port file, which is gone by then in exactly the
races that matter -- so the entry leaked, and the next daemon handed that
recycled port was sent the previous daemon's secret and rejected the MAC.

This is harness-only: the daemon itself reads its secret from its own home on
every request. These tests pin both halves of the fix.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from one_link import control_ipc
from tests import harness


@pytest.fixture(autouse=True)
def _isolate_cache():
    saved = dict(harness._CONTROL_SECRETS)
    harness._CONTROL_SECRETS.clear()
    try:
        yield
    finally:
        harness._CONTROL_SECRETS.clear()
        harness._CONTROL_SECRETS.update(saved)


def test_teardown_purges_by_home_when_the_port_is_unknown(tmp_path: Path) -> None:
    """The leak that caused the flake: no port available at teardown."""

    home = tmp_path / "A"
    harness._CONTROL_SECRETS[51234] = ("secret-A", home)
    harness._CONTROL_SECRETS[51235] = ("secret-B", tmp_path / "B")

    # Port is None, exactly what _read_port returns after the daemon removed
    # its port file. Before the fix this purged nothing at all.
    harness.purge_control_secrets(port=None, home=home)

    assert 51234 not in harness._CONTROL_SECRETS, "leaked A's secret for a recyclable port"
    assert 51235 in harness._CONTROL_SECRETS, "purge must not touch another daemon"


def test_stale_cached_secret_is_re_read_instead_of_failing_a_healthy_daemon(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "fresh-daemon"
    (home / "data").mkdir(parents=True)
    port = 51300
    # A leaked entry from a previous daemon that held this same port.
    harness._CONTROL_SECRETS[port] = ("STALE-from-previous-daemon", home)

    calls: list[str] = []

    def _request_control(_port, _req, *, timeout, secret):
        calls.append(secret)
        if secret != "CURRENT":
            raise control_ipc.ControlAuthenticationError(
                "daemon did not authenticate the response"
            )
        return {"ok": True}

    monkeypatch.setattr(control_ipc, "request_control", _request_control)
    monkeypatch.setattr(control_ipc, "read_control_secret", lambda _root: "CURRENT")

    assert harness.request(port, op="status") == {"ok": True}
    assert calls == ["STALE-from-previous-daemon", "CURRENT"], (
        "must retry exactly once with the secret re-read from the daemon's home"
    )
    assert harness._CONTROL_SECRETS[port] == ("CURRENT", home), "cache must be refreshed"


def test_failed_re_read_preserves_the_authentication_diagnosis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A torn-down home must not replace the real error with a file error.

    The recovery path reads the secret from disk. If that read fails because the
    home is already gone, reporting "control secret unavailable" would bury the
    authentication failure that actually happened.
    """

    home = tmp_path / "already-removed"
    port = 51302
    harness._CONTROL_SECRETS[port] = ("STALE", home)

    def _request_control(_port, _req, *, timeout, secret):
        raise control_ipc.ControlAuthenticationError("daemon did not authenticate")

    def _read_control_secret(_root):
        raise RuntimeError("control secret unavailable")

    monkeypatch.setattr(control_ipc, "request_control", _request_control)
    monkeypatch.setattr(control_ipc, "read_control_secret", _read_control_secret)

    with pytest.raises(
        control_ipc.ControlAuthenticationError,
        match="daemon did not authenticate",
    ):
        harness.request(port, op="status")


def test_authentication_failure_with_a_current_secret_still_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The retry must not mask a genuine authentication failure.

    If the cached secret already matches the daemon's own file, the rejection is
    real and must surface rather than being retried into silence.
    """

    home = tmp_path / "daemon"
    (home / "data").mkdir(parents=True)
    port = 51301
    harness._CONTROL_SECRETS[port] = ("CURRENT", home)

    attempts: list[str] = []

    def _request_control(_port, _req, *, timeout, secret):
        attempts.append(secret)
        raise control_ipc.ControlAuthenticationError("tampered response")

    monkeypatch.setattr(control_ipc, "request_control", _request_control)
    monkeypatch.setattr(control_ipc, "read_control_secret", lambda _root: "CURRENT")

    with pytest.raises(control_ipc.ControlAuthenticationError, match="tampered response"):
        harness.request(port, op="status")
    assert attempts == ["CURRENT"], "a real rejection must not be retried"
