"""The daemon must not die because a virus scanner held a file for 5ms.

windows-latest/py3.11 failed with the daemon CRASHING AT STARTUP:

    File "src/one_link/daemon.py", in _publish_runtime_ascii_scalar
        os.replace(temporary, target)
    PermissionError: [WinError 5] Access is denied:
        '...\\data\\.control.port.9076.<hex>.tmp'

A POSIX rename over an existing entry always succeeds. On Windows any process
holding either path open without FILE_SHARE_DELETE makes it fail, and that
happens routinely for a file created milliseconds ago because scanners open new
files to inspect them. A user with antivirus would see One Link fail to start
intermittently, with nothing they could act on.

Five call sites did a write-temp-then-replace with no tolerance for it,
including the one that lands a COMPLETED file transfer. They all now go through
_atomic_replace. These tests pin its contract without needing Windows.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from one_link import daemon as daemon_module


def _permission_error(winerror: int) -> PermissionError:
    exc = PermissionError("simulated sharing violation")
    exc.winerror = winerror  # type: ignore[attr-defined]
    return exc


def test_transient_sharing_violation_is_retried_until_it_succeeds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    real_replace = os.replace

    def _flaky(src, dst):
        calls.append(1)
        if len(calls) <= 3:
            raise _permission_error(32)  # ERROR_SHARING_VIOLATION
        return real_replace(src, dst)

    monkeypatch.setattr(daemon_module.os, "name", "nt")
    monkeypatch.setattr(daemon_module.os, "replace", _flaky)

    src = tmp_path / "src.tmp"
    dst = tmp_path / "dst"
    src.write_text("54321", encoding="utf-8")

    daemon_module._atomic_replace(src, dst)
    assert len(calls) == 4, "must retry a transient violation, not give up"
    assert dst.read_text(encoding="utf-8") == "54321"


def test_access_denied_is_also_treated_as_transient(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """WinError 5 is the exact code the crash reported."""

    calls: list[int] = []
    real_replace = os.replace

    def _flaky(src, dst):
        calls.append(1)
        if len(calls) == 1:
            raise _permission_error(5)  # ERROR_ACCESS_DENIED
        return real_replace(src, dst)

    monkeypatch.setattr(daemon_module.os, "name", "nt")
    monkeypatch.setattr(daemon_module.os, "replace", _flaky)

    src = tmp_path / "s.tmp"
    dst = tmp_path / "d"
    src.write_text("1", encoding="utf-8")
    daemon_module._atomic_replace(src, dst)
    assert len(calls) == 2


def test_a_non_transient_permission_error_is_raised_immediately(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retrying a real permission problem would just delay the truth."""

    calls: list[int] = []

    def _always(src, dst):
        calls.append(1)
        raise _permission_error(1314)  # ERROR_PRIVILEGE_NOT_HELD

    monkeypatch.setattr(daemon_module.os, "name", "nt")
    monkeypatch.setattr(daemon_module.os, "replace", _always)

    with pytest.raises(PermissionError):
        daemon_module._atomic_replace(tmp_path / "a", tmp_path / "b")
    assert calls == [1], "a non-transient error must not be slept over"


def test_a_persistent_violation_eventually_gives_up(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bounded, so startup cannot hang forever behind a stuck handle."""

    calls: list[int] = []

    def _always(src, dst):
        calls.append(1)
        raise _permission_error(32)

    monkeypatch.setattr(daemon_module.os, "name", "nt")
    monkeypatch.setattr(daemon_module.os, "replace", _always)
    monkeypatch.setattr(daemon_module.time, "sleep", lambda _s: None)

    with pytest.raises(PermissionError):
        daemon_module._atomic_replace(tmp_path / "a", tmp_path / "b", attempts=4)
    assert calls == [1, 1, 1, 1]


def test_posix_does_exactly_one_unretried_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POSIX rename cannot fail this way, so a failure there is real."""

    calls: list[int] = []

    def _always(src, dst):
        calls.append(1)
        raise _permission_error(32)

    monkeypatch.setattr(daemon_module.os, "name", "posix")
    monkeypatch.setattr(daemon_module.os, "replace", _always)

    with pytest.raises(PermissionError):
        daemon_module._atomic_replace(tmp_path / "a", tmp_path / "b")
    assert calls == [1]


def test_helper_does_not_call_itself(tmp_path: Path) -> None:
    """Regression: routing the call sites once rewrote the helper's OWN body.

    The bulk edit that pointed every write-temp-then-replace at the helper also
    matched the two identical lines inside the helper, turning it into infinite
    recursion. A real replace through the helper proves the base case survives.
    """

    src = tmp_path / "real.tmp"
    dst = tmp_path / "real"
    src.write_text("ok", encoding="utf-8")
    daemon_module._atomic_replace(src, dst)
    assert dst.read_text(encoding="utf-8") == "ok"
    assert not src.exists()


def test_no_bare_os_replace_remains_on_a_publish_path() -> None:
    """Every atomic publish must route through the retrying helper.

    A new write-temp-then-replace added later would silently reintroduce the
    crash, so the absence is asserted rather than remembered.
    """

    import inspect

    source = inspect.getsource(daemon_module)
    helper = source.split("def _atomic_replace(", 1)[1].split("\ndef ", 1)[0]
    # The helper itself legitimately calls os.replace twice (POSIX + retry).
    assert helper.count("os.replace(") == 2
    assert source.count("os.replace(") == 2, (
        "a bare os.replace() outside _atomic_replace reintroduces the "
        "Windows startup crash; route it through the helper"
    )
