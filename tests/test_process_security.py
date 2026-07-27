"""Regression coverage for process provenance and child isolation."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from one_link import process_security as ps


def _make_executable(path: Path) -> Path:
    path.write_bytes(b"test executable")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def test_system_resolution_never_consults_path_or_current_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted = tmp_path / "trusted"
    attacker = tmp_path / "attacker"
    trusted.mkdir()
    attacker.mkdir()
    real = _make_executable(trusted / "probe")
    _make_executable(attacker / "probe")
    monkeypatch.setattr(ps, "_POSIX_SYSTEM_DIRS", (trusted,))
    monkeypatch.setenv("PATH", str(attacker))
    monkeypatch.chdir(attacker)

    assert ps.resolve_system_executable("probe", platform_name="posix") == str(
        real.resolve(),
    )


@pytest.mark.parametrize(
    "name",
    ("../probe", "subdir/probe", r"subdir\probe", ".", "..", ""),
)
def test_system_resolution_rejects_non_basename(name: str) -> None:
    with pytest.raises((ValueError, FileNotFoundError)):
        ps.resolve_system_executable(name, platform_name="posix")


def test_explicit_resolution_requires_existing_absolute_regular_file(
    tmp_path: Path,
) -> None:
    name = "helper.exe" if os.name == "nt" else "helper"
    executable = _make_executable(tmp_path / name)
    assert ps.resolve_explicit_executable(executable) == str(executable.resolve())
    with pytest.raises(ValueError):
        ps.resolve_explicit_executable("helper")
    with pytest.raises(FileNotFoundError):
        missing_name = "missing.exe" if os.name == "nt" else "missing"
        ps.resolve_explicit_executable(tmp_path / missing_name)
    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(ValueError):
        ps.resolve_explicit_executable(directory)


def test_trusted_child_environment_drops_credentials_and_loader_injection() -> None:
    env = ps.trusted_process_env(
        platform_name="posix",
        base={
            "PATH": "/attacker/bin",
            "LD_PRELOAD": "/attacker/inject.so",
            "DYLD_INSERT_LIBRARIES": "/attacker/inject.dylib",
            "PYTHONPATH": "/attacker/python",
            "AWS_SECRET_ACCESS_KEY": "secret",
            "ANTHROPIC_API_KEY": "secret",
            "HTTP_PROXY": "http://attacker.invalid:8080",
            "XDG_DATA_DIRS": "/attacker/desktop-handlers",
            "XDG_SESSION_TYPE": "wayland",
            "HOME": "/home/alice",
            "DISPLAY": ":1",
        },
    )
    assert env["PATH"] == os.pathsep.join(str(p) for p in ps._POSIX_SYSTEM_DIRS)
    assert env["HOME"] == "/home/alice"
    assert env["DISPLAY"] == ":1"
    assert "LD_PRELOAD" not in env
    assert "DYLD_INSERT_LIBRARIES" not in env
    assert "PYTHONPATH" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "ANTHROPIC_API_KEY" not in env
    assert "HTTP_PROXY" not in env
    assert "XDG_DATA_DIRS" not in env
    assert env["XDG_SESSION_TYPE"] == "wayland"


def test_windows_child_environment_canonicalizes_process_selectors() -> None:
    env = ps.trusted_process_env(
        platform_name="windows",
        base={
            "PATH": r"C:\attacker",
            "ComSpec": r"C:\attacker\cmd.exe",
            "PATHEXT": ".BAT;.CMD;.EXE",
            "SystemRoot": r"C:\attacker",
            "PSModulePath": r"C:\attacker\Modules",
        },
    )
    windows = ps._windows_directory()
    assert env["SystemRoot"] == str(windows)
    assert env["WINDIR"] == str(windows)
    assert env["COMSPEC"] == str(windows / "System32" / "cmd.exe")
    assert env["PATHEXT"] == ".COM;.EXE"
    assert "attacker" not in env["PATH"].lower()
    assert "attacker" not in env["PSModulePath"].lower()


def test_daemon_child_environment_keeps_config_but_drops_code_injection() -> None:
    env = ps.sanitized_process_env(
        base={
            "ONE_LINK_BIND_HOST": "127.0.0.1",
            "PYTHONPATH": "/attacker/python",
            "PYTHONWARNINGS": "error",
            "LD_PRELOAD": "/attacker/inject.so",
            "LD_DEBUG_OUTPUT": "/attacker/output",
            "NODE_OPTIONS": "--require=/attacker/inject.js",
        },
    )
    assert env["ONE_LINK_BIND_HOST"] == "127.0.0.1"
    assert "PYTHONPATH" not in env
    assert "PYTHONWARNINGS" not in env
    assert "LD_PRELOAD" not in env
    assert "LD_DEBUG_OUTPUT" not in env
    assert "NODE_OPTIONS" not in env


def test_opener_uses_absolute_binary_no_shell_closed_handles_and_reaper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = _make_executable(tmp_path / "xdg-open")
    target = tmp_path / "inbox"
    target.mkdir()
    calls: list[tuple[list[str], dict[str, object]]] = []
    starts: list[bool] = []

    class _Proc:
        def wait(self) -> int:
            return 0

    class _Thread:
        def __init__(self, *, target, args, **_kwargs: object) -> None:
            self._target = target
            self._args = args

        def start(self) -> None:
            starts.append(True)
            self._target(*self._args)

    def fake_popen(argv: list[str], **kwargs: object) -> _Proc:
        calls.append((list(argv), kwargs))
        return _Proc()

    monkeypatch.setattr(ps, "resolve_system_executable", lambda *_a, **_k: str(executable))
    monkeypatch.setattr(ps.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(ps.threading, "Thread", _Thread)

    ps.launch_system_opener(target, platform_name="posix")

    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert argv == [str(executable), str(target.resolve())]
    assert kwargs["shell"] is False
    assert kwargs["close_fds"] is True
    assert kwargs["stdin"] == ps.subprocess.DEVNULL
    assert kwargs["stdout"] == ps.subprocess.DEVNULL
    assert kwargs["stderr"] == ps.subprocess.DEVNULL
    assert kwargs["cwd"] == str(executable.parent)
    assert kwargs["start_new_session"] is True
    assert starts == [True]


def test_opener_rejects_relative_target() -> None:
    with pytest.raises(ValueError):
        ps.launch_system_opener("relative/path")


def test_launcher_capacity_fails_before_spawning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _NoCapacity:
        @staticmethod
        def acquire(*, blocking: bool) -> bool:
            assert blocking is False
            return False

    monkeypatch.setattr(ps, "_PROCESS_REAPER_SLOTS", _NoCapacity())
    popen = lambda *_args, **_kwargs: pytest.fail("process spawned without a reaper slot")
    monkeypatch.setattr(ps.subprocess, "Popen", popen)
    with pytest.raises(ps.ProcessSecurityError, match="too many active"):
        ps._launch_resolved_argv(
            [str(Path(sys.executable).resolve())],
            platform_name="posix",
        )


def test_launcher_thread_failure_terminates_child_and_releases_capacity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = _make_executable(tmp_path / "helper")
    events: list[object] = []

    class _Slots:
        def acquire(self, *, blocking: bool) -> bool:
            events.append(("acquire", blocking))
            return True

        def release(self) -> None:
            events.append("release")

    class _Proc:
        def terminate(self) -> None:
            events.append("terminate")

        def wait(self, timeout: float | None = None) -> int:
            events.append(("wait", timeout))
            return 0

    class _Thread:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def start(self) -> None:
            raise RuntimeError("thread creation failed")

    monkeypatch.setattr(ps, "_PROCESS_REAPER_SLOTS", _Slots())
    monkeypatch.setattr(ps.subprocess, "Popen", lambda *_a, **_k: _Proc())
    monkeypatch.setattr(ps.threading, "Thread", _Thread)

    with pytest.raises(RuntimeError, match="thread creation failed"):
        ps._launch_resolved_argv([str(executable.resolve())], platform_name="posix")

    assert events == [
        ("acquire", False),
        "terminate",
        ("wait", 2.0),
        "release",
    ]


def test_launcher_releases_capacity_when_environment_setup_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[object] = []

    class _Slots:
        def acquire(self, *, blocking: bool) -> bool:
            events.append(("acquire", blocking))
            return True

        def release(self) -> None:
            events.append("release")

    def fail_env(**_kwargs: object) -> dict[str, str]:
        raise RuntimeError("env failed")

    monkeypatch.setattr(ps, "_PROCESS_REAPER_SLOTS", _Slots())
    monkeypatch.setattr(ps, "trusted_process_env", fail_env)
    monkeypatch.setattr(
        ps.subprocess,
        "Popen",
        lambda *_a, **_k: pytest.fail("spawned after environment setup failure"),
    )

    with pytest.raises(RuntimeError, match="env failed"):
        ps._launch_resolved_argv(
            [str(Path(sys.executable).resolve())],
            platform_name="posix",
        )
    assert events == [("acquire", False), "release"]


def test_desktop_launcher_rejects_external_or_credentialed_urls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link import app

    launches: list[object] = []
    monkeypatch.setattr(app, "launch_explicit_command", lambda *a, **k: launches.append((a, k)))
    for url in (
        "https://example.com/",
        "http://example.com:8080/",
        "http://user:password@127.0.0.1:8080/",
        "file:///etc/passwd",
    ):
        with pytest.raises(ValueError):
            app._open_browser_url(url)
    assert launches == []


@pytest.mark.parametrize(
    "url",
    (
        "http://127.0.0.1/",
        "http://127.0.0.1:0/",
        "https://127.0.0.1:7117/",
        "http://127.0.0.1:7117/\nheader: injected",
        "http://user@localhost:7117/",
        "http://localhost:99999/",
    ),
)
def test_loopback_url_validator_rejects_ambiguous_targets(url: str) -> None:
    with pytest.raises(ValueError):
        ps.validate_loopback_url(url)


def test_loopback_url_launcher_ignores_browser_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], str | None]] = []
    monkeypatch.setenv("BROWSER", "/attacker/browser --execute")
    monkeypatch.setattr(
        ps,
        "launch_system_command",
        lambda argv, *, platform_name=None: calls.append((list(argv), platform_name)),
    )

    ps.launch_loopback_url(
        "http://127.0.0.1:7117/?t=owner-token",
        platform_name="posix",
    )

    assert calls == [
        (["xdg-open", "http://127.0.0.1:7117/?t=owner-token"], "posix"),
    ]


def test_tray_converts_lan_display_url_to_loopback_before_launch() -> None:
    from one_link.tray import _local_ui_url

    assert _local_ui_url("http://192.168.1.9:7117/?t=secret") == (
        "http://127.0.0.1:7117/?t=secret"
    )
    with pytest.raises(ValueError):
        _local_ui_url("http://user:password@192.168.1.9:7117/")


def test_cover_thinning_generator_is_reproducible_cryptographic_stream() -> None:
    from one_link.cover_traffic import _DeterministicSecureRandom

    left = _DeterministicSecureRandom(b"a" * 32)
    right = _DeterministicSecureRandom(b"a" * 32)
    other = _DeterministicSecureRandom(b"b" * 32)
    left_values = [left.random() for _ in range(16)]
    assert left_values == [right.random() for _ in range(16)]
    assert left_values != [other.random() for _ in range(16)]
    assert all(0.0 <= value < 1.0 for value in left_values)


def test_updater_script_generation_is_unconditionally_disabled(tmp_path: Path) -> None:
    from one_link.updater import write_updater_script

    wheel = tmp_path / "verified.whl"
    wheel.write_bytes(b"verified wheel bytes")
    with pytest.raises(RuntimeError, match="transactional full-app rollback"):
        write_updater_script(
            wheel,
            parent_pid=1,
            python_exe=sys.executable,
        )


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits only")
def test_group_writable_interpreter_relaunches_but_other_binaries_still_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A group-writable Python must not make this app unstartable.

    GitHub's hosted toolcache ships /opt/hostedtoolcache/Python/*/bin/python
    as mode 0775, which made every autostart/supervisor re-launch raise
    ProcessSecurityError on CI while passing locally. Refusing to re-exec the
    interpreter that is ALREADY executing us protects nothing, so that one
    case is waived -- and this test pins that the waiver does not leak to any
    other executable.
    """

    from one_link.process_security import (
        ProcessSecurityError,
        resolve_current_interpreter,
        resolve_explicit_executable,
    )

    interpreter = tmp_path / "python3"
    interpreter.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    interpreter.chmod(0o775)  # exactly the hosted-toolcache mode
    assert interpreter.stat().st_mode & stat.S_IWGRP

    # The interpreter running us: permitted, and returned verbatim.
    monkeypatch.setattr(sys, "executable", str(interpreter))
    assert resolve_current_interpreter() == str(interpreter)

    # And permitted through the PLAIN entry point with no flag threaded
    # through. This is the class-closure property: updater's
    # _resolve_target_python_executable resolves sys.executable itself and
    # still failed on CI after the first fix, because that fix only taught
    # resolve_current_interpreter about the waiver. Any call site that resolves
    # the running interpreter is now covered, including ones not yet written.
    assert resolve_explicit_executable(interpreter) == str(interpreter.resolve())

    # A DIFFERENT group-writable binary is still refused. The waiver is scoped
    # to the interpreter executing us, not to "group-writable is fine now".
    helper = tmp_path / "helper"
    helper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    helper.chmod(0o775)
    with pytest.raises(ProcessSecurityError, match="writable by group/others"):
        resolve_explicit_executable(helper)
    with pytest.raises(ProcessSecurityError, match="writable by group/others"):
        resolve_explicit_executable(helper, preserve_path=True)

    # And a self-relaunch is still not a blanket bypass: every other check
    # holds, so a directory or a missing path fails as before.
    monkeypatch.setattr(sys, "executable", str(tmp_path))
    with pytest.raises(ProcessSecurityError, match="not a regular file"):
        resolve_current_interpreter()
    monkeypatch.setattr(sys, "executable", str(tmp_path / "absent"))
    with pytest.raises(FileNotFoundError):
        resolve_current_interpreter()


def test_autostart_python_fallback_uses_safe_path_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link import autostart

    python_exe = str(Path(sys.executable).resolve())

    # autostart re-launches THIS interpreter, so it resolves through
    # resolve_current_interpreter (which deliberately preserves a virtualenv
    # symlink instead of collapsing it to the system python). The stub takes
    # no argument because the function reads sys.executable itself.
    monkeypatch.setattr(
        autostart, "resolve_current_interpreter", lambda: python_exe
    )
    monkeypatch.setattr(autostart.sys, "frozen", False, raising=False)
    command = autostart._launch_command()
    assert command[:4] == [python_exe, "-P", "-m", "one_link.cli"]


def test_updater_script_rechecks_caller_verified_digest(tmp_path: Path) -> None:
    from one_link.updater import write_updater_script

    wheel = tmp_path / "changed.whl"
    wheel.write_bytes(b"changed after the caller verified it")
    with pytest.raises(RuntimeError, match="transactional full-app rollback"):
        write_updater_script(
            wheel,
            parent_pid=1,
            python_exe=sys.executable,
            expected_sha256="0" * 64,
        )


def test_updater_spawn_is_unconditionally_disabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link import updater

    script = tmp_path / "updater.py"
    script.write_text("pass\n", encoding="utf-8")
    script.chmod(0o600)
    captured: dict[str, object] = {}

    class _Proc:
        pid = 1234

    def fake_popen(argv: list[str], **kwargs: object) -> _Proc:
        captured["argv"] = argv
        captured.update(kwargs)
        return _Proc()

    monkeypatch.setattr(updater.subprocess, "Popen", fake_popen)
    with pytest.raises(RuntimeError, match="transactional full-app rollback"):
        updater.spawn_detached(script, python_exe=sys.executable)
    assert captured == {}


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")
def test_autostart_private_write_is_atomic_and_owner_only(tmp_path: Path) -> None:
    from one_link.autostart import _atomic_private_write

    target = tmp_path / "config" / "autostart" / "one-link.desktop"
    _atomic_private_write(target, b"first")
    _atomic_private_write(target, b"replacement")

    assert target.read_bytes() == b"replacement"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert list(target.parent.glob(".*.tmp")) == []
