"""v0.21.x listener hardening: race-free singleton lock + Windows
SO_EXCLUSIVEADDRUSE on the UI bind.

Two complementary defenses that prevent two daemons from ever
sharing a single ONE_LINK_HOME's listening port:

1. _acquire_instance_lock now grabs the OS-level file lock
   IMMEDIATELY after opening the lockfile, BEFORE reading any
   existing PID. The previous order (open → read PID → liveness
   check → lock) had a window where two daemons could both pass
   the PID-liveness check before either held the lock. Now both
   block at the kernel lock call; only one wins.

2. _bind_exclusive_socket creates the UI listening socket with
   SO_EXCLUSIVEADDRUSE on Windows so a hostile local process
   that sets SO_REUSEADDR cannot steal our port. Non-Windows
   platforms use polite SO_REUSEADDR semantics by default; no
   equivalent footgun to defend against there.

These tests pin the source-level shape so a future refactor can't
silently revert either fix.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest


_DAEMON = (
    Path(__file__).resolve().parents[1] / "src" / "one_link" / "daemon.py"
)
_SERVER = (
    Path(__file__).resolve().parents[1] / "src" / "one_link" / "server.py"
)


@pytest.fixture(scope="module")
def daemon_src() -> str:
    return _DAEMON.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def server_src() -> str:
    return _SERVER.read_text(encoding="utf-8")


# ── singleton-lock race fix ─────────────────────────────────────────


def test_acquire_instance_lock_locks_before_pid_read(daemon_src):
    """v0.21.x: the OS-level lock acquisition MUST happen before the
    PID-file read. Pre-v0.21.x order was open → read PID → liveness
    check → lock, creating a race window where two daemons could
    both pass the liveness check before either held the lock."""
    idx = daemon_src.find("def _acquire_instance_lock(")
    assert idx > 0
    end = daemon_src.find("\n    def _release_instance_lock(", idx)
    body = daemon_src[idx:end if end > 0 else idx + 6000]

    # The msvcrt.locking call must come BEFORE f.read(64) for the
    # PID-file liveness check.
    lock_idx = body.find("msvcrt.locking(")
    read_idx = body.find("f.read(64)")
    # Both must be present.
    assert lock_idx > 0, (
        "missing msvcrt.locking call in _acquire_instance_lock — the "
        "Windows OS-level lock is the strongest singleton guard"
    )
    assert read_idx > 0, (
        "missing PID-file read in _acquire_instance_lock — the "
        "defence-in-depth liveness check would be gone"
    )
    # The KEY constraint: lock before read.
    assert lock_idx < read_idx, (
        "msvcrt.locking must run BEFORE f.read(64) — otherwise two "
        "daemons can both pass the PID-liveness check before either "
        "holds the OS lock (the race window we're closing)"
    )


def test_acquire_instance_lock_includes_pid_in_error(daemon_src):
    """When the lock is already held, the error message should name
    the holding PID so the user can diagnose which process is alive.
    Previously the error was generic 'already running'; v0.21.x reads
    the PID file (inside the OSError handler) to surface it."""
    idx = daemon_src.find("def _acquire_instance_lock(")
    body = daemon_src[idx:idx + 5000]
    assert "pid_hint" in body, (
        "error path should compute a pid_hint so the message names "
        "the holder when possible"
    )


def test_acquire_instance_lock_defence_in_depth_pid_check(daemon_src):
    """After acquiring the OS lock, a second defence-in-depth check
    on the PID file catches the corner case where the kernel lock
    isn't authoritative (e.g. Windows network share lock loss). Pin
    the stale-lock / corrupted-state language so it stays clear."""
    idx = daemon_src.find("def _acquire_instance_lock(")
    body = daemon_src[idx:idx + 6000]
    assert "stale lock or corrupted state" in body, (
        "post-lock PID-liveness check must include the stale-lock "
        "diagnostic so a user with a bad lock state can understand "
        "why the daemon refused to start"
    )
    assert "_pid_is_alive" in body, (
        "missing _pid_is_alive call — without it the defence-in-depth "
        "check can't distinguish a stale PID file from a live rival"
    )


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["python", "-m", "one_link.cli", "daemon", "-v"], True),
        (["python", "-P", "-m", "one_link.cli", "daemon", "-v"], True),
        # A Windows install path is only parseable as a path ON Windows:
        # pathlib does not treat "\\" as a separator on POSIX, so basename
        # extraction cannot work there. No Linux process will ever present
        # this argv, so gate the case rather than assert it everywhere.
        pytest.param(
            [r"C:\\Program Files\\One Link\\one-link.exe", "daemon"],
            True,
            marks=pytest.mark.skipif(
                os.name != "nt",
                reason="Windows install path is not a path on POSIX",
            ),
        ),
        # The POSIX frozen form had NO coverage: the frozen-daemon branch was
        # only ever exercised through its Windows spelling, so PID-reuse
        # protection for a packaged Linux/macOS daemon went unasserted.
        pytest.param(
            ["/opt/One Link/one-link", "daemon"],
            True,
            marks=pytest.mark.skipif(
                os.name == "nt",
                reason="POSIX install path form",
            ),
        ),
        (["python", "-c", "from multiprocessing.spawn import spawn_main"], False),
        (["one-link.exe", "supervisor"], False),
    ],
)
def test_daemon_process_command_line_classification(argv, expected):
    """PID-reuse protection recognizes only the daemon command itself."""
    from one_link.daemon import _argv_is_one_link_daemon

    assert _argv_is_one_link_daemon(argv) is expected


def test_acquire_instance_lock_ignores_reused_pid(tmp_path, monkeypatch):
    """A stale lock PID reused by an unrelated live process cannot brick startup."""
    from one_link import daemon as daemon_mod

    home = tmp_path / "home"
    data = home / "data"
    data.mkdir(parents=True)
    monkeypatch.setenv("ONE_LINK_HOME", str(home))
    sleeper = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    daemon = object.__new__(daemon_mod.Daemon)
    daemon._lock_file = None
    try:
        (data / daemon_mod.DAEMON_LOCK_FILE).write_text(
            str(sleeper.pid), encoding="ascii"
        )
        daemon._acquire_instance_lock()

        assert sleeper.poll() is None
        daemon._lock_file.seek(0)
        assert daemon._lock_file.read().decode("ascii").strip() == str(os.getpid())
    finally:
        daemon._release_instance_lock()
        sleeper.terminate()
        sleeper.wait(timeout=5)


def test_handshake_source_buckets_are_globally_bounded(monkeypatch):
    from collections import OrderedDict
    from one_link import daemon as daemon_mod

    daemon = object.__new__(daemon_mod.Daemon)
    daemon._handshake_history = OrderedDict()
    daemon._handshake_inflight = {}
    monkeypatch.setattr(daemon_mod, "HANDSHAKE_SOURCE_BUCKETS_MAX", 3)

    assert daemon._handshake_admit("198.51.100.1") is True
    assert daemon._handshake_admit("198.51.100.2") is True
    assert daemon._handshake_admit("198.51.100.3") is True
    assert daemon._handshake_admit("198.51.100.4") is False
    assert len(daemon._handshake_history) == 3


def test_handshake_source_bucket_expires_and_releases_capacity(monkeypatch):
    from collections import OrderedDict
    from one_link import daemon as daemon_mod

    daemon = object.__new__(daemon_mod.Daemon)
    daemon._handshake_history = OrderedDict({"198.51.100.1": [1.0]})
    daemon._handshake_inflight = {}
    monkeypatch.setattr(daemon_mod, "HANDSHAKE_SOURCE_BUCKETS_MAX", 1)
    monkeypatch.setattr(daemon_mod.time, "monotonic", lambda: 1000.0)

    assert daemon._handshake_admit("198.51.100.2") is True
    assert list(daemon._handshake_history) == ["198.51.100.2"]


# ── SO_EXCLUSIVEADDRUSE hardening ────────────────────────────────────


def test_bind_exclusive_socket_helper_exists(server_src):
    """A dedicated helper centralises the Windows SO_EXCLUSIVEADDRUSE
    setup so both the HTTP and HTTPS bind sites can share it."""
    assert "def _bind_exclusive_socket(" in server_src, (
        "missing _bind_exclusive_socket helper — the SO_EXCLUSIVEADDRUSE "
        "logic would have to be duplicated at every bind site"
    )


def test_bind_exclusive_socket_sets_so_exclusiveaddruse(server_src):
    """Pin the actual socket-option name + the Windows-only guard."""
    idx = server_src.find("def _bind_exclusive_socket(")
    end = server_src.find("\n    async def _probe_owned_http_port(", idx)
    body = server_src[idx:end if end > 0 else idx + 3000]
    # Windows guard up top — non-Windows must short-circuit.
    assert "os.name != \"nt\"" in body, (
        "helper must short-circuit on non-Windows so we don't try to "
        "set a Windows-only socket option there"
    )
    # The actual option name.
    assert "SO_EXCLUSIVEADDRUSE" in body, (
        "helper must reference SO_EXCLUSIVEADDRUSE — that's the option "
        "that prevents REUSEADDR-armed local processes from stealing "
        "our port"
    )
    # bind() + listen() + non-blocking before handoff.
    assert "s.bind(" in body
    assert "s.listen(" in body
    assert "setblocking" in body


def test_http_bind_uses_exclusive_socket_on_windows(server_src):
    """The main HTTP UI bind must invoke _bind_exclusive_socket
    BEFORE falling back to plain TCPSite. On Windows the fallback
    is skipped entirely (no point in a non-exclusive bind that
    would re-introduce the steal vulnerability)."""
    # Find the bind loop in serve() — pin the helper call shape.
    bind_call_idx = server_src.find("self._bind_exclusive_socket(bind_host, candidate)")
    assert bind_call_idx > 0, (
        "main UI bind must call self._bind_exclusive_socket so the "
        "Windows hardening is on the hot path"
    )
    # Around the call, web.SockSite is used to wrap the pre-bound socket.
    nearby = server_src[bind_call_idx:bind_call_idx + 1500]
    assert "web.SockSite(self.runner, ex_sock)" in nearby, (
        "exclusive socket must be handed to web.SockSite — TCPSite "
        "would re-bind and undo the exclusive-bind benefit"
    )
    # Windows must NOT fall through to a non-exclusive TCPSite path.
    assert 'if os.name == "nt":' in nearby, (
        "missing Windows guard that skips the non-exclusive fallback; "
        "without it the loop could try a non-exclusive bind after the "
        "exclusive one failed, re-opening the steal window"
    )


def test_https_bind_uses_exclusive_socket_on_windows(server_src):
    """The TLS UI bind must apply the same hardening as HTTP — a
    user who reaches over LAN HTTPS can still be displaced if the
    HTTPS port itself is steal-able."""
    # Find both occurrences of the helper call by iterative search.
    needle = "self._bind_exclusive_socket(bind_host, candidate)"
    occurrences: list[int] = []
    start = 0
    while True:
        found = server_src.find(needle, start)
        if found < 0:
            break
        occurrences.append(found)
        start = found + 1
    assert len(occurrences) >= 2, (
        "HTTPS bind site must also call _bind_exclusive_socket — "
        "found only one occurrence, the TLS bind is unhardened"
    )
    # Second occurrence (HTTPS) should be near a ssl_context= use.
    https_idx = occurrences[1]
    nearby = server_src[https_idx:https_idx + 1500]
    assert "web.SockSite(self.runner, ex_sock, ssl_context=ctx)" in nearby, (
        "HTTPS bind must use SockSite with the ssl_context — without "
        "that the TLS handshake never happens"
    )


def test_bind_exclusive_socket_returns_none_on_non_windows():
    """Live behavioural test: on non-Windows the helper must
    cleanly return None so the caller falls through to the normal
    TCPSite code path."""
    import os as _os
    from one_link.server import UIServer
    # Skip cleanly on actual Windows since the helper would try to
    # really bind a socket.
    if _os.name == "nt":
        pytest.skip("non-Windows behavioural test; we're on Windows")
    result = UIServer._bind_exclusive_socket("127.0.0.1", 0)
    assert result is None, (
        "non-Windows code path must return None so the caller falls "
        "through to TCPSite"
    )


def test_bind_exclusive_socket_succeeds_then_blocks_second_bind():
    """Live behavioural test (Windows): a successful exclusive bind
    must REFUSE a second bind on the same (host, port) — that's the
    whole point. We verify by binding ourselves twice."""
    import os as _os
    import socket as _socket
    if _os.name != "nt":
        pytest.skip("Windows-only behavioural test for the exclusive bind")
    from one_link.server import UIServer
    # Use port 0 to let the kernel assign; then read the actual port.
    first = UIServer._bind_exclusive_socket("127.0.0.1", 0)
    assert first is not None, "exclusive bind on a free port should succeed"
    try:
        port = first.getsockname()[1]
        # Second exclusive bind on the same port MUST fail (returns None).
        second = UIServer._bind_exclusive_socket("127.0.0.1", port)
        if second is not None:
            second.close()
            pytest.fail(
                "exclusive bind on an occupied port should have failed; "
                "instead got a second socket — SO_EXCLUSIVEADDRUSE isn't "
                "being honoured"
            )
        # A normal (non-exclusive) socket attempt with SO_REUSEADDR
        # also must fail — that's the WHOLE POINT of SO_EXCLUSIVEADDRUSE
        # vs the default Windows behaviour.
        s2 = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        try:
            s2.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
            with pytest.raises(OSError):
                s2.bind(("127.0.0.1", port))
        finally:
            s2.close()
    finally:
        first.close()
