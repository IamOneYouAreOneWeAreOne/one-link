"""No synchronous name resolution may run unbounded.

The C resolver takes no timeout and cannot be cancelled. On macOS a host's own
name is typically a ``.local`` name answered over mDNS, so on a degraded
network these calls block for a minute or more. On the event-loop thread that
is not slowness -- it is an outage that looks exactly like health: the kernel
keeps accepting connections on every listener, nothing is ever read from them,
and the process logs nothing, because the code that would log is not running.

One Link shipped this defect twice. The first copy blocked TLS cert minting;
after it was fixed, the loop watchdog caught the SECOND copy in a release
build, blocking a macOS daemon for 64 seconds:

    one_link/daemon.py  _delayed_announcement
    one_link/daemon.py  broadcast_endpoint_to_paired
    one_link/rendezvous_client.py  discover_local_endpoints
    socket.py  getaddrinfo

Fixing one copy at a time is how the second one survived. This sweeps them all.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "one_link"

# Every synchronous resolver entry point that can block indefinitely.
BLOCKING_CALLS = (
    "getaddrinfo",
    "gethostbyname",
    "gethostbyname_ex",
    "gethostbyaddr",
    "getfqdn",
    "getnameinfo",
)

CALL_RE = re.compile(
    r"socket\.(" + "|".join(sorted(BLOCKING_CALLS, key=len, reverse=True)) + r")\s*\("
)

# How far back a `resolve_bounded(` wrapper may sit from the call it bounds.
WRAPPER_WINDOW = 8


def _unbounded_sites() -> list[tuple[str, int, str]]:
    offenders: list[tuple[str, int, str]] = []
    for path in sorted(SRC.rglob("*.py")):
        lines = path.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if not CALL_RE.search(line):
                continue
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith(('"', "'")):
                continue  # prose, not a call
            window = "\n".join(lines[max(0, i - WRAPPER_WINDOW):i + 1])
            if "resolve_bounded(" in window:
                continue
            offenders.append((path.name, i + 1, stripped))
    return offenders


def test_no_unbounded_resolver_call_anywhere_in_the_package():
    offenders = _unbounded_sites()
    assert not offenders, (
        "unbounded synchronous name resolution -- on the event-loop thread "
        "this freezes the whole daemon while every listener still accepts "
        "connections it will never read. Wrap with "
        "one_link.bounded_resolver.resolve_bounded:\n"
        + "\n".join(f"  {n}:{ln}  {src}" for n, ln, src in offenders)
    )


def test_the_sweep_can_actually_fail(tmp_path, monkeypatch):
    """A guard that cannot fail proves nothing.

    Point the sweep at a file with a bare resolver call and it must object;
    otherwise a green run above is ambient luck rather than evidence.
    """
    planted = tmp_path / "one_link"
    planted.mkdir()
    (planted / "regression.py").write_text(
        "import socket\n\n\ndef go():\n    return socket.getaddrinfo('host', None)\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "tests.test_no_unbounded_resolution_v0210.SRC", planted, raising=False
    )
    import tests.test_no_unbounded_resolution_v0210 as mod

    monkeypatch.setattr(mod, "SRC", planted)
    offenders = mod._unbounded_sites()
    assert offenders, "the sweep failed to notice a bare socket.getaddrinfo call"
    assert offenders[0][0] == "regression.py"

    # ...and it must accept the bounded form.
    (planted / "regression.py").write_text(
        "import socket\n"
        "from one_link.bounded_resolver import resolve_bounded\n\n\n"
        "def go():\n"
        "    return resolve_bounded(\n"
        "        socket.getaddrinfo, 'host', None, default=[], label='x',\n"
        "    )\n",
        encoding="utf-8",
    )
    assert mod._unbounded_sites() == []


def test_bounded_resolver_returns_the_default_instead_of_waiting():
    import time

    from one_link.bounded_resolver import resolve_bounded

    def _never_answers():
        time.sleep(30)

    started = time.monotonic()
    assert resolve_bounded(
        _never_answers, default=["fallback"], label="test", timeout=0.5
    ) == ["fallback"]
    assert time.monotonic() - started < 5.0


def test_bounded_resolver_does_not_swallow_real_errors():
    from one_link.bounded_resolver import resolve_bounded

    def _refuse():
        raise OSError("no route to host")

    with pytest.raises(OSError):
        resolve_bounded(_refuse, default=[], label="test")


def test_bounded_resolver_passes_arguments_and_results_through():
    from one_link.bounded_resolver import resolve_bounded

    def _echo(a, b, *, c):
        return (a, b, c)

    assert resolve_bounded(_echo, 1, 2, c=3, default=None, label="test") == (1, 2, 3)
