"""First-run HTTPS setup must not freeze the daemon.

Minting the peer-HTTPS cert enumerates this host's addresses, and that ends in
``socket.gethostbyname_ex(socket.gethostname())`` -- a synchronous resolver
call with no timeout. On macOS the machine's own name is a ``.local`` name
answered over mDNS, so on a host whose network is degraded it blocks for tens
of seconds. Run on the event-loop thread it froze the whole daemon: every
listener still ACCEPTED connections (the kernel does that), nothing was ever
read from them, and the log went silent because the code that would log was
not running -- a daemon that looked healthy and answered nothing.
"""

from __future__ import annotations

import re
import time
from pathlib import Path



def test_a_wedged_resolver_costs_a_san_entry_not_the_daemon(monkeypatch):
    from one_link import peer_https

    def _never_answers(_name):
        time.sleep(30)
        raise AssertionError("unreachable")

    monkeypatch.setattr(peer_https.socket, "gethostbyname_ex", _never_answers)
    monkeypatch.setattr(peer_https, "OWN_ADDRESS_RESOLVE_TIMEOUT_SECONDS", 0.5)

    started = time.monotonic()
    assert peer_https._resolve_own_addresses_bounded() == []
    assert time.monotonic() - started < 5.0, "the deadline did not bound the caller"


def test_a_healthy_resolver_still_contributes_its_addresses(monkeypatch):
    from one_link import peer_https

    monkeypatch.setattr(
        peer_https.socket,
        "gethostbyname_ex",
        lambda _n: ("host", [], ["192.168.1.50", "10.0.0.7"]),
    )
    assert peer_https._resolve_own_addresses_bounded() == ["192.168.1.50", "10.0.0.7"]

    # And it reaches the SAN set the cert is built from.
    monkeypatch.setattr(peer_https.socket, "gethostname", lambda: "host")
    detected = peer_https._detect_lan_addresses()
    assert "192.168.1.50" in detected and "10.0.0.7" in detected
    assert "127.0.0.1" in detected


def test_a_resolver_error_is_not_fatal(monkeypatch):
    from one_link import peer_https

    def _refuse(_name):
        raise OSError("no route to host")

    monkeypatch.setattr(peer_https.socket, "gethostbyname_ex", _refuse)
    assert peer_https._resolve_own_addresses_bounded() == []


def test_cert_building_is_never_awaited_on_the_loop_thread():
    """Guard the placement, not just the timeout.

    Even bounded, this work belongs off the loop -- 5s of frozen daemon is
    still 5s in which no request of any kind can be served.
    """
    source = (
        Path(__file__).resolve().parents[1] / "src" / "one_link" / "server.py"
    ).read_text(encoding="utf-8")

    lines = source.splitlines()
    # Every mention that is an invocation -- `build_ssl_context(` for a direct
    # call, `build_ssl_context,` when passed to a runner -- excluding imports.
    sites = [
        i for i, line in enumerate(lines)
        if re.search(r"build_ssl_context\s*[(,]", line)
        and not line.lstrip().startswith(("from ", "import ", "def "))
    ]
    assert sites, "build_ssl_context call site not found"

    for i in sites:
        window = "\n".join(lines[max(0, i - 3):i + 1])
        assert "to_thread" in window, (
            "build_ssl_context runs on the event loop; its host-address "
            "enumeration can block for tens of seconds on a degraded "
            f"network. Found at line {i + 1}: {window!r}"
        )


def test_the_bound_is_sane():
    from one_link import peer_https

    assert 0 < peer_https.OWN_ADDRESS_RESOLVE_TIMEOUT_SECONDS <= 30
