"""This host's own addresses must never be resolved on the hot path.

`resolve_bounded` caps a resolver call at a deadline, but the join happens on
the CALLING thread -- so a bounded call still freezes an event loop for the
whole deadline. Five call sites reach `discover_local_endpoints`, and two of
them are SYNCHRONOUS methods running on the loop
(`Daemon._local_endpoint_announcement_signature`,
`UIServer._mint_route_bootstrap_token`), which no `to_thread` wrapping can
reach without changing their signatures and every caller above them.

So the address list -- ambient host state, not a per-request computation -- is
cached and refreshed off-loop. The release-run evidence this comes from: the
loop watchdog caught `_delayed_announcement` blocked 64s inside
`socket.getaddrinfo` on a macOS runner resolving its own `.local` name.
"""

from __future__ import annotations

import socket
import time

import pytest

from one_link import rendezvous_client as rc


@pytest.fixture(autouse=True)
def _clean_cache():
    rc.reset_own_address_cache()
    yield
    rc.reset_own_address_cache()


def test_a_wedged_resolver_never_blocks_twice(monkeypatch):
    """The first call is bounded; every later call must not wait at all."""
    def _never_answers(*_a, **_k):
        time.sleep(30)

    monkeypatch.setattr(socket, "getaddrinfo", _never_answers)
    monkeypatch.setattr(rc, "_OWN_ADDR_FIRST_CALL_BUDGET_SECONDS", 0.3)
    monkeypatch.setattr(rc, "_OWN_ADDR_TTL_SECONDS", 0.2)

    started = time.monotonic()
    assert rc.own_ipv4_addresses() == []
    first = time.monotonic() - started
    assert first < 2.0, f"first call was not bounded: {first:.1f}s"

    # Let the entry go stale, then hammer it: a stale entry is served AS IS
    # and refreshed in the background. None of these may wait.
    time.sleep(0.25)
    worst = 0.0
    for _ in range(5):
        started = time.monotonic()
        rc.own_ipv4_addresses()
        worst = max(worst, time.monotonic() - started)
    assert worst < 0.1, (
        f"a stale lookup blocked the caller for {worst:.2f}s -- on the event "
        "loop that is a frozen daemon"
    )


def test_a_healthy_resolver_answers_on_the_first_call(monkeypatch):
    """A correct first advertisement matters: it must not be empty."""
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *_a, **_k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                            ("10.1.2.3", 0))],
    )
    assert rc.own_ipv4_addresses() == ["10.1.2.3"]
    # ...and is then served from cache without touching the resolver again.
    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    assert rc.own_ipv4_addresses() == ["10.1.2.3"]


def _boom(*_a, **_k):
    raise AssertionError("the resolver was consulted despite a fresh cache")


def test_a_programming_error_is_not_swallowed(monkeypatch):
    """Convention in this package: network errors degrade, bugs propagate."""
    def _contract_violation(*_a, **_k):
        raise RuntimeError("unexpected resolver contract violation")

    monkeypatch.setattr(socket, "getaddrinfo", _contract_violation)
    with pytest.raises(RuntimeError, match="contract violation"):
        rc.own_ipv4_addresses()


def test_discover_local_endpoints_still_filters_per_call(monkeypatch):
    """The cache holds RAW addresses; filtering stays per-call.

    Otherwise the first caller's include_loopback choice would be baked in
    for every later caller.
    """
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *_a, **_k: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))
            for ip in ("127.0.0.1", "169.254.9.9", "10.0.0.4")
        ],
    )
    # Neutralise the second, independent address source (a UDP egress probe)
    # so this test sees only what the cache contributed.
    monkeypatch.setattr(rc.socket, "socket", _no_egress_probe)

    default = {e.host for e in rc.discover_local_endpoints(peer_port=7777)}
    assert default == {"10.0.0.4"}

    with_loopback = {
        e.host
        for e in rc.discover_local_endpoints(peer_port=7777, include_loopback=True)
    }
    assert "127.0.0.1" in with_loopback

    with_link_local = {
        e.host
        for e in rc.discover_local_endpoints(peer_port=7777, include_link_local=True)
    }
    assert "169.254.9.9" in with_link_local


class _no_egress_probe:
    def __init__(self, *_a, **_k):
        pass

    def connect(self, *_a, **_k):
        raise OSError("no egress in this test")

    def getsockname(self):
        raise OSError("no egress in this test")

    def close(self):
        pass


def test_every_loop_side_caller_goes_through_the_cache():
    """Twin-copy guard over the five call sites.

    Two of them are synchronous methods on the event loop, so the ONLY thing
    keeping them off the resolver is that discover_local_endpoints consults
    the cache rather than socket.getaddrinfo directly.
    """
    from pathlib import Path

    src = (
        Path(__file__).resolve().parents[1]
        / "src" / "one_link" / "rendezvous_client.py"
    ).read_text(encoding="utf-8")

    body = src[src.index("def discover_local_endpoints"):]
    body = body[: body.index("\ndef ", 1)] if "\ndef " in body[1:] else body
    assert "own_ipv4_addresses()" in body
    assert "getaddrinfo" not in body, (
        "discover_local_endpoints resolves directly again -- every loop-side "
        "caller, including the two synchronous ones, is back on the hot path"
    )
