"""v0.20.7 (audit H5 + L1) — mDNS announcement hygiene.

Two defenses already live in `discovery.py` but lacked test pins:

  - **H5 — non-LAN address rejection**: an mDNS record pointing at
    a public / non-private IPv4 is either misconfigured or a steering
    attack (RFC 6762 says mDNS is link-local-only). The registry
    must drop such announcements rather than letting outbound dial
    traffic be redirected at attacker-chosen hosts.

  - **L1 — pubkey-swap on pinned short_id**: a LAN attacker who
    advertises a victim's short_id with a different pubkey would
    silently overwrite the registry entry. The handshake's mutual
    auth catches impersonation, but the UI surface (pair-flow,
    /api/peers) would have already rendered the attacker's pub.
    The registry must refuse the swap when the existing pubkey is
    pinned (SAS-paired).

These tests pin both behaviors so a future refactor can't quietly
regress them.
"""
from __future__ import annotations

from one_link import discovery


# ── H5 — _is_lan_safe_address ────────────────────────────────────────


def test_lan_safe_accepts_private_ipv4():
    for addr in [
        "10.0.0.1",
        "172.16.5.10",
        "192.168.1.42",
        "169.254.10.1",  # link-local
        "127.0.0.1",     # loopback
    ]:
        assert discovery._is_lan_safe_address(addr), addr


def test_lan_safe_rejects_public_ipv4():
    # Note: Python's ipaddress module marks the IANA TEST-NET ranges
    # (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) as is_private,
    # so we use real routable space for the negative cases.
    for addr in [
        "8.8.8.8",
        "1.1.1.1",
        "172.32.5.10",   # juuust outside RFC1918 172.16.0.0/12
        "192.169.1.1",   # juuust outside RFC1918 192.168.0.0/16
        "11.0.0.1",      # juuust outside RFC1918 10.0.0.0/8
    ]:
        assert not discovery._is_lan_safe_address(addr), addr


def test_lan_safe_rejects_garbage():
    for addr in ["", "not-an-ip", "999.999.999.999", "10.0.0.1.4"]:
        assert not discovery._is_lan_safe_address(addr), addr


# ── L1 — pubkey-swap defense on pinned short_id ──────────────────────


def _make_peer(short_id: str, pub_hex: str, addr: str = "192.168.1.1"):
    return discovery.Peer(
        short_id=short_id,
        hostname="dev",
        address=addr,
        port=1337,
        ed_pub_hex=pub_hex,
    )


PUB_A = "a" * 64
PUB_B = "b" * 64


def test_swap_accepted_when_no_pin_predicate_set():
    """Without is_pinned_pubkey installed, swaps are allowed (the
    classic mDNS first-meet behavior)."""
    reg = discovery.Registry()
    reg.upsert(_make_peer("alice", PUB_A))
    reg.upsert(_make_peer("alice", PUB_B))
    assert reg.peers["alice"].ed_pub_hex == PUB_B


def test_swap_accepted_when_existing_pub_not_pinned():
    """A predicate that returns False for the existing pub allows the
    swap (the existing entry was never pinned)."""
    reg = discovery.Registry(is_pinned_pubkey=lambda pub: False)
    reg.upsert(_make_peer("alice", PUB_A))
    reg.upsert(_make_peer("alice", PUB_B))
    assert reg.peers["alice"].ed_pub_hex == PUB_B


def test_swap_refused_when_existing_pub_is_pinned(caplog):
    """The audit defense: existing pub is pinned (SAS-paired). Refuse
    the swap and log a warning."""
    pinned_pubs = {PUB_A}
    reg = discovery.Registry(
        is_pinned_pubkey=lambda pub: pub in pinned_pubs,
    )
    reg.upsert(_make_peer("alice", PUB_A))
    with caplog.at_level("WARNING", logger="one_link.discovery"):
        reg.upsert(_make_peer("alice", PUB_B))
    # Existing entry untouched.
    assert reg.peers["alice"].ed_pub_hex == PUB_A
    # Warning surfaced.
    assert any(
        "refusing pub-hex swap" in r.message for r in caplog.records
    ), [r.message for r in caplog.records]


def test_swap_to_same_pub_is_idempotent():
    """Re-advertising the same pub (e.g. mDNS retransmit) under a
    pinned entry must NOT be rejected — it isn't a swap."""
    pinned_pubs = {PUB_A}
    reg = discovery.Registry(
        is_pinned_pubkey=lambda pub: pub in pinned_pubs,
    )
    reg.upsert(_make_peer("alice", PUB_A, addr="192.168.1.10"))
    reg.upsert(_make_peer("alice", PUB_A, addr="192.168.1.20"))
    # Second upsert kept; the address swap is fine, only pub-swap is gated.
    assert reg.peers["alice"].address == "192.168.1.20"


def test_predicate_exception_refuses_identity_swap(caplog):
    """Trust lookup failure retains the known identity fail-closed."""
    def _boom(pub):
        raise RuntimeError("predicate bug")

    reg = discovery.Registry(is_pinned_pubkey=_boom)
    reg.upsert(_make_peer("alice", PUB_A))
    with caplog.at_level("ERROR", logger="one_link.discovery"):
        reg.upsert(_make_peer("alice", PUB_B))
    assert reg.peers["alice"].ed_pub_hex == PUB_A
    assert any(
        "refusing pub-hex swap (fail-closed)" in r.message
        for r in caplog.records
    )


def test_invalid_pub_drops_existing_entry():
    """An upsert with an invalid pub_hex removes any existing entry
    (canonical mDNS hygiene — don't let garbage shadow a real peer)."""
    reg = discovery.Registry()
    reg.upsert(_make_peer("alice", PUB_A))
    reg.upsert(_make_peer("alice", "not-a-pubhex"))
    assert "alice" not in reg.peers
