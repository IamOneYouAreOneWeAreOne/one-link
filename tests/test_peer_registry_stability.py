from __future__ import annotations

from one_link.discovery import Peer, Registry


def _peer(short_id: str, pub: str, *, host: str = "Laptop", port: int = 1111) -> Peer:
    return Peer(
        short_id=short_id,
        hostname=host,
        address="192.168.1.50",
        port=port,
        ed_pub_hex=pub,
    )


def test_registry_suppresses_self_by_public_key_even_if_short_id_differs():
    own_pub = "aa" * 32
    reg = Registry(self_ed_pub_hex=own_pub)
    reg.upsert(_peer("oldself1", own_pub))
    assert reg.list() == []


def test_registry_collapses_duplicate_advertisements_by_public_key():
    pub = "bb" * 32
    reg = Registry()
    reg.upsert(_peer("first111", pub, port=1111))
    reg.upsert(_peer("second22", pub, port=2222))
    peers = reg.list()
    assert len(peers) == 1
    assert peers[0].short_id == "second22"
    assert peers[0].port == 2222


def test_registry_candidates_prefer_short_id_before_hostname():
    reg = Registry()
    reg.upsert(_peer("abc12345", "aa" * 32, host="SameName"))
    reg.upsert(_peer("def67890", "bb" * 32, host="SameName"))
    assert [p.short_id for p in reg.candidates("abc")] == ["abc12345"]
    assert [p.short_id for p in reg.candidates("SameName")] == ["abc12345", "def67890"]
