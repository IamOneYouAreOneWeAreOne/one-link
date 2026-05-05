"""Discovery registry: add/find/remove/list. Network-free."""

from __future__ import annotations

from one_link.discovery import Peer, Registry


def _peer(short_id: str, host: str = "host", addr: str = "10.0.0.2", port: int = 1234) -> Peer:
    return Peer(
        short_id=short_id,
        hostname=host,
        address=addr,
        port=port,
        ed_pub_hex="00" * 32,
    )


def test_upsert_and_find_by_short_id():
    r = Registry()
    p = _peer("abcdef12", "alice")
    r.upsert(p)
    assert r.find("abcdef12") is p


def test_find_by_hostname_case_insensitive():
    r = Registry()
    p = _peer("abcdef12", "Alice-Mac")
    r.upsert(p)
    assert r.find("alice-mac") is p
    assert r.find("ALICE-MAC") is p


def test_find_by_short_id_prefix():
    r = Registry()
    p = _peer("abcdef12")
    r.upsert(p)
    assert r.find("abc") is p
    assert r.find("abcde") is p


def test_find_returns_none_for_unknown():
    r = Registry()
    r.upsert(_peer("abcdef12"))
    assert r.find("zzzzzzzz") is None
    assert r.find("nope") is None


def test_remove():
    r = Registry()
    r.upsert(_peer("abcdef12"))
    r.remove("abcdef12")
    assert r.find("abcdef12") is None


def test_remove_unknown_is_noop():
    r = Registry()
    r.remove("nope")  # no error


def test_list_sorted_by_hostname():
    r = Registry()
    r.upsert(_peer("aaaaaaaa", "charlie"))
    r.upsert(_peer("bbbbbbbb", "alice"))
    r.upsert(_peer("cccccccc", "bob"))
    out = r.list()
    assert [p.hostname for p in out] == ["alice", "bob", "charlie"]


def test_upsert_overwrites_same_id():
    r = Registry()
    r.upsert(_peer("abcdef12", "alice", "10.0.0.1", 1111))
    r.upsert(_peer("abcdef12", "alice2", "10.0.0.2", 2222))
    p = r.find("abcdef12")
    assert p is not None
    assert p.hostname == "alice2"
    assert p.address == "10.0.0.2"
    assert p.port == 2222


def test_on_change_callback():
    seen = []
    r = Registry(on_change=lambda: seen.append(1))
    r.upsert(_peer("a"))
    r.upsert(_peer("b"))
    r.remove("a")
    r.remove("nope")  # should NOT fire (nothing removed)
    assert len(seen) == 3
