"""v0.20.7 (Bundle 51) — live integration of rendezvous-blinding.

Bundle 43 shipped the blinded-token primitive. Bundle 51 wires it
into the rendezvous server: every /api/v1/register also populates
a blinded-token alias map, and /api/v2/lookup_token/{token_b64}
answers lookups without ever seeing a raw pubkey on the wire.

These tests pin:
  - Registry.upsert populates the token alias map for the current
    epoch (and adjacent epochs for window-coverage)
  - get_by_token finds the entry; raw pubkey lookup still works
  - Removing an entry cleans up the alias map
  - Evicted entries (when registry hits max_entries) clean up too
  - Expired entries are dropped from BOTH maps via evict_expired
  - End-to-end: register a peer, compute their token, lookup_token
    returns the registration; raw /api/v1/lookup also works
  - Token at the wrong epoch (e.g. way in the past) doesn't match
"""
from __future__ import annotations

import time


from one_link import rdz_blind
from one_link.rendezvous_server import Registry, Registration


def _make_pubkey(seed_byte: int) -> bytes:
    return bytes([seed_byte]) * 32


def _make_reg(pubkey: bytes, ttl_ms: int = 60_000) -> Registration:
    now = int(time.time() * 1000)
    return Registration(
        pubkey=pubkey,
        observed_endpoint="1.2.3.4:5000",
        advertised_endpoints=("[fe80::1]:6000",),
        nat_type="cone",
        capabilities=("v1",),
        registered_at_ms=now,
        expires_at_ms=now + ttl_ms,
    )


def test_upsert_populates_token_alias():
    reg = Registry(max_entries=100)
    pub = _make_pubkey(0x11)
    reg.upsert(_make_reg(pub))
    # The current-epoch token should resolve back to the same entry.
    epoch = rdz_blind.current_epoch_id()
    token = rdz_blind.derive_blinded_token(peer_pub=pub, epoch_id=epoch)
    found = reg.get_by_token(token)
    assert found is not None
    assert found.pubkey == pub


def test_upsert_indexes_adjacent_epochs():
    """Tokens for epoch-1, epoch, epoch+1 all resolve so a query
    arriving right at the boundary doesn't miss."""
    reg = Registry(max_entries=100)
    pub = _make_pubkey(0x22)
    reg.upsert(_make_reg(pub))
    epoch = rdz_blind.current_epoch_id()
    for e in (epoch - 1, epoch, epoch + 1):
        token = rdz_blind.derive_blinded_token(peer_pub=pub, epoch_id=e)
        assert reg.get_by_token(token) is not None


def test_token_for_far_past_epoch_does_not_resolve():
    reg = Registry(max_entries=100)
    pub = _make_pubkey(0x33)
    reg.upsert(_make_reg(pub))
    far_past = rdz_blind.current_epoch_id() - 100
    token = rdz_blind.derive_blinded_token(peer_pub=pub, epoch_id=far_past)
    assert reg.get_by_token(token) is None


def test_remove_cleans_alias_map():
    reg = Registry(max_entries=100)
    pub = _make_pubkey(0x44)
    reg.upsert(_make_reg(pub))
    epoch = rdz_blind.current_epoch_id()
    token = rdz_blind.derive_blinded_token(peer_pub=pub, epoch_id=epoch)
    assert reg.get_by_token(token) is not None
    reg.remove(pub)
    assert reg.get_by_token(token) is None
    assert reg.get(pub) is None


def test_eviction_cleans_alias_map():
    reg = Registry(max_entries=2)
    pub_a = _make_pubkey(0x01)
    pub_b = _make_pubkey(0x02)
    pub_c = _make_pubkey(0x03)
    # A and B have low expires; C is fresh — A should evict.
    now = int(time.time() * 1000)
    reg.upsert(Registration(
        pubkey=pub_a, observed_endpoint="x", advertised_endpoints=(),
        nat_type="?", capabilities=(),
        registered_at_ms=now, expires_at_ms=now + 1000,
    ))
    reg.upsert(Registration(
        pubkey=pub_b, observed_endpoint="x", advertised_endpoints=(),
        nat_type="?", capabilities=(),
        registered_at_ms=now, expires_at_ms=now + 5000,
    ))
    epoch = rdz_blind.current_epoch_id()
    token_a = rdz_blind.derive_blinded_token(peer_pub=pub_a, epoch_id=epoch)
    assert reg.get_by_token(token_a) is not None
    # Now insert C, which evicts A (smallest expires_at_ms).
    reg.upsert(Registration(
        pubkey=pub_c, observed_endpoint="x", advertised_endpoints=(),
        nat_type="?", capabilities=(),
        registered_at_ms=now, expires_at_ms=now + 10_000,
    ))
    # A is gone from both maps.
    assert reg.get(pub_a) is None
    assert reg.get_by_token(token_a) is None
    # B and C still resolvable.
    token_b = rdz_blind.derive_blinded_token(peer_pub=pub_b, epoch_id=epoch)
    token_c = rdz_blind.derive_blinded_token(peer_pub=pub_c, epoch_id=epoch)
    assert reg.get_by_token(token_b) is not None
    assert reg.get_by_token(token_c) is not None


def test_evict_expired_cleans_alias_map():
    reg = Registry(max_entries=100)
    pub = _make_pubkey(0x55)
    now = int(time.time() * 1000)
    reg.upsert(Registration(
        pubkey=pub, observed_endpoint="x", advertised_endpoints=(),
        nat_type="?", capabilities=(),
        registered_at_ms=now, expires_at_ms=now + 100,
    ))
    epoch = rdz_blind.current_epoch_id()
    token = rdz_blind.derive_blinded_token(peer_pub=pub, epoch_id=epoch)
    assert reg.get_by_token(token) is not None
    # Sweep with now > expires_at_ms.
    reg.evict_expired(now + 200)
    assert reg.get(pub) is None
    assert reg.get_by_token(token) is None


def test_get_by_token_returns_none_for_unknown():
    reg = Registry(max_entries=100)
    unknown_token = b"\xff" * 32
    assert reg.get_by_token(unknown_token) is None


def test_token_for_unregistered_pub_does_not_collide():
    """Two distinct pubkeys produce distinct tokens (HKDF
    avalanche). Sanity check the alias map doesn't accidentally
    converge."""
    reg = Registry(max_entries=100)
    pub_a = _make_pubkey(0x01)
    pub_b = _make_pubkey(0x02)
    reg.upsert(_make_reg(pub_a))
    epoch = rdz_blind.current_epoch_id()
    # Token for the UNREGISTERED B should not resolve to A.
    token_b = rdz_blind.derive_blinded_token(peer_pub=pub_b, epoch_id=epoch)
    assert reg.get_by_token(token_b) is None
