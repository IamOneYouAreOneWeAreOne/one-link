"""v0.20.7 (Bundle 56) — CapStore: live capability-grant integration.

CapStore wraps Bundle 44's signed grants in a per-daemon store with
verify-on-accept, replay defense, auto-expiry on read + periodic
prune, and revoke-by-(granter|subject) operations. The daemon
attaches one + queries it from ``_capability_allowed``.

These tests pin:
  - accept() verifies + stores a valid grant
  - has_capability() returns True for the expected (granter, subject,
    capability, scope) tuple
  - has_capability returns False for missing capability / wrong
    granter / wrong subject / wrong scope
  - Expired grants are auto-suppressed at read time
  - prune_expired drops expired grants + returns the count
  - revoke_subject drops every grant addressed at the subject
  - revoke_granter drops every grant issued by the granter
  - Replay defense: re-accepting the same grant blob fails
  - list_grants_for returns active grants for a subject + suppresses
    expired
"""
from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import cap_store, caps_grants


def _gen_ed25519():
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes_raw()
    pub = priv.public_key().public_bytes_raw()
    return seed, pub


def _now_ms():
    return int(time.time() * 1000)


def _make_grant(
    *, granter_seed, granter_pub, subject_pub,
    capabilities, scope=b"", duration_ms=60_000, base_now=None,
):
    base_now = base_now if base_now is not None else _now_ms()
    return caps_grants.encode_grant(
        granter_priv_seed=granter_seed,
        granter_pub=granter_pub,
        subject_pub=subject_pub,
        capabilities=capabilities,
        not_before_ms=base_now,
        not_after_ms=base_now + duration_ms,
        scope=scope,
    )


# ── accept + has_capability ───────────────────────────────────────


def test_accept_valid_grant():
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    store = cap_store.CapStore()
    blob = _make_grant(
        granter_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=subject_pub, capabilities=["files:read"],
    )
    g = store.accept(blob, expected_subject_pub=subject_pub)
    assert "files:read" in g.capabilities
    assert len(store) == 1


def test_has_capability_match():
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    store = cap_store.CapStore()
    blob = _make_grant(
        granter_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=subject_pub, capabilities=["files:read", "chat:send"],
        scope=b"folder-X",
    )
    store.accept(blob, expected_subject_pub=subject_pub)
    assert store.has_capability(
        granter_pub=granter_pub, subject_pub=subject_pub,
        capability="files:read", scope=b"folder-X",
    )
    assert store.has_capability(
        granter_pub=granter_pub, subject_pub=subject_pub,
        capability="chat:send", scope=b"folder-X",
    )


def test_has_capability_missing_returns_false():
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    store = cap_store.CapStore()
    blob = _make_grant(
        granter_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=subject_pub, capabilities=["files:read"],
    )
    store.accept(blob, expected_subject_pub=subject_pub)
    # Wrong capability.
    assert not store.has_capability(
        granter_pub=granter_pub, subject_pub=subject_pub,
        capability="files:write",
    )
    # Wrong scope.
    assert not store.has_capability(
        granter_pub=granter_pub, subject_pub=subject_pub,
        capability="files:read", scope=b"different",
    )
    # Wrong granter.
    _, other_granter_pub = _gen_ed25519()
    assert not store.has_capability(
        granter_pub=other_granter_pub, subject_pub=subject_pub,
        capability="files:read",
    )


def test_expired_grant_auto_dropped_on_read():
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    store = cap_store.CapStore()
    base = _now_ms()
    blob = _make_grant(
        granter_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=subject_pub, capabilities=["x"],
        duration_ms=1_000, base_now=base,
    )
    store.accept(blob, expected_subject_pub=subject_pub, now_ms=base)
    assert len(store) == 1
    # Look up with now past expiry — should be False AND drop the
    # entry from the store.
    assert not store.has_capability(
        granter_pub=granter_pub, subject_pub=subject_pub,
        capability="x", now_ms=base + 5_000,
    )
    assert len(store) == 0


def test_prune_expired():
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    store = cap_store.CapStore()
    base = _now_ms()
    # 3 grants with different lifetimes.
    for i, dur in enumerate((500, 5_000, 50_000)):
        blob = _make_grant(
            granter_seed=granter_seed, granter_pub=granter_pub,
            subject_pub=subject_pub, capabilities=[f"cap-{i}"],
            duration_ms=dur, base_now=base,
        )
        store.accept(blob, expected_subject_pub=subject_pub, now_ms=base)
    assert len(store) == 3
    dropped = store.prune_expired(now_ms=base + 1_000)
    assert dropped == 1
    assert len(store) == 2
    dropped = store.prune_expired(now_ms=base + 10_000)
    assert dropped == 1
    assert len(store) == 1


def test_revoke_subject():
    granter_seed, granter_pub = _gen_ed25519()
    _, sub_a = _gen_ed25519()
    _, sub_b = _gen_ed25519()
    store = cap_store.CapStore()
    for sub_pub in (sub_a, sub_b):
        for cap in ("read", "write"):
            blob = _make_grant(
                granter_seed=granter_seed, granter_pub=granter_pub,
                subject_pub=sub_pub, capabilities=[cap],
            )
            store.accept(blob, expected_subject_pub=sub_pub)
    assert len(store) == 4
    dropped = store.revoke_subject(sub_a)
    assert dropped == 2
    assert len(store) == 2
    # Only sub_b's grants remain.
    assert store.has_capability(
        granter_pub=granter_pub, subject_pub=sub_b, capability="read",
    )
    assert not store.has_capability(
        granter_pub=granter_pub, subject_pub=sub_a, capability="read",
    )


def test_revoke_granter():
    g1_seed, g1_pub = _gen_ed25519()
    g2_seed, g2_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    store = cap_store.CapStore()
    for granter_seed, granter_pub in [(g1_seed, g1_pub), (g2_seed, g2_pub)]:
        blob = _make_grant(
            granter_seed=granter_seed, granter_pub=granter_pub,
            subject_pub=subject_pub, capabilities=["x"],
        )
        store.accept(blob, expected_subject_pub=subject_pub)
    assert len(store) == 2
    dropped = store.revoke_granter(g1_pub)
    assert dropped == 1
    assert not store.has_capability(
        granter_pub=g1_pub, subject_pub=subject_pub, capability="x",
    )
    assert store.has_capability(
        granter_pub=g2_pub, subject_pub=subject_pub, capability="x",
    )


def test_replay_rejected():
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    store = cap_store.CapStore()
    blob = _make_grant(
        granter_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=subject_pub, capabilities=["x"],
    )
    store.accept(blob, expected_subject_pub=subject_pub)
    with pytest.raises(ValueError, match="replayed"):
        store.accept(blob, expected_subject_pub=subject_pub)


def test_wrong_subject_rejected():
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    _, other_pub = _gen_ed25519()
    store = cap_store.CapStore()
    blob = _make_grant(
        granter_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=subject_pub, capabilities=["x"],
    )
    with pytest.raises(ValueError):
        store.accept(blob, expected_subject_pub=other_pub)


def test_list_grants_for_filters_expired():
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    store = cap_store.CapStore()
    base = _now_ms()
    # One short-lived + one long-lived grant.
    short = _make_grant(
        granter_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=subject_pub, capabilities=["short"],
        duration_ms=500, base_now=base,
    )
    long_ = _make_grant(
        granter_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=subject_pub, capabilities=["long"],
        duration_ms=50_000, base_now=base,
    )
    store.accept(short, expected_subject_pub=subject_pub, now_ms=base)
    store.accept(long_, expected_subject_pub=subject_pub, now_ms=base)
    out = store.list_grants_for(subject_pub=subject_pub, now_ms=base + 1_000)
    assert len(out) == 1
    assert "long" in out[0].capabilities


def test_grant_outside_window_inline_dropped():
    """A grant whose not_after has passed must be dropped on read,
    not just suppressed silently."""
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    store = cap_store.CapStore()
    base = _now_ms()
    blob = _make_grant(
        granter_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=subject_pub, capabilities=["x"],
        duration_ms=100, base_now=base,
    )
    store.accept(blob, expected_subject_pub=subject_pub, now_ms=base)
    assert len(store) == 1
    # has_capability past expiry: returns False AND drops.
    assert not store.has_capability(
        granter_pub=granter_pub, subject_pub=subject_pub,
        capability="x", now_ms=base + 1_000,
    )
    assert len(store) == 0
