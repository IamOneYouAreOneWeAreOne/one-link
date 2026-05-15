"""Audit L13 May 2026 — delegation-chain enforcement on
``Daemon._cap_authorized_via_chain``.

Before this fix, ``_capability_allowed`` only knew self-issued
grants. A paired peer who held a cap and wished to delegate a
narrow slice to a co-worker could mint a sub-grant, but the
daemon's authorization check ignored anything whose granter was
not the daemon itself.

These tests pin the new behavior:

  - Direct self → subject grant authorizes (unchanged).
  - Chain self → delegator → subject authorizes (NEW).
  - Two-hop chain (self → A → B → subject) DOES NOT authorize
    when ``max_depth=2``: the trailing edge is the third hop.
    (Realistic depth bound — keep transitive trust shallow.)
  - Missing middle edge: subject who has a (delegator → subject)
    grant but no (self → delegator) grant is REJECTED.
  - Scope mismatch on either edge breaks the chain.
  - Capability mismatch on either edge breaks the chain.
  - Cycle detection: a cycle self → A → self → subject does not
    revisit ``self`` and resolves cleanly without infinite loop.
"""
from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import cap_store, caps_grants


def _gen():
    priv = Ed25519PrivateKey.generate()
    return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()


def _now_ms():
    return int(time.time() * 1000)


def _mint(
    *, granter_seed, granter_pub, subject_pub,
    capabilities, scope=b"", duration_ms=60_000,
):
    base = _now_ms()
    return caps_grants.encode_grant(
        granter_priv_seed=granter_seed,
        granter_pub=granter_pub,
        subject_pub=subject_pub,
        capabilities=capabilities,
        not_before_ms=base,
        not_after_ms=base + duration_ms,
        scope=scope,
    )


class _Walker:
    """Tiny shim exposing only ``_cap_store`` and the chain-walker
    method copied off ``Daemon`` — sufficient for the structural
    test without spinning a full daemon process."""
    def __init__(self, store):
        self._cap_store = store

    from one_link.daemon import Daemon as _Daemon
    _cap_authorized_via_chain = _Daemon._cap_authorized_via_chain
    del _Daemon


def _walker(store):
    return _Walker(store)


# ── direct grant (regression: self → subject) ─────────────────────

def test_direct_self_grant_authorizes():
    me_seed, me_pub = _gen()
    bob_seed, bob_pub = _gen()
    store = cap_store.CapStore()
    blob = _mint(
        granter_seed=me_seed, granter_pub=me_pub,
        subject_pub=bob_pub, capabilities=["files:read"],
    )
    store.accept(blob, expected_subject_pub=bob_pub)
    d = _walker(store)
    assert d._cap_authorized_via_chain(
        root_granter_pub=me_pub,
        subject_pub=bob_pub,
        capability="files:read",
    )


# ── single-hop delegation (the L13 fix's headline behavior) ───────

def test_single_hop_delegation_authorizes():
    me_seed, me_pub = _gen()
    alice_seed, alice_pub = _gen()
    bob_seed, bob_pub = _gen()
    store = cap_store.CapStore()
    # me → alice
    store.accept(
        _mint(
            granter_seed=me_seed, granter_pub=me_pub,
            subject_pub=alice_pub, capabilities=["files:read"],
        ),
        expected_subject_pub=alice_pub,
    )
    # alice → bob (sub-grant)
    store.accept(
        _mint(
            granter_seed=alice_seed, granter_pub=alice_pub,
            subject_pub=bob_pub, capabilities=["files:read"],
        ),
        expected_subject_pub=bob_pub,
    )
    d = _walker(store)
    assert d._cap_authorized_via_chain(
        root_granter_pub=me_pub,
        subject_pub=bob_pub,
        capability="files:read",
        max_depth=2,
    )


# ── depth bound (chain length > max_depth rejected) ───────────────

def test_three_hop_chain_rejected_at_depth_two():
    me_seed, me_pub = _gen()
    a_seed, a_pub = _gen()
    b_seed, b_pub = _gen()
    c_seed, c_pub = _gen()
    store = cap_store.CapStore()
    for (gs, gp, sp) in [
        (me_seed, me_pub, a_pub),
        (a_seed, a_pub, b_pub),
        (b_seed, b_pub, c_pub),
    ]:
        store.accept(
            _mint(
                granter_seed=gs, granter_pub=gp,
                subject_pub=sp, capabilities=["files:read"],
            ),
            expected_subject_pub=sp,
        )
    d = _walker(store)
    # me → a → b → c is length 3, max_depth=2 rejects.
    assert not d._cap_authorized_via_chain(
        root_granter_pub=me_pub,
        subject_pub=c_pub,
        capability="files:read",
        max_depth=2,
    )
    # max_depth=3 admits it (sanity check the walker is correct).
    assert d._cap_authorized_via_chain(
        root_granter_pub=me_pub,
        subject_pub=c_pub,
        capability="files:read",
        max_depth=3,
    )


# ── missing root edge (delegator NOT authorized by us) ────────────

def test_unauthorized_delegator_rejected():
    me_seed, me_pub = _gen()
    rogue_seed, rogue_pub = _gen()
    bob_seed, bob_pub = _gen()
    store = cap_store.CapStore()
    # rogue → bob exists, but we never gave rogue anything.
    store.accept(
        _mint(
            granter_seed=rogue_seed, granter_pub=rogue_pub,
            subject_pub=bob_pub, capabilities=["files:read"],
        ),
        expected_subject_pub=bob_pub,
    )
    d = _walker(store)
    assert not d._cap_authorized_via_chain(
        root_granter_pub=me_pub,
        subject_pub=bob_pub,
        capability="files:read",
    )


# ── scope mismatch breaks the chain ───────────────────────────────

def test_scope_mismatch_on_intermediate_breaks_chain():
    me_seed, me_pub = _gen()
    alice_seed, alice_pub = _gen()
    bob_seed, bob_pub = _gen()
    store = cap_store.CapStore()
    # me → alice with scope "folder-A"
    store.accept(
        _mint(
            granter_seed=me_seed, granter_pub=me_pub,
            subject_pub=alice_pub, capabilities=["files:read"],
            scope=b"folder-A",
        ),
        expected_subject_pub=alice_pub,
    )
    # alice → bob with scope "folder-B" (mismatch)
    store.accept(
        _mint(
            granter_seed=alice_seed, granter_pub=alice_pub,
            subject_pub=bob_pub, capabilities=["files:read"],
            scope=b"folder-B",
        ),
        expected_subject_pub=bob_pub,
    )
    d = _walker(store)
    # Query for folder-A: bob's leaf is folder-B, doesn't match.
    assert not d._cap_authorized_via_chain(
        root_granter_pub=me_pub,
        subject_pub=bob_pub,
        capability="files:read",
        scope=b"folder-A",
    )
    # Query for folder-B: alice's me-issued grant is folder-A, no
    # match on the root edge.
    assert not d._cap_authorized_via_chain(
        root_granter_pub=me_pub,
        subject_pub=bob_pub,
        capability="files:read",
        scope=b"folder-B",
    )


# ── capability mismatch breaks the chain ──────────────────────────

def test_capability_mismatch_on_root_breaks_chain():
    me_seed, me_pub = _gen()
    alice_seed, alice_pub = _gen()
    bob_seed, bob_pub = _gen()
    store = cap_store.CapStore()
    # me → alice for "chat:send" only
    store.accept(
        _mint(
            granter_seed=me_seed, granter_pub=me_pub,
            subject_pub=alice_pub, capabilities=["chat:send"],
        ),
        expected_subject_pub=alice_pub,
    )
    # alice → bob for "files:read" (alice doesn't have files:read
    # from us)
    store.accept(
        _mint(
            granter_seed=alice_seed, granter_pub=alice_pub,
            subject_pub=bob_pub, capabilities=["files:read"],
        ),
        expected_subject_pub=bob_pub,
    )
    d = _walker(store)
    # No chain because alice's grant from us doesn't carry files:read.
    assert not d._cap_authorized_via_chain(
        root_granter_pub=me_pub,
        subject_pub=bob_pub,
        capability="files:read",
    )


# ── cycle safety (no infinite loop) ───────────────────────────────

def test_cycle_in_grants_does_not_loop():
    me_seed, me_pub = _gen()
    a_seed, a_pub = _gen()
    store = cap_store.CapStore()
    # me → a
    store.accept(
        _mint(
            granter_seed=me_seed, granter_pub=me_pub,
            subject_pub=a_pub, capabilities=["files:read"],
        ),
        expected_subject_pub=a_pub,
    )
    # a → me (pathological cycle: a tries to grant us)
    store.accept(
        _mint(
            granter_seed=a_seed, granter_pub=a_pub,
            subject_pub=me_pub, capabilities=["files:read"],
        ),
        expected_subject_pub=me_pub,
    )
    d = _walker(store)
    # Asking about a-as-subject: direct edge me → a authorizes.
    assert d._cap_authorized_via_chain(
        root_granter_pub=me_pub,
        subject_pub=a_pub,
        capability="files:read",
    )
    # Asking about an unrelated subject: cycle does not produce a
    # false positive AND does not hang.
    _u_seed, u_pub = _gen()
    assert not d._cap_authorized_via_chain(
        root_granter_pub=me_pub,
        subject_pub=u_pub,
        capability="files:read",
    )
