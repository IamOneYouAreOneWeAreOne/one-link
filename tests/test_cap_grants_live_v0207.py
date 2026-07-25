"""v0.20.7 (Bundle 56) — capability grants LIVE in the daemon's
``_capability_allowed`` check.

Bundle 44 shipped the signed grant primitive; Bundle 56 ships the
CapStore + wires it into the daemon. This test pins the live
behavior: a peer with a valid signed grant for ``cap`` is allowed
EVEN IF the binary policy denies it; an expired/revoked grant
falls through to the policy check.

We don't need a full daemon-pair fixture for this — the
_capability_allowed method takes (peer_fp, cap) + reads from
``self._cap_store`` + ``self.state.get_peer`` + ``self.state.
get_peer_capability_policy``. Wire those up minimally.
"""
from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import cap_store, caps_grants


def _gen_ed25519():
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes_raw()
    pub = priv.public_key().public_bytes_raw()
    return seed, pub


class _FakeState:
    """Minimum state surface for ``_capability_allowed``."""
    def __init__(self):
        self._peers: dict[str, SimpleNamespace] = {}
        self._policies: dict[str, Optional[set[str]]] = {}

    def get_peer(self, fp: str):
        return self._peers.get(fp)

    def get_peer_capability_policy(self, fp: str):
        return self._policies.get(fp)


def _make_daemon_for_capability_test():
    """Build a Daemon-like object with just enough surface for
    _capability_allowed to run. We avoid the real Daemon.__init__
    because it kicks off background tasks + reads paths."""
    from one_link.daemon import Daemon
    from one_link.identity import Identity

    me_priv = Ed25519PrivateKey.generate()
    me_pub_obj = me_priv.public_key()
    me_pub = me_pub_obj.public_bytes_raw()
    me = Identity(
        private=me_priv,
        public=me_pub_obj,
        public_bytes=me_pub,
        fingerprint=me_pub.hex(),
        short_id=me_pub.hex()[:8],
        hostname="test",
    )
    # Build a stripped Daemon: just the methods we need, plumbed by
    # hand. We don't call Daemon.__init__() (that wires up many
    # tasks) — instead we instantiate the class via __new__ and set
    # the necessary attrs directly.
    d = Daemon.__new__(Daemon)
    d.me = me
    d.state = _FakeState()
    d._cap_store = cap_store.CapStore()
    return d


def _now_ms():
    return int(time.time() * 1000)


# ── live integration ────────────────────────────────────────────────


def test_grant_allows_capability_denied_by_policy():
    """A peer with a valid grant for files:read is allowed even if
    the binary policy denies files:read."""
    d = _make_daemon_for_capability_test()
    _, peer_pub = _gen_ed25519()
    peer_fp = peer_pub.hex()
    d.state._peers[peer_fp] = SimpleNamespace(pubkey=peer_pub, trust="pinned")
    # Binary policy explicitly denies files:read.
    d.state._policies[peer_fp] = {"chat:send"}  # only chat allowed
    # Without a grant, files:read is denied.
    assert not d._capability_allowed(peer_fp, "files:read")
    assert d._capability_allowed(peer_fp, "chat:send")
    # Mint a self-signed grant authorizing files:read.
    me_seed = d.me.private.private_bytes_raw()
    blob = caps_grants.encode_grant(
        granter_priv_seed=me_seed,
        granter_pub=d.me.public_bytes,
        subject_pub=peer_pub,
        capabilities=["files:read"],
        not_before_ms=_now_ms(),
        not_after_ms=_now_ms() + 60_000,
    )
    d._cap_store.accept(blob, expected_subject_pub=peer_pub)
    # Now files:read is allowed via the grant.
    assert d._capability_allowed(peer_fp, "files:read")
    # chat:send still allowed (via policy).
    assert d._capability_allowed(peer_fp, "chat:send")
    # files:write still denied (no grant covers it).
    assert not d._capability_allowed(peer_fp, "files:write")


def test_expired_grant_falls_through_to_policy():
    d = _make_daemon_for_capability_test()
    _, peer_pub = _gen_ed25519()
    peer_fp = peer_pub.hex()
    d.state._peers[peer_fp] = SimpleNamespace(pubkey=peer_pub, trust="pinned")
    d.state._policies[peer_fp] = set()  # deny all
    me_seed = d.me.private.private_bytes_raw()
    base = _now_ms()
    blob = caps_grants.encode_grant(
        granter_priv_seed=me_seed,
        granter_pub=d.me.public_bytes,
        subject_pub=peer_pub,
        capabilities=["files:read"],
        not_before_ms=base, not_after_ms=base + 1_000,
    )
    d._cap_store.accept(blob, expected_subject_pub=peer_pub, now_ms=base)
    # Within window: allowed.
    # We can't pass now_ms into _capability_allowed (real method uses
    # wall-clock). Instead we exercise the cap_store directly with a
    # forced now_ms past expiry.
    assert d._cap_store.has_capability(
        granter_pub=d.me.public_bytes, subject_pub=peer_pub,
        capability="files:read", now_ms=base + 500,
    )
    # Past expiry: cap_store auto-drops; falls through to policy
    # (which denies).
    assert not d._cap_store.has_capability(
        granter_pub=d.me.public_bytes, subject_pub=peer_pub,
        capability="files:read", now_ms=base + 5_000,
    )


def test_revoked_grant_no_longer_allows():
    d = _make_daemon_for_capability_test()
    _, peer_pub = _gen_ed25519()
    peer_fp = peer_pub.hex()
    d.state._peers[peer_fp] = SimpleNamespace(pubkey=peer_pub, trust="pinned")
    d.state._policies[peer_fp] = set()  # deny all
    me_seed = d.me.private.private_bytes_raw()
    blob = caps_grants.encode_grant(
        granter_priv_seed=me_seed,
        granter_pub=d.me.public_bytes,
        subject_pub=peer_pub,
        capabilities=["files:read"],
        not_before_ms=_now_ms(),
        not_after_ms=_now_ms() + 60_000,
    )
    d._cap_store.accept(blob, expected_subject_pub=peer_pub)
    assert d._capability_allowed(peer_fp, "files:read")
    # Revoke the subject.
    d._cap_store.revoke_subject(peer_pub)
    assert not d._capability_allowed(peer_fp, "files:read")


def test_grant_for_other_subject_does_not_apply():
    """A grant addressed to peer A doesn't help peer B."""
    d = _make_daemon_for_capability_test()
    _, peer_a_pub = _gen_ed25519()
    _, peer_b_pub = _gen_ed25519()
    peer_a_fp = peer_a_pub.hex()
    peer_b_fp = peer_b_pub.hex()
    d.state._peers[peer_a_fp] = SimpleNamespace(pubkey=peer_a_pub, trust="pinned")
    d.state._peers[peer_b_fp] = SimpleNamespace(pubkey=peer_b_pub, trust="pinned")
    d.state._policies[peer_a_fp] = set()  # deny all
    d.state._policies[peer_b_fp] = set()  # deny all

    me_seed = d.me.private.private_bytes_raw()
    blob = caps_grants.encode_grant(
        granter_priv_seed=me_seed,
        granter_pub=d.me.public_bytes,
        subject_pub=peer_a_pub,
        capabilities=["files:read"],
        not_before_ms=_now_ms(),
        not_after_ms=_now_ms() + 60_000,
    )
    d._cap_store.accept(blob, expected_subject_pub=peer_a_pub)
    # Peer A: allowed.
    assert d._capability_allowed(peer_a_fp, "files:read")
    # Peer B: denied (their own policy + no grant applies).
    assert not d._capability_allowed(peer_b_fp, "files:read")


def test_grant_from_other_granter_not_recognized():
    """Today's CapStore only recognizes self-issued grants (the
    daemon's own identity == granter). A grant from a third-party
    pubkey is irrelevant. (Future bundle: delegation chains.)"""
    d = _make_daemon_for_capability_test()
    _, peer_pub = _gen_ed25519()
    peer_fp = peer_pub.hex()
    d.state._peers[peer_fp] = SimpleNamespace(pubkey=peer_pub, trust="pinned")
    d.state._policies[peer_fp] = set()  # deny all

    other_seed, other_pub = _gen_ed25519()
    blob = caps_grants.encode_grant(
        granter_priv_seed=other_seed, granter_pub=other_pub,
        subject_pub=peer_pub, capabilities=["files:read"],
        not_before_ms=_now_ms(),
        not_after_ms=_now_ms() + 60_000,
    )
    # Accept the grant in the store.
    d._cap_store.accept(blob, expected_subject_pub=peer_pub)
    # _capability_allowed only consults grants from self.me — so
    # a grant issued by a different pubkey doesn't help.
    assert not d._capability_allowed(peer_fp, "files:read")


def test_unknown_peer_fp_is_not_authorized_by_missing_policy():
    """A missing policy is legacy allow-all only for pinned peers."""
    d = _make_daemon_for_capability_test()
    unknown_fp = "ff" * 32
    assert not d._capability_allowed(unknown_fp, "files:read")


def test_no_state_returns_false():
    """Defensive: when state is None (very early boot), fail closed."""
    from one_link.daemon import Daemon
    d = Daemon.__new__(Daemon)
    d.state = None
    d._cap_store = None  # type: ignore[assignment]
    assert not d._capability_allowed("ff" * 32, "files:read")
