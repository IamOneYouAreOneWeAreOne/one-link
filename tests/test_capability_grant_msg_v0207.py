"""v0.20.7 (Bundle 58) — CAPABILITY_GRANT peer message handler.

Bundle 56 wired CapStore into Daemon._capability_allowed. Bundle 58
adds the wire format: a peer ships a signed grant via the
``CAPABILITY_GRANT`` peer message; the receiver verifies the
granter == sender, the subject == self, and accepts into its local
CapStore.

These tests pin the inbound handler logic by calling
``_on_peer_message`` directly with a synthetic mock channel.
End-to-end via real daemons is in test_cap_grant_e2e_v0207.py.

Pinned:
  - Valid grant accepted, ACK ok
  - Wrong subject (not self) rejected
  - Wrong granter (not the channel peer) rejected
  - Tampered blob rejected
  - Missing grant_b64 rejected
  - Replayed grant rejected (CapStore replay defense)
  - issue_capability_grant mints + stores locally + ships
"""
from __future__ import annotations

import asyncio
import base64
import time
from types import SimpleNamespace
from typing import Optional

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import cap_store, caps_grants


def _gen_ed25519():
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes_raw()
    pub = priv.public_key().public_bytes_raw()
    return seed, pub


class _FakeChannel:
    """Mock channel that captures sent frames so the test can
    inspect ACK responses + verify the ``send`` was invoked."""
    def __init__(self, peer_ed_pub: bytes, peer_short_id: str):
        self.peer_ed_pub = peer_ed_pub
        self.peer_short_id = peer_short_id
        self.sent: list[bytes] = []

    async def send(self, frame: bytes):
        self.sent.append(frame)


def _make_daemon():
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
    d = Daemon.__new__(Daemon)
    d.me = me
    d.state = None
    d._cap_store = cap_store.CapStore()
    # _on_peer_message reads several attributes; stub them.
    d._inbound_is_rejected = lambda fp: False
    d._is_pinned = lambda fp: True
    d._stamp_pair_health = lambda fp, **kw: None
    d.record_peer_presence = lambda fp, presence: None
    return d


def _now_ms():
    return int(time.time() * 1000)


def _make_grant_blob(*, granter_seed, granter_pub, subject_pub,
                     capabilities, duration_ms=60_000):
    return caps_grants.encode_grant(
        granter_priv_seed=granter_seed,
        granter_pub=granter_pub,
        subject_pub=subject_pub,
        capabilities=capabilities,
        not_before_ms=_now_ms(),
        not_after_ms=_now_ms() + duration_ms,
    )


def _b64(blob: bytes) -> str:
    return base64.urlsafe_b64encode(blob).rstrip(b"=").decode("ascii")


def _decode_ack(frame: bytes) -> dict:
    """Parse the ACK frame the handler emitted via channel.send."""
    from one_link.wire import decode_msg
    return decode_msg(frame)


# ── valid grant flow ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_valid_grant_accepted_and_acked():
    d = _make_daemon()
    granter_seed, granter_pub = _gen_ed25519()
    blob = _make_grant_blob(
        granter_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=d.me.public_bytes,
        capabilities=["files:read"],
    )
    channel = _FakeChannel(
        peer_ed_pub=granter_pub, peer_short_id=granter_pub.hex()[:8],
    )
    msg = {"t": "CAPABILITY_GRANT", "id": "test-id-1",
           "grant_b64": _b64(blob)}
    await d._on_peer_message(channel, msg)
    assert len(d._cap_store) == 1
    assert len(channel.sent) == 1
    ack = _decode_ack(channel.sent[0])
    assert ack["t"] == "ACK"
    assert ack.get("ok") is True


@pytest.mark.asyncio
async def test_grant_for_wrong_subject_rejected():
    """A grant whose subject_pub is NOT this daemon's identity must
    be rejected. Defends against a peer trying to install an
    arbitrary grant chain in our store."""
    d = _make_daemon()
    granter_seed, granter_pub = _gen_ed25519()
    _, other_pub = _gen_ed25519()  # NOT us
    blob = _make_grant_blob(
        granter_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=other_pub,
        capabilities=["x"],
    )
    channel = _FakeChannel(
        peer_ed_pub=granter_pub, peer_short_id=granter_pub.hex()[:8],
    )
    await d._on_peer_message(
        channel,
        {"t": "CAPABILITY_GRANT", "id": "x", "grant_b64": _b64(blob)},
    )
    assert len(d._cap_store) == 0
    ack = _decode_ack(channel.sent[0])
    assert ack.get("rejected", "").startswith("grant_rejected")


@pytest.mark.asyncio
async def test_grant_with_wrong_granter_rejected():
    """The grant's GRANTER_PUB must match the channel peer (the
    sender of this message). A peer trying to forward a third
    party's grant via their channel doesn't get it accepted."""
    d = _make_daemon()
    real_granter_seed, real_granter_pub = _gen_ed25519()
    _, channel_peer_pub = _gen_ed25519()  # different from the granter
    blob = _make_grant_blob(
        granter_seed=real_granter_seed, granter_pub=real_granter_pub,
        subject_pub=d.me.public_bytes, capabilities=["x"],
    )
    channel = _FakeChannel(
        peer_ed_pub=channel_peer_pub,  # NOT the granter
        peer_short_id=channel_peer_pub.hex()[:8],
    )
    await d._on_peer_message(
        channel,
        {"t": "CAPABILITY_GRANT", "id": "x", "grant_b64": _b64(blob)},
    )
    assert len(d._cap_store) == 0
    ack = _decode_ack(channel.sent[0])
    assert "rejected" in ack


@pytest.mark.asyncio
async def test_tampered_grant_rejected():
    d = _make_daemon()
    granter_seed, granter_pub = _gen_ed25519()
    blob = bytearray(_make_grant_blob(
        granter_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=d.me.public_bytes, capabilities=["x"],
    ))
    blob[-1] ^= 0xff
    channel = _FakeChannel(
        peer_ed_pub=granter_pub, peer_short_id=granter_pub.hex()[:8],
    )
    await d._on_peer_message(
        channel,
        {"t": "CAPABILITY_GRANT", "id": "x",
         "grant_b64": _b64(bytes(blob))},
    )
    assert len(d._cap_store) == 0
    ack = _decode_ack(channel.sent[0])
    assert "rejected" in ack


@pytest.mark.asyncio
async def test_missing_grant_b64_rejected():
    d = _make_daemon()
    _, granter_pub = _gen_ed25519()
    channel = _FakeChannel(
        peer_ed_pub=granter_pub, peer_short_id=granter_pub.hex()[:8],
    )
    await d._on_peer_message(
        channel,
        {"t": "CAPABILITY_GRANT", "id": "x"},  # no grant_b64
    )
    assert len(d._cap_store) == 0
    ack = _decode_ack(channel.sent[0])
    assert "rejected" in ack


@pytest.mark.asyncio
async def test_replayed_grant_rejected():
    d = _make_daemon()
    granter_seed, granter_pub = _gen_ed25519()
    blob = _make_grant_blob(
        granter_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=d.me.public_bytes, capabilities=["x"],
    )
    channel = _FakeChannel(
        peer_ed_pub=granter_pub, peer_short_id=granter_pub.hex()[:8],
    )
    msg = {"t": "CAPABILITY_GRANT", "id": "x", "grant_b64": _b64(blob)}
    await d._on_peer_message(channel, msg)
    # First accept ok.
    assert len(d._cap_store) == 1
    # Replay same blob.
    await d._on_peer_message(channel, dict(msg, id="y"))
    # Still 1 (replay caught by CapStore).
    assert len(d._cap_store) == 1
    second_ack = _decode_ack(channel.sent[1])
    assert "rejected" in second_ack


# ── issue_capability_grant flow ──────────────────────────────────


@pytest.mark.asyncio
async def test_issue_capability_grant_stores_locally():
    """The granter side: issue_capability_grant mints a grant +
    stores it in OUR own cap_store, even if the peer is unreachable."""
    d = _make_daemon()
    # Set up a fake state so _peer_pub_for_fp returns a known pub.
    _, peer_pub = _gen_ed25519()

    class _FakeState:
        def get_peer(self, fp):
            return SimpleNamespace(pubkey=peer_pub)

    d.state = _FakeState()
    # No discovery → peer_from_fp returns None → wire send is skipped
    # but the local store should still have the grant.
    d.discovery = None
    blob = await d.issue_capability_grant(
        peer_pub.hex(),
        capabilities=["files:read"],
        duration_ms=60_000,
    )
    assert isinstance(blob, bytes) and len(blob) > 0
    assert d._cap_store.has_capability(
        granter_pub=d.me.public_bytes,
        subject_pub=peer_pub,
        capability="files:read",
    )
    # Verify the local _capability_allowed picks it up.
    assert d._capability_allowed(peer_pub.hex(), "files:read")
