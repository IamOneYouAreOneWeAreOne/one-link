"""v0.20.7 (audit M1) — bind responder identity into HELLO prologue
to defeat unknown-key-share (UKS) attacks.

Pre-v0.20.7 the initiator's HELLO sig covered only
``HELLO_TAG + me_pub + x_pub + nonce_i``. An attacker re-routing a
HELLO destined for paired peer B to a different paired peer C would
get C to verify the sig (it doesn't depend on C's identity), C signs
a normal REPLY, the initiator accepts it — and now thinks it's
talking to B but is actually talking to C.

v0.20.7 binds ``expected_responder_ed_pub`` into the sig. The
responder verifies using its OWN pubkey, so a redirect to a
different responder fails verification. Plus the initiator
strict-equality-checks the REPLY pubkey against the claim, so even
legacy v1 is rejected by default on both ends; an explicit migration-only
override is required to interoperate with an old peer.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from one_link import channel as ch
from one_link.wire import write_frame


def _make_identity():
    """Construct an Identity from a fresh Ed25519 keypair via the
    same path the daemon uses (Identity.generate / load_or_create
    isn't a pure constructor we can use here; build by going through
    a tmpfile-free synthesis)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    # Identity dataclass: priv + public_bytes + sign() helper.
    # The Identity in identity.py exposes .sign(data) and .public_bytes.
    return _MiniIdentity(priv, pub)


class _MiniIdentity:
    """Subset of Identity used by channel.initiate / respond — just
    .public_bytes and .sign(data). Avoids touching the on-disk PEM."""

    def __init__(self, priv, pub):
        self._priv = priv
        self.public_bytes = pub
        self.short_id = pub.hex()[:16]
        self.fingerprint = pub.hex()
        self.hostname = "test"

    def sign(self, data: bytes) -> bytes:
        return self._priv.sign(data)


async def _socketpair():
    """asyncio StreamReader/Writer pair connected over a localhost
    socket — same shape as the daemon's real channel transport."""
    server = await asyncio.start_server(
        lambda r, w: None,
        host="127.0.0.1",
        port=0,
    )
    sockname = server.sockets[0].getsockname()

    accepted_event = asyncio.Event()
    accepted = {}

    async def _accept(r, w):
        accepted["reader"] = r
        accepted["writer"] = w
        accepted_event.set()

    server.close()
    await server.wait_closed()
    server = await asyncio.start_server(
        _accept,
        host="127.0.0.1",
        port=sockname[1],
    )
    rA, wA = await asyncio.open_connection("127.0.0.1", sockname[1])
    await accepted_event.wait()
    rB, wB = accepted["reader"], accepted["writer"]
    return server, (rA, wA), (rB, wB)


@pytest.mark.asyncio
async def test_v2_handshake_round_trip_with_correct_pubkey():
    """Targeted handshake: initiator binds responder's actual pubkey;
    both sides complete the handshake."""
    alice = _make_identity()
    bob = _make_identity()
    server, (rA, wA), (rB, wB) = await _socketpair()
    try:
        results = await asyncio.gather(
            ch.initiate(
                rA,
                wA,
                alice,
                expected_responder_ed_pub=bob.public_bytes,
            ),
            ch.respond(rB, wB, bob),
        )
        chan_a, chan_b = results
        assert chan_a.peer_ed_pub == bob.public_bytes
        assert chan_b.peer_ed_pub == alice.public_bytes
    finally:
        wA.close()
        wB.close()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_v2_handshake_rejected_when_expected_pubkey_wrong():
    """If the initiator binds a pubkey OTHER than the responder's
    actual pubkey, the responder rejects the HELLO sig (it can't
    verify under its own pubkey or under the legacy v1 material)."""
    alice = _make_identity()
    bob = _make_identity()
    chuck = _make_identity()  # the wrong-target identity
    server, (rA, wA), (rB, wB) = await _socketpair()
    try:
        # Alice thinks she's talking to Chuck; the wire actually goes
        # to Bob. Bob's verification under his OWN pubkey fails (the
        # sig was made with Chuck bound), and the v1 fallback also
        # fails (Alice's sig material includes the bind, not v1 shape).
        with pytest.raises(Exception):  # either side may raise first
            await asyncio.gather(
                ch.initiate(
                    rA,
                    wA,
                    alice,
                    expected_responder_ed_pub=chuck.public_bytes,
                ),
                ch.respond(rB, wB, bob),
            )
    finally:
        wA.close()
        wB.close()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_legacy_v1_initiate_rejected_by_default(monkeypatch):
    """Unbound HELLO must fail before network I/O unless explicitly enabled."""
    alice = _make_identity()
    server, (rA, wA), (rB, wB) = await _socketpair()
    monkeypatch.delenv("ONE_LINK_ALLOW_V1_HELLO", raising=False)
    try:
        with pytest.raises(ValueError, match="legacy unbound v1 is disabled"):
            await ch.initiate(rA, wA, alice)
    finally:
        wA.close()
        wB.close()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_responder_rejects_wire_valid_legacy_v1_by_default(monkeypatch):
    """A hand-crafted, correctly signed v1 frame cannot bypass the default."""
    alice = _make_identity()
    bob = _make_identity()
    server, (rA, wA), (rB, wB) = await _socketpair()
    monkeypatch.delenv("ONE_LINK_ALLOW_V1_HELLO", raising=False)
    try:
        _, ephemeral_public = ch._x25519_keypair()
        nonce = os.urandom(ch.NONCE_LEN)
        material = ch.HELLO_TAG + alice.public_bytes + ephemeral_public + nonce
        hello = alice.public_bytes + ephemeral_public + nonce + alice.sign(material)
        await write_frame(wA, hello)
        with pytest.raises(RuntimeError, match="legacy unbound v1 is disabled"):
            await ch.respond(rB, wB, bob)
    finally:
        wA.close()
        wB.close()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_legacy_v1_migration_override_is_explicit(monkeypatch):
    """The migration-only override remains interoperable and observable."""
    alice = _make_identity()
    bob = _make_identity()
    server, (rA, wA), (rB, wB) = await _socketpair()
    monkeypatch.setenv("ONE_LINK_ALLOW_V1_HELLO", "1")
    try:
        results = await asyncio.gather(
            ch.initiate(rA, wA, alice),
            ch.respond(rB, wB, bob),
        )
        chan_a, chan_b = results
        assert chan_a.peer_ed_pub == bob.public_bytes
        assert chan_b.peer_ed_pub == alice.public_bytes
    finally:
        wA.close()
        wB.close()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_initiate_rejects_wrong_size_pubkey():
    """Calling initiate with a non-32-byte pubkey raises before any
    network I/O happens."""
    alice = _make_identity()
    with pytest.raises(ValueError, match="32 bytes"):
        await ch.initiate(
            None,
            None,
            alice,
            expected_responder_ed_pub=b"\x00" * 31,
        )
