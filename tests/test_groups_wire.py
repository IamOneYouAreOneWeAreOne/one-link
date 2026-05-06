"""End-to-end tests for v0.6.2 group wire protocol.

These start two daemons, pin them to each other, persist a group
event log on each, and exercise the full send → fan-out → 1-on-1
encrypted GROUP_KEY_OFFER + GROUP_MSG → decrypt → persist round-trip.
"""
from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path
from typing import AsyncIterator

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link import groups as gmod
from one_link.identity import Identity, fingerprint_of
from one_link.state import State


def _new_identity(hostname: str = "test") -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname=hostname,
    )


async def _start_minimal_peer_server(daemon: Daemon):
    server = await asyncio.start_server(
        daemon._handle_peer, host="127.0.0.1", port=0
    )
    port = server.sockets[0].getsockname()[1]
    return server, port


def _persist_events(state: State, events: list[gmod.GroupEvent]) -> None:
    for ev in events:
        state.upsert_group_event(
            group_id=ev.group_id,
            event_id=ev.event_id,
            timestamp_ms=ev.timestamp_ms,
            wire_dict=ev.to_wire(),
        )


@pytest.mark.asyncio
async def test_two_daemon_group_chat_round_trip(tmp_path: Path):
    """A and B are paired, both members of a group. A sends a chat
    message via send_group_message → fan-out → B's _handle_peer →
    GROUP_KEY_OFFER + GROUP_MSG processed → plaintext lands in B's
    state.recent_group_messages."""
    me_a = _new_identity("alice")
    me_b = _new_identity("bob")

    (tmp_path / "a").mkdir(parents=True, exist_ok=True)
    (tmp_path / "b").mkdir(parents=True, exist_ok=True)
    state_a = State(db_path=tmp_path / "a" / "state.db")
    state_b = State(db_path=tmp_path / "b" / "state.db")

    # Mutual pinning so trust gates pass.
    state_a.upsert_peer(
        fingerprint=me_b.fingerprint, short_id=me_b.short_id,
        pubkey=me_b.public_bytes,
    )
    state_a.set_peer_trust(me_b.fingerprint, "pinned")
    state_b.upsert_peer(
        fingerprint=me_a.fingerprint, short_id=me_a.short_id,
        pubkey=me_a.public_bytes,
    )
    state_b.set_peer_trust(me_a.fingerprint, "pinned")

    daemon_a = Daemon(me_a)
    daemon_a.state = state_a
    daemon_a.discovery = None

    daemon_b = Daemon(me_b)
    daemon_b.state = state_b
    daemon_b.discovery = None

    # Build a group: A is owner, A adds B as member. Persist the
    # event log on BOTH daemons so they both share the same group state.
    base = 1_700_000_000_000
    ev_create = gmod.sign_create_group(
        private_key=me_a.private, pubkey=me_a.public_bytes,
        name="Family", timestamp_ms=base,
    )
    gid = ev_create.group_id
    ev_add_b = gmod.sign_add_member(
        private_key=me_a.private, pubkey=me_a.public_bytes,
        group_id=gid, member_pubkey=me_b.public_bytes,
        timestamp_ms=base + 1,
    )
    for st in (state_a, state_b):
        for ev in (ev_create, ev_add_b):
            st.upsert_group_event(
                group_id=gid, event_id=ev.event_id,
                timestamp_ms=ev.timestamp_ms,
                wire_dict=ev.to_wire(),
            )
        st.upsert_group_meta(
            group_id=gid, name="Family",
            created_ms=base, state_hash="",
        )

    # B needs a peer-server listening so A's send_to can reach it.
    server_b, b_port = await _start_minimal_peer_server(daemon_b)

    # Make A's resolve_for_send find B at the test port.
    state_a.upsert_peer(
        fingerprint=me_b.fingerprint, short_id=me_b.short_id,
        pubkey=me_b.public_bytes, address="127.0.0.1", port=b_port,
    )
    # A also needs to know how to dial B — pre-populate a fake
    # discovery entry by putting B's address+port on the peer record.
    # resolve_for_send checks pinned + state.get_peer for off-mDNS dial.
    # The current path uses `resolve_peer_endpoint` which relies on
    # mDNS or rendezvous; for this test, just set up a Peer manually
    # via the discovery mock.
    from types import SimpleNamespace
    from one_link.discovery import Peer
    b_peer = Peer(
        short_id=me_b.short_id, hostname="bob",
        address="127.0.0.1", port=b_port,
        ed_pub_hex=me_b.public_bytes.hex(),
    )
    daemon_a.discovery = SimpleNamespace(
        registry=SimpleNamespace(list=lambda: [b_peer], find=lambda _x: b_peer),
    )

    try:
        # A sends a group message. This triggers:
        #   1. Build outbound chain at epoch=1 (first send)
        #   2. GROUP_KEY_OFFER to every member except A → B receives,
        #      stores incoming chain at epoch=1
        #   3. Encrypt body, fan-out GROUP_MSG to every member
        #   4. B's _handle_group_msg decrypts, persists to group_messages
        result = await asyncio.wait_for(
            daemon_a.send_group_message(group_id=gid, body="hello group"),
            timeout=15.0,
        )
        assert result["recipients"] == 1
        assert result["delivered"] == 1
        assert result["failures"] == []

        # Give B's persistence a moment.
        await asyncio.sleep(0.1)

        # B's group inbox has the message.
        msgs = state_b.recent_group_messages(group_id=gid)
        bodies = [m["body"] for m in msgs]
        assert "hello group" in bodies, f"not received: {msgs!r}"
        # Sender pubkey is A's.
        assert msgs[0]["sender_pub"] == me_a.public_bytes
        assert msgs[0]["direction"] == "in"
        assert msgs[0]["epoch"] == 1
        assert msgs[0]["counter"] == 0

        # A also has a record in their own outbound history.
        a_msgs = state_a.recent_group_messages(group_id=gid)
        a_bodies = [m["body"] for m in a_msgs]
        assert "hello group" in a_bodies
        assert a_msgs[0]["direction"] == "out"

        # Send a second message. Chain advances to counter=1.
        result2 = await daemon_a.send_group_message(group_id=gid, body="second")
        assert result2["delivered"] == 1
        await asyncio.sleep(0.1)
        msgs2 = state_b.recent_group_messages(group_id=gid)
        # Most-recent first.
        assert msgs2[0]["body"] == "second"
        assert msgs2[0]["counter"] == 1
    finally:
        for fp in list(daemon_a._outbound_sessions):  # type: ignore[attr-defined]
            await daemon_a._drop_outbound_session(fp)
        for fp in list(daemon_b._outbound_sessions):  # type: ignore[attr-defined]
            await daemon_b._drop_outbound_session(fp)
        server_b.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(server_b.wait_closed(), timeout=2.0)
        state_a.close()
        state_b.close()


@pytest.mark.asyncio
async def test_send_group_message_rejects_non_member(tmp_path: Path):
    """If we're not actually in the group, send_group_message refuses."""
    me_a = _new_identity("alice")
    me_b = _new_identity("bob")
    (tmp_path / "a").mkdir(parents=True, exist_ok=True)
    state_a = State(db_path=tmp_path / "a" / "state.db")
    daemon_a = Daemon(me_a)
    daemon_a.state = state_a
    daemon_a.discovery = None

    # Create a group where B is owner; A is not a member.
    ev_create = gmod.sign_create_group(
        private_key=me_b.private, pubkey=me_b.public_bytes,
        name="B-only",
    )
    state_a.upsert_group_event(
        group_id=ev_create.group_id,
        event_id=ev_create.event_id,
        timestamp_ms=ev_create.timestamp_ms,
        wire_dict=ev_create.to_wire(),
    )
    try:
        with pytest.raises(RuntimeError, match="not a member"):
            await daemon_a.send_group_message(
                group_id=ev_create.group_id, body="forbidden",
            )
    finally:
        state_a.close()


@pytest.mark.asyncio
async def test_send_group_message_rejects_unknown_group(tmp_path: Path):
    me_a = _new_identity("alice")
    state_a = State(db_path=tmp_path / "state.db")
    daemon_a = Daemon(me_a)
    daemon_a.state = state_a
    daemon_a.discovery = None
    try:
        with pytest.raises(RuntimeError, match="unknown group"):
            await daemon_a.send_group_message(
                group_id=b"\x00" * 16, body="x",
            )
    finally:
        state_a.close()


@pytest.mark.asyncio
async def test_group_msg_without_chain_is_rejected_with_clear_reason(tmp_path: Path):
    """If A sends a GROUP_MSG to B but B has no incoming chain for
    that (sender, epoch) — e.g., the GROUP_KEY_OFFER got lost — the
    decrypt-side rejects with `no_chain_for_epoch`. The receiver
    state.recent_group_messages stays empty."""
    me_a = _new_identity("alice")
    me_b = _new_identity("bob")
    (tmp_path / "a").mkdir(parents=True, exist_ok=True)
    state_b = State(db_path=tmp_path / "a" / "state.db")
    daemon_b = Daemon(me_b)
    daemon_b.state = state_b
    daemon_b.discovery = None

    state_b.upsert_peer(
        fingerprint=me_a.fingerprint, short_id=me_a.short_id,
        pubkey=me_a.public_bytes,
    )
    state_b.set_peer_trust(me_a.fingerprint, "pinned")

    # Synthesize an incoming GROUP_MSG for a real group where A is a
    # member, but with NO key shared first.
    from one_link import groups_crypto as gc
    ev_create = gmod.sign_create_group(
        private_key=me_b.private,
        pubkey=me_b.public_bytes,
        name="Missing Chain",
        timestamp_ms=1_700_000_000_000,
    )
    gid = ev_create.group_id
    ev_add_a = gmod.sign_add_member(
        private_key=me_b.private,
        pubkey=me_b.public_bytes,
        group_id=gid,
        member_pubkey=me_a.public_bytes,
        timestamp_ms=1_700_000_000_001,
    )
    _persist_events(state_b, [ev_create, ev_add_a])
    sender_chain = gc.SenderChain(
        group_id=gid,
        sender_pubkey=me_a.public_bytes,
        epoch=1,
        chain_key=b"\x33" * 32,
    )
    wire, _ = gc.encrypt_message(
        plaintext=b"sneak", chain=sender_chain, private_key=me_a.private,
    )

    # Build the outer wrapper.
    from one_link.wire import make_msg
    outer = make_msg(
        "GROUP_MSG", me_a.short_id,
        group_id_b64=gc._b64(gid),
        wire=wire,
    )

    # Synthesize a channel with peer_ed_pub set to A's pubkey.
    from types import SimpleNamespace
    sent_back = []
    class _FakeChannel:
        peer_ed_pub = me_a.public_bytes
        peer_short_id = me_a.short_id

        async def send(self, raw):
            from one_link.wire import decode_msg
            sent_back.append(decode_msg(raw))

    fake_ch = _FakeChannel()
    try:
        await daemon_b._handle_group_msg(
            fake_ch, outer, peer_fp=me_a.fingerprint, peer_sid=me_a.short_id,
        )
        # Reply must be ACK with rejected="no_chain_for_epoch".
        assert sent_back, "no reply sent"
        ack = sent_back[0]
        assert ack["t"] == "ACK"
        assert ack.get("rejected") == "no_chain_for_epoch"
        # Group message store untouched.
        assert state_b.recent_group_messages(group_id=gid) == []
    finally:
        state_b.close()


@pytest.mark.asyncio
async def test_group_key_offer_from_unpinned_peer_dropped(tmp_path: Path):
    """A non-pinned peer can't slip a GROUP_KEY_OFFER into our chain
    table. The handler returns silently and no chain is persisted."""
    me_self = _new_identity()
    me_evil = _new_identity()
    (tmp_path / "x").mkdir(parents=True, exist_ok=True)
    state = State(db_path=tmp_path / "x" / "state.db")
    daemon = Daemon(me_self)
    daemon.state = state
    daemon.discovery = None

    # Note: NOT pinning evil.
    state.upsert_peer(
        fingerprint=me_evil.fingerprint, short_id=me_evil.short_id,
        pubkey=me_evil.public_bytes,
    )

    from one_link import groups_crypto as gc
    gid = b"\xab" * 16
    from one_link.wire import make_msg
    offer = make_msg(
        "GROUP_KEY_OFFER", me_evil.short_id,
        group_id_b64=gc._b64(gid),
        epoch=1,
        chain_key_b64=gc._b64(b"\xff" * 32),
    )

    class _FakeChannel:
        peer_ed_pub = me_evil.public_bytes
        peer_short_id = me_evil.short_id

        async def send(self, raw):
            pass

    try:
        await daemon._handle_group_key_offer(
            _FakeChannel(), offer, peer_fp=me_evil.fingerprint,
        )
        # Nothing persisted.
        chain = state.get_sender_chain(
            group_id=gid, sender_pub=me_evil.public_bytes, direction="in",
        )
        assert chain is None
    finally:
        state.close()


@pytest.mark.asyncio
async def test_group_key_offer_from_pinned_non_member_rejected(tmp_path: Path):
    """A pinned device still cannot inject sender-chain material for
    a group unless the signed group log says it is a current member."""
    me_self = _new_identity("owner")
    me_evil = _new_identity("intruder")
    (tmp_path / "x").mkdir(parents=True, exist_ok=True)
    state = State(db_path=tmp_path / "x" / "state.db")
    daemon = Daemon(me_self)
    daemon.state = state
    daemon.discovery = None

    state.upsert_peer(
        fingerprint=me_evil.fingerprint,
        short_id=me_evil.short_id,
        pubkey=me_evil.public_bytes,
    )
    state.set_peer_trust(me_evil.fingerprint, "pinned")

    ev_create = gmod.sign_create_group(
        private_key=me_self.private,
        pubkey=me_self.public_bytes,
        name="Private",
        timestamp_ms=1_700_000_000_000,
    )
    gid = ev_create.group_id
    _persist_events(state, [ev_create])

    from one_link import groups_crypto as gc
    from one_link.wire import make_msg, decode_msg
    offer = make_msg(
        "GROUP_KEY_OFFER", me_evil.short_id,
        group_id_b64=gc._b64(gid),
        epoch=1,
        chain_key_b64=gc._b64(b"\xfe" * 32),
    )

    sent_back = []

    class _FakeChannel:
        peer_ed_pub = me_evil.public_bytes
        peer_short_id = me_evil.short_id

        async def send(self, raw):
            sent_back.append(decode_msg(raw))

    try:
        await daemon._handle_group_key_offer(
            _FakeChannel(), offer, peer_fp=me_evil.fingerprint,
        )
        assert sent_back
        assert sent_back[0]["t"] == "ACK"
        assert sent_back[0].get("rejected") == "group_not_member"
        chain = state.get_sender_chain(
            group_id=gid, sender_pub=me_evil.public_bytes, direction="in",
        )
        assert chain is None
    finally:
        state.close()


@pytest.mark.asyncio
async def test_group_msg_from_pinned_non_member_rejected_even_with_chain(tmp_path: Path):
    """Membership is checked at message time too, so a stale or injected
    sender chain cannot keep a removed/non-member sender alive."""
    me_self = _new_identity("owner")
    me_evil = _new_identity("intruder")
    (tmp_path / "x").mkdir(parents=True, exist_ok=True)
    state = State(db_path=tmp_path / "x" / "state.db")
    daemon = Daemon(me_self)
    daemon.state = state
    daemon.discovery = None

    state.upsert_peer(
        fingerprint=me_evil.fingerprint,
        short_id=me_evil.short_id,
        pubkey=me_evil.public_bytes,
    )
    state.set_peer_trust(me_evil.fingerprint, "pinned")

    ev_create = gmod.sign_create_group(
        private_key=me_self.private,
        pubkey=me_self.public_bytes,
        name="Private",
        timestamp_ms=1_700_000_000_000,
    )
    gid = ev_create.group_id
    _persist_events(state, [ev_create])

    from one_link import groups_crypto as gc
    state.upsert_sender_chain(
        group_id=gid,
        sender_pub=me_evil.public_bytes,
        direction="in",
        epoch=1,
        chain_key=b"\x44" * 32,
        counter=0,
    )
    sender_chain = gc.SenderChain(
        group_id=gid,
        sender_pubkey=me_evil.public_bytes,
        epoch=1,
        chain_key=b"\x44" * 32,
    )
    wire, _ = gc.encrypt_message(
        plaintext=b"should not land",
        chain=sender_chain,
        private_key=me_evil.private,
    )

    from one_link.wire import make_msg, decode_msg
    outer = make_msg(
        "GROUP_MSG", me_evil.short_id,
        group_id_b64=gc._b64(gid),
        wire=wire,
    )
    sent_back = []

    class _FakeChannel:
        peer_ed_pub = me_evil.public_bytes
        peer_short_id = me_evil.short_id

        async def send(self, raw):
            sent_back.append(decode_msg(raw))

    try:
        await daemon._handle_group_msg(
            _FakeChannel(), outer,
            peer_fp=me_evil.fingerprint,
            peer_sid=me_evil.short_id,
        )
        assert sent_back
        assert sent_back[0]["t"] == "ACK"
        assert sent_back[0].get("rejected") == "group_not_member"
        assert state.recent_group_messages(group_id=gid) == []
        chain = state.get_sender_chain(
            group_id=gid,
            sender_pub=me_evil.public_bytes,
            direction="in",
            epoch=1,
        )
        assert chain is not None
        assert int(chain["counter"]) == 0
    finally:
        state.close()
