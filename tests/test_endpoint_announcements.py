from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.rendezvous_proto import Endpoint
from one_link.state import State


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key()
    pub_bytes = pub.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk,
        public=pub,
        public_bytes=pub_bytes,
        fingerprint=fp,
        short_id=fp[:8],
        hostname="endpoint-test",
    )


@pytest.mark.asyncio
async def test_endpoint_change_announcer_broadcasts_only_on_signature_change(monkeypatch):
    daemon = Daemon(_identity())
    daemon._rendezvous_peer_port = 7777
    endpoint_sets = [
        [Endpoint(host="10.0.0.2", port=7777)],
        [Endpoint(host="10.0.0.2", port=7777)],
        [Endpoint(host="10.0.0.9", port=7777)],
    ]
    calls = 0

    def discover_local_endpoints(*, peer_port):
        assert peer_port == 7777
        return endpoint_sets.pop(0)

    async def broadcast_endpoint_to_paired():
        nonlocal calls
        calls += 1
        return 3

    monkeypatch.setattr(
        "one_link.rendezvous_client.discover_local_endpoints",
        discover_local_endpoints,
    )
    daemon.broadcast_endpoint_to_paired = broadcast_endpoint_to_paired  # type: ignore[method-assign]

    first = await daemon.broadcast_endpoint_to_paired_if_changed()
    second = await daemon.broadcast_endpoint_to_paired_if_changed()
    third = await daemon.broadcast_endpoint_to_paired_if_changed()

    assert first["changed"] is True
    assert second["changed"] is False
    assert second["reason"] == "unchanged"
    assert third["changed"] is True
    assert third["previous"] == ["10.0.0.2:7777"]
    assert third["current"] == ["10.0.0.9:7777"]
    assert calls == 2


def test_endpoint_signature_is_empty_without_peer_port():
    daemon = Daemon(_identity())
    daemon._rendezvous_peer_port = 0

    assert daemon._local_endpoint_announcement_signature() == ()


@pytest.mark.asyncio
async def test_group_event_fanout_queues_for_offline_pinned_member(tmp_path):
    me = _identity()
    peer = _identity()
    state = State(db_path=tmp_path / "state.db")
    try:
        state.upsert_peer(
            fingerprint=peer.fingerprint,
            short_id=peer.short_id,
            pubkey=peer.public_bytes,
            hostname="offline-member",
        )
        state.set_peer_trust(peer.fingerprint, "pinned")
        daemon = Daemon(me)
        daemon.state = state

        async def resolve_for_send(_peer_fp):
            return None

        daemon.resolve_for_send = resolve_for_send  # type: ignore[method-assign]

        result = await daemon._broadcast_group_event(
            b"group-id-12345678",
            {"event_id": "event-1", "kind": "ADD_MEMBER"},
            [peer.public_bytes],
        )

        pending = state.list_outbox(peer_fp=peer.fingerprint, pending_only=True)
        assert result["delivered"] == 0
        assert result["queued"] == 1
        assert len(pending) == 1
        assert pending[0].msg_kind == "GROUP_EVENT"
        assert pending[0].msg_body["t"] == "GROUP_EVENT"
        assert pending[0].msg_body["event"]["event_id"] == "event-1"
    finally:
        state.close()


@pytest.mark.asyncio
async def test_group_event_fanout_queues_after_send_failure(tmp_path):
    me = _identity()
    peer = _identity()
    state = State(db_path=tmp_path / "state.db")
    try:
        state.upsert_peer(
            fingerprint=peer.fingerprint,
            short_id=peer.short_id,
            pubkey=peer.public_bytes,
            hostname="flaky-member",
        )
        state.set_peer_trust(peer.fingerprint, "pinned")
        daemon = Daemon(me)
        daemon.state = state

        async def resolve_for_send(_peer_fp):
            return object()

        async def send_to(_peer_obj, _msgs):
            raise OSError("network moved")

        daemon.resolve_for_send = resolve_for_send  # type: ignore[method-assign]
        daemon.send_to = send_to  # type: ignore[method-assign]

        result = await daemon._broadcast_group_event(
            b"group-id-12345678",
            {"event_id": "event-2", "kind": "CHANGE_ROLE"},
            [peer.public_bytes],
        )

        pending = state.list_outbox(peer_fp=peer.fingerprint, pending_only=True)
        assert result["queued"] == 1
        assert len(pending) == 1
        assert pending[0].msg_id == "group-event:event-2"
        assert "network moved" in result["failures"][0]
    finally:
        state.close()
