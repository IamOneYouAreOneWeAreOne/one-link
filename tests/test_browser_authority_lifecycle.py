"""Browser-owner authorization and channel-bound identity proof regressions.

These tests pin the lifecycle that matters for a phone browser: authority is a
live, root-certified self-mesh row; every reconnect proves the enrolled private
key on the current DataChannel; and revoke/freeze/delete cannot leave a cached
owner credential or a usable in-flight request behind.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import one_link.peer_rtc as peer_rtc_module
from one_link.identity import Identity, fingerprint_of
from one_link.peer_rtc import (
    BROWSER_IDENTITY_CHALLENGE_TTL_MS,
    BROWSER_IDENTITY_POSSESSION_SCHEMA,
    PEER_DC_PROTOCOL_VERSION,
    BrowserPeer,
    BrowserPeerManager,
    _b64u,
    _identity_possession_signing_bytes,
    _now_ms,
)
from one_link.self_mesh_enrollment import MeshRoot, mint_device_cert
from one_link.state import State


class _DataChannel:
    def __init__(self) -> None:
        self.readyState = "open"
        self.sent: list[str] = []
        self.closed = False

    def send(self, data: str) -> None:
        if self.readyState != "open":
            raise RuntimeError("channel is not open")
        self.sent.append(data)

    def close(self) -> None:
        self.closed = True
        self.readyState = "closed"


def _identity(hostname: str = "authority-daemon") -> Identity:
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    public_bytes = public.public_bytes_raw()
    fingerprint = fingerprint_of(public_bytes)
    return Identity(
        private=private,
        public=public,
        public_bytes=public_bytes,
        fingerprint=fingerprint,
        short_id=fingerprint[:8],
        hostname=hostname,
    )


@pytest.fixture
def authority(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "authority.db")
    root = MeshRoot.create()
    state.upsert_self_mesh_root(
        root_pub=root.root_pub,
        root_seed=root.root_seed,
        label="Authority test root",
    )
    device_private = Ed25519PrivateKey.generate()
    device_pub = device_private.public_key().public_bytes_raw()
    device_kind = "phone-browser"
    cert = mint_device_cert(
        root_seed=root.root_seed,
        root_pub=root.root_pub,
        device_pub=device_pub,
        device_kind=device_kind,
    )
    row = state.upsert_self_mesh_device(
        root_pub=root.root_pub,
        device_pub=device_pub,
        cert=cert,
        device_kind=device_kind,
        label="Authorized browser",
        trusted=True,
        local=False,
    )
    daemon = SimpleNamespace(
        state=state,
        me=_identity(),
        require_browser_identity_possession=False,
        require_attested_peers=False,
        _gate_drop_count=0,
        _telemetry_lock=threading.Lock(),
    )
    manager = BrowserPeerManager(daemon)
    context = SimpleNamespace(
        state=state,
        root=root,
        device_private=device_private,
        device_pub=device_pub,
        device_kind=device_kind,
        cert=cert,
        row=row,
        daemon=daemon,
        manager=manager,
    )
    try:
        yield context
    finally:
        state.close()


def _fingerprint(device_pub: bytes) -> str:
    return "sha256:" + hashlib.sha256(device_pub).hexdigest()


def _peer(authority: Any) -> BrowserPeer:
    row = authority.state.get_self_mesh_device(
        root_pub=authority.root.root_pub,
        device_pub=authority.device_pub,
    )
    assert row is not None
    return BrowserPeer(
        fingerprint=_fingerprint(authority.device_pub),
        pubkey_bytes=authority.device_pub,
        control_dc=_DataChannel(),
        bulk_dc=_DataChannel(),
        authorized_root_pub=authority.root.root_pub,
        authorized_device_pub=authority.device_pub,
        authorized_guardian_epoch=int(row.get("guardian_epoch") or 0),
    )


def _challenge(authority: Any, peer: BrowserPeer) -> dict[str, Any]:
    assert authority.manager.init_identity_possession(peer) is True
    wire = json.loads(peer.control_dc.sent[-1])
    assert wire == peer.identity_challenge
    return wire


def _response(
    authority: Any,
    peer: BrowserPeer,
    challenge: dict[str, Any],
    *,
    signer: Ed25519PrivateKey | None = None,
) -> dict[str, Any]:
    signing_key = signer or authority.device_private
    return {
        "v": PEER_DC_PROTOCOL_VERSION,
        "t": "identity_possession_response",
        "schema": BROWSER_IDENTITY_POSSESSION_SCHEMA,
        "challenge_id": challenge["challenge_id"],
        "session_id": challenge["session_id"],
        "peer_fingerprint": peer.fingerprint,
        "signature": _b64u(
            signing_key.sign(_identity_possession_signing_bytes(challenge))
        ),
    }


def test_pairing_handoff_requires_one_live_root_certified_roster_row(authority):
    pairing = authority.manager.mint_pairing_token(
        device_pub=authority.device_pub,
        fp_hint=_fingerprint(authority.device_pub),
    )
    assert pairing.root_pub == authority.root.root_pub
    assert pairing.device_pub == authority.device_pub
    assert pairing.fp_hint == _fingerprint(authority.device_pub)

    unknown_pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    with pytest.raises(PermissionError, match="not currently authorized"):
        authority.manager.mint_pairing_token(device_pub=unknown_pub)
    with pytest.raises(TypeError):
        authority.manager.mint_pairing_token()  # type: ignore[call-arg]


def test_corrupt_or_ambiguous_certified_roster_fails_closed(authority):
    authority.state.upsert_self_mesh_device(
        root_pub=authority.root.root_pub,
        device_pub=authority.device_pub,
        cert=b"not-a-root-certificate",
        device_kind=authority.device_kind,
        trusted=True,
    )
    assert authority.manager.authorization_for_pubkey(authority.device_pub) is None

    # Restore the valid first row and enroll the same key under a second live
    # root. Database ordering must never silently select the owning principal.
    authority.state.upsert_self_mesh_device(
        root_pub=authority.root.root_pub,
        device_pub=authority.device_pub,
        cert=authority.cert,
        device_kind=authority.device_kind,
        trusted=True,
    )
    other_root = MeshRoot.create()
    authority.state.upsert_self_mesh_root(root_pub=other_root.root_pub)
    other_cert = mint_device_cert(
        root_seed=other_root.root_seed,
        root_pub=other_root.root_pub,
        device_pub=authority.device_pub,
        device_kind=authority.device_kind,
    )
    authority.state.upsert_self_mesh_device(
        root_pub=other_root.root_pub,
        device_pub=authority.device_pub,
        cert=other_cert,
        device_kind=authority.device_kind,
        trusted=True,
    )
    assert authority.manager.authorization_for_pubkey(authority.device_pub) is None


def test_revoke_invalidates_unredeemed_device_bound_handoff(authority):
    pairing = authority.manager.mint_pairing_token(device_pub=authority.device_pub)
    authority.state.revoke_self_mesh_device(
        root_pub=authority.root.root_pub,
        device_pub=authority.device_pub,
    )
    assert authority.manager.redeem_pairing_token(
        pairing.token,
        fingerprint=_fingerprint(authority.device_pub),
    ) is None
    assert pairing.token not in authority.manager._pending_pairings


@pytest.mark.asyncio
async def test_revoke_closes_channels_and_cancels_yielded_dispatch(authority):
    peer = _peer(authority)
    authority.manager.register_peer(peer)
    in_flight = asyncio.create_task(asyncio.sleep(60))
    peer._dispatch_tasks.add(in_flight)

    authority.state.revoke_self_mesh_device(
        root_pub=authority.root.root_pub,
        device_pub=authority.device_pub,
    )
    result = authority.manager.revoke_device(
        root_pub=authority.root.root_pub,
        device_pub=authority.device_pub,
    )
    await asyncio.sleep(0)

    assert result == {"pending_tokens": 0, "active_peers": 1}
    assert peer.closed is True
    assert peer.control_dc.closed is True
    assert peer.bulk_dc.closed is True
    assert in_flight.cancelled() is True
    assert authority.manager.get_peer(peer.fingerprint) is None


@pytest.mark.asyncio
async def test_dispatch_rechecks_roster_even_without_explicit_evict(authority):
    peer = _peer(authority)
    authority.manager.register_peer(peer)
    delivered: list[str] = []

    async def listener(*_args: Any) -> None:
        delivered.append("delivered")

    authority.manager.add_dc_listener(listener)
    authority.state.revoke_self_mesh_device(
        root_pub=authority.root.root_pub,
        device_pub=authority.device_pub,
    )
    await authority.manager._dispatch_dc(
        peer,
        "control",
        json.dumps({"v": PEER_DC_PROTOCOL_VERSION, "t": "fetch_peers"}),
    )
    assert delivered == []
    assert peer.closed is True


def test_outbound_send_rechecks_roster_even_without_explicit_evict(authority):
    peer = _peer(authority)
    authority.manager.register_peer(peer)
    authority.state.revoke_self_mesh_device(
        root_pub=authority.root.root_pub,
        device_pub=authority.device_pub,
    )

    queued = authority.manager.send_dc(
        peer,
        "control",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "owner_notification"},
    )

    assert queued is False
    assert peer.control_dc.sent == []
    assert peer.control_dc.closed is True
    assert peer.bulk_dc.closed is True
    assert peer.closed is True


def test_staged_connection_teardown_cannot_evict_current_peer(authority):
    current = _peer(authority)
    authority.manager.register_peer(current)
    staged = _peer(authority)

    authority.manager._close_peer(staged)

    assert authority.manager.get_peer(current.fingerprint) is current
    assert current.closed is False
    assert staged.closed is True
    with pytest.raises(PermissionError, match="closed browser peer"):
        authority.manager.register_peer(staged)


@pytest.mark.asyncio
async def test_required_gate_accepts_fresh_channel_bound_identity_proof(authority):
    authority.daemon.require_browser_identity_possession = True
    peer = _peer(authority)
    authority.manager.register_peer(peer)
    delivered: list[str] = []

    async def listener(
        _peer_value: BrowserPeer,
        _kind: str,
        msg_t: str,
        _envelope: dict[str, Any],
    ) -> None:
        delivered.append(msg_t)

    authority.manager.add_dc_listener(listener)
    challenge = _challenge(authority, peer)
    timeout_handle = peer.identity_timeout_handle
    assert timeout_handle is not None
    assert set(challenge) == {
        "v", "t", "schema", "challenge_id", "nonce", "session_id",
        "peer_fingerprint", "daemon_fingerprint", "issued_ms", "expires_ms",
    }
    assert challenge["expires_ms"] - challenge["issued_ms"] == (
        BROWSER_IDENTITY_CHALLENGE_TTL_MS
    )

    await authority.manager._dispatch_dc(
        peer,
        "control",
        json.dumps({"v": PEER_DC_PROTOCOL_VERSION, "t": "fetch_peers"}),
    )
    assert delivered == []
    assert authority.daemon._gate_drop_count == 1

    await authority.manager._dispatch_dc(
        peer,
        "control",
        json.dumps(_response(authority, peer, challenge)),
    )
    assert peer.closed is False
    assert peer.identity_verified_ms is not None
    assert peer.identity_verified_dc_id == id(peer.control_dc)
    assert timeout_handle.cancelled() is True
    assert peer.identity_timeout_handle is None
    acknowledgement = json.loads(peer.control_dc.sent[-1])
    assert set(acknowledgement) == {
        "v", "t", "schema", "challenge_id", "session_id", "verified_ms",
    }
    assert acknowledgement["t"] == "identity_possession_verified"

    await authority.manager._dispatch_dc(
        peer,
        "control",
        json.dumps({"v": PEER_DC_PROTOCOL_VERSION, "t": "fetch_peers"}),
    )
    assert delivered == ["fetch_peers"]


@pytest.mark.asyncio
async def test_required_silent_peer_is_evicted_when_challenge_expires(
    authority,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        peer_rtc_module,
        "BROWSER_IDENTITY_CHALLENGE_TTL_MS",
        5,
    )
    authority.daemon.require_browser_identity_possession = True
    peer = _peer(authority)
    authority.manager.register_peer(peer)
    _challenge(authority, peer)
    timeout_handle = peer.identity_timeout_handle
    assert timeout_handle is not None
    await asyncio.sleep(0.05)

    assert peer.closed is True
    assert peer.identity_challenge is None
    assert authority.manager.get_peer(peer.fingerprint) is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "attack",
    ["wrong_signer", "wrong_nonce_signature", "extra_field", "wrong_session"],
)
async def test_identity_proof_adversarial_mutations_close_peer(authority, attack):
    peer = _peer(authority)
    authority.manager.register_peer(peer)
    challenge = _challenge(authority, peer)
    signer = Ed25519PrivateKey.generate() if attack == "wrong_signer" else None
    signed_challenge = challenge
    if attack == "wrong_nonce_signature":
        signed_challenge = dict(challenge)
        signed_challenge["nonce"] = _b64u(b"n" * 32)
    response = _response(authority, peer, signed_challenge, signer=signer)
    if attack == "extra_field":
        response["ignored"] = "parser-confusion"
    elif attack == "wrong_session":
        response["session_id"] = _b64u(b"s" * 16)

    await authority.manager._dispatch_dc(
        peer,
        "control",
        json.dumps(response),
    )
    assert peer.closed is True
    assert peer.identity_verified_ms is None


@pytest.mark.asyncio
async def test_expired_identity_challenge_closes_peer(authority):
    peer = _peer(authority)
    authority.manager.register_peer(peer)
    challenge = _challenge(authority, peer)
    challenge["expires_ms"] = _now_ms() - 1
    challenge["issued_ms"] = (
        challenge["expires_ms"] - BROWSER_IDENTITY_CHALLENGE_TTL_MS
    )
    peer.identity_challenge = challenge

    await authority.manager._dispatch_dc(
        peer,
        "control",
        json.dumps(_response(authority, peer, challenge)),
    )
    assert peer.closed is True


@pytest.mark.asyncio
async def test_identity_challenge_is_bound_to_exact_control_channel(authority):
    peer = _peer(authority)
    authority.manager.register_peer(peer)
    challenge = _challenge(authority, peer)
    original_channel = peer.control_dc
    peer.control_dc = _DataChannel()

    await authority.manager._dispatch_dc(
        peer,
        "control",
        json.dumps(_response(authority, peer, challenge)),
    )
    assert peer.closed is True
    assert original_channel.closed is False
    assert peer.control_dc.closed is True


@pytest.mark.asyncio
async def test_consumed_challenge_cannot_cross_session_replay(authority):
    first = _peer(authority)
    authority.manager.register_peer(first)
    challenge = _challenge(authority, first)
    response = _response(authority, first, challenge)
    await authority.manager._dispatch_dc(first, "control", json.dumps(response))
    assert first.identity_verified_ms is not None

    second = _peer(authority)
    second.identity_session_id = challenge["session_id"]
    second.identity_challenge = dict(challenge)
    second.identity_challenge_dc_id = id(second.control_dc)
    authority.manager.register_peer(second)
    await authority.manager._dispatch_dc(second, "control", json.dumps(response))
    assert second.closed is True
    assert second.identity_verified_ms is None


def test_peer_registry_rejects_fingerprint_alias(authority):
    peer = _peer(authority)
    peer.fingerprint = "sha256:" + "0" * 64
    with pytest.raises(PermissionError, match="not currently authorized"):
        authority.manager.register_peer(peer)
