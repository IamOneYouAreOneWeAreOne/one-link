from __future__ import annotations

import base64
import asyncio
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.capabilities import SELF_MESH_SEND
from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.identity_dag import encode_device_cert
from one_link.personal_device_mesh import sign_remote_instruction
from one_link.state import State
from one_link.wire import decode_msg


def _identity(hostname: str) -> Identity:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    fp = fingerprint_of(pub)
    return Identity(
        private=priv,
        public=priv.public_key(),
        public_bytes=pub,
        fingerprint=fp,
        short_id=fp[:8],
        hostname=hostname,
    )


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class _LiveChannel:
    def __init__(self, peer: Identity):
        self.peer_ed_pub = peer.public_bytes
        self.peer_short_id = peer.short_id
        self.sent: list[bytes] = []

    async def send(self, frame: bytes) -> None:
        self.sent.append(frame)


def _daemon(me: Identity, db: Path) -> Daemon:
    d = Daemon.__new__(Daemon)
    d.me = me
    d.state = State(db_path=db)
    d.state.set_setting("self_mesh_allowed_roots", str(db.parent))
    d.ui_server = SimpleNamespace(broadcast=lambda evt: None)
    d._inbound_is_rejected = lambda fp: False
    d._stamp_pair_health = lambda fp, **kw: None
    d._is_pinned = lambda fp: True
    d._emit_capability_request = lambda fp, sid, cap: None
    d._peer_presence = {}
    return d


@pytest.mark.asyncio
async def test_two_enrolled_daemons_remote_send_file_e2e(tmp_path: Path):
    phone = _identity("phone")
    laptop = _identity("laptop")
    friend = _identity("friend")
    phone_daemon = _daemon(phone, tmp_path / "phone.db")
    laptop_daemon = _daemon(laptop, tmp_path / "laptop.db")
    root_priv = Ed25519PrivateKey.generate()
    root_seed = root_priv.private_bytes_raw()
    root_pub = root_priv.public_key().public_bytes_raw()
    phone_cert = encode_device_cert(
        root_priv_seed=root_seed,
        root_pub=root_pub,
        device_pub=phone.public_bytes,
        device_kind="phone",
    )
    laptop_cert = encode_device_cert(
        root_priv_seed=root_seed,
        root_pub=root_pub,
        device_pub=laptop.public_bytes,
        device_kind="laptop",
    )
    for d, me, cert, kind in (
        (phone_daemon, phone, phone_cert, "phone"),
        (laptop_daemon, laptop, laptop_cert, "laptop"),
    ):
        d.state.upsert_self_mesh_root(
            root_pub=root_pub,
            root_seed=root_seed if d is phone_daemon else None,
            label="My devices",
        )
        d.state.upsert_self_mesh_device(
            root_pub=root_pub,
            device_pub=me.public_bytes,
            cert=cert,
            device_kind=kind,
            label=kind.title(),
            local=True,
            trusted=True,
        )

    laptop_daemon.state.upsert_peer(
        fingerprint=phone.fingerprint,
        short_id=phone.short_id,
        pubkey=phone.public_bytes,
        hostname="phone",
    )
    laptop_daemon.state.set_peer_trust(phone.fingerprint, "pinned")
    laptop_daemon.state.set_peer_capability_policy(
        phone.fingerprint,
        [SELF_MESH_SEND],
    )
    payload = tmp_path / "clip.mov"
    payload.write_bytes(b"movie")
    sent = []

    async def resolve_friend(needle: str):
        assert needle == friend.fingerprint
        return SimpleNamespace(short_id=friend.short_id, ed_pub_hex=friend.public_bytes.hex())

    async def fake_send_file(peer, path, *, transfer_id=None):
        sent.append((peer.short_id, Path(path).name))
        return {"ok": True}

    laptop_daemon.resolve_for_send = resolve_friend
    laptop_daemon.send_file = fake_send_file
    command = sign_remote_instruction(
        controller_device_seed=phone.private.private_bytes_raw(),
        controller_cert=phone_cert,
        target_device_pub=laptop.public_bytes,
        action="send_file_from_device",
        scope={
            "path": str(payload),
            "recipient_fp": friend.fingerprint,
            "max_bytes": 1024,
        },
        created_ms=int(time.time() * 1000),
        expires_ms=int(time.time() * 1000) + 60_000,
    )
    channel = _LiveChannel(phone)

    await laptop_daemon._on_peer_message(channel, {
        "t": "SELF_MESH_REMOTE_INSTRUCTION",
        "id": "e2e-command",
        "command_b64": _b64(command),
    })
    await asyncio.sleep(0.01)

    ack = decode_msg(channel.sent[-1])
    assert ack["ok"] is True
    assert ack["action"] == "send_file_from_device"
    assert sent == [(friend.short_id, "clip.mov")]
    events = [row["event"] for row in laptop_daemon.state.list_self_mesh_audit()]
    assert "controller_cert_learned" in events
    assert "command_accepted" in events
    assert "remote_send_complete" in events
