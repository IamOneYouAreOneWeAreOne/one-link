from __future__ import annotations

import base64
import asyncio
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import identity_dag as idag
from one_link.identity import Identity, fingerprint_of
from one_link.personal_device_mesh import sign_remote_instruction
from one_link.state import State
from one_link.wire import decode_msg


def _ed25519_pair():
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key().public_bytes_raw()


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _make_identity() -> Identity:
    priv, pub = _ed25519_pair()
    return Identity(
        private=priv,
        public=priv.public_key(),
        public_bytes=pub,
        fingerprint=fingerprint_of(pub),
        short_id=fingerprint_of(pub)[:8],
        hostname="test-device",
    )


class _FakeChannel:
    def __init__(self, peer_pub: bytes):
        self.peer_ed_pub = peer_pub
        self.peer_short_id = fingerprint_of(peer_pub)[:8]
        self.sent: list[bytes] = []

    async def send(self, frame: bytes) -> None:
        self.sent.append(frame)


def _ack(channel: _FakeChannel) -> dict:
    assert channel.sent
    return decode_msg(channel.sent[-1])


def _make_daemon(tmp_path: Path):
    from one_link.daemon import Daemon

    d = Daemon.__new__(Daemon)
    d.me = _make_identity()
    d.state = State(db_path=tmp_path / "state.db")
    d.ui_server = SimpleNamespace(broadcast=lambda evt: None)
    d._inbound_is_rejected = lambda fp: False
    d._stamp_pair_health = lambda fp, **kw: None
    d._is_pinned = lambda fp: True
    d._peer_presence = {}
    return d


def _register_self_mesh_target(d, root_seed: bytes, root_pub: bytes) -> bytes:
    target_cert = idag.encode_device_cert(
        root_priv_seed=root_seed,
        root_pub=root_pub,
        device_pub=d.me.public_bytes,
        device_kind="windows-laptop",
    )
    d.state.upsert_self_mesh_device(
        root_pub=root_pub,
        device_pub=d.me.public_bytes,
        device_kind="windows-laptop",
        label="Laptop",
        cert=target_cert,
        local=True,
        trusted=True,
    )
    return target_cert


def _remote_command(
    d,
    *,
    root_seed: bytes,
    root_pub: bytes,
    action: str,
    scope: dict,
) -> bytes:
    controller_priv, controller_pub = _ed25519_pair()
    controller_cert = idag.encode_device_cert(
        root_priv_seed=root_seed,
        root_pub=root_pub,
        device_pub=controller_pub,
        device_kind="phone",
    )
    return sign_remote_instruction(
        controller_device_seed=controller_priv.private_bytes_raw(),
        controller_cert=controller_cert,
        target_device_pub=d.me.public_bytes,
        action=action,
        scope=scope,
        created_ms=int(time.time() * 1000),
        expires_ms=int(time.time() * 1000) + 60_000,
    )


@pytest.mark.asyncio
async def test_self_mesh_presence_frame_persists_and_acks(tmp_path: Path):
    d = _make_daemon(tmp_path)
    _, peer_pub = _ed25519_pair()
    channel = _FakeChannel(peer_pub)
    await d._on_peer_message(channel, {
        "t": "SELF_MESH_PRESENCE",
        "id": "presence-1",
        "device_pub_b64": _b64u(peer_pub),
        "state": "awake",
        "sequence": 7,
        "updated_ms": 12345,
        "network": "wifi",
        "free_bytes": 4096,
        "route": "peer_channel",
    })

    ack = _ack(channel)
    assert ack["t"] == "ACK"
    assert ack["ok"] is True
    rows = d.state.list_self_mesh_presence()
    assert rows[0]["device_pub"] == peer_pub
    assert rows[0]["state"] == "awake"
    assert rows[0]["network"] == "wifi"


@pytest.mark.asyncio
async def test_remote_instruction_manifest_executes_once_and_replay_rejects(
    tmp_path: Path,
):
    d = _make_daemon(tmp_path)
    root_priv, root_pub = _ed25519_pair()
    root_seed = root_priv.private_bytes_raw()
    _register_self_mesh_target(d, root_seed, root_pub)
    target = tmp_path / "note.txt"
    target.write_text("for the people\n", encoding="utf-8")
    command = _remote_command(
        d,
        root_seed=root_seed,
        root_pub=root_pub,
        action="pull_file_manifest",
        scope={"path": str(target)},
    )
    _, peer_pub = _ed25519_pair()
    channel = _FakeChannel(peer_pub)

    await d._on_peer_message(channel, {
        "t": "SELF_MESH_REMOTE_INSTRUCTION",
        "id": "cmd-1",
        "command_b64": _b64u(command),
    })
    ack = _ack(channel)
    assert ack["ok"] is True
    assert ack["action"] == "pull_file_manifest"
    assert ack["result"]["manifest"]["name"] == "note.txt"
    assert ack["result"]["manifest"]["size"] == target.stat().st_size

    await d._on_peer_message(channel, {
        "t": "SELF_MESH_REMOTE_INSTRUCTION",
        "id": "cmd-2",
        "command_b64": _b64u(command),
    })
    replay = _ack(channel)
    assert "replayed" in replay["rejected"]


@pytest.mark.asyncio
async def test_remote_instruction_requires_registered_local_root(tmp_path: Path):
    d = _make_daemon(tmp_path)
    root_priv, root_pub = _ed25519_pair()
    root_seed = root_priv.private_bytes_raw()
    target = tmp_path / "note.txt"
    target.write_text("we are one\n", encoding="utf-8")
    command = _remote_command(
        d,
        root_seed=root_seed,
        root_pub=root_pub,
        action="pull_file_manifest",
        scope={"path": str(target)},
    )
    _, peer_pub = _ed25519_pair()
    channel = _FakeChannel(peer_pub)

    await d._on_peer_message(channel, {
        "t": "SELF_MESH_REMOTE_INSTRUCTION",
        "id": "unregistered-root",
        "command_b64": _b64u(command),
    })

    ack = _ack(channel)
    assert ack["t"] == "ACK"
    assert "no local self-mesh target for root" in ack["rejected"]


@pytest.mark.asyncio
async def test_remote_instruction_send_file_queues_live_send(tmp_path: Path):
    d = _make_daemon(tmp_path)
    root_priv, root_pub = _ed25519_pair()
    root_seed = root_priv.private_bytes_raw()
    _register_self_mesh_target(d, root_seed, root_pub)
    target = tmp_path / "photo.bin"
    target.write_bytes(b"abc123")
    calls = []

    async def fake_resolve(needle: str):
        return SimpleNamespace(short_id="peer1", ed_pub_hex="11" * 32)

    async def fake_send_file(peer, path, *, transfer_id=None):
        calls.append((peer.short_id, Path(path).name, transfer_id))
        return {"ok": True}

    d.resolve_for_send = fake_resolve
    d.send_file = fake_send_file
    command = _remote_command(
        d,
        root_seed=root_seed,
        root_pub=root_pub,
        action="send_file_from_device",
        scope={
            "path": str(target),
            "recipient_fp": "ab" * 32,
            "max_bytes": 64,
        },
    )
    _, peer_pub = _ed25519_pair()
    channel = _FakeChannel(peer_pub)

    await d._on_peer_message(channel, {
        "t": "SELF_MESH_REMOTE_INSTRUCTION",
        "id": "cmd-send",
        "command_b64": _b64u(command),
    })
    assert _ack(channel)["ok"] is True
    await asyncio.sleep(0.01)
    assert calls == [("peer1", "photo.bin", None)]


def test_send_self_mesh_remote_instruction_uses_wire_frame(tmp_path: Path):
    d = _make_daemon(tmp_path)
    sent = []

    async def fake_send_to(peer, messages):
        sent.extend(messages)
        return [{"ok": True}]

    d.send_to = fake_send_to

    async def run():
        return await d.send_self_mesh_remote_instruction(
            SimpleNamespace(short_id="peer"),
            b'{"command":true}',
        )

    result = asyncio.run(run())
    assert result["ack"] == {"ok": True}
    assert sent[0]["t"] == "SELF_MESH_REMOTE_INSTRUCTION"
    assert base64.urlsafe_b64decode(sent[0]["command_b64"] + "==") == b'{"command":true}'
