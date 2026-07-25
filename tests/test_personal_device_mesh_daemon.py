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


def _pin_channel_peer(d, peer_pub: bytes) -> str:
    """Model the SAS-pinned transport precondition for privileged commands."""
    peer_fp = fingerprint_of(peer_pub)
    d.state.upsert_peer(
        fingerprint=peer_fp,
        short_id=peer_fp[:8],
        pubkey=peer_pub,
        hostname="self-phone",
        trust_default="pinned",
    )
    return peer_fp


def _enroll_channel_peer(d, peer_pub: bytes) -> str:
    """Enroll the authenticated channel key as a trusted self device."""
    root_priv, root_pub = _ed25519_pair()
    cert = idag.encode_device_cert(
        root_priv_seed=root_priv.private_bytes_raw(),
        root_pub=root_pub,
        device_pub=peer_pub,
        device_kind="phone",
    )
    d.state.upsert_self_mesh_device(
        root_pub=root_pub,
        device_pub=peer_pub,
        device_kind="phone",
        label="Phone",
        cert=cert,
        local=False,
        trusted=True,
        safety_state="trusted",
    )
    return _pin_channel_peer(d, peer_pub)


def _make_daemon(tmp_path: Path):
    from one_link.daemon import Daemon

    d = Daemon.__new__(Daemon)
    d.me = _make_identity()
    d.state = State(db_path=tmp_path / "state.db")
    d.state.set_setting("self_mesh_allowed_roots", str(tmp_path))
    d.ui_server = SimpleNamespace(broadcast=lambda evt: None)
    d._inbound_is_rejected = lambda fp: False
    d._stamp_pair_health = lambda fp, **kw: None
    d._is_pinned = lambda fp: True
    d._emit_capability_request = lambda fp, sid, cap: None
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
    controller_priv: Ed25519PrivateKey | None = None,
) -> bytes:
    if controller_priv is None:
        controller_priv = Ed25519PrivateKey.generate()
    controller_pub = controller_priv.public_key().public_bytes_raw()
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
    _enroll_channel_peer(d, peer_pub)
    channel = _FakeChannel(peer_pub)
    now_ms = int(time.time() * 1000)
    await d._on_peer_message(channel, {
        "t": "SELF_MESH_PRESENCE",
        "id": "presence-1",
        "device_pub_b64": _b64u(peer_pub),
        "state": "awake",
        "sequence": 7,
        "updated_ms": now_ms,
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
async def test_self_mesh_presence_rejects_pinned_but_unenrolled_peer(tmp_path: Path):
    d = _make_daemon(tmp_path)
    _, peer_pub = _ed25519_pair()
    _pin_channel_peer(d, peer_pub)
    channel = _FakeChannel(peer_pub)

    await d._on_peer_message(channel, {
        "t": "SELF_MESH_PRESENCE",
        "id": "presence-unenrolled",
        "device_pub_b64": _b64u(peer_pub),
        "state": "awake",
        "sequence": 1,
        "updated_ms": int(time.time() * 1000),
    })

    assert _ack(channel)["rejected"] == "self_mesh_presence_rejected: invalid"
    assert d.state.list_self_mesh_presence() == []


@pytest.mark.asyncio
async def test_self_mesh_presence_rejects_identity_spoof(tmp_path: Path):
    d = _make_daemon(tmp_path)
    _, peer_pub = _ed25519_pair()
    _, spoofed_pub = _ed25519_pair()
    _enroll_channel_peer(d, peer_pub)
    channel = _FakeChannel(peer_pub)

    await d._on_peer_message(channel, {
        "t": "SELF_MESH_PRESENCE",
        "id": "presence-spoof",
        "device_pub_b64": _b64u(spoofed_pub),
        "state": "awake",
        "sequence": 1,
        "updated_ms": int(time.time() * 1000),
    })

    assert _ack(channel)["rejected"] == "self_mesh_presence_rejected: invalid"
    assert d.state.list_self_mesh_presence() == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        {"unexpected": "alias"},
        {"sequence": True},
        {"updated_ms": True},
        {"battery_pct": True},
        {"latency_ms": float("nan")},
        {"device_pub_b64": "A" * 44},
    ],
)
async def test_self_mesh_presence_rejects_noncanonical_or_ambiguous_fields(
    tmp_path: Path,
    mutation: dict,
):
    d = _make_daemon(tmp_path)
    _, peer_pub = _ed25519_pair()
    _enroll_channel_peer(d, peer_pub)
    channel = _FakeChannel(peer_pub)
    frame = {
        "t": "SELF_MESH_PRESENCE",
        "id": "presence-invalid",
        "device_pub_b64": _b64u(peer_pub),
        "state": "awake",
        "sequence": 1,
        "updated_ms": int(time.time() * 1000),
    }
    frame.update(mutation)

    await d._handle_self_mesh_presence(
        channel,
        frame,
        fingerprint_of(peer_pub),
    )

    assert _ack(channel)["rejected"] == "self_mesh_presence_rejected: invalid"
    assert d.state.list_self_mesh_presence() == []


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
    peer_priv, peer_pub = _ed25519_pair()
    command = _remote_command(
        d,
        root_seed=root_seed,
        root_pub=root_pub,
        action="pull_file_manifest",
        scope={"path": str(target)},
        controller_priv=peer_priv,
    )
    _pin_channel_peer(d, peer_pub)
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
    metrics = [
        (row["metadata"] or {}).get("metric")
        for row in d.state.list_self_mesh_perf_samples(limit=20)
    ]
    assert "command_verify" in metrics
    assert "command_replay_check" in metrics
    assert "command_total" in metrics


@pytest.mark.asyncio
async def test_remote_instruction_requires_registered_local_root(tmp_path: Path):
    d = _make_daemon(tmp_path)
    root_priv, root_pub = _ed25519_pair()
    root_seed = root_priv.private_bytes_raw()
    target = tmp_path / "note.txt"
    target.write_text("we are one\n", encoding="utf-8")
    peer_priv, peer_pub = _ed25519_pair()
    command = _remote_command(
        d,
        root_seed=root_seed,
        root_pub=root_pub,
        action="pull_file_manifest",
        scope={"path": str(target)},
        controller_priv=peer_priv,
    )
    channel = _FakeChannel(peer_pub)

    await d._on_peer_message(channel, {
        "t": "SELF_MESH_REMOTE_INSTRUCTION",
        "id": "unregistered-root",
        "command_b64": _b64u(command),
    })

    ack = _ack(channel)
    assert ack["t"] == "ACK"
    assert ack["rejected"] == "self_mesh_instruction_rejected: invalid"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        {"unexpected": "alias"},
        {"command_b64": True},
        {"command_b64": "A" * 11_000},
        {"ts": True},
    ],
)
async def test_remote_instruction_outer_frame_fails_closed(
    tmp_path: Path,
    mutation: dict,
):
    d = _make_daemon(tmp_path)
    _, peer_pub = _ed25519_pair()
    peer_fp = _pin_channel_peer(d, peer_pub)
    channel = _FakeChannel(peer_pub)
    frame = {
        "t": "SELF_MESH_REMOTE_INSTRUCTION",
        "id": "malformed-command",
        "command_b64": _b64u(b"{}"),
    }
    frame.update(mutation)

    await d._handle_self_mesh_remote_instruction(channel, frame, peer_fp)

    assert _ack(channel)["rejected"] == "self_mesh_instruction_rejected: invalid"


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
    peer_priv, peer_pub = _ed25519_pair()
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
        controller_priv=peer_priv,
    )
    _pin_channel_peer(d, peer_pub)
    channel = _FakeChannel(peer_pub)

    await d._on_peer_message(channel, {
        "t": "SELF_MESH_REMOTE_INSTRUCTION",
        "id": "cmd-send",
        "command_b64": _b64u(command),
    })
    assert _ack(channel)["ok"] is True
    await asyncio.sleep(0.01)
    assert calls == [("peer1", "photo.bin", None)]


@pytest.mark.asyncio
async def test_remote_instruction_rejects_paths_outside_allowed_roots(tmp_path: Path):
    d = _make_daemon(tmp_path)
    d.state.set_setting("self_mesh_allowed_roots", str(tmp_path / "allowed"))
    root_priv, root_pub = _ed25519_pair()
    root_seed = root_priv.private_bytes_raw()
    _register_self_mesh_target(d, root_seed, root_pub)
    target = tmp_path / "blocked.txt"
    target.write_text("not in allowed root\n", encoding="utf-8")
    peer_priv, peer_pub = _ed25519_pair()
    command = _remote_command(
        d,
        root_seed=root_seed,
        root_pub=root_pub,
        action="pull_file_manifest",
        scope={"path": str(target)},
        controller_priv=peer_priv,
    )
    _pin_channel_peer(d, peer_pub)
    channel = _FakeChannel(peer_pub)

    await d._on_peer_message(channel, {
        "t": "SELF_MESH_REMOTE_INSTRUCTION",
        "id": "blocked-path",
        "command_b64": _b64u(command),
    })

    ack = _ack(channel)
    assert "outside allowed self-mesh roots" in ack["rejected"]
    assert d.state.list_self_mesh_audit()[0]["event"] == "command_rejected"


@pytest.mark.asyncio
async def test_remote_instruction_requires_action_capability(tmp_path: Path):
    from one_link.capabilities import CHAT

    d = _make_daemon(tmp_path)
    root_priv, root_pub = _ed25519_pair()
    root_seed = root_priv.private_bytes_raw()
    _register_self_mesh_target(d, root_seed, root_pub)
    target = tmp_path / "note.txt"
    target.write_text("cap gated\n", encoding="utf-8")
    peer_priv, peer_pub = _ed25519_pair()
    command = _remote_command(
        d,
        root_seed=root_seed,
        root_pub=root_pub,
        action="pull_file_manifest",
        scope={"path": str(target)},
        controller_priv=peer_priv,
    )
    peer_fp = fingerprint_of(peer_pub)
    d.state.upsert_peer(
        fingerprint=peer_fp,
        short_id=peer_fp[:8],
        pubkey=peer_pub,
        hostname="self-phone",
    )
    d.state.set_peer_trust(peer_fp, "pinned")
    d.state.set_peer_capability_policy(peer_fp, [CHAT])
    requests = []
    d._emit_capability_request = lambda fp, sid, cap: requests.append((fp, cap))
    channel = _FakeChannel(peer_pub)

    await d._on_peer_message(channel, {
        "t": "SELF_MESH_REMOTE_INSTRUCTION",
        "id": "cap-denied",
        "command_b64": _b64u(command),
    })

    ack = _ack(channel)
    assert "capability disabled: self_mesh_manifest" in ack["rejected"]
    assert requests == [(peer_fp, "self_mesh_manifest")]


@pytest.mark.asyncio
async def test_remote_instruction_cannot_be_relayed_by_different_pinned_peer(
    tmp_path: Path,
):
    d = _make_daemon(tmp_path)
    root_priv, root_pub = _ed25519_pair()
    root_seed = root_priv.private_bytes_raw()
    _register_self_mesh_target(d, root_seed, root_pub)
    target = tmp_path / "private.txt"
    target.write_text("owner only\n", encoding="utf-8")
    controller_priv, _ = _ed25519_pair()
    command = _remote_command(
        d,
        root_seed=root_seed,
        root_pub=root_pub,
        action="pull_file_manifest",
        scope={"path": str(target)},
        controller_priv=controller_priv,
    )
    _, relay_pub = _ed25519_pair()
    relay_fp = _pin_channel_peer(d, relay_pub)
    channel = _FakeChannel(relay_pub)

    await d._handle_self_mesh_remote_instruction(
        channel,
        {
            "t": "SELF_MESH_REMOTE_INSTRUCTION",
            "id": "captured-command",
            "command_b64": _b64u(command),
        },
        relay_fp,
    )

    assert _ack(channel)["rejected"] == "self_mesh_instruction_rejected: invalid"
    events = [row["event"] for row in d.state.list_self_mesh_audit()]
    assert events == ["command_rejected"]


def test_choose_self_mesh_route_selects_best_device(tmp_path: Path):
    d = _make_daemon(tmp_path)
    root_priv, root_pub = _ed25519_pair()
    root_seed = root_priv.private_bytes_raw()
    _register_self_mesh_target(d, root_seed, root_pub)
    d.state.upsert_self_mesh_presence(
        device_pub=d.me.public_bytes,
        state="awake",
        sequence=10,
        updated_ms=int(time.time() * 1000),
        network="ethernet",
        free_bytes=1_000_000,
        route="self_lan",
    )

    decision = d.choose_self_mesh_route(root_pub=root_pub, kind="send")

    assert decision["ready"] is True
    assert decision["target"]["fingerprint"] == d.me.fingerprint
    assert decision["route"] == "self_lan"


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


def test_resolve_for_send_prefers_live_fingerprint_endpoint(tmp_path: Path):
    from one_link.discovery import Peer

    d = _make_daemon(tmp_path)
    peer_priv, peer_pub = _ed25519_pair()
    peer_fp = fingerprint_of(peer_pub)
    d.state.upsert_peer(
        fingerprint=peer_fp,
        short_id=peer_fp[:8],
        pubkey=peer_pub,
        hostname="laptop",
        address="127.0.0.1",
        port=1,
        trust_default="pinned",
    )
    live = Peer(
        short_id=peer_fp[:8],
        hostname="laptop",
        address="127.0.0.1",
        port=54321,
        ed_pub_hex=peer_pub.hex(),
    )
    d.discovery = SimpleNamespace(
        registry=SimpleNamespace(
            find=lambda needle: None,
            list=lambda: [live],
        ),
    )

    async def run():
        return await d.resolve_for_send(peer_fp)

    assert asyncio.run(run()).port == 54321
