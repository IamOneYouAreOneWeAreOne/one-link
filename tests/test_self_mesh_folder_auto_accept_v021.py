"""v0.21.x self-mesh implicit consent for folder receive.

When the sender of a MANIFEST_PUSH is one of OUR OWN devices (same
identity root, different physical device per self_mesh_devices),
the receiver auto-accepts the folder offer instead of waiting for
a human Accept/Decline click. Sending a folder between your own
devices shouldn't require consent — that's friction for the most
common case.

Coverage:
  - state.is_self_mesh_peer: True for a registered self-mesh device,
    False for unknown peers, False for malformed input
  - daemon._handle_manifest_push: when sender is self-mesh + folder
    is unknown, auto-accept (folder created at inbox/<name>/, peer
    added to shared_with, offer marked accepted)
  - daemon._handle_manifest_push: when sender is NOT self-mesh,
    still produces a pending offer (no auto-accept)
  - auto-accept skips when a folder with that name already exists
    (don't clobber user data)
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import foldersync
from one_link import identity_dag as idag
from one_link.blobstore import BlobStore
from one_link.capabilities import FOLDER_SYNC, FOLDER_SYNC_COMMIT_V1
from one_link.daemon import Daemon
from one_link.foldersync import FolderEngine
from one_link.identity import Identity, fingerprint_of
from one_link.state import State
from one_link.wire import make_msg


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw()
    return Identity(
        private=sk, public=sk.public_key(), public_bytes=pub,
        fingerprint=fingerprint_of(pub), short_id=fingerprint_of(pub)[:8],
        hostname="self-mesh-host",
    )


def _folder_channel(*, transcript: str) -> MagicMock:
    channel = MagicMock()
    channel.send = AsyncMock()
    channel.transcript_hex = transcript
    channel.peer_caps = {
        "features": [FOLDER_SYNC, FOLDER_SYNC_COMMIT_V1],
    }
    return channel


def _manifest_push(*, sender_fp: str, folder: str) -> dict:
    entries: list[dict] = []
    return make_msg(
        "MANIFEST_PUSH",
        sender_fp[:8],
        folder=folder,
        merkle_root=foldersync.manifest_root_for_entries(entries),
        manifest_digest=Daemon._folder_manifest_digest(entries),
        entry_count=0,
        entries=entries,
    )


# ── state.is_self_mesh_peer ──────────────────────────────────────


def test_is_self_mesh_peer_false_for_empty_state(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    assert state.is_self_mesh_peer("aa" * 32) is False
    assert state.is_self_mesh_peer("") is False
    assert state.is_self_mesh_peer(None) is False
    state.close()


def test_is_self_mesh_peer_true_after_register(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    # Register a self-mesh device. The schema requires root_pub +
    # device_pub. Compute device_pub as an Ed25519 key.
    sk = Ed25519PrivateKey.generate()
    device_pub = sk.public_key().public_bytes_raw()
    root_sk = Ed25519PrivateKey.generate()
    root_pub = root_sk.public_key().public_bytes_raw()
    cert = idag.encode_device_cert(
        root_priv_seed=root_sk.private_bytes_raw(),
        root_pub=root_pub,
        device_pub=device_pub,
        device_kind="laptop",
    )
    state.upsert_self_mesh_device(
        root_pub=root_pub,
        device_pub=device_pub,
        cert=cert,
        device_kind="laptop",
        label="laptop",
        local=False,
        trusted=True,
    )
    fp = fingerprint_of(device_pub)
    assert state.is_self_mesh_peer(fp) is True
    assert state.is_self_mesh_peer(fp.upper()) is True
    # Random other fingerprint is not self-mesh.
    assert state.is_self_mesh_peer("ff" * 32) is False
    state.close()


def test_is_self_mesh_peer_false_for_revoked(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    sk = Ed25519PrivateKey.generate()
    device_pub = sk.public_key().public_bytes_raw()
    root_sk = Ed25519PrivateKey.generate()
    root_pub = root_sk.public_key().public_bytes_raw()
    cert = idag.encode_device_cert(
        root_priv_seed=root_sk.private_bytes_raw(),
        root_pub=root_pub,
        device_pub=device_pub,
        device_kind="laptop",
    )
    state.upsert_self_mesh_device(
        root_pub=root_pub,
        device_pub=device_pub,
        cert=cert,
        device_kind="laptop",
        label="lost-device",
        local=False,
        trusted=True,
        revoked=True,
    )
    fp = fingerprint_of(device_pub)
    assert state.is_self_mesh_peer(fp) is False
    state.close()


@pytest.mark.parametrize(
    ("trusted", "safety_state", "with_cert"),
    [
        (False, "trusted", True),
        (True, "frozen", True),
        (True, "trusted", False),
    ],
)
def test_is_self_mesh_peer_requires_live_certified_authority(
    tmp_path: Path,
    trusted: bool,
    safety_state: str,
    with_cert: bool,
):
    state = State(db_path=tmp_path / "s.db")
    device_sk = Ed25519PrivateKey.generate()
    device_pub = device_sk.public_key().public_bytes_raw()
    root_sk = Ed25519PrivateKey.generate()
    root_pub = root_sk.public_key().public_bytes_raw()
    cert = idag.encode_device_cert(
        root_priv_seed=root_sk.private_bytes_raw(),
        root_pub=root_pub,
        device_pub=device_pub,
        device_kind="phone",
    )
    state.upsert_self_mesh_device(
        root_pub=root_pub,
        device_pub=device_pub,
        cert=cert if with_cert else None,
        device_kind="phone",
        label="phone",
        local=False,
        trusted=trusted,
        safety_state=safety_state,
    )

    assert state.is_self_mesh_peer(fingerprint_of(device_pub)) is False
    state.close()


# ── _handle_manifest_push self-mesh auto-accept ─────────────────


@pytest_asyncio.fixture
async def receive_ctx(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    blob_store = BlobStore(root=tmp_path / "blobs")
    daemon = Daemon(me)
    daemon.state = state
    daemon.blob_store = blob_store
    daemon.folder_engine = FolderEngine(
        state=state, blob_store=blob_store,
        my_fingerprint=me.fingerprint,
        loop=asyncio.get_running_loop(),
    )
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    daemon.ui_server = MagicMock()
    daemon.ui_server.broadcast = MagicMock()
    # Pin sender as a "self-mesh device" of our root.
    sender_sk = Ed25519PrivateKey.generate()
    sender_device_pub = sender_sk.public_key().public_bytes_raw()
    sender_fp = fingerprint_of(sender_device_pub)
    state.upsert_peer(
        fingerprint=sender_fp, short_id=sender_fp[:8],
        pubkey=sender_device_pub, hostname="sender-device",
    )
    state.set_peer_trust(sender_fp, "pinned")
    root_sk = Ed25519PrivateKey.generate()
    root_pub = root_sk.public_key().public_bytes_raw()
    sender_cert = idag.encode_device_cert(
        root_priv_seed=root_sk.private_bytes_raw(),
        root_pub=root_pub,
        device_pub=sender_device_pub,
        device_kind="laptop",
    )
    state.upsert_self_mesh_device(
        root_pub=root_pub,
        device_pub=sender_device_pub,
        cert=sender_cert,
        device_kind="laptop",
        label="sender",
        local=False,
        trusted=True,
    )
    # Stub push_folder_to_peer so the auto-accept pull-back attempt
    # doesn't try to dial (we have no real peer registry).
    daemon.push_folder_to_peer = AsyncMock(
        return_value={"ok": True, "blobs_sent": 0},
    )
    daemon._peer_from_fp = lambda fp: None
    yield {
        "daemon": daemon, "state": state, "sender_fp": sender_fp,
        "sender_device_pub": sender_device_pub,
        "tmp_path": tmp_path,
    }
    state.close()


@pytest.mark.asyncio
async def test_self_mesh_sender_auto_accepted(receive_ctx):
    """MANIFEST_PUSH for an unknown folder from a self-mesh sender:
    auto-accept fires (folder created, peer added to shared_with)."""
    daemon = receive_ctx["daemon"]
    state = receive_ctx["state"]
    sender_fp = receive_ctx["sender_fp"]
    channel = _folder_channel(transcript="a" * 64)
    msg = _manifest_push(
        sender_fp=sender_fp,
        folder="from_my_laptop",
    )
    await daemon._handle_manifest_push(channel, msg, sender_fp)
    # Give the auto-accept task a tick.
    for _ in range(20):
        await asyncio.sleep(0.02)
        if state.get_folder("from_my_laptop") is not None:
            break
    f = state.get_folder("from_my_laptop")
    assert f is not None, "self-mesh sender should auto-create folder"
    assert sender_fp in f["shared_with"]
    # WS broadcast carries the self-mesh marker.
    calls = daemon.ui_server.broadcast.call_args_list
    types_broadcast = [c.args[0].get("type") for c in calls if c.args]
    assert "folder_self_mesh_auto_accepted" in types_broadcast
    # v0.21.x bug fix: for self-mesh senders we must NOT broadcast
    # folder_offer_received (which would show an Accept/Decline card
    # the user could click WHILE auto-accept is running → race causes
    # "could not create folder" UNIQUE-collision errors).
    assert "folder_offer_received" not in types_broadcast, (
        "self-mesh fast-path must NOT broadcast folder_offer_received "
        "— that would race with the auto-accept's add_folder call"
    )


@pytest.mark.asyncio
async def test_non_self_mesh_sender_stays_pending(receive_ctx, tmp_path):
    """Sender NOT in self_mesh_devices → no auto-accept. The pending
    offer stays for the user to manually Accept/Decline."""
    daemon = receive_ctx["daemon"]
    state = receive_ctx["state"]
    # Pin a different peer who is NOT in self_mesh_devices.
    other_sk = Ed25519PrivateKey.generate()
    other_pub = other_sk.public_key().public_bytes_raw()
    other_fp = fingerprint_of(other_pub)
    state.upsert_peer(
        fingerprint=other_fp, short_id=other_fp[:8],
        pubkey=other_pub, hostname="other",
    )
    state.set_peer_trust(other_fp, "pinned")
    channel = _folder_channel(transcript="b" * 64)
    msg = _manifest_push(
        sender_fp=other_fp,
        folder="from_stranger",
    )
    await daemon._handle_manifest_push(channel, msg, other_fp)
    await asyncio.sleep(0.1)
    # Folder NOT auto-created.
    assert state.get_folder("from_stranger") is None
    # Pending offer exists.
    offers = state.list_folder_offers()
    assert any(o["folder_name"] == "from_stranger" for o in offers)


@pytest.mark.asyncio
async def test_auto_accept_skips_when_folder_already_exists(receive_ctx, tmp_path):
    """If the receiver ALREADY has a folder named the same, auto-
    accept must NOT clobber it — leaves the pending offer for
    the user to handle manually (e.g. rename + accept)."""
    daemon = receive_ctx["daemon"]
    state = receive_ctx["state"]
    sender_fp = receive_ctx["sender_fp"]
    # Pre-existing folder with the same name.
    existing_local = tmp_path / "preexisting"
    existing_local.mkdir()
    state.add_folder(
        name="from_my_laptop", local_path=str(existing_local),
        shared_with=[],
    )
    channel = _folder_channel(transcript="c" * 64)
    msg = _manifest_push(
        sender_fp=sender_fp,
        folder="from_my_laptop",
    )
    await daemon._handle_manifest_push(channel, msg, sender_fp)
    await asyncio.sleep(0.1)
    # Existing folder is UNCHANGED.
    f = state.get_folder("from_my_laptop")
    assert f is not None
    assert f["local_path"] == str(existing_local)
    # Sender was NOT auto-added to shared_with.
    assert sender_fp not in f["shared_with"]
