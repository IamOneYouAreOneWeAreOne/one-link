"""Daemon-side dispatch test for FILE_PROVENANCE.

Builds a real Daemon instance (no network), constructs a properly-
signed FILE_PROVENANCE wire message, calls ``_on_peer_message``
directly, and asserts the provenance lands in the daemon's
ProvenanceStore + a tail event is broadcast.

Doesn't spin up two daemons — that's covered by the higher-level
integration tests. This isolates the dispatch hook itself so a
regression there fails loud and fast.
"""

from __future__ import annotations

import asyncio
import hashlib

import blake3
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.frame_provenance import FrameKind, PathClass, RecordingState
from one_link.identity import Identity
from one_link.provenance_wiring import (
    build_provenance_for_file,
    make_send_provenance_msg,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_identity(name: str) -> Identity:
    """Deterministic Identity without disk persistence."""
    seed = blake3.blake3(name.encode()).digest()[:32]
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fp = blake3.blake3(pub_bytes).hexdigest()
    return Identity(
        private=priv,
        public=priv.public_key(),
        public_bytes=pub_bytes,
        fingerprint=fp,
        short_id=fp[:8],
        hostname=name,
    )


class _FakePeerRecord:
    """Minimal stand-in for ``state.get_peer(peer_fp)``."""

    def __init__(self, ed_pub_hex: str) -> None:
        self.ed_pub_hex = ed_pub_hex
        self.trust = "pinned"


class _FakeState:
    """Minimal stand-in for ``Daemon.state``. Only the methods the
    FILE_PROVENANCE dispatch case calls are implemented."""

    def __init__(self, peer_pub_hex_by_fp: dict[str, str]) -> None:
        self._peers = {
            fp: _FakePeerRecord(pub) for fp, pub in peer_pub_hex_by_fp.items()
        }

    def get_peer(self, peer_fp: str) -> _FakePeerRecord | None:
        return self._peers.get(peer_fp)


class _FakeChannel:
    """Stand-in for a peer channel. The daemon's _on_peer_message
    reads channel.peer_ed_pub and channel.peer_short_id from the
    channel object; we provide them. The FILE_PROVENANCE dispatch
    case never calls .send."""

    def __init__(self, peer_ed_pub: bytes, peer_short_id: str) -> None:
        self.peer_ed_pub = peer_ed_pub
        self.peer_short_id = peer_short_id
        self.peer_caps: dict = {"features": ["frame_provenance_v1"]}
        self.sent: list[bytes] = []

    async def send(self, payload: bytes) -> None:
        self.sent.append(payload)


# ---------------------------------------------------------------------------
# Daemon fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def alice() -> Identity:
    return _make_identity("alice-daemon-test")


@pytest.fixture
def bob() -> Identity:
    return _make_identity("bob-daemon-test")


@pytest.fixture
def bob_daemon(bob: Identity, alice: Identity) -> Daemon:
    """Bob's daemon. The fake state knows about Alice's public key so
    inbound FILE_PROVENANCE from her verifies."""
    d = Daemon(me=bob)
    d.state = _FakeState({alice.fingerprint: alice.public_bytes.hex()})
    return d


@pytest.fixture
def voice_blob() -> bytes:
    return b"<opus voice frame bytes>" + b"\x00" * 1024


@pytest.fixture
def voice_blob_hex(voice_blob: bytes) -> str:
    return hashlib.sha256(voice_blob).hexdigest()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_daemon_constructor_initialises_provenance_store(bob: Identity) -> None:
    """The store must be present on every Daemon instance, even one
    constructed without a state object (the dispatch case checks for
    None defensively)."""
    d = Daemon(me=bob)
    assert hasattr(d, "_provenance_store")
    assert d._provenance_store is not None
    assert len(d._provenance_store) == 0


def test_dispatch_records_verified_inbound(
    bob_daemon: Daemon,
    alice: Identity,
    voice_blob: bytes,
    voice_blob_hex: str,
) -> None:
    """Honest sender → dispatch records as verified."""
    p = build_provenance_for_file(
        identity=alice,
        file_bytes=voice_blob,
        path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
        frame_kind=FrameKind.REAL,
    )
    msg = make_send_provenance_msg(
        sender_short_id=alice.short_id,
        blob_hex=voice_blob_hex,
        provenance=p,
    )
    channel = _FakeChannel(peer_ed_pub=alice.public_bytes, peer_short_id=alice.short_id)
    # Capture tail events
    tail_events: list[dict] = []
    bob_daemon._broadcast_tail = lambda ev: tail_events.append(ev)  # type: ignore

    # Run the dispatch through the daemon's own _on_peer_message.
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(
            bob_daemon._on_peer_message(channel, msg)
        )
    finally:
        loop.close()

    # Provenance landed in the store, marked verified.
    entry = bob_daemon._provenance_store.get_inbound(voice_blob_hex)
    assert entry is not None
    assert entry.verified is True

    # Tail event broadcast with the UI dict.
    fp_events = [e for e in tail_events if e.get("type") == "frame_provenance"]
    assert len(fp_events) == 1
    ev = fp_events[0]
    assert ev["blob"] == voice_blob_hex
    assert ev["verified"] is True
    assert ev["kind"] == "Real"
    assert ev["path"] == "Local network"
    assert ev["recording"] == "Not recording"


def test_dispatch_records_unverified_on_forged_signature(
    bob_daemon: Daemon,
    alice: Identity,
    voice_blob: bytes,
    voice_blob_hex: str,
) -> None:
    """Sender claims to be Alice but signed with a different key.
    Verification fails; store records unverified; tail event has
    verified=False."""
    attacker = _make_identity("attacker-daemon-test")
    fake = build_provenance_for_file(identity=attacker, file_bytes=voice_blob)
    msg = make_send_provenance_msg(
        sender_short_id=alice.short_id,
        blob_hex=voice_blob_hex,
        provenance=fake,
    )
    channel = _FakeChannel(peer_ed_pub=alice.public_bytes, peer_short_id=alice.short_id)
    tail_events: list[dict] = []
    bob_daemon._broadcast_tail = lambda ev: tail_events.append(ev)  # type: ignore

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(
            bob_daemon._on_peer_message(channel, msg)
        )
    finally:
        loop.close()

    entry = bob_daemon._provenance_store.get_inbound(voice_blob_hex)
    assert entry is not None
    assert entry.verified is False
    fp_events = [e for e in tail_events if e.get("type") == "frame_provenance"]
    assert len(fp_events) == 1
    assert fp_events[0]["verified"] is False


def test_dispatch_rejects_when_state_unknown(
    bob: Identity,
    alice: Identity,
    voice_blob: bytes,
    voice_blob_hex: str,
) -> None:
    """2026-05-22 audit FO-2: when daemon.state is None,
    _inbound_is_rejected now returns True (fail-closed) so the
    dispatch path raises ``rejected peer attempted message``.
    The old contract was "drop silently"; the new contract is
    "refuse with a hard error so a state-DB outage / corruption
    window can't accept frames from peers we'd previously revoked".

    Both behaviors leave the provenance store empty and the tail
    event un-fired; the difference is fail-closed vs fail-silent.
    """
    d = Daemon(me=bob)
    d.state = None  # explicitly unset
    p = build_provenance_for_file(identity=alice, file_bytes=voice_blob)
    msg = make_send_provenance_msg(
        sender_short_id=alice.short_id,
        blob_hex=voice_blob_hex,
        provenance=p,
    )
    channel = _FakeChannel(peer_ed_pub=alice.public_bytes, peer_short_id=alice.short_id)
    tail_events: list[dict] = []
    d._broadcast_tail = lambda ev: tail_events.append(ev)  # type: ignore

    loop = asyncio.new_event_loop()
    try:
        with pytest.raises(RuntimeError, match="rejected peer"):
            loop.run_until_complete(
                d._on_peer_message(channel, msg)
            )
    finally:
        loop.close()

    # Nothing recorded, nothing broadcast — the dispatch was refused
    # before it reached the provenance handler.
    assert len(d._provenance_store) == 0
    assert not any(e.get("type") == "frame_provenance" for e in tail_events)


def test_dispatch_silently_drops_when_peer_unknown(
    bob: Identity,
    alice: Identity,
    voice_blob: bytes,
    voice_blob_hex: str,
) -> None:
    """When daemon.state has no record of the peer (e.g., never
    paired), no public key is available so we can't verify. Drop
    silently."""
    d = Daemon(me=bob)
    d.state = _FakeState({})  # empty
    p = build_provenance_for_file(identity=alice, file_bytes=voice_blob)
    msg = make_send_provenance_msg(
        sender_short_id=alice.short_id,
        blob_hex=voice_blob_hex,
        provenance=p,
    )
    channel = _FakeChannel(peer_ed_pub=alice.public_bytes, peer_short_id=alice.short_id)
    tail_events: list[dict] = []
    d._broadcast_tail = lambda ev: tail_events.append(ev)  # type: ignore

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(
            d._on_peer_message(channel, msg)
        )
    finally:
        loop.close()

    assert len(d._provenance_store) == 0


def test_dispatch_drops_malformed_without_crashing(
    bob_daemon: Daemon,
    alice: Identity,
) -> None:
    """A malformed FILE_PROVENANCE (e.g., garbage prov dict) must be
    logged and dropped — never crash the daemon."""
    channel = _FakeChannel(peer_ed_pub=alice.public_bytes, peer_short_id=alice.short_id)
    bob_daemon._broadcast_tail = lambda ev: None  # type: ignore

    bad_msg = {
        "t": "FILE_PROVENANCE",
        "id": "x",
        "ts": 0,
        "from": alice.short_id,
        "blob": "a" * 64,
        "prov": {"v": "garbage"},  # not an int
    }

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(
            bob_daemon._on_peer_message(channel, bad_msg)
        )
    finally:
        loop.close()

    # Store remains empty; no crash.
    assert len(bob_daemon._provenance_store) == 0
