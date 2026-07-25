"""Bounded, roster-aware telemetry for authenticated legacy-v1 HELLOs."""

from __future__ import annotations

import asyncio
import os
import struct
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import channel as ch
from one_link.identity import Identity, fingerprint_of


def _identity() -> Identity:
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
        hostname="telemetry-test",
    )


@pytest.fixture(autouse=True)
def _reset_telemetry() -> None:
    with ch._v1_sig_telemetry_lock:
        ch._v1_sig_fallback_counts.clear()
        ch._v1_sig_unknown_attempts = 0
        ch._v1_sig_known_attempts = 0
        ch._v1_sig_known_evictions = 0
    with ch._handshake_replay_lock:
        ch._handshake_replay_cache.clear()
    yield
    with ch._v1_sig_telemetry_lock:
        ch._v1_sig_fallback_counts.clear()
        ch._v1_sig_unknown_attempts = 0
        ch._v1_sig_known_attempts = 0
        ch._v1_sig_known_evictions = 0
    with ch._handshake_replay_lock:
        ch._handshake_replay_cache.clear()


def test_unknown_key_flood_uses_one_fixed_memory_counter() -> None:
    attempts = 20_000
    for index in range(attempts):
        ch._bump_v1_sig_counter(index.to_bytes(32, "big"), is_pinned=False, now=float(index))

    assert len(ch._v1_sig_fallback_counts) == 0
    assert ch.v1_sig_fallback_summary(now=float(attempts))["__unknown_attempts__"] == attempts
    assert ch.v1_sig_fallback_summary(now=float(attempts))["__known_tracked__"] == 0


def test_known_peer_table_is_deterministic_lru(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ch, "_V1_SIG_KNOWN_MAX_ENTRIES", 3)
    monkeypatch.setattr(ch, "_V1_SIG_KNOWN_TTL_S", 1_000.0)
    peers = [bytes([value]) * 32 for value in range(1, 5)]
    for offset, peer in enumerate(peers[:3]):
        ch._bump_v1_sig_counter(peer, is_pinned=True, now=float(offset))

    # Refresh peer 1, making peer 2 the deterministic least-recently used.
    assert ch._bump_v1_sig_counter(peers[0], is_pinned=True, now=3.0) == 2
    ch._bump_v1_sig_counter(peers[3], is_pinned=True, now=4.0)
    summary = ch.v1_sig_fallback_summary(now=4.0)

    assert peers[0].hex()[:16] in summary
    assert peers[1].hex()[:16] not in summary
    assert peers[2].hex()[:16] in summary
    assert peers[3].hex()[:16] in summary
    assert summary["__known_tracked__"] == 3
    assert summary["__known_attempts__"] == 5
    assert summary["__known_evictions__"] == 1


def test_known_peer_slots_expire_by_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ch, "_V1_SIG_KNOWN_TTL_S", 10.0)
    old_peer = b"o" * 32
    fresh_peer = b"f" * 32
    ch._bump_v1_sig_counter(old_peer, is_pinned=True, now=0.0)
    ch._bump_v1_sig_counter(fresh_peer, is_pinned=True, now=5.0)

    summary = ch.v1_sig_fallback_summary(now=10.5)
    assert old_peer.hex()[:16] not in summary
    assert fresh_peer.hex()[:16] in summary
    assert summary["__known_tracked__"] == 1


def test_telemetry_updates_are_thread_safe() -> None:
    peer = b"p" * 32

    def bump_many() -> None:
        for _ in range(2_000):
            ch._bump_v1_sig_counter(peer, is_pinned=True)

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(lambda _index: bump_many(), range(8)))

    assert ch.v1_sig_fallback_summary()[peer.hex()[:16]] == 16_000


class _SinkWriter:
    def __init__(self) -> None:
        self.data = bytearray()

    def write(self, data: bytes) -> None:
        self.data.extend(data)

    async def drain(self) -> None:
        return None


def _legacy_v1_reader(identity: Identity) -> asyncio.StreamReader:
    _private, ephemeral_public = ch._x25519_keypair()
    nonce = os.urandom(ch.NONCE_LEN)
    signed = ch.HELLO_TAG + identity.public_bytes + ephemeral_public + nonce
    hello = identity.public_bytes + ephemeral_public + nonce + identity.sign(signed)
    reader = asyncio.StreamReader()
    reader.feed_data(struct.pack(">I", len(hello)) + hello)
    return reader


@pytest.mark.asyncio
async def test_responder_retains_detail_only_for_roster_confirmed_peer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ONE_LINK_ALLOW_V1_HELLO", raising=False)
    pinned = _identity()
    unknown = _identity()
    responder = _identity()

    with pytest.raises(RuntimeError, match="legacy unbound v1 is disabled"):
        await ch.respond(
            _legacy_v1_reader(pinned),
            _SinkWriter(),  # type: ignore[arg-type]
            responder,
            is_pinned_peer=lambda peer: peer == pinned.public_bytes,
        )
    with pytest.raises(RuntimeError, match="legacy unbound v1 is disabled"):
        await ch.respond(
            _legacy_v1_reader(unknown),
            _SinkWriter(),  # type: ignore[arg-type]
            responder,
            is_pinned_peer=lambda peer: peer == pinned.public_bytes,
        )

    summary = ch.v1_sig_fallback_summary()
    assert summary[pinned.public_bytes.hex()[:16]] == 1
    assert unknown.public_bytes.hex()[:16] not in summary
    assert summary["__unknown_attempts__"] == 1
    assert summary["__known_tracked__"] == 1


@pytest.mark.asyncio
async def test_roster_lookup_failure_falls_back_to_unknown_aggregate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ONE_LINK_ALLOW_V1_HELLO", raising=False)
    initiator = _identity()
    responder = _identity()

    def broken_roster(_peer: bytes) -> bool:
        raise RuntimeError("trust store unavailable")

    with pytest.raises(RuntimeError, match="legacy unbound v1 is disabled"):
        await ch.respond(
            _legacy_v1_reader(initiator),
            _SinkWriter(),  # type: ignore[arg-type]
            responder,
            is_pinned_peer=broken_roster,
        )

    summary = ch.v1_sig_fallback_summary()
    assert summary["__unknown_attempts__"] == 1
    assert summary["__known_tracked__"] == 0
