"""Live v3 X25519 + ML-KEM-768 channel-handshake security gates."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from one_link import capabilities, channel, pq_hybrid, pqkem_native
from one_link.identity import Identity, load_or_create
from one_link.wire import read_frame, write_frame


ConnectedPair = tuple[
    asyncio.StreamReader,
    asyncio.StreamWriter,
    asyncio.StreamReader,
    asyncio.StreamWriter,
    asyncio.AbstractServer,
    asyncio.Event,
]


async def _connected_pair() -> ConnectedPair:
    accepted: asyncio.Future[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = (
        asyncio.get_running_loop().create_future()
    )
    hold = asyncio.Event()

    async def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        accepted.set_result((reader, writer))
        await hold.wait()

    server = await asyncio.start_server(accept, "127.0.0.1", 0)
    port = int(server.sockets[0].getsockname()[1])
    client_reader, client_writer = await asyncio.open_connection("127.0.0.1", port)
    server_reader, server_writer = await accepted
    return client_reader, client_writer, server_reader, server_writer, server, hold


async def _close_pair(pair: ConnectedPair) -> None:
    _cr, cw, _sr, sw, server, hold = pair
    cw.close()
    sw.close()
    hold.set()
    server.close()
    await server.wait_closed()
    await asyncio.gather(cw.wait_closed(), sw.wait_closed(), return_exceptions=True)


async def _live_channels(
    alice: Identity,
    bob: Identity,
) -> tuple[channel.Channel, channel.Channel, ConnectedPair]:
    pair = await _connected_pair()
    ar, aw, br, bw, _server, _hold = pair
    initiator, responder = await asyncio.gather(
        channel.initiate(
            ar,
            aw,
            alice,
            expected_responder_ed_pub=bob.public_bytes,
        ),
        channel.respond(br, bw, bob),
    )
    return initiator, responder, pair


@pytest.mark.asyncio
async def test_live_channel_is_pq_transcript_authenticated_and_key_confirmed(
    tmp_path: Path,
) -> None:
    assert pqkem_native.runtime_is_usable()
    alice = load_or_create(tmp_path / "alice.key")
    bob = load_or_create(tmp_path / "bob.key")
    initiator, responder, pair = await _live_channels(alice, bob)
    try:
        for established in (initiator, responder):
            assert established.handshake_version == channel.PQ_HANDSHAKE_VERSION
            assert established.handshake_suite == channel.PQ_HYBRID_HANDSHAKE_CAP
            assert established.pq_protected is True
            assert established.key_confirmed is True
        assert initiator.transcript_hash == responder.transcript_hash
        assert len(initiator.transcript_hash) == 32
        await initiator.send(b"pq channel payload")
        assert await responder.recv() == b"pq channel payload"
        await responder.send(b"confirmed response")
        assert await initiator.recv() == b"confirmed response"
    finally:
        await asyncio.gather(initiator.close(), responder.close())
        await _close_pair(pair)


def test_pq_hello_codec_is_canonical_and_length_exact() -> None:
    raw_unsigned = channel._encode_pq_hello_unsigned(
        offered_suites=(channel.PQ_SUITE_X25519_MLKEM768_V1,),
        initiator_ed=b"e" * 32,
        initiator_x25519=b"x" * 32,
        nonce=b"n" * channel.NONCE_LEN,
        kem_public_key=b"p" * channel.PQ_KEM_PUBLIC_KEY_LEN,
    )
    parsed = channel._parse_pq_hello(raw_unsigned + (b"s" * 64))
    assert parsed.offered_suites == (channel.PQ_SUITE_X25519_MLKEM768_V1,)
    assert parsed.kem_public_key == b"p" * channel.PQ_KEM_PUBLIC_KEY_LEN
    with pytest.raises(RuntimeError, match="bad PQ HELLO length"):
        channel._parse_pq_hello(raw_unsigned + (b"s" * 64) + b"trailing")
    with pytest.raises(ValueError, match="unique and canonically sorted"):
        channel._encode_pq_hello_unsigned(
            offered_suites=(1, 1),
            initiator_ed=b"e" * 32,
            initiator_x25519=b"x" * 32,
            nonce=b"n" * channel.NONCE_LEN,
            kem_public_key=b"p" * channel.PQ_KEM_PUBLIC_KEY_LEN,
        )


def test_legacy_hybrid_key_decoder_rejects_trailing_ambiguity() -> None:
    encoded = pq_hybrid.HybridKey(classical=b"classical", pq=b"pq").encode()
    assert pq_hybrid.HybridKey.decode(encoded).pq == b"pq"
    with pytest.raises(ValueError, match="trailing bytes"):
        pq_hybrid.HybridKey.decode(encoded + b"smuggled")


def test_key_confirmation_rejects_tamper_wrong_transcript_and_wrong_key() -> None:
    key = os.urandom(32)
    transcript = os.urandom(32)
    frame = channel._build_pq_confirmation(
        confirmation_key=key,
        transcript_hash=transcript,
        suite=channel.PQ_SUITE_X25519_MLKEM768_V1,
        role=b"I",
    )
    assert channel._verify_pq_confirmation(
        frame,
        confirmation_key=key,
        transcript_hash=transcript,
        suite=channel.PQ_SUITE_X25519_MLKEM768_V1,
        role=b"I",
    ) == frame[-32:]

    tampered = bytearray(frame)
    tampered[-1] ^= 1
    adversarial = (
        (bytes(tampered), key, transcript),
        (frame, os.urandom(32), transcript),
        (frame, key, os.urandom(32)),
    )
    for candidate, candidate_key, candidate_transcript in adversarial:
        with pytest.raises(RuntimeError, match="PQ key confirmation failed"):
            channel._verify_pq_confirmation(
                candidate,
                confirmation_key=candidate_key,
                transcript_hash=candidate_transcript,
                suite=channel.PQ_SUITE_X25519_MLKEM768_V1,
                role=b"I",
            )


@pytest.mark.asyncio
async def test_tampered_responder_key_confirmation_aborts_initiator(
    tmp_path: Path,
) -> None:
    """A framed MITM cannot make an unconfirmed PQ secret become a channel."""
    alice = load_or_create(tmp_path / "alice.key")
    bob = load_or_create(tmp_path / "bob.key")
    initiator_pair = await _connected_pair()
    responder_pair = await _connected_pair()
    ar, aw, proxy_from_alice, proxy_to_alice, *_ = initiator_pair
    proxy_from_bob, proxy_to_bob, br, bw, *_ = responder_pair

    initiate_task = asyncio.create_task(
        channel.initiate(
            ar,
            aw,
            alice,
            expected_responder_ed_pub=bob.public_bytes,
        )
    )
    respond_task = asyncio.create_task(channel.respond(br, bw, bob))
    responder_channel: channel.Channel | None = None
    try:
        await write_frame(proxy_to_bob, await read_frame(proxy_from_alice))
        await write_frame(proxy_to_alice, await read_frame(proxy_from_bob))
        await write_frame(proxy_to_bob, await read_frame(proxy_from_alice))
        responder_confirmation = bytearray(await read_frame(proxy_from_bob))
        responder_confirmation[-1] ^= 1
        await write_frame(proxy_to_alice, bytes(responder_confirmation))

        with pytest.raises(RuntimeError, match="PQ key confirmation failed"):
            await initiate_task
        responder_channel = await respond_task
        assert responder_channel.key_confirmed is True
    finally:
        for task in (initiate_task, respond_task):
            if not task.done():
                task.cancel()
        await asyncio.gather(initiate_task, respond_task, return_exceptions=True)
        if responder_channel is not None:
            await responder_channel.close()
        await _close_pair(initiator_pair)
        await _close_pair(responder_pair)


@pytest.mark.asyncio
async def test_missing_native_runtime_fails_before_any_wire_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alice = load_or_create(tmp_path / "alice.key")
    bob = load_or_create(tmp_path / "bob.key")
    pair = await _connected_pair()
    ar, aw, proxy_reader, _proxy_writer, *_ = pair
    monkeypatch.setattr(pqkem_native, "HAS_NATIVE", False)
    try:
        with pytest.raises(pq_hybrid.PQUnavailableError):
            await channel.initiate(
                ar,
                aw,
                alice,
                expected_responder_ed_pub=bob.public_bytes,
            )
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(read_frame(proxy_reader), timeout=0.05)
    finally:
        await _close_pair(pair)


@pytest.mark.asyncio
async def test_forced_classical_handshake_requires_double_explicit_policy(
    tmp_path: Path,
) -> None:
    alice = load_or_create(tmp_path / "alice.key")
    bob = load_or_create(tmp_path / "bob.key")
    pair = await _connected_pair()
    ar, aw, *_ = pair
    try:
        with pytest.raises(ValueError, match="requires allow_classical_downgrade=True"):
            await channel.initiate(
                ar,
                aw,
                alice,
                expected_responder_ed_pub=bob.public_bytes,
                force_classical_handshake=True,
            )
    finally:
        await _close_pair(pair)


def test_pq_capability_tracks_native_runtime_self_test(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert capabilities.PQ_HYBRID_HANDSHAKE_V1 in capabilities.advertised_capabilities()
    monkeypatch.setattr(pqkem_native, "runtime_is_usable", lambda: False)
    assert capabilities.PQ_HYBRID_HANDSHAKE_V1 not in capabilities.advertised_capabilities()


def test_native_runtime_self_test_fails_closed_on_abi_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert pqkem_native.runtime_is_usable()
    pqkem_native._runtime_self_test_cached.cache_clear()
    monkeypatch.setattr(pqkem_native, "HYBRID_CIPHERTEXT_LEN", 1119)
    try:
        assert pqkem_native.runtime_is_usable() is False
    finally:
        pqkem_native._runtime_self_test_cached.cache_clear()
