"""Authenticated Double-Ratchet cutover and downgrade rejection.

CAPS is the exact, transcript-bound final legacy frame. After activation the
channel accepts only ratchet frames; there is no heuristic legacy grace count.
Bob queues outbound sends until Alice's first authenticated ratchet frame
derives his send chain. These tests pin fail-closed framing and state atomicity.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
import os
import struct

import pytest
import pytest_asyncio
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import channel as ch
from one_link.channel import Channel, DR_CAP, DR_CUTOVER_CAP
from one_link.identity import Identity, fingerprint_of


ActivatedPairFactory = Callable[..., Awaitable[tuple[Channel, Channel]]]


def _new_identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk,
        public=pub_obj,
        public_bytes=pub_bytes,
        fingerprint=fp,
        short_id=fp[:8],
        hostname="x",
    )


def _make_stream_pair(loop):
    reader = asyncio.StreamReader(loop=loop)
    proto = asyncio.StreamReaderProtocol(reader, loop=loop)
    transport = _MemoryTransport(reader, proto, loop)
    proto.connection_made(transport)
    writer = asyncio.StreamWriter(transport, proto, reader, loop)
    return reader, writer


class _MemoryTransport(asyncio.Transport):
    def __init__(self, reader, proto, loop):
        super().__init__()
        self._reader = reader
        self._proto = proto
        self._closed = False

    def write(self, data: bytes) -> None:
        if not self._closed:
            self._reader.feed_data(bytes(data))

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._proto.connection_lost(None)

    def is_closing(self) -> bool:
        return self._closed

    def get_extra_info(self, name, default=None):
        return default

    def can_write_eof(self) -> bool:
        return True

    def write_eof(self) -> None:
        self.close()


def _connected_pipe():
    loop = asyncio.get_event_loop()
    a_reader, b_writer = _make_stream_pair(loop)
    b_reader, a_writer = _make_stream_pair(loop)
    return a_reader, a_writer, b_reader, b_writer


async def _activated_pair(
    *,
    send_commit: bool = True,
    cutover_v2: bool = True,
) -> tuple[Channel, Channel]:
    """Return a fully-activated Alice + Bob channel pair where
    DR is on for both directions."""
    me = _new_identity()
    them = _new_identity()
    ar, aw, br, bw = _connected_pipe()
    tasks = (
        asyncio.create_task(ch.initiate(ar, aw, me, expected_responder_ed_pub=them.public_bytes)),
        asyncio.create_task(ch.respond(br, bw, them)),
    )
    try:
        a_chan, b_chan = await asyncio.gather(*tasks)
    except BaseException:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        aw.close()
        bw.close()
        await asyncio.gather(aw.wait_closed(), bw.wait_closed(), return_exceptions=True)
        raise
    # Walk both sides through the caps-exchange dance.
    features = [DR_CAP, DR_CUTOVER_CAP] if cutover_v2 else [DR_CAP]
    a_chan.note_caps_sent()
    a_chan.note_caps_received(features)
    a_chan.maybe_activate_ratchet()
    b_chan.note_caps_sent()
    b_chan.note_caps_received(features)
    b_chan.maybe_activate_ratchet()
    assert a_chan.is_ratchet_active and b_chan.is_ratchet_active
    if send_commit and cutover_v2:
        assert await a_chan.send_ratchet_cutover_commit()
    return a_chan, b_chan


@pytest_asyncio.fixture
async def activated_pair() -> AsyncIterator[ActivatedPairFactory]:
    """Create activated channels and close all pairs before loop teardown."""
    channels: list[Channel] = []

    async def _open(
        *,
        send_commit: bool = True,
        cutover_v2: bool = True,
    ) -> tuple[Channel, Channel]:
        pair = await _activated_pair(send_commit=send_commit, cutover_v2=cutover_v2)
        channels.extend(pair)
        return pair

    try:
        yield _open
    finally:
        await asyncio.gather(*(channel.close() for channel in reversed(channels)))


# ───────── authenticated cutover boundary ────────────────────────────


@pytest.mark.asyncio
async def test_dr_active_recv_rejects_delayed_legacy_frame(
    activated_pair: ActivatedPairFactory,
):
    """Even authentic legacy ciphertext is invalid beyond CAPS."""
    a_chan, b_chan = await activated_pair(send_commit=False)
    initial_rx_seq = b_chan.rx_seq
    pt = b"voice-message-chunk-0"
    nonce = a_chan._nonce(a_chan.tx_seq)
    a_chan.tx_seq += 1
    legacy_ct = a_chan.tx_aead.encrypt(nonce, pt, a_chan._aad())
    from one_link.channel import write_frame

    await write_frame(a_chan.writer, legacy_ct)
    with pytest.raises(RuntimeError, match="ratchet frame too short"):
        await asyncio.wait_for(b_chan.recv(), timeout=2.0)
    assert b_chan.rx_seq == initial_rx_seq
    assert b_chan._dr_cutover_phase == "ratchet_wait_peer"


@pytest.mark.asyncio
async def test_dr_active_recv_handles_normal_dr_frames(
    activated_pair: ActivatedPairFactory,
):
    """Sanity: post-fix, normal DR send/recv still works."""
    a_chan, b_chan = await activated_pair()
    pt = b"hello world"
    await a_chan.send(pt)
    out = await asyncio.wait_for(b_chan.recv(), timeout=2.0)
    assert out == pt


@pytest.mark.asyncio
async def test_legacy_frame_with_valid_dr_header_prefix_is_not_a_downgrade_hatch(
    activated_pair: ActivatedPairFactory,
):
    """A crafted legacy ciphertext that parses as DR still fails DR AEAD."""
    a_chan, b_chan = await activated_pair(send_commit=False)
    from one_link.double_ratchet import Header as DRHeader
    from one_link.channel import write_frame

    # ChaCha ciphertext is plaintext XOR a deterministic keystream. Derive
    # that stream, then choose plaintext whose authenticated legacy
    # ciphertext starts with a syntactically valid DR header. DR parsing gets
    # all the way to AEAD InvalidTag. It must never retry the legacy key.
    nonce = a_chan._nonce(a_chan.tx_seq)
    desired = DRHeader(
        v=1,
        flags=0,
        dh=a_chan._dr_state.dh_send_pub,
        pn=0,
        n=0,
    ).encode()
    zero_ct = a_chan.tx_aead.encrypt(nonce, b"\x00" * len(desired), a_chan._aad())
    plaintext = bytes(a ^ b for a, b in zip(desired, zero_ct[: len(desired)]))
    legacy_ct = a_chan.tx_aead.encrypt(nonce, plaintext, a_chan._aad())
    assert legacy_ct.startswith(desired)
    a_chan.tx_seq += 1

    await write_frame(a_chan.writer, legacy_ct)
    with pytest.raises(InvalidTag):
        await asyncio.wait_for(b_chan.recv(), timeout=2.0)
    assert b_chan._dr_cutover_phase == "ratchet_wait_peer"

    # Failed authentication is atomic: the next genuine n=0 frame succeeds
    # and alone commits responder send readiness.
    await a_chan.send(b"authenticated-bootstrap")
    assert await b_chan.recv() == b"authenticated-bootstrap"
    assert b_chan._dr_cutover_phase == "ratchet_ready"


@pytest.mark.asyncio
async def test_corrupt_dr_frame_raises_not_silent(
    activated_pair: ActivatedPairFactory,
):
    """Corruption that looks like DR must surface the DR failure."""
    a_chan, b_chan = await activated_pair()
    # Build a frame with the right DR header version but garbage CT.
    from one_link.double_ratchet import Header as DRHeader

    header = DRHeader(v=1, flags=0, dh=b"\x00" * 32, pn=0, n=0)
    bad_payload = header.encode() + os.urandom(64)
    from one_link.channel import write_frame

    await write_frame(a_chan.writer, bad_payload)
    with pytest.raises(Exception):
        await asyncio.wait_for(b_chan.recv(), timeout=2.0)


@pytest.mark.asyncio
async def test_random_garbage_frame_raises(
    activated_pair: ActivatedPairFactory,
):
    """Pure garbage must raise, never reach the retired legacy path."""
    a_chan, b_chan = await activated_pair()
    from one_link.channel import write_frame

    await write_frame(a_chan.writer, os.urandom(80))
    with pytest.raises(Exception):
        await asyncio.wait_for(b_chan.recv(), timeout=2.0)


@pytest.mark.asyncio
async def test_post_cutover_receive_never_invokes_legacy_crypto_provider(
    activated_pair: ActivatedPairFactory,
):
    a_chan, b_chan = await activated_pair()

    class BrokenLegacyCipher:
        calls = 0

        def decrypt(self, *_args, **_kwargs):
            self.calls += 1
            raise RuntimeError("local crypto provider unavailable")

    broken = BrokenLegacyCipher()
    b_chan.rx_aead = broken  # type: ignore[assignment]
    from one_link.channel import write_frame

    await write_frame(a_chan.writer, b"short")
    with pytest.raises(RuntimeError, match="ratchet frame too short"):
        await asyncio.wait_for(b_chan.recv(), timeout=2.0)
    assert broken.calls == 0


@pytest.mark.asyncio
async def test_failed_post_boundary_legacy_does_not_advance_either_state(
    activated_pair: ActivatedPairFactory,
):
    """Rejected downgrade bytes cannot consume legacy or DR counters."""
    a_chan, b_chan = await activated_pair(send_commit=False)
    # Initial state.
    initial_rx_seq = b_chan.rx_seq
    initial_dr_n_recv = b_chan._dr_state.recv_n if b_chan._dr_state else None
    # Send a legacy frame from Alice's legacy path.
    pt = b"queued-before-dr"
    nonce = a_chan._nonce(a_chan.tx_seq)
    a_chan.tx_seq += 1
    legacy_ct = a_chan.tx_aead.encrypt(nonce, pt, a_chan._aad())
    from one_link.channel import write_frame

    await write_frame(a_chan.writer, legacy_ct)
    with pytest.raises(RuntimeError):
        await asyncio.wait_for(b_chan.recv(), timeout=2.0)
    assert b_chan.rx_seq == initial_rx_seq
    if initial_dr_n_recv is not None:
        assert b_chan._dr_state.recv_n == initial_dr_n_recv


@pytest.mark.asyncio
async def test_responder_queues_two_immediate_sends_until_authenticated_dr(
    activated_pair: ActivatedPairFactory,
):
    """The deterministic regression: Bob must not emit unlimited legacy."""
    a_chan, b_chan = await activated_pair()
    first = asyncio.create_task(b_chan.send(b"bob-1"))
    second = asyncio.create_task(b_chan.send(b"bob-2"))
    await asyncio.sleep(0)
    assert not first.done()
    assert not second.done()
    assert b_chan.tx_seq == b_chan._legacy_tx_final_seq

    await a_chan.send(b"alice-bootstrap")
    assert await b_chan.recv() == b"alice-bootstrap"
    assert b_chan._dr_cutover_commit_received
    await asyncio.wait_for(asyncio.gather(first, second), timeout=2.0)

    assert await a_chan.recv() == b"bob-1"
    assert await a_chan.recv() == b"bob-2"
    assert b_chan.tx_seq == b_chan._legacy_tx_final_seq


@pytest.mark.asyncio
async def test_responder_commit_noop_cannot_deadlock_queued_send_lock(
    activated_pair: ActivatedPairFactory,
):
    a_chan, b_chan = await activated_pair(send_commit=False)
    bob_send = asyncio.create_task(b_chan.send(b"queued-behind-cutover"))
    await asyncio.sleep(0)
    assert not bob_send.done()

    # The daemon invokes this after activation on both roles. Bob's no-op must
    # return without acquiring the send lock held by his queued application.
    assert not await asyncio.wait_for(b_chan.send_ratchet_cutover_commit(), timeout=0.2)

    assert await a_chan.send_ratchet_cutover_commit()
    bob_receive = asyncio.create_task(b_chan.recv())
    await asyncio.wait_for(b_chan._dr_send_ready.wait(), timeout=2.0)
    await asyncio.wait_for(bob_send, timeout=2.0)
    assert await a_chan.recv() == b"queued-behind-cutover"

    await a_chan.send(b"finish-recv")
    assert await asyncio.wait_for(bob_receive, timeout=2.0) == b"finish-recv"


@pytest.mark.asyncio
async def test_simultaneous_first_sends_complete_without_downgrade(
    activated_pair: ActivatedPairFactory,
):
    a_chan, b_chan = await activated_pair()
    alice_send = asyncio.create_task(a_chan.send(b"alice-simultaneous"))
    bob_send = asyncio.create_task(b_chan.send(b"bob-simultaneous"))
    await asyncio.sleep(0)
    assert not bob_send.done()

    assert await b_chan.recv() == b"alice-simultaneous"
    await asyncio.wait_for(asyncio.gather(alice_send, bob_send), timeout=2.0)
    assert await a_chan.recv() == b"bob-simultaneous"


@pytest.mark.asyncio
async def test_concurrent_bidirectional_ratchet_mutations_are_serialized(
    activated_pair: ActivatedPairFactory,
):
    a_chan, b_chan = await activated_pair()
    # Consume the internal commit and one app frame so Bob is fully ready.
    await a_chan.send(b"prime")
    assert await b_chan.recv() == b"prime"

    for index in range(100):
        a_payload = f"a-{index}".encode()
        b_payload = f"b-{index}".encode()
        a_send = asyncio.create_task(a_chan.send(a_payload))
        b_send = asyncio.create_task(b_chan.send(b_payload))
        a_receive = asyncio.create_task(a_chan.recv())
        b_receive = asyncio.create_task(b_chan.recv())
        await asyncio.wait_for(asyncio.gather(a_send, b_send), timeout=2.0)
        received_by_a, received_by_b = await asyncio.wait_for(
            asyncio.gather(a_receive, b_receive),
            timeout=2.0,
        )
        assert received_by_a == b_payload
        assert received_by_b == a_payload


@pytest.mark.asyncio
async def test_v1_peer_compatibility_waits_for_first_application_dr(
    activated_pair: ActivatedPairFactory,
):
    """No v2 marker is sent to an older DR-v1 peer that cannot parse it."""
    a_chan, b_chan = await activated_pair(cutover_v2=False)
    assert not await a_chan.send_ratchet_cutover_commit()
    bob_send = asyncio.create_task(b_chan.send(b"old-peer-compatible-response"))
    await asyncio.sleep(0)
    assert not bob_send.done()

    await a_chan.send(b"first-v1-application-frame")
    assert await b_chan.recv() == b"first-v1-application-frame"
    await asyncio.wait_for(bob_send, timeout=2.0)
    assert await a_chan.recv() == b"old-peer-compatible-response"
    assert not a_chan._dr_cutover_commit_sent
    assert not b_chan._dr_cutover_commit_received


@pytest.mark.asyncio
async def test_authenticated_commit_with_wrong_boundary_fails_waiters_closed(
    activated_pair: ActivatedPairFactory,
):
    from one_link.double_ratchet import encrypt as dr_encrypt
    from one_link.channel import write_frame

    a_chan, b_chan = await activated_pair(send_commit=False)
    waiting = asyncio.create_task(b_chan.send(b"must-not-escape"))
    await asyncio.sleep(0)

    bad_commit = (
        ch.DR_CUTOVER_COMMIT_PREFIX
        + a_chan.transcript_hash
        + struct.pack(
            ">QQ",
            a_chan._legacy_tx_final_seq + 1,
            a_chan._legacy_rx_final_seq,
        )
    )
    header, ciphertext = dr_encrypt(
        a_chan._dr_state,
        bad_commit,
        ad=a_chan.transcript_hash,
    )
    await write_frame(a_chan.writer, header.encode() + ciphertext)
    with pytest.raises(RuntimeError, match="legacy sequence mismatch"):
        await b_chan.recv()
    with pytest.raises(RuntimeError, match="cutover failed"):
        await asyncio.wait_for(waiting, timeout=2.0)
    assert b_chan._dr_cutover_phase == "failed"


@pytest.mark.asyncio
async def test_tampered_first_dr_does_not_release_responder_send_queue(
    activated_pair: ActivatedPairFactory,
):
    from one_link.double_ratchet import encrypt as dr_encrypt
    from one_link.channel import write_frame

    a_chan, b_chan = await activated_pair(send_commit=False)
    bob_send = asyncio.create_task(b_chan.send(b"held-until-authenticated"))
    await asyncio.sleep(0)

    header, ciphertext = dr_encrypt(
        a_chan._dr_state,
        b"forged-in-transit",
        ad=a_chan.transcript_hash,
    )
    tampered = bytearray(header.encode() + ciphertext)
    tampered[-1] ^= 0x01
    await write_frame(a_chan.writer, bytes(tampered))
    with pytest.raises(InvalidTag):
        await b_chan.recv()
    await asyncio.sleep(0)
    assert not bob_send.done()
    assert b_chan._dr_cutover_phase == "ratchet_wait_peer"

    # Alice's next frame is n=1. Bob can authenticate it via bounded skipped
    # key derivation; only that successful frame releases the queued send.
    await a_chan.send(b"valid-after-tamper")
    assert await b_chan.recv() == b"valid-after-tamper"
    await asyncio.wait_for(bob_send, timeout=2.0)
    assert await a_chan.recv() == b"held-until-authenticated"


@pytest.mark.asyncio
async def test_reordered_first_dr_frame_is_authenticated_before_commit(
    activated_pair: ActivatedPairFactory,
):
    from one_link.double_ratchet import encrypt as dr_encrypt
    from one_link.channel import write_frame

    a_chan, b_chan = await activated_pair(send_commit=False)
    header0, ciphertext0 = dr_encrypt(
        a_chan._dr_state,
        b"first-on-chain",
        ad=a_chan.transcript_hash,
    )
    header1, ciphertext1 = dr_encrypt(
        a_chan._dr_state,
        b"second-on-chain",
        ad=a_chan.transcript_hash,
    )
    bob_send = asyncio.create_task(b_chan.send(b"response"))

    await write_frame(a_chan.writer, header1.encode() + ciphertext1)
    assert await b_chan.recv() == b"second-on-chain"
    await asyncio.wait_for(bob_send, timeout=2.0)
    assert await a_chan.recv() == b"response"

    # The delayed n=0 frame consumes the authenticated skipped key exactly once.
    await write_frame(a_chan.writer, header0.encode() + ciphertext0)
    assert await b_chan.recv() == b"first-on-chain"
    await write_frame(a_chan.writer, header0.encode() + ciphertext0)
    with pytest.raises(RuntimeError, match="replayed message"):
        await b_chan.recv()


@pytest.mark.asyncio
async def test_close_wakes_responder_send_waiters_fail_closed(
    activated_pair: ActivatedPairFactory,
):
    _a_chan, b_chan = await activated_pair()
    waiting = asyncio.create_task(b_chan.send(b"never-downgrade"))
    await asyncio.sleep(0)
    assert not waiting.done()

    await b_chan.close()
    with pytest.raises(RuntimeError, match="channel closed"):
        await asyncio.wait_for(waiting, timeout=2.0)


@pytest.mark.asyncio
async def test_reconnected_channels_have_independent_cutover_barriers(
    activated_pair: ActivatedPairFactory,
):
    a1, b1 = await activated_pair()
    a2, b2 = await activated_pair()
    send1 = asyncio.create_task(b1.send(b"session-one"))
    send2 = asyncio.create_task(b2.send(b"session-two"))

    await a1.send(b"bootstrap-one")
    assert await b1.recv() == b"bootstrap-one"
    await asyncio.wait_for(send1, timeout=2.0)
    await asyncio.sleep(0)
    assert not send2.done()
    assert await a1.recv() == b"session-one"

    await a2.send(b"bootstrap-two")
    assert await b2.recv() == b"bootstrap-two"
    await asyncio.wait_for(send2, timeout=2.0)
    assert await a2.recv() == b"session-two"


@pytest.mark.asyncio
async def test_decode_ratchet_payload_helper_present(
    activated_pair: ActivatedPairFactory,
):
    """The synchronous authenticated DR decoder remains explicit."""
    _a_chan, b_chan = await activated_pair()
    assert hasattr(b_chan, "_decode_ratchet_payload")
    assert callable(b_chan._decode_ratchet_payload)


def test_cutover_v2_is_advertised_as_transport_capability() -> None:
    from one_link.capabilities import (
        DOUBLE_RATCHET_CUTOVER_V2,
        LOCAL_CAPABILITIES,
        TRANSPORT_LAYER_CAPS,
    )

    assert DR_CUTOVER_CAP == DOUBLE_RATCHET_CUTOVER_V2
    assert DOUBLE_RATCHET_CUTOVER_V2 in LOCAL_CAPABILITIES
    assert DOUBLE_RATCHET_CUTOVER_V2 in TRANSPORT_LAYER_CAPS
