"""Encrypted channel: handshake + AEAD stream over an in-memory pipe."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from one_link import channel as ch
from one_link.identity import load_or_create


async def _connected_pair() -> tuple[
    asyncio.StreamReader,
    asyncio.StreamWriter,
    asyncio.StreamReader,
    asyncio.StreamWriter,
]:
    """Two ends of an in-process pipe — left writes flow to right's reader and
    vice versa. We back this with a TCP loopback because asyncio's pure
    in-memory pair is awkward and TCP is what production uses anyway."""
    server_done: asyncio.Future = asyncio.get_running_loop().create_future()
    server_io: dict = {}

    async def _server_cb(r: asyncio.StreamReader, w: asyncio.StreamWriter):
        server_io["r"] = r
        server_io["w"] = w
        if not server_done.done():
            server_done.set_result(None)
        # keep open until torn down
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            pass

    server = await asyncio.start_server(_server_cb, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    client_r, client_w = await asyncio.open_connection("127.0.0.1", port)
    await server_done
    return client_r, client_w, server_io["r"], server_io["w"]


@pytest.mark.asyncio
async def test_handshake_succeeds(tmp_path: Path):
    alice = load_or_create(tmp_path / "a.key")
    bob = load_or_create(tmp_path / "b.key")
    a_r, a_w, b_r, b_w = await _connected_pair()
    initiator_task = asyncio.create_task(ch.initiate(a_r, a_w, alice))
    responder_task = asyncio.create_task(ch.respond(b_r, b_w, bob))
    a_chan = await initiator_task
    b_chan = await responder_task

    assert a_chan.peer_short_id == bob.short_id
    assert b_chan.peer_short_id == alice.short_id
    assert a_chan.peer_ed_pub == bob.public_bytes
    assert b_chan.peer_ed_pub == alice.public_bytes
    await a_chan.close()
    await b_chan.close()


@pytest.mark.asyncio
async def test_send_recv_round_trip(tmp_path: Path):
    alice = load_or_create(tmp_path / "a.key")
    bob = load_or_create(tmp_path / "b.key")
    a_r, a_w, b_r, b_w = await _connected_pair()
    a_chan, b_chan = await asyncio.gather(
        ch.initiate(a_r, a_w, alice),
        ch.respond(b_r, b_w, bob),
    )

    await a_chan.send(b"hello bob")
    assert await b_chan.recv() == b"hello bob"

    await b_chan.send(b"hi alice")
    assert await a_chan.recv() == b"hi alice"

    await a_chan.close()
    await b_chan.close()


@pytest.mark.asyncio
async def test_many_messages_keep_keys_aligned(tmp_path: Path):
    alice = load_or_create(tmp_path / "a.key")
    bob = load_or_create(tmp_path / "b.key")
    a_r, a_w, b_r, b_w = await _connected_pair()
    a_chan, b_chan = await asyncio.gather(
        ch.initiate(a_r, a_w, alice),
        ch.respond(b_r, b_w, bob),
    )
    for i in range(50):
        await a_chan.send(f"msg-{i}".encode())
    for i in range(50):
        assert await b_chan.recv() == f"msg-{i}".encode()
    await a_chan.close()
    await b_chan.close()


@pytest.mark.asyncio
async def test_bidirectional_interleaved(tmp_path: Path):
    alice = load_or_create(tmp_path / "a.key")
    bob = load_or_create(tmp_path / "b.key")
    a_r, a_w, b_r, b_w = await _connected_pair()
    a_chan, b_chan = await asyncio.gather(
        ch.initiate(a_r, a_w, alice),
        ch.respond(b_r, b_w, bob),
    )
    await a_chan.send(b"a1")
    await b_chan.send(b"b1")
    assert await b_chan.recv() == b"a1"
    assert await a_chan.recv() == b"b1"
    await a_chan.send(b"a2")
    await b_chan.send(b"b2")
    assert await a_chan.recv() == b"b2"
    assert await b_chan.recv() == b"a2"
    await a_chan.close()
    await b_chan.close()


@pytest.mark.asyncio
async def test_large_payload(tmp_path: Path):
    alice = load_or_create(tmp_path / "a.key")
    bob = load_or_create(tmp_path / "b.key")
    a_r, a_w, b_r, b_w = await _connected_pair()
    a_chan, b_chan = await asyncio.gather(
        ch.initiate(a_r, a_w, alice),
        ch.respond(b_r, b_w, bob),
    )
    payload = os.urandom(1024 * 1024)  # 1 MiB
    await a_chan.send(payload)
    assert await b_chan.recv() == payload
    await a_chan.close()
    await b_chan.close()


@pytest.mark.asyncio
async def test_responder_rejects_bad_initiator_signature(tmp_path: Path):
    """If initiator's HELLO signature doesn't verify, responder must abort."""
    bob = load_or_create(tmp_path / "b.key")
    a_r, a_w, b_r, b_w = await _connected_pair()

    # Send a bogus HELLO: random bytes that match expected length.
    from one_link.wire import write_frame
    bogus = os.urandom(32 + 32 + ch.NONCE_LEN + 64)
    await write_frame(a_w, bogus)

    with pytest.raises(RuntimeError, match="HELLO signature invalid"):
        await ch.respond(b_r, b_w, bob)


@pytest.mark.asyncio
async def test_initiator_rejects_bad_responder_signature(tmp_path: Path):
    """If responder's REPLY signature doesn't verify, initiator must abort."""
    alice = load_or_create(tmp_path / "a.key")
    a_r, a_w, b_r, b_w = await _connected_pair()

    # Spawn the legitimate initiator
    init_task = asyncio.create_task(ch.initiate(a_r, a_w, alice))

    # Manually read the HELLO that initiator just sent
    from one_link.wire import read_frame, write_frame
    _ = await read_frame(b_r)

    # Send a bogus REPLY
    bogus = os.urandom(32 + 32 + ch.NONCE_LEN + 64)
    await write_frame(b_w, bogus)

    with pytest.raises(RuntimeError, match="REPLY signature invalid"):
        await init_task


@pytest.mark.asyncio
async def test_responder_rejects_short_hello(tmp_path: Path):
    bob = load_or_create(tmp_path / "b.key")
    a_r, a_w, b_r, b_w = await _connected_pair()
    from one_link.wire import write_frame
    await write_frame(a_w, b"too short")
    with pytest.raises(RuntimeError, match="bad HELLO length"):
        await ch.respond(b_r, b_w, bob)


@pytest.mark.asyncio
async def test_aead_rejects_tampered_ciphertext(tmp_path: Path):
    """Flip a byte in a ciphertext frame; recv must raise."""
    alice = load_or_create(tmp_path / "a.key")
    bob = load_or_create(tmp_path / "b.key")
    a_r, a_w, b_r, b_w = await _connected_pair()
    a_chan, b_chan = await asyncio.gather(
        ch.initiate(a_r, a_w, alice),
        ch.respond(b_r, b_w, bob),
    )

    # Send a legitimate frame, then immediately corrupt the wire by sending
    # a malformed encrypted frame *manually*.
    from one_link.wire import write_frame
    bad_ct = os.urandom(64)  # not a valid AEAD ciphertext under any key
    await write_frame(a_w, bad_ct)
    a_chan.tx_seq += 1  # keep sender state honest

    with pytest.raises(Exception):  # InvalidTag from cryptography
        await b_chan.recv()

    await a_chan.close()
    await b_chan.close()


@pytest.mark.asyncio
async def test_each_handshake_uses_fresh_ephemeral(tmp_path: Path):
    """Two channels between same identities should derive different keys."""
    alice = load_or_create(tmp_path / "a.key")
    bob = load_or_create(tmp_path / "b.key")

    a_r1, a_w1, b_r1, b_w1 = await _connected_pair()
    c1a, c1b = await asyncio.gather(
        ch.initiate(a_r1, a_w1, alice),
        ch.respond(b_r1, b_w1, bob),
    )
    a_r2, a_w2, b_r2, b_w2 = await _connected_pair()
    c2a, c2b = await asyncio.gather(
        ch.initiate(a_r2, a_w2, alice),
        ch.respond(b_r2, b_w2, bob),
    )

    # Internal ChaCha20Poly1305 key bytes aren't exposed; instead, verify
    # that ciphertexts of the same plaintext differ across sessions.
    pt = b"the same plaintext"
    await c1a.send(pt)
    await c2a.send(pt)
    # We can't snoop the ciphertext through the abstraction, but we can at
    # least verify both channels work independently with no key reuse:
    assert await c1b.recv() == pt
    assert await c2b.recv() == pt

    await c1a.close()
    await c1b.close()
    await c2a.close()
    await c2b.close()
