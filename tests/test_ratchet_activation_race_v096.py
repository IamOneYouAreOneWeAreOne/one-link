"""v0.9.6 — ratchet activation-race tolerance.

The Double Ratchet activation flips both directions of a Channel
when caps_sent + caps_received are both true. But the two ends of
a connection flip at slightly different wall-clock moments, and a
frame queued by the peer's send-side BEFORE peer's local activation
arrives at our recv-side AFTER our local activation. We then try
to decode a legacy AEAD ciphertext as a DR header → "unsupported
ratchet header version: <random byte>".

The fix: when DR is active and the header parse fails specifically
on version mismatch, fall back to the legacy AEAD path with the
same payload bytes. The two paths use disjoint keys (DR derived
from the chain root; legacy from the original handshake KDF), so
a successful decrypt under either is unambiguous — an attacker
forging a frame to bypass DR can't succeed because neither key
authenticates their content.

These tests pin the fallback's behavior + safety properties.
"""

from __future__ import annotations

import asyncio
import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import channel as ch
from one_link.channel import Channel, DR_CAP
from one_link.identity import Identity, fingerprint_of


def _new_identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname="x",
    )


def _make_stream_pair(loop):
    reader = asyncio.StreamReader(loop=loop)
    proto = asyncio.StreamReaderProtocol(reader, loop=loop)
    transport = _MemoryTransport(reader, proto, loop)
    writer = asyncio.StreamWriter(transport, proto, reader, loop)
    return reader, writer


class _MemoryTransport(asyncio.Transport):
    def __init__(self, reader, proto, loop):
        super().__init__()
        self._reader = reader
        self._closed = False

    def write(self, data: bytes) -> None:
        if not self._closed:
            self._reader.feed_data(bytes(data))

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._reader.feed_eof()

    def is_closing(self) -> bool: return self._closed
    def get_extra_info(self, name, default=None): return default
    def can_write_eof(self) -> bool: return True
    def write_eof(self) -> None: self.close()


def _connected_pipe():
    loop = asyncio.get_event_loop()
    a_reader, b_writer = _make_stream_pair(loop)
    b_reader, a_writer = _make_stream_pair(loop)
    return a_reader, a_writer, b_reader, b_writer


async def _activated_pair() -> tuple[Channel, Channel]:
    """Return a fully-activated Alice + Bob channel pair where
    DR is on for both directions."""
    me = _new_identity()
    them = _new_identity()
    ar, aw, br, bw = _connected_pipe()
    a_chan, b_chan = await asyncio.gather(
        ch.initiate(ar, aw, me),
        ch.respond(br, bw, them),
    )
    # Walk both sides through the caps-exchange dance.
    a_chan.note_caps_sent()
    a_chan.note_caps_received([DR_CAP])
    a_chan.maybe_activate_ratchet()
    b_chan.note_caps_sent()
    b_chan.note_caps_received([DR_CAP])
    b_chan.maybe_activate_ratchet()
    assert a_chan.is_ratchet_active and b_chan.is_ratchet_active
    return a_chan, b_chan


# ───────── activation-race tolerance ─────────────────────────────────

@pytest.mark.asyncio
async def test_dr_active_recv_falls_back_to_legacy_on_version_mismatch():
    """The race scenario: peer's send-side activated AFTER they
    queued a frame. They sent legacy. We're DR on recv. Receiving
    must NOT crash — we should fall back to legacy decode."""
    a_chan, b_chan = await _activated_pair()
    # Force Alice to send a LEGACY frame even though she's "activated".
    # We do this by calling the legacy send path directly instead of
    # going through the activated send().
    pt = b"voice-message-chunk-0"
    nonce = a_chan._nonce(a_chan.tx_seq)
    a_chan.tx_seq += 1
    legacy_ct = a_chan.tx_aead.encrypt(nonce, pt, a_chan._aad())
    from one_link.channel import write_frame
    await write_frame(a_chan.writer, legacy_ct)
    # Bob recvs in DR mode. The fallback should decode as legacy.
    out = await asyncio.wait_for(b_chan.recv(), timeout=2.0)
    assert out == pt


@pytest.mark.asyncio
async def test_dr_active_recv_handles_normal_dr_frames():
    """Sanity: post-fix, normal DR send/recv still works."""
    a_chan, b_chan = await _activated_pair()
    pt = b"hello world"
    await a_chan.send(pt)
    out = await asyncio.wait_for(b_chan.recv(), timeout=2.0)
    assert out == pt


@pytest.mark.asyncio
async def test_corrupt_dr_frame_raises_not_silent():
    """Corruption that LOOKS like a DR frame (correct version byte
    but bad ciphertext) must NOT trigger the fallback — that path
    is reserved for header-version mismatches. A bad CT under the
    legacy key would also fail, so we need to surface the original
    DR error."""
    a_chan, b_chan = await _activated_pair()
    # Build a frame with the right DR header version but garbage CT.
    from one_link.double_ratchet import Header as DRHeader
    header = DRHeader(v=1, flags=0, dh=b"\x00" * 32, pn=0, n=0)
    bad_payload = header.encode() + os.urandom(64)
    from one_link.channel import write_frame
    await write_frame(a_chan.writer, bad_payload)
    with pytest.raises(Exception):
        await asyncio.wait_for(b_chan.recv(), timeout=2.0)


@pytest.mark.asyncio
async def test_random_garbage_frame_raises():
    """Pure garbage that doesn't decode under EITHER path must
    raise, not return some accidental plaintext."""
    a_chan, b_chan = await _activated_pair()
    from one_link.channel import write_frame
    await write_frame(a_chan.writer, os.urandom(80))
    with pytest.raises(Exception):
        await asyncio.wait_for(b_chan.recv(), timeout=2.0)


@pytest.mark.asyncio
async def test_legacy_fallback_advances_legacy_counter_only():
    """When the fallback succeeds, ONLY the legacy rx_seq advances —
    the DR state's recv counter must NOT advance (otherwise the next
    real DR frame from the peer would be interpreted as 'skipped'
    and the chain would diverge)."""
    a_chan, b_chan = await _activated_pair()
    # Initial state.
    initial_rx_seq = b_chan.rx_seq
    initial_dr_n_recv = (
        b_chan._dr_state.recv_n if b_chan._dr_state else None
    )
    # Send a legacy frame from Alice's legacy path.
    pt = b"queued-before-dr"
    nonce = a_chan._nonce(a_chan.tx_seq)
    a_chan.tx_seq += 1
    legacy_ct = a_chan.tx_aead.encrypt(nonce, pt, a_chan._aad())
    from one_link.channel import write_frame
    await write_frame(a_chan.writer, legacy_ct)
    out = await asyncio.wait_for(b_chan.recv(), timeout=2.0)
    assert out == pt
    # rx_seq advanced by the fallback path.
    assert b_chan.rx_seq == initial_rx_seq + 1
    # DR receive counter UNCHANGED — the chain didn't see this msg.
    if initial_dr_n_recv is not None:
        assert b_chan._dr_state.recv_n == initial_dr_n_recv


@pytest.mark.asyncio
async def test_decode_ratchet_payload_helper_present():
    """The fix splits the synchronous DR-decode out of _recv_ratchet
    so recv() can try it on already-buffered bytes. Pin that the
    helper exists."""
    a_chan, b_chan = await _activated_pair()
    assert hasattr(b_chan, "_decode_ratchet_payload")
    assert callable(b_chan._decode_ratchet_payload)
