"""v0.20.7 — traffic-shaping primitive (cover frames + fixed size).

Even with sealed sender + onion routing + channel AEAD, a wire-
watching adversary can correlate by timing (burst patterns) and
size (chat vs file). The mitigation is fixed-rate constant-size
shaped frames: COVER fills gaps in real traffic, REAL fragments
across multiple frames if longer than one body capacity.

These tests pin:
  - Frame is exactly ``frame_size`` bytes regardless of payload
  - SOLO (small payload) round-trips through wrap+feed
  - Multi-frame fragmentation: HEAD + MIDs + TAIL reassembles
    to original
  - COVER frames are dropped silently by Reassembler
  - Cover and real frames are indistinguishable at fixed size
    (the desired property — same length on the wire)
  - Channel-desync sequences (TAIL without HEAD, etc.) raise
  - Frame-size mismatch between shaper and reassembler raises
  - Out-of-bounds frame-size rejected at construction
"""
from __future__ import annotations

import os

import pytest

from one_link import traffic_shaper as ts


# ── basic frame structure ──────────────────────────────────────────


def test_cover_frame_is_fixed_size():
    s = ts.Shaper(frame_size=512)
    f = s.cover()
    assert len(f.raw) == 512
    assert f.kind == ts.KIND_COVER


def test_solo_real_frame_is_fixed_size():
    s = ts.Shaper(frame_size=512)
    [f] = s.wrap_real(b"short msg")
    assert len(f.raw) == 512
    assert f.kind == ts.KIND_REAL_SOLO
    assert f.body == b"short msg"


def test_cover_and_real_indistinguishable_size():
    """Wire-pattern privacy: cover frames must be exactly the same
    length as real frames. Anyone watching the wire sees only
    'frames at rate R, size S' regardless of conversation state."""
    s = ts.Shaper(frame_size=1024)
    cover = s.cover()
    [real] = s.wrap_real(b"payload")
    assert len(cover.raw) == len(real.raw) == 1024


# ── round-trips ────────────────────────────────────────────────────


def test_solo_round_trip():
    s = ts.Shaper(frame_size=256)
    r = ts.Reassembler(frame_size=256)
    payload = b"hello, this is a short payload that fits one body"
    [frame] = s.wrap_real(payload)
    out = r.feed(frame)
    assert out == payload


def test_multi_frame_fragmentation_round_trip():
    s = ts.Shaper(frame_size=128)
    r = ts.Reassembler(frame_size=128)
    body_cap = ts._max_body_len(128)
    payload = os.urandom(body_cap * 4 + 17)  # 4-and-a-bit fragments
    frames = s.wrap_real(payload)
    assert len(frames) == 5  # HEAD + 3 MID + TAIL
    assert frames[0].kind == ts.KIND_REAL_HEAD
    assert frames[-1].kind == ts.KIND_REAL_TAIL
    for mid in frames[1:-1]:
        assert mid.kind == ts.KIND_REAL_MID
    # Reassemble.
    out = None
    for frame in frames:
        result = r.feed(frame)
        if result is not None:
            out = result
    assert out == payload


def test_two_frame_fragmentation():
    """Edge case: payload exactly straddles two frames.
    HEAD + TAIL (no MIDs)."""
    s = ts.Shaper(frame_size=64)
    r = ts.Reassembler(frame_size=64)
    body_cap = ts._max_body_len(64)
    payload = os.urandom(body_cap + 10)
    frames = s.wrap_real(payload)
    assert len(frames) == 2
    assert frames[0].kind == ts.KIND_REAL_HEAD
    assert frames[1].kind == ts.KIND_REAL_TAIL
    out = r.feed(frames[0])
    assert out is None
    out = r.feed(frames[1])
    assert out == payload


def test_cover_frames_dropped():
    """COVER frames return None from feed, don't disrupt real-flow
    state."""
    s = ts.Shaper(frame_size=256)
    r = ts.Reassembler(frame_size=256)
    payload = b"real msg"
    [real] = s.wrap_real(payload)
    cover = s.cover()
    # Cover before real: still works.
    assert r.feed(cover) is None
    out = r.feed(real)
    assert out == payload
    # Cover after real: still works.
    assert r.feed(cover) is None


def test_cover_frames_interleaved_with_fragments():
    """Real-world flow: cover frames fill gaps BETWEEN HEAD and TAIL
    when the shaping scheduler ticks faster than real frames arrive.
    Reassembly must tolerate this — COVER drops silently while the
    fragment chain stays open."""
    s = ts.Shaper(frame_size=64)
    r = ts.Reassembler(frame_size=64)
    body_cap = ts._max_body_len(64)
    payload = os.urandom(body_cap * 3 + 5)
    frames = s.wrap_real(payload)
    sequence = []
    for f in frames:
        sequence.append(f)
        sequence.append(s.cover())  # one cover after each real
    out = None
    for f in sequence:
        r_out = r.feed(f)
        if r_out is not None:
            out = r_out
    assert out == payload


def test_back_to_back_payloads_round_trip():
    """Two distinct payloads through one Reassembler: the second
    must NOT collide with the first's buffer."""
    s = ts.Shaper(frame_size=128)
    r = ts.Reassembler(frame_size=128)
    p1 = os.urandom(50)
    p2 = os.urandom(300)  # multi-frame
    frames = s.wrap_real(p1) + s.wrap_real(p2)
    outputs = []
    for f in frames:
        out = r.feed(f)
        if out is not None:
            outputs.append(out)
    assert outputs == [p1, p2]


# ── desync detection ───────────────────────────────────────────────


def test_tail_without_head_raises():
    s = ts.Shaper(frame_size=128)
    r = ts.Reassembler(frame_size=128)
    body_cap = ts._max_body_len(128)
    [head, tail] = s.wrap_real(os.urandom(body_cap + 5))
    # Feeding TAIL without prior HEAD desyncs.
    with pytest.raises(ValueError, match="without prior HEAD"):
        r.feed(tail)


def test_mid_without_head_raises():
    s = ts.Shaper(frame_size=64)
    r = ts.Reassembler(frame_size=64)
    body_cap = ts._max_body_len(64)
    frames = s.wrap_real(os.urandom(body_cap * 3 + 5))
    mid = frames[1]
    with pytest.raises(ValueError, match="without prior HEAD"):
        r.feed(mid)


def test_solo_mid_fragment_chain_raises():
    """Receiving a SOLO while a fragment chain is open is a desync."""
    s = ts.Shaper(frame_size=64)
    r = ts.Reassembler(frame_size=64)
    body_cap = ts._max_body_len(64)
    frames = s.wrap_real(os.urandom(body_cap * 2 + 5))
    [solo] = s.wrap_real(b"x")
    r.feed(frames[0])  # HEAD opens the chain
    with pytest.raises(ValueError, match="mid-fragment-chain"):
        r.feed(solo)


def test_double_head_raises():
    s = ts.Shaper(frame_size=64)
    r = ts.Reassembler(frame_size=64)
    body_cap = ts._max_body_len(64)
    f1 = s.wrap_real(os.urandom(body_cap * 2 + 5))
    f2 = s.wrap_real(os.urandom(body_cap * 2 + 5))
    r.feed(f1[0])  # HEAD opens
    with pytest.raises(ValueError, match="mid-fragment-chain"):
        r.feed(f2[0])  # second HEAD = desync


def test_frame_size_mismatch_raises():
    s = ts.Shaper(frame_size=128)
    r = ts.Reassembler(frame_size=256)  # different size
    [solo] = s.wrap_real(b"x")
    with pytest.raises(ValueError, match="frame_size mismatch"):
        r.feed(solo)


def test_invalid_frame_size_at_construction():
    with pytest.raises(ValueError):
        ts.Shaper(frame_size=10)  # below MIN
    with pytest.raises(ValueError):
        ts.Shaper(frame_size=ts.MAX_FRAME_SIZE + 1)
    with pytest.raises(ValueError):
        ts.Reassembler(frame_size=10)


def test_unknown_kind_raises():
    """A wire-tampered frame with kind=99 (or any unknown) raises
    so the channel can tear down rather than silently mis-frame."""
    s = ts.Shaper(frame_size=64)
    r = ts.Reassembler(frame_size=64)
    [solo] = s.wrap_real(b"x")
    bad_raw = bytes([99]) + solo.raw[1:]  # corrupt kind byte
    bad = ts.ShapedFrame(raw=bad_raw, frame_size=64)
    with pytest.raises(ValueError, match="unknown frame kind"):
        r.feed(bad)


def test_payload_at_body_capacity_is_solo():
    """A payload exactly equal to the per-frame body capacity should
    be a single SOLO frame, not HEAD+TAIL."""
    s = ts.Shaper(frame_size=64)
    body_cap = ts._max_body_len(64)
    frames = s.wrap_real(os.urandom(body_cap))
    assert len(frames) == 1
    assert frames[0].kind == ts.KIND_REAL_SOLO


def test_payload_one_byte_over_capacity_is_two_frames():
    s = ts.Shaper(frame_size=64)
    body_cap = ts._max_body_len(64)
    frames = s.wrap_real(os.urandom(body_cap + 1))
    assert len(frames) == 2
    assert frames[0].kind == ts.KIND_REAL_HEAD
    assert frames[1].kind == ts.KIND_REAL_TAIL


def test_empty_payload_is_solo():
    s = ts.Shaper(frame_size=64)
    r = ts.Reassembler(frame_size=64)
    [f] = s.wrap_real(b"")
    assert f.kind == ts.KIND_REAL_SOLO
    assert r.feed(f) == b""
