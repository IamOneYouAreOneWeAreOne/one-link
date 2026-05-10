"""Traffic shaping — defeat timing + size correlation analysis.

Sealed Sender hides WHO sent; onion routing hides the path; the
channel AEAD hides content. But an adversary watching the wire can
still correlate by **timing** and **size**:

  - Burst of 5 frames from peer A immediately followed by 5 frames
    arriving at peer B = "A is talking to B right now."
  - Frame sizes (small for chat, big for files) leak conversation
    type even when content is encrypted.

The standard mitigation is **traffic shaping**: emit frames at a
constant rate (regardless of whether there's real content) and at
a fixed size (regardless of payload length). The wire pattern is
indistinguishable whether the user is having a heated argument,
sending a 4 GB video, or has the daemon idle in their pocket.

Bundle 41 ships the primitive:

  - ``ShapedFrame`` — a fixed-size wire frame with a 1-byte kind
    tag (REAL=1 / COVER=0), a 2-byte length prefix, the payload,
    and PKCS#7-style zero padding to the frame ceiling.

  - ``Shaper`` — wraps real-payload bytes into a list of REAL frames
    (fragmenting if the payload exceeds the per-frame body capacity)
    and emits COVER frames on demand. The caller integrates with
    its own scheduler; the algorithm itself is sync + deterministic.

  - ``Reassembler`` — receives shaped frames in order, drops COVERs,
    reassembles fragmented REALs, yields original bytes.

A future bundle wires this to the actual channel.send loop with an
asyncio timer that fires every 1/rate seconds, popping a real
frame off a queue or emitting a COVER if the queue is empty.

Wire format (per shaped frame, fixed size = ``frame_size``)
----------------------------------------------------------

  [u8 kind]                  # 0 = COVER, 1 = REAL_HEAD, 2 = REAL_MID,
                             # 3 = REAL_TAIL, 4 = REAL_SOLO
  [u16 body_len]             # length of meaningful payload bytes
  [body: variable]
  [zero padding to frame_size]

The kind tag distinguishes:
  - SOLO: the entire payload fits in one frame.
  - HEAD/MID/TAIL: the payload spans multiple frames; reassembly
    walks HEAD → MID* → TAIL.

A peer that receives a COVER drops it. A peer that receives an
out-of-order or incomplete fragment chain raises (the channel's
underlying ordering guarantee is the caller's problem).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator, Optional


KIND_COVER = 0
KIND_REAL_HEAD = 1
KIND_REAL_MID = 2
KIND_REAL_TAIL = 3
KIND_REAL_SOLO = 4

# Header overhead: 1-byte kind + 2-byte length.
HEADER_LEN = 1 + 2

# Frame-size sanity bounds. Too small → tons of fragmentation
# overhead; too large → padding waste for small chat. 1024 is a
# reasonable default that fits one MTU comfortably and pads a
# typical short chat to ~1KB without burning much.
DEFAULT_FRAME_SIZE = 1024
MIN_FRAME_SIZE = 64       # at minimum, header + 1 body byte + some pad
MAX_FRAME_SIZE = 1 << 20  # 1 MiB cap — preserves "fixed size" while
                           # allowing big-file transports to dial up


def _max_body_len(frame_size: int) -> int:
    return frame_size - HEADER_LEN


def _validate_frame_size(frame_size: int) -> None:
    if not (MIN_FRAME_SIZE <= frame_size <= MAX_FRAME_SIZE):
        raise ValueError(
            f"frame_size must be {MIN_FRAME_SIZE}..{MAX_FRAME_SIZE} "
            f"bytes, got {frame_size}"
        )


@dataclass(frozen=True)
class ShapedFrame:
    """A serialized fixed-size frame ready for the wire. The
    ``raw`` bytes are exactly ``frame_size`` long; the caller
    wraps them in the existing channel AEAD before transmission."""
    raw: bytes
    frame_size: int

    @property
    def kind(self) -> int:
        return self.raw[0]

    @property
    def body(self) -> bytes:
        body_len = struct.unpack(">H", self.raw[1:3])[0]
        return self.raw[3:3 + body_len]


# ── Shaper (sender side) ───────────────────────────────────────────


class Shaper:
    """Fragment + pad real payloads into fixed-size shaped frames.
    Stateless — call ``wrap_real`` per real payload, ``cover`` per
    cover beat. Caller's scheduler decides emission order."""

    def __init__(self, frame_size: int = DEFAULT_FRAME_SIZE):
        _validate_frame_size(frame_size)
        self.frame_size = frame_size
        self._max_body = _max_body_len(frame_size)

    def cover(self) -> ShapedFrame:
        """Mint a COVER frame. Cheap; emit one per scheduler tick
        whenever the real-payload queue is empty."""
        body = b""  # cover frames carry no body — purely shaping noise
        return self._compose(KIND_COVER, body)

    def wrap_real(self, payload: bytes) -> list[ShapedFrame]:
        """Fragment ``payload`` into ShapedFrames. Returns a list
        of 1+ frames (HEAD + 0 or more MIDs + TAIL, OR a single
        SOLO if it fits in one body)."""
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("payload must be bytes")
        if len(payload) <= self._max_body:
            return [self._compose(KIND_REAL_SOLO, bytes(payload))]
        # Multi-frame: HEAD + MIDs* + TAIL.
        frames: list[ShapedFrame] = []
        chunks = [
            payload[i:i + self._max_body]
            for i in range(0, len(payload), self._max_body)
        ]
        for i, chunk in enumerate(chunks):
            if i == 0:
                kind = KIND_REAL_HEAD
            elif i == len(chunks) - 1:
                kind = KIND_REAL_TAIL
            else:
                kind = KIND_REAL_MID
            frames.append(self._compose(kind, bytes(chunk)))
        return frames

    def _compose(self, kind: int, body: bytes) -> ShapedFrame:
        if len(body) > self._max_body:
            raise ValueError(
                f"body {len(body)} exceeds per-frame max {self._max_body}"
            )
        header = bytes([kind]) + struct.pack(">H", len(body))
        pad_len = self.frame_size - len(header) - len(body)
        raw = header + body + b"\x00" * pad_len
        assert len(raw) == self.frame_size
        return ShapedFrame(raw=raw, frame_size=self.frame_size)


# ── Reassembler (receiver side) ───────────────────────────────────


class Reassembler:
    """Stateful receiver: walks a sequence of shaped frames + emits
    reassembled real-payload bytes. COVER frames are silently
    dropped. Out-of-order / illegal kind sequences raise so the
    caller can tear down the channel rather than silently mis-frame."""

    def __init__(self, frame_size: int = DEFAULT_FRAME_SIZE):
        _validate_frame_size(frame_size)
        self.frame_size = frame_size
        self._buf: list[bytes] = []
        self._in_fragment = False

    def feed(self, frame: ShapedFrame) -> Optional[bytes]:
        """Consume one shaped frame. Returns reassembled bytes when
        a complete REAL message has arrived; None when the frame
        was a COVER, a HEAD, or a MID (still accumulating)."""
        if frame.frame_size != self.frame_size:
            raise ValueError(
                f"frame_size mismatch: shaper={self.frame_size}, "
                f"frame={frame.frame_size}"
            )
        if len(frame.raw) != self.frame_size:
            raise ValueError(
                f"frame raw length {len(frame.raw)} != {self.frame_size}"
            )
        kind = frame.kind
        body = frame.body
        if kind == KIND_COVER:
            return None
        if kind == KIND_REAL_SOLO:
            if self._in_fragment:
                raise ValueError(
                    "received SOLO mid-fragment-chain; channel desync"
                )
            return body
        if kind == KIND_REAL_HEAD:
            if self._in_fragment:
                raise ValueError(
                    "received HEAD mid-fragment-chain; channel desync"
                )
            self._buf = [body]
            self._in_fragment = True
            return None
        if kind == KIND_REAL_MID:
            if not self._in_fragment:
                raise ValueError(
                    "received MID without prior HEAD; channel desync"
                )
            self._buf.append(body)
            return None
        if kind == KIND_REAL_TAIL:
            if not self._in_fragment:
                raise ValueError(
                    "received TAIL without prior HEAD; channel desync"
                )
            self._buf.append(body)
            full = b"".join(self._buf)
            self._buf = []
            self._in_fragment = False
            return full
        raise ValueError(f"unknown frame kind: {kind}")
