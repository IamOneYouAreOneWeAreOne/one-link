"""High-level fountain encoder / decoder over `ol_fountain` LT codes
(ADR-0015 — Phase B item 2).

The native crate exposes raw `LtEncoder` / `LtDecoder` classes and
packet-level `encode_packet` / `decode_packet` helpers. This adapter
wraps them with the call shapes the daemon's transfer pipeline +
swarm-distribution scheduler want: "encode N packets from this
plaintext", "decode this stream until reconstruction succeeds".

Why LT codes
------------

  - Receiver gets ANY sufficient subset of packets and reconstructs.
    No retransmit handshake; resilient to lossy transports + arbitrary
    reorderings + many-senders-one-receiver topologies.
  - Encoder is rateless — once the plaintext is encoded as a stream,
    arbitrarily many packets can be produced from it. Lets a sender
    keep emitting until the receiver signals "got it" or the link
    flatlines.
  - The Robust Soliton distribution (c=0.03, δ=0.05) gives ~1.05–1.10×
    overhead at typical chunk sizes.

When to use vs Reed-Solomon (`ol_erasure`)
------------------------------------------

  - **Erasure** (k+m fixed overhead): durability storage —
    "encode once, keep all shards, recover from any k of k+m".
  - **Fountain** (rateless): transport — "encode once, emit unbounded
    stream, receiver stops listening when they have enough".

A swarm download with N sources contributing different packets is
the canonical fountain win.
"""
from __future__ import annotations

import logging
from typing import Iterable, Iterator

log = logging.getLogger(__name__)

from one_link import fountain_native as _fn

# Public re-exports.
HAS_NATIVE = _fn.HAS_NATIVE
SYMBOL_LEN = _fn.SYMBOL_LEN
PACKET_HEADER_LEN = _fn.PACKET_HEADER_LEN
MAX_ENCODED_PER_CHUNK = _fn.MAX_ENCODED_PER_CHUNK


class FountainEncoder:
    """Encode a chunk's plaintext into a stream of LT-code packets.

    Constructed once per chunk. The encoder is stateful but
    cheap-to-instantiate; reuse across calls within a session.

    The output stream is **deterministic across senders** for a given
    chunk_id — two senders independently encoding the same plaintext
    with the same chunk_id produce the same packet bytes for the
    same symbol_id. That's the property that lets multi-source swarm
    download work: receivers can deduplicate across peers.
    """

    def __init__(
        self,
        chunk_id: bytes,
        plaintext: bytes,
        *,
        symbol_len: int = SYMBOL_LEN,
    ):
        if not isinstance(chunk_id, (bytes, bytearray)) or len(chunk_id) != 32:
            raise ValueError("chunk_id must be 32 bytes")
        if not plaintext:
            raise ValueError("plaintext must be non-empty")
        if symbol_len <= 0:
            raise ValueError("symbol_len must be positive")
        self.chunk_id = bytes(chunk_id)
        self.plaintext = bytes(plaintext)
        self.symbol_len = symbol_len
        self.source_length = len(plaintext)
        # k = ceil(plaintext_len / symbol_len), bounded by
        # MAX_ENCODED_PER_CHUNK. A chunk too big to encode raises
        # immediately so callers can pick a smaller chunk size or a
        # bigger symbol size.
        self.k = (len(plaintext) + symbol_len - 1) // symbol_len
        if self.k > MAX_ENCODED_PER_CHUNK:
            raise ValueError(
                f"chunk too big: k={self.k} > MAX_ENCODED_PER_CHUNK={MAX_ENCODED_PER_CHUNK}; "
                f"pick larger symbol_len or chunk the input first"
            )
        # Build the native LT encoder once.
        self._encoder = _fn.make_encoder(self.plaintext, symbol_len)

    def encode_one(self, symbol_id: int) -> bytes:
        """Emit a single on-wire packet for the given symbol_id.

        ``symbol_id`` is the seed that selects which source symbols
        the produced packet XORs together. Different IDs produce
        different packets; the same ID produces the same packet
        deterministically across senders.
        """
        if symbol_id < 0 or symbol_id > 0xFFFF_FFFF:
            raise ValueError("symbol_id must fit in u32")
        # Encoder produces the payload at this symbol_id.
        payload = self._encoder.encode_symbol(symbol_id)
        return _fn.encode_packet(
            self.chunk_id,
            self.k,
            symbol_id,
            self.source_length,
            payload,
        )

    def encode_stream(
        self,
        *,
        start: int = 0,
        count: int,
    ) -> Iterator[bytes]:
        """Yield ``count`` packets starting at ``symbol_id=start``.

        Useful when the caller already knows roughly how many
        packets they'll send (e.g. for ~10% overhead, count = 1.1*k).
        Receivers can decode after collecting any ~1.05–1.10×k
        packets thanks to the Robust Soliton distribution.
        """
        if count < 0:
            raise ValueError("count must be non-negative")
        for i in range(count):
            yield self.encode_one(start + i)


class FountainDecoder:
    """Reconstruct a chunk's plaintext from a stream of LT packets.

    Stateful: feed packets via ``ingest``; check completion via
    ``is_complete``; pull the result via ``plaintext()``. Tolerates
    duplicate packets (no-op), reorderings (irrelevant), and
    overshoot (extra packets after completion are ignored).
    """

    def __init__(
        self,
        chunk_id: bytes,
        k: int,
        source_length: int,
        *,
        symbol_len: int = SYMBOL_LEN,
    ):
        if not isinstance(chunk_id, (bytes, bytearray)) or len(chunk_id) != 32:
            raise ValueError("chunk_id must be 32 bytes")
        if k <= 0 or k > MAX_ENCODED_PER_CHUNK:
            raise ValueError(f"k must be in 1..={MAX_ENCODED_PER_CHUNK}")
        if source_length <= 0:
            raise ValueError("source_length must be positive")
        self.chunk_id = bytes(chunk_id)
        self.k = k
        self.source_length = source_length
        self.symbol_len = symbol_len
        self._decoder = _fn.make_decoder(k, symbol_len, source_length)
        self._complete = False

    def ingest(self, packet: bytes) -> bool:
        """Feed a single on-wire packet into the decoder.

        Returns True iff the decoder has now reconstructed the
        full plaintext (i.e. ``is_complete`` flipped to True).
        Returns False on duplicate packets, malformed packets,
        chunk_id mismatch, or insufficient evidence.
        """
        try:
            chunk_id, k, symbol_id, source_length, payload = _fn.decode_packet(packet)
        except Exception as exc:  # malformed packet
            log.debug("fountain: malformed packet ignored: %s", exc)
            return False
        if chunk_id != self.chunk_id:
            log.debug("fountain: packet for wrong chunk_id ignored")
            return False
        if k != self.k or source_length != self.source_length:
            log.debug("fountain: packet params mismatch (k/source_length)")
            return False
        try:
            # LtDecoder.ingest takes `(symbol_id, payload)` — it's
            # the inner symbol absorption, after the wire-frame has
            # already been parsed. The header parse + chunk_id + k
            # match are done above; here we just feed the symbol.
            became_complete = self._decoder.ingest(symbol_id, payload)
        except Exception as exc:
            log.debug("fountain: decoder rejected symbol %d: %s", symbol_id, exc)
            return False
        if not self._complete and (became_complete or self._decoder.is_complete()):
            self._complete = True
            return True
        return False

    def is_complete(self) -> bool:
        return self._complete

    def plaintext(self) -> bytes:
        """Return the reconstructed plaintext. Raises RuntimeError if
        decoding hasn't completed yet."""
        if not self._complete:
            raise RuntimeError("fountain decode not yet complete")
        # The native finish() consumes the decoder; cache the result
        # so subsequent calls don't error.
        if not hasattr(self, "_plaintext_cache"):
            self._plaintext_cache = self._decoder.finish()
        return self._plaintext_cache


def round_trip_chunk(
    chunk_id: bytes,
    plaintext: bytes,
    *,
    overhead: float = 1.10,
    symbol_len: int = SYMBOL_LEN,
) -> bytes:
    """Convenience: encode ``plaintext`` then decode it, exercising
    the round-trip with ``overhead × k`` packets. Used by tests +
    the smoke-test path; not for production where the actual stream
    is split across the wire."""
    enc = FountainEncoder(chunk_id, plaintext, symbol_len=symbol_len)
    dec = FountainDecoder(
        chunk_id, enc.k, len(plaintext), symbol_len=symbol_len,
    )
    target_packets = max(enc.k + 1, int(enc.k * overhead) + 1)
    for symbol_id in range(target_packets * 2):  # generous safety margin
        packet = enc.encode_one(symbol_id)
        if dec.ingest(packet):
            return dec.plaintext()
    raise RuntimeError(
        f"fountain round-trip failed to converge after "
        f"{target_packets * 2} packets (k={enc.k}, overhead={overhead})"
    )
