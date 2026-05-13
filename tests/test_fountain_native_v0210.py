"""ADR-0015 algebraic-correctness tests for ``one_link.fountain_native``.

LT fountain codes:

- module loadability + version + ADR constants
- encoder K computed correctly + deterministic encoding
- decoder round trip at small K
- decoder round trip at K=64 (the common chunk size)
- packet wire-format encode/decode is the identity
- decode at 5% packet loss completes (sanity)
"""

from __future__ import annotations

import hashlib
import random

import pytest

from one_link import fountain_native

pytestmark = pytest.mark.skipif(
    not fountain_native.HAS_NATIVE,
    reason="one_link_native not installed; run `cd native && maturin develop --release`",
)


def _det_buf(seed: int, size: int) -> bytes:
    """Deterministic non-byte-periodic buffer.

    Uses BLAKE3 stream-mode (or SHA-256 keyed) so successive 1 KiB
    symbols are guaranteed distinct (the source for the fountain encoder
    needs unique symbols or even-degree XOR collapses to zero).
    """
    out = bytearray()
    counter = 0
    while len(out) < size:
        block = hashlib.sha256(f"{seed}:{counter}".encode()).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:size])


def test_module_metadata() -> None:
    assert fountain_native.NATIVE_VERSION is not None
    assert fountain_native.PACKET_HEADER_LEN == 44
    assert fountain_native.MAX_ENCODED_PER_CHUNK == 2048
    assert fountain_native.SOLITON_C == pytest.approx(0.03)
    assert fountain_native.SOLITON_DELTA == pytest.approx(0.05)


def test_encoder_k_computed_correctly() -> None:
    buf = _det_buf(0x42, 4096)
    enc = fountain_native.make_encoder(buf)
    assert enc.k == 4
    assert enc.symbol_len == fountain_native.SYMBOL_LEN
    assert enc.source_len == 4096


def test_encoder_deterministic() -> None:
    buf = _det_buf(0x99, 4096)
    enc = fountain_native.make_encoder(buf)
    a = enc.encode_symbol(123)
    b = enc.encode_symbol(123)
    assert a == b


def test_round_trip_k_8() -> None:
    buf = _det_buf(0xAA, 8 * 1024)
    enc = fountain_native.make_encoder(buf)
    dec = fountain_native.make_decoder(enc.k, enc.symbol_len, enc.source_len)
    for sid in range(200):
        if dec.ingest(sid, enc.encode_symbol(sid)):
            break
    assert dec.is_complete()
    assert dec.finish() == buf


def test_round_trip_k_64_with_blake3_check() -> None:
    buf = _det_buf(0xCD, 64 * 1024)
    enc = fountain_native.make_encoder(buf)
    dec = fountain_native.make_decoder(enc.k, enc.symbol_len, enc.source_len)
    for sid in range(500):
        if dec.ingest(sid, enc.encode_symbol(sid)):
            break
    assert dec.is_complete()
    recovered = dec.finish()
    assert recovered == buf
    # BLAKE3 invariant: address of recovered == address of original.
    # Use hashlib.blake3 if available (Python 3.14+), else skip.
    if hasattr(hashlib, "blake3"):
        assert hashlib.blake3(recovered).digest() == hashlib.blake3(buf).digest()


def test_round_trip_with_5pct_loss() -> None:
    buf = _det_buf(0x11, 32 * 1024)
    enc = fountain_native.make_encoder(buf)
    dec = fountain_native.make_decoder(enc.k, enc.symbol_len, enc.source_len)
    rng = random.Random(42)
    for sid in range(800):
        if rng.random() < 0.05:
            continue  # simulate loss
        if dec.ingest(sid, enc.encode_symbol(sid)):
            break
    assert dec.is_complete()
    assert dec.finish() == buf


def test_packet_round_trip() -> None:
    chunk_id = b"\xAB" * 32
    payload = b"\xCD" * 256
    encoded = fountain_native.encode_packet(chunk_id, 64, 42, 64 * 1024, payload)
    assert len(encoded) == fountain_native.PACKET_HEADER_LEN + len(payload)
    (cid, k, sid, src_len, p) = fountain_native.decode_packet(encoded)
    assert cid == chunk_id
    assert k == 64
    assert sid == 42
    assert src_len == 64 * 1024
    assert p == payload


def test_rejects_wrong_chunk_id_length() -> None:
    with pytest.raises(Exception):
        fountain_native.encode_packet(b"short", 8, 0, 1024, b"x" * 16)


def test_decoder_finish_on_incomplete_fails() -> None:
    dec = fountain_native.make_decoder(8, fountain_native.SYMBOL_LEN, 8 * 1024)
    with pytest.raises(Exception):
        dec.finish()


def test_decoder_rejects_wrong_symbol_len() -> None:
    dec = fountain_native.make_decoder(8, fountain_native.SYMBOL_LEN, 8 * 1024)
    with pytest.raises(Exception):
        dec.ingest(0, b"\x00" * 512)


def test_encoder_distinct_payloads_for_different_sids() -> None:
    buf = _det_buf(0x77, 16 * 1024)
    enc = fountain_native.make_encoder(buf)
    seen = {enc.encode_symbol(sid) for sid in range(30)}
    # Robust Soliton with K=16 produces mostly-distinct encodings.
    assert len(seen) >= 20
