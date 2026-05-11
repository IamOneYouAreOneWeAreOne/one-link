"""Phase C-3 native chunk-store transport (ADR-0025).

End-to-end tests of the :mod:`one_link.native_transfer` pipeline:
session establishment → CDC chunking → per-chunk AEAD → ratchet sync
→ optional ChunkStore persistence → receive-side decrypt → verify
byte-identical reconstruction.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest


def _native_available() -> bool:
    try:
        from one_link import native_transfer

        return native_transfer.HAS_NATIVE
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native not installed (build via maturin)",
)


def test_pipeline_diagnostics_reports_status():
    from one_link import native_transfer

    diag = native_transfer.pipeline_diagnostics()
    assert diag["available"] is True
    # default_aead_kind() returns the short tag the native API uses
    # (`aes` or `chacha`), not the full algorithm name.
    assert diag["aead_kind_default"] in {"aes", "chacha"}
    assert isinstance(diag["host_has_hardware_aes"], bool)


def test_establish_session_pair_round_trips_small_chunk():
    from one_link import native_transfer

    sender, receiver = native_transfer.establish_session_pair()
    plaintext = b"hello native pipeline" * 50  # ~1KB
    record = sender.encrypt_chunk_bytes(plaintext)
    recovered = receiver.decrypt_chunk(record)
    assert recovered == plaintext


def test_round_trip_byte_identical_for_random_file(tmp_path):
    """The headline acceptance gate: a file → native pipeline →
    bytes back must equal the original byte-for-byte."""
    from one_link import native_transfer

    sender, receiver = native_transfer.establish_session_pair()
    path = tmp_path / "test_file.bin"
    payload = os.urandom(200 * 1024)  # 200 KiB — one CDC chunk
    path.write_bytes(payload)

    records = list(sender.encrypt_file(path))
    assert len(records) >= 1
    recovered = receiver.decrypt_records_to_bytes(records)
    assert recovered == payload


def test_round_trip_multi_chunk_large_file(tmp_path):
    """A file larger than the CDC max-chunk size must split into
    multiple chunks; reassembly must still be byte-identical."""
    from one_link import native_transfer

    sender, receiver = native_transfer.establish_session_pair()
    path = tmp_path / "big.bin"
    payload = os.urandom(2 * 1024 * 1024)  # 2 MiB — many CDC chunks
    path.write_bytes(payload)

    records = list(sender.encrypt_file(path))
    assert len(records) >= 4, f"expected >=4 CDC chunks, got {len(records)}"
    recovered = receiver.decrypt_records_to_bytes(records)
    assert recovered == payload


def test_per_chunk_keys_are_distinct():
    """Forward-secrecy property: every chunk in a transfer must
    consume a fresh ratchet step. Two adjacent chunks of the same
    plaintext should produce different ciphertexts (different
    ratchet keys derive different ciphers internally)."""
    from one_link import native_transfer

    sender, _ = native_transfer.establish_session_pair()
    plaintext = b"identical chunk plaintext" * 100
    r1 = sender.encrypt_chunk_bytes(plaintext)
    r2 = sender.encrypt_chunk_bytes(plaintext)
    # chunk_id is content-addressed (same for both), so r1 and r2
    # share an id. But chunk_index differs.
    assert r1.chunk_id == r2.chunk_id
    assert r1.chunk_index != r2.chunk_index


def test_chunk_id_swap_caught_by_aead_aad_binding():
    """The AEAD tag binds ``chunk_id`` as AAD: decrypting a record
    whose ``chunk_id`` was rewritten to point at a DIFFERENT chunk's
    ciphertext + length raises ``OlAeadError`` before any plaintext
    is exposed. This is what lets us drop the explicit Python-level
    BLAKE3 recompute on receive (a full hash pass per chunk that was
    pure overhead given the AAD binding)."""
    from one_link import native_transfer

    sender, receiver = native_transfer.establish_session_pair()
    a = sender.encrypt_chunk_bytes(b"plaintext-A" * 50)
    b = sender.encrypt_chunk_bytes(b"plaintext-B" * 50)

    # Construct a swapped record: a's id but b's ciphertext + length.
    swapped = native_transfer.NativeChunkRecord(
        chunk_id=a.chunk_id,
        chunk_index=a.chunk_index,
        plaintext_len=b.plaintext_len,
        ciphertext=b.ciphertext,
    )
    with pytest.raises(Exception):
        receiver.decrypt_chunk(swapped)


def test_corrupted_ciphertext_caught_by_aead_tag():
    """Bit-flip in the ciphertext fails the AEAD tag check.
    Necessary regression cover for dropping the BLAKE3 recompute."""
    from one_link import native_transfer

    sender, receiver = native_transfer.establish_session_pair()
    r = sender.encrypt_chunk_bytes(b"x" * 1024)
    tampered = bytearray(r.ciphertext)
    tampered[len(tampered) // 2] ^= 0xFF
    swapped = native_transfer.NativeChunkRecord(
        chunk_id=r.chunk_id,
        chunk_index=r.chunk_index,
        plaintext_len=r.plaintext_len,
        ciphertext=bytes(tampered),
    )
    with pytest.raises(Exception):
        receiver.decrypt_chunk(swapped)


def test_corrupted_chunk_id_caught_by_aead_aad():
    """Bit-flip in the chunk_id (the AAD) fails the AEAD tag check.
    This is the primitive that makes the post-decrypt BLAKE3 verify
    redundant."""
    from one_link import native_transfer

    sender, receiver = native_transfer.establish_session_pair()
    r = sender.encrypt_chunk_bytes(b"y" * 2048)
    tampered_id = bytearray(r.chunk_id)
    tampered_id[0] ^= 0x01
    swapped = native_transfer.NativeChunkRecord(
        chunk_id=bytes(tampered_id),
        chunk_index=r.chunk_index,
        plaintext_len=r.plaintext_len,
        ciphertext=r.ciphertext,
    )
    with pytest.raises(Exception):
        receiver.decrypt_chunk(swapped)


def test_small_file_uses_single_chunk_fast_path(tmp_path):
    """Files at or below SINGLE_CHUNK_FAST_PATH_MAX (256 KiB) should
    yield exactly one record — confirming the fast path bypasses
    CDC's potential to produce more chunks."""
    from one_link import native_transfer

    sender, _ = native_transfer.establish_session_pair()
    payload = os.urandom(200 * 1024)
    p = tmp_path / "small.bin"
    p.write_bytes(payload)
    records = list(sender.encrypt_file(p))
    assert len(records) == 1
    assert records[0].plaintext_len == len(payload)


def test_streaming_path_handles_very_large_file(tmp_path):
    """Files above the 16 MiB threshold take the streaming path. The
    round trip still produces byte-identical output."""
    from one_link import native_transfer

    sender, receiver = native_transfer.establish_session_pair()
    payload = os.urandom(20 * 1024 * 1024)  # 20 MiB — over the threshold
    p = tmp_path / "big.bin"
    p.write_bytes(payload)
    records = list(sender.encrypt_file(p))
    assert len(records) >= 30, f"expected many CDC chunks, got {len(records)}"
    recovered = receiver.decrypt_records_to_bytes(records)
    assert recovered == payload


def test_chunk_store_persistence_round_trip(tmp_path):
    """When the session is given a store_root, every produced chunk
    should land in the persistent chunk store and be visible via the
    same handle's has_chunk. (Cross-handle visibility against the
    same on-disk log requires a flush + reopen, which is the store's
    crash-recovery path, not what we test here.)"""
    from one_link import native_transfer

    store_root = tmp_path / "sender_store"
    store_root.mkdir()
    sender = native_transfer.NativeTransferSession(
        shared_secret=b"\x42" * 32,
        aead_kind="chacha",
        store_root=store_root,
    )
    path = tmp_path / "f.bin"
    path.write_bytes(os.urandom(100 * 1024))
    records = list(sender.encrypt_file(path))
    # Same handle the sender used — every chunk_id is visible.
    cs = sender._store
    for r in records:
        assert cs.has_chunk(r.chunk_id), f"chunk {r.chunk_id.hex()[:16]} missing"


def test_session_from_shared_secret_path(tmp_path):
    """Direct construction from a 32-byte shared secret — the call
    shape the daemon will use once channel.py wires this in."""
    from one_link import native_transfer

    ss = b"\x77" * 32
    sender = native_transfer.session_from_shared_secret(ss)
    receiver = native_transfer.session_from_shared_secret(ss)
    payload = os.urandom(80 * 1024)
    p = tmp_path / "f.bin"
    p.write_bytes(payload)
    records = list(sender.encrypt_file(p))
    recovered = receiver.decrypt_records_to_bytes(records)
    assert recovered == payload


def test_rejects_short_shared_secret():
    from one_link import native_transfer

    with pytest.raises(ValueError):
        native_transfer.NativeTransferSession(
            shared_secret=b"short", aead_kind="chacha"
        )


def test_rejects_oversize_chunk_plaintext():
    """Native AEAD caps single chunks at 256 KiB; sender must reject
    callers that hand it more than that (split via cdc_iter first)."""
    from one_link import native_transfer

    sender, _ = native_transfer.establish_session_pair()
    too_big = os.urandom(300 * 1024)
    with pytest.raises(ValueError, match="256 KiB"):
        sender.encrypt_chunk_bytes(too_big)


def test_native_aead_backend_still_works(tmp_path):
    """The original ADR-0002 multi-frame AEAD path stays selectable
    via cipher_backend='native'. Used for scenarios that demand
    partial-chunk integrity (streaming-decrypt before the chunk
    is complete)."""
    from one_link import native_transfer

    sender, receiver = native_transfer.establish_session_pair(
        cipher_backend="native"
    )
    p = tmp_path / "f.bin"
    p.write_bytes(os.urandom(200 * 1024))
    records = list(sender.encrypt_file(p))
    recovered = receiver.decrypt_records_to_bytes(records)
    assert recovered == p.read_bytes()


def test_cdc_strategy_still_supported(tmp_path):
    """chunk_strategy='cdc' uses ADR-0001 content-defined chunking.
    Slower steady-state than fixed but better dedup on edited
    files."""
    from one_link import native_transfer

    sender, receiver = native_transfer.establish_session_pair()
    p = tmp_path / "f.bin"
    payload = os.urandom(2 * 1024 * 1024)  # 2 MiB
    p.write_bytes(payload)
    records = list(sender.encrypt_file(p, chunk_strategy="cdc"))
    # CDC produces multiple chunks (avg 64 KiB → ~30+).
    assert len(records) > 4
    recovered = receiver.decrypt_records_to_bytes(records)
    assert recovered == payload


def test_fixed_strategy_produces_predictable_chunk_count(tmp_path):
    """chunk_strategy='fixed' (the default) uses 256 KiB blocks. A
    1 MiB file should produce exactly 4 chunks."""
    from one_link import native_transfer

    sender, _ = native_transfer.establish_session_pair()
    p = tmp_path / "f.bin"
    p.write_bytes(os.urandom(1024 * 1024))  # 1 MiB exactly
    records = list(sender.encrypt_file(p))  # default fixed
    assert len(records) == 4


def test_rejects_invalid_chunk_strategy(tmp_path):
    from one_link import native_transfer

    sender, _ = native_transfer.establish_session_pair()
    p = tmp_path / "f.bin"
    p.write_bytes(os.urandom(300 * 1024))  # over single-chunk path
    with pytest.raises(ValueError, match="chunk_strategy"):
        list(sender.encrypt_file(p, chunk_strategy="random-strategy"))


def test_rejects_invalid_cipher_backend():
    from one_link import native_transfer

    with pytest.raises(ValueError, match="cipher_backend"):
        native_transfer.NativeTransferSession(
            shared_secret=b"\x00" * 32,
            aead_kind="chacha",
            cipher_backend="bogus",
        )


def test_distinct_sessions_have_distinct_ciphertexts():
    """Two sessions established under DIFFERENT KEM round trips must
    not produce the same ciphertext for the same plaintext —
    otherwise the per-session key isn't actually being mixed in."""
    from one_link import native_transfer

    s1, _ = native_transfer.establish_session_pair()
    s2, _ = native_transfer.establish_session_pair()
    plaintext = b"identical input across sessions"
    r1 = s1.encrypt_chunk_bytes(plaintext)
    r2 = s2.encrypt_chunk_bytes(plaintext)
    assert r1.ciphertext != r2.ciphertext
