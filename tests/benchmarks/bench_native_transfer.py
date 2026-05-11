"""Throughput benchmark for the Phase C-3 native chunk-store transport
(ADR-0025): native pipeline vs legacy per-message ChaCha20Poly1305.

Methodology:
  - 5 input sizes: 64 KiB, 256 KiB, 1 MiB, 4 MiB, 16 MiB random bytes.
  - Each size: 3 timed runs, report median MiB/s.
  - Native: full pipeline (CDC + per-chunk AEAD + ratchet tick +
    chunk-id verify on receive).
  - Legacy: cryptography.hazmat ChaCha20Poly1305 fed 256-KiB blocks
    in a tight loop (matches the daemon's channel.py AEAD shape).

Run::

    cd One_link
    python -m tests.benchmarks.bench_native_transfer
"""

from __future__ import annotations

import os
import statistics
import time
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def _legacy_round_trip(plaintext: bytes, chunk_size: int = 256 * 1024) -> bytes:
    """Match the daemon's channel.py shape: single per-channel
    ChaCha20Poly1305 key, monotonic nonce, AAD-bound per-frame."""
    key = os.urandom(32)
    aead = ChaCha20Poly1305(key)
    aad = b"OL1/data|" + b"\x00" * 32
    out = bytearray()
    seq = 0
    for i in range(0, len(plaintext), chunk_size):
        chunk = plaintext[i : i + chunk_size]
        nonce = seq.to_bytes(12, "little")
        ct = aead.encrypt(nonce, chunk, aad)
        out.extend(ct)
        seq += 1
    # Decrypt the whole thing back.
    plaintext_back = bytearray()
    seq = 0
    ct_offset = 0
    for i in range(0, len(plaintext), chunk_size):
        chunk_len = min(chunk_size, len(plaintext) - i)
        ct_len = chunk_len + 16  # ChaCha20Poly1305 tag is 16 bytes
        nonce = seq.to_bytes(12, "little")
        decoded = aead.decrypt(nonce, bytes(out[ct_offset : ct_offset + ct_len]), aad)
        plaintext_back.extend(decoded)
        ct_offset += ct_len
        seq += 1
    assert bytes(plaintext_back) == plaintext
    return bytes(plaintext_back)


def _native_round_trip(plaintext: bytes, *, tmp_path: Path) -> bytes:
    from one_link import native_transfer

    p = tmp_path / "bench.bin"
    p.write_bytes(plaintext)
    sender, receiver = native_transfer.establish_session_pair()
    records = list(sender.encrypt_file(p))
    out = receiver.decrypt_records_to_bytes(records)
    return out


def bench(size_bytes: int, *, runs: int = 3) -> tuple[float, float]:
    """Run ``runs`` trials; return (legacy MiB/s, native MiB/s) medians."""
    payload = os.urandom(size_bytes)

    legacy_speeds = []
    for _ in range(runs):
        start = time.perf_counter()
        _legacy_round_trip(payload)
        elapsed = time.perf_counter() - start
        legacy_speeds.append(size_bytes / (1024 * 1024) / elapsed)

    native_speeds = []
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        for _ in range(runs):
            start = time.perf_counter()
            _native_round_trip(payload, tmp_path=tmp)
            elapsed = time.perf_counter() - start
            native_speeds.append(size_bytes / (1024 * 1024) / elapsed)

    return statistics.median(legacy_speeds), statistics.median(native_speeds)


def main() -> int:
    sizes = [64 * 1024, 256 * 1024, 1 * 1024 * 1024, 4 * 1024 * 1024, 16 * 1024 * 1024]
    print(
        f"{'size':>12}  {'legacy MiB/s':>14}  {'native MiB/s':>14}  {'ratio':>10}"
    )
    print("-" * 60)
    for size in sizes:
        legacy, native = bench(size, runs=3)
        ratio = native / legacy if legacy > 0 else float("inf")
        size_label = (
            f"{size // 1024} KiB" if size < 1024 * 1024 else f"{size // (1024 * 1024)} MiB"
        )
        print(f"{size_label:>12}  {legacy:>14.2f}  {native:>14.2f}  {ratio:>10.3f}x")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
