"""Throughput benchmark for the Phase C-3 native chunk-store transport
(ADR-0025): native pipeline vs legacy per-message ChaCha20Poly1305.

Methodology v2: apples-to-apples — session establishment (KEM
handshake, key derivation, file I/O) is AMORTIZED outside the timed
region. Each timed iteration measures only the steady-state
"encrypt N bytes + decrypt them back" work that the daemon performs
per message in production.

Methodology details:
  - 8 input sizes: 4 KiB → 64 MiB.
  - Each size: 5 timed runs, report median MiB/s.
  - Native and legacy each measure the same steady-state operation:
      bytes_in → encrypted bytes → bytes_out (assert equal).
  - File I/O is excluded from the timer (uses in-memory payloads).
  - KEM handshake / cipher construction is excluded from the timer
    (session is set up once before the loop starts).

Run::

    cd One_link
    python -m tests.benchmarks.bench_native_transfer
"""

from __future__ import annotations

import os
import statistics
import time
from typing import Callable

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


# ---------------------------------------------------------------------------
# Legacy: cryptography.hazmat ChaCha20Poly1305 in 256 KiB chunks. Matches
# the daemon's channel.py shape (single per-channel key, monotonic nonce,
# AAD bound to transcript). Session setup amortized.
# ---------------------------------------------------------------------------


class _LegacySession:
    AAD = b"OL1/data|" + b"\x00" * 32
    CHUNK_SIZE = 256 * 1024

    def __init__(self) -> None:
        self.aead = ChaCha20Poly1305(os.urandom(32))

    def round_trip(self, plaintext: bytes) -> bytes:
        ct_blocks = []
        seq = 0
        for i in range(0, len(plaintext), self.CHUNK_SIZE):
            block = plaintext[i : i + self.CHUNK_SIZE]
            nonce = seq.to_bytes(12, "little")
            ct_blocks.append(self.aead.encrypt(nonce, block, self.AAD))
            seq += 1
        # Decrypt every block.
        pt_blocks = []
        seq = 0
        for ct in ct_blocks:
            nonce = seq.to_bytes(12, "little")
            pt_blocks.append(self.aead.decrypt(nonce, ct, self.AAD))
            seq += 1
        return b"".join(pt_blocks)


# ---------------------------------------------------------------------------
# Native: NativeTransferSession driven from in-memory bytes (no file I/O).
# ---------------------------------------------------------------------------


class _NativeSession:
    """Session pair sharing the SAME shared secret so they advance the
    same ratchet in lockstep. Mirrors what
    ``native_transfer.establish_session_pair`` produces, minus the
    KEM round trip cost on every iteration. Uses
    ``cipher_backend='fast'`` (cryptography.hazmat / BoringSSL)."""

    BACKEND = "fast"

    def __init__(self) -> None:
        from one_link import native_transfer

        # Use the same shared secret on both ends — eliminates the
        # ML-KEM-768 keypair generation cost from the timed region.
        ss = os.urandom(32)
        self.sender = native_transfer.session_from_shared_secret(
            ss, cipher_backend=self.BACKEND
        )
        self.receiver = native_transfer.session_from_shared_secret(
            ss, cipher_backend=self.BACKEND
        )

    def round_trip(self, plaintext: bytes) -> bytes:
        from one_link_native import chunk as _native_chunk

        # Drive the same paths encrypt_file uses (fixed 256 KiB
        # chunking — same granularity as the legacy channel).
        if len(plaintext) <= 256 * 1024:
            chunk_id = _native_chunk.chunk_address_raw(plaintext)
            records = [
                self.sender.encrypt_chunk_bytes(plaintext, chunk_id=chunk_id)
            ]
        else:
            records = []
            step = 256 * 1024
            for i in range(0, len(plaintext), step):
                chunk = plaintext[i : i + step]
                chunk_id = _native_chunk.chunk_address_raw(chunk)
                records.append(
                    self.sender.encrypt_chunk_bytes(chunk, chunk_id=chunk_id)
                )
        return self.receiver.decrypt_records_to_bytes(records)


# ---------------------------------------------------------------------------
# Bench harness
# ---------------------------------------------------------------------------


def _bench_one_session(
    session_factory: Callable[[], object],
    plaintext: bytes,
    runs: int,
) -> float:
    """Build ONE session, run the round-trip ``runs`` times, return
    median MiB/s. Session construction is amortized."""
    session = session_factory()
    # Warm up.
    for _ in range(2):
        out = session.round_trip(plaintext)
        assert out == plaintext, "round trip mismatch in warm-up"
    speeds = []
    size_mib = len(plaintext) / (1024 * 1024)
    for _ in range(runs):
        start = time.perf_counter()
        out = session.round_trip(plaintext)
        elapsed = time.perf_counter() - start
        speeds.append(size_mib / elapsed)
    return statistics.median(speeds)


class _NativeSessionRing(_NativeSession):
    """Native session pinned to ``cipher_backend='native'`` — uses
    ``ol_aead`` (ring-backed AES-GCM / ChaCha20-Poly1305) instead of
    cryptography.hazmat. Post Phase-C-3 ol_aead upgrade these should
    be at parity."""

    BACKEND = "native"


def bench(size_bytes: int, *, runs: int = 5) -> tuple[float, float, float]:
    """Return (legacy MiB/s, native-fast MiB/s, native-ring MiB/s)
    medians on ``size_bytes``."""
    payload = os.urandom(size_bytes)
    legacy = _bench_one_session(_LegacySession, payload, runs)
    native_fast = _bench_one_session(_NativeSession, payload, runs)
    native_ring = _bench_one_session(_NativeSessionRing, payload, runs)
    return legacy, native_fast, native_ring


def main() -> int:
    sizes = [
        4 * 1024,           # 4 KiB   (control / chat frame size)
        16 * 1024,          # 16 KiB
        64 * 1024,          # 64 KiB
        256 * 1024,         # 256 KiB (single-chunk fast-path boundary)
        1 * 1024 * 1024,    # 1 MiB
        4 * 1024 * 1024,    # 4 MiB
        16 * 1024 * 1024,   # 16 MiB
        64 * 1024 * 1024,   # 64 MiB  (large-file regime)
    ]
    print(
        f"{'size':>10}  {'legacy':>10}  {'fast (Py)':>10}  {'ring (Rs)':>10}  "
        f"{'f/leg':>7}  {'r/leg':>7}"
    )
    print("-" * 70)
    for size in sizes:
        legacy, fast, ring = bench(size, runs=5)
        r_fast = fast / legacy if legacy > 0 else float("inf")
        r_ring = ring / legacy if legacy > 0 else float("inf")
        size_label = (
            f"{size // 1024}K" if size < 1024 * 1024 else f"{size // (1024 * 1024)}M"
        )
        print(
            f"{size_label:>10}  {legacy:>10.0f}  {fast:>10.0f}  {ring:>10.0f}  "
            f"{r_fast:>6.2f}x  {r_ring:>6.2f}x"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
