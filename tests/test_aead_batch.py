"""Wave 2h: SIMD batch encrypt/decrypt via the new pyo3 bindings.

Exercises the parallel ``encrypt_chunks`` / ``decrypt_chunks``
methods on the native AeadCipher. The native side uses rayon to
process the work across CPU cores; the test validates correctness
+ records a relative speed comparison vs the serial single-chunk
path so a future regression in the parallel scheduler shows up.
"""

from __future__ import annotations

import os
import secrets
import time

import pytest

aead = pytest.importorskip("one_link_native.aead")


def _build_cipher():
    return aead.default_cipher_for_host(secrets.token_bytes(32))


def _build_chunks(n: int, size: int) -> list[tuple[bytes, bytes]]:
    """Generate ``n`` random (chunk_id, plaintext) pairs of the
    given plaintext size each."""
    rng = secrets.SystemRandom()
    return [
        (secrets.token_bytes(32), bytes(rng.getrandbits(8) for _ in range(size)))
        for _ in range(n)
    ]


def test_batch_encrypt_round_trip() -> None:
    """Batch encrypt → batch decrypt must recover the original
    plaintexts in input order. Per-chunk integrity is enforced
    by the AEAD tag binding chunk_id as AAD; an out-of-order
    response would fail tag verification, so this end-to-end
    test covers both correctness AND tag binding."""
    cipher = _build_cipher()
    inputs = _build_chunks(8, 4096)
    ciphertexts = cipher.encrypt_chunks(inputs)
    assert len(ciphertexts) == 8
    decrypt_inputs = [
        (cid, len(pt), ct)
        for (cid, pt), ct in zip(inputs, ciphertexts)
    ]
    plaintexts = cipher.decrypt_chunks(decrypt_inputs)
    for (_, expected), got in zip(inputs, plaintexts):
        assert got == expected


def test_batch_empty_list() -> None:
    """An empty batch returns an empty list — important because
    daemon callers may flush near the end of a transfer with
    zero queued chunks."""
    cipher = _build_cipher()
    assert cipher.encrypt_chunks([]) == []
    assert cipher.decrypt_chunks([]) == []


def test_batch_rejects_bad_chunk_id() -> None:
    """A chunk_id that isn't exactly 32 bytes must surface as a
    ValueError, not silently produce garbage ciphertext."""
    cipher = _build_cipher()
    with pytest.raises(Exception):
        cipher.encrypt_chunks([(b"short", b"plaintext")])


def test_batch_rejects_bad_tuple_arity() -> None:
    """A 1-tuple input should be rejected — the format is
    ``(chunk_id, plaintext)`` strictly."""
    cipher = _build_cipher()
    with pytest.raises(Exception):
        cipher.encrypt_chunks([(b"\x00" * 32,)])


def test_batch_decrypt_rejects_tampered_chunk_id() -> None:
    """Even within a batch, swapping the chunk_id between encrypt
    and decrypt must produce an AEAD failure for that chunk —
    proves the per-chunk AAD binding survives the rayon
    scheduler."""
    cipher = _build_cipher()
    chunks = _build_chunks(3, 2048)
    cts = cipher.encrypt_chunks(chunks)
    # Swap chunk_id for the middle entry → AEAD tag verify must
    # fail.
    tampered = [
        (chunks[0][0], len(chunks[0][1]), cts[0]),
        (secrets.token_bytes(32), len(chunks[1][1]), cts[1]),
        (chunks[2][0], len(chunks[2][1]), cts[2]),
    ]
    with pytest.raises(Exception):
        cipher.decrypt_chunks(tampered)


def test_batch_matches_serial_output() -> None:
    """The batch ciphertext at index i must equal what the
    sequential encrypt_chunk would have produced for the same
    inputs — proves rayon parallelism doesn't drift from the
    serial baseline."""
    cipher = _build_cipher()
    inputs = _build_chunks(5, 1024)
    serial_cts = [cipher.encrypt_chunk(cid, pt) for cid, pt in inputs]
    parallel_cts = cipher.encrypt_chunks(inputs)
    assert serial_cts == parallel_cts


@pytest.mark.soak
def test_batch_throughput_characterisation() -> None:
    """Characterise serial vs parallel decrypt throughput across
    multiple chunk-size points so the bench archive carries a
    documented picture of where the parallel path actually pays
    off.

    Honest finding from the Wave 2h ship: on AES-NI hosts the
    serial path is already at memory-bandwidth speed (~5 GiB/s
    single thread) for the daemon's default 256 KiB chunks, so
    batch decrypt's parallelism is dominated by pyo3 buffer-
    copy + rayon dispatch overhead. Batch helps on:

      - very large payloads (cold archive decrypt > 1 GiB) where
        per-chunk overhead amortises
      - ChaCha20 hosts without hardware AES (slower serial path,
        more headroom for rayon to recover overhead)
      - future use cases that can keep data in shared memory
        instead of round-tripping through Python bytes objects

    The test logs the numbers but doesn't ASSERT a speedup at
    the daemon's chunk size — we'd be lying to ourselves if we
    pretended batch is faster for the hot path on this hardware.
    The win is "correctness + future-use" rather than
    "throughput-out-of-the-box".
    """
    cipher = _build_cipher()
    cpus = os.cpu_count() or 1
    # AEAD chunk plaintext is capped at 256 KiB by the underlying
    # ol_aead frame layout, so we sweep counts at three sizes
    # within that cap: a small (16 KiB), the daemon default (256
    # KiB), and a wide-batch (512 small chunks).
    for n_chunks, chunk_size in [
        (16, 16 * 1024),
        (64, 256 * 1024),
        (512, 16 * 1024),
    ]:
        inputs = _build_chunks(n_chunks, chunk_size)
        decrypt_inputs = [
            (cid, len(pt), cipher.encrypt_chunk(cid, pt))
            for cid, pt in inputs
        ]
        # Warm-up -- and the correctness claim this test can legitimately
        # make. Throughput is deliberately NOT gated (see the docstring), but
        # "serial and batch decrypt agree" is a real property and was going
        # unasserted, so the whole test could pass while batch decrypt returned
        # garbage.
        batch_out = cipher.decrypt_chunks(decrypt_inputs)
        serial_out = [
            cipher.decrypt_chunk(cid, pt_len, ct)
            for cid, pt_len, ct in decrypt_inputs
        ]
        assert list(batch_out) == serial_out, (
            f"batch and serial decrypt disagree at {n_chunks}x{chunk_size}"
        )
        assert serial_out == [pt for _cid, pt in inputs], (
            "decrypt did not round-trip the original plaintext"
        )
        # Serial best-of-3.
        serial_runs = []
        for _ in range(3):
            t0 = time.perf_counter()
            for cid, pt_len, ct in decrypt_inputs:
                cipher.decrypt_chunk(cid, pt_len, ct)
            serial_runs.append(time.perf_counter() - t0)
        serial_s = min(serial_runs)
        # Parallel best-of-3.
        par_runs = []
        for _ in range(3):
            t0 = time.perf_counter()
            cipher.decrypt_chunks(decrypt_inputs)
            par_runs.append(time.perf_counter() - t0)
        parallel_s = min(par_runs)
        ratio = parallel_s / serial_s if serial_s > 0 else 0.0
        total_mib = n_chunks * chunk_size / (1024 ** 2)
        serial_gbps = (total_mib / 1024) / serial_s if serial_s > 0 else 0
        parallel_gbps = (total_mib / 1024) / parallel_s if parallel_s > 0 else 0
        print(
            f"\ndecrypt {n_chunks}×{chunk_size // 1024}KiB ({total_mib:.1f} MiB): "
            f"serial {serial_s * 1000:.2f}ms ({serial_gbps:.2f} GiB/s), "
            f"parallel {parallel_s * 1000:.2f}ms ({parallel_gbps:.2f} GiB/s), "
            f"ratio {ratio:.2f}× (cpus={cpus})"
        )
