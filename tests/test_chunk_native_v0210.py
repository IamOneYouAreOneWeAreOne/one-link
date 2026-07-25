"""File engine v2 — algebraic-correctness tests for ``one_link.chunk_native``.

Per ADR-0001 verification gate: the FastCDC v2020 kernel ported to Rust
produces deterministic, exactly-tiling chunk boundaries whose raw_address
fields match BLAKE3-256 of the chunk content. Tests in this file exercise:

- The native module's loadability (skipped if not built).
- Boundary tiling (no gaps, no overlap, full coverage).
- Address consistency (raw_address == BLAKE3 of chunk content).
- Cross-run determinism (same input → same boundaries).
- Domain-separated derivation per ADR-0006 (raw vs convergent address;
  AEAD key, ratchet_key_id, stripe_seed all distinct on shared inputs).
- Diagnostics surface contract (stable JSON-serializable schema).

These are NOT regression tests against the legacy ``cdc.py`` kernel —
ADR-0001 deliberately upgrades from custom Gear-CDC to FastCDC v2020 and
the kernels produce different boundaries on the same input. The wire-compat
migration is handled by the foldersync kernel-version negotiation in a
later ship.
"""

from __future__ import annotations

import secrets

import pytest

from one_link import chunk_native


pytestmark = pytest.mark.skipif(
    not chunk_native.HAS_NATIVE,
    reason="one_link_native not installed; run `cd native && maturin develop --release`",
)


def _xorshift_buf(seed: int, size: int) -> bytes:
    """Deterministic xorshift fill so the engine builds reproducibly across machines."""
    state = seed & 0xFFFF_FFFF_FFFF_FFFF
    out = bytearray(size)
    for i in range(size):
        state ^= (state << 13) & 0xFFFF_FFFF_FFFF_FFFF
        state ^= state >> 7
        state ^= (state << 17) & 0xFFFF_FFFF_FFFF_FFFF
        out[i] = state & 0xFF
    return bytes(out)


# ─── basic loadability ────────────────────────────────────────────────


def test_native_module_loaded():
    assert chunk_native.HAS_NATIVE is True
    assert chunk_native.NATIVE_VERSION is not None
    assert chunk_native.CDC_PARAMS == (8 * 1024, 64 * 1024, 256 * 1024)
    assert chunk_native.AEAD_FRAME_PLAINTEXT_LEN == 16 * 1024
    assert chunk_native.AEAD_TAG_LEN == 16


def test_diagnostics_schema_when_native_available():
    diag = chunk_native.diagnostics()
    assert diag["native_available"] is True
    assert isinstance(diag["version"], str)
    assert diag["kernel"] == "FastCDC v2020 + Gear-256"
    assert diag["cdc_min_avg_max"] == (8 * 1024, 64 * 1024, 256 * 1024)
    assert diag["aead_frame_plaintext_len"] == 16 * 1024
    assert diag["aead_tag_len"] == 16


# ─── algebraic correctness of the CDC scan ─────────────────────────────


def test_cdc_scan_empty_buffer_yields_no_boundaries():
    boundaries = list(chunk_native.cdc_iter(b""))
    assert boundaries == []


def test_cdc_scan_small_buffer_yields_single_chunk():
    buf = b"\xAB" * 4096
    boundaries = list(chunk_native.cdc_iter(buf))
    assert len(boundaries) == 1
    b = boundaries[0]
    assert b.start == 0
    assert b.end == 4096
    # Raw address must equal BLAKE3-256 of the full buffer.
    import blake3
    expected = blake3.blake3(buf).digest()
    assert b.raw_address == expected


def test_cdc_boundaries_tile_exactly():
    buf = _xorshift_buf(0x1234_5678_9ABC_DEF0, 1024 * 1024)
    boundaries = list(chunk_native.cdc_iter(buf))
    assert boundaries, "1 MiB buffer must produce at least one boundary"
    assert boundaries[0].start == 0
    assert boundaries[-1].end == len(buf)
    for prev, nxt in zip(boundaries, boundaries[1:]):
        assert prev.end == nxt.start, "boundaries must be contiguous"


def test_cdc_boundary_addresses_match_blake3():
    import blake3

    buf = _xorshift_buf(0xCAFE_BABE_F00D_BAAD, 256 * 1024)
    for b in chunk_native.cdc_iter(buf):
        expected = blake3.blake3(buf[b.start : b.end]).digest()
        assert b.raw_address == expected


def test_cdc_scan_is_deterministic_across_runs():
    buf = _xorshift_buf(0xDEAD_BEEF_CAFE_F00D, 1024 * 1024)
    a = [(b.start, b.end, b.raw_address) for b in chunk_native.cdc_iter(buf)]
    b = [(b.start, b.end, b.raw_address) for b in chunk_native.cdc_iter(buf)]
    assert a == b


def test_cdc_chunks_within_size_bounds():
    buf = _xorshift_buf(0xABCD_EF01_2345_6789, 2 * 1024 * 1024)
    boundaries = list(chunk_native.cdc_iter(buf))
    min_size, _avg_size, max_size = chunk_native.CDC_PARAMS
    for i, bnd in enumerate(boundaries):
        is_last = i == len(boundaries) - 1
        length = bnd.end - bnd.start
        assert length <= max_size, f"chunk {i} exceeds max: {length}"
        if not is_last:
            assert length >= min_size, f"interior chunk {i} below min: {length}"


# ─── ADR-0006 domain-separated derivation ──────────────────────────────


def test_raw_vs_convergent_addresses_differ():
    plain = b"shared content sent by two peers"
    raw = chunk_native.chunk_address_raw(plain)
    conv = chunk_native.chunk_address_convergent(plain)
    assert raw != conv, "raw and convergent addresses must be domain-separated"


def test_convergent_address_is_deterministic_across_callers():
    plain = b"identical plaintext"
    a = chunk_native.chunk_address_convergent(plain)
    b = chunk_native.chunk_address_convergent(plain)
    assert a == b


def test_aead_key_changes_with_chunk_id():
    chain = secrets.token_bytes(32)
    chunk_a = secrets.token_bytes(32)
    chunk_b = secrets.token_bytes(32)
    while chunk_b == chunk_a:
        chunk_b = secrets.token_bytes(32)
    key_a = chunk_native.derive_aead_key(chain, chunk_a)
    key_b = chunk_native.derive_aead_key(chain, chunk_b)
    assert key_a != key_b
    assert len(key_a) == 32


def test_aead_key_changes_with_chain_key():
    chunk = secrets.token_bytes(32)
    chain_a = secrets.token_bytes(32)
    chain_b = secrets.token_bytes(32)
    while chain_b == chain_a:
        chain_b = secrets.token_bytes(32)
    key_a = chunk_native.derive_aead_key(chain_a, chunk)
    key_b = chunk_native.derive_aead_key(chain_b, chunk)
    assert key_a != key_b


def test_ratchet_key_id_is_16_bytes_and_independent_of_aead_key():
    chain = secrets.token_bytes(32)
    chunk = secrets.token_bytes(32)
    aead = chunk_native.derive_aead_key(chain, chunk)
    rid = chunk_native.derive_ratchet_key_id(chain, chunk)
    assert len(rid) == 16
    # Domain-separation: prefix of AEAD key must NOT equal the ratchet_key_id.
    assert aead[:16] != rid


def test_stripe_seed_clears_low_6_bits():
    chunk = secrets.token_bytes(32)
    seed, _pos = chunk_native.derive_stripe_seed(chunk, 10)
    assert seed & 0x3F == 0


def test_stripe_position_within_k_range():
    for i in range(200):
        chunk = bytes([i & 0xFF, (i >> 8) & 0xFF] + [0] * 30)
        seed, pos = chunk_native.derive_stripe_seed(chunk, 10)
        assert 0 <= pos < 10


def test_stripe_seed_rejects_invalid_inputs():
    chunk_short = b"\x00" * 31
    with pytest.raises(Exception):
        chunk_native.derive_stripe_seed(chunk_short, 10)

    chunk_full = b"\x00" * 32
    with pytest.raises(Exception):
        chunk_native.derive_stripe_seed(chunk_full, 0)


def test_aead_key_rejects_short_inputs():
    chain_short = b"\x00" * 31
    chunk = b"\x00" * 32
    with pytest.raises(Exception):
        chunk_native.derive_aead_key(chain_short, chunk)


# ─── frame layout (ADR-0002) ───────────────────────────────────────────


def test_frame_count_zero_for_empty_chunk():
    assert chunk_native.frame_count(0) == 0


def test_frame_count_one_for_subframe_chunk():
    assert chunk_native.frame_count(1) == 1
    assert chunk_native.frame_count(chunk_native.AEAD_FRAME_PLAINTEXT_LEN) == 1


def test_frame_count_rounds_up():
    n = chunk_native.AEAD_FRAME_PLAINTEXT_LEN
    assert chunk_native.frame_count(n + 1) == 2
    assert chunk_native.frame_count(64 * 1024) == 4   # 64 KiB chunk = 4 frames
    assert chunk_native.frame_count(256 * 1024) == 16  # 256 KiB chunk = 16 frames
