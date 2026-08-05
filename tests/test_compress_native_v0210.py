"""Tests for ``one_link.compress_native`` — D14 codec dispatcher."""

from __future__ import annotations

import pytest

from one_link import compress_native as cn


pytestmark = pytest.mark.skipif(
    not cn.HAS_NATIVE,
    reason="one_link_native.compress not installed; run "
    "`cd native && maturin develop --release`",
)


def test_module_metadata() -> None:
    assert cn.NATIVE_VERSION is not None


def test_compressor_repr() -> None:
    c = cn.compressor()
    assert "Compressor" in repr(c)


# ---------- pick() ----------


def test_pick_msg_small_none() -> None:
    c = cn.compressor()
    assert c.pick("msg", 200) == "none"


def test_pick_msg_large_lz4() -> None:
    c = cn.compressor()
    assert c.pick("msg", 5000) == "lz4"


def test_pick_heartbeat_always_none() -> None:
    c = cn.compressor()
    assert c.pick("heartbeat", 64) == "none"
    assert c.pick("ping", 8000) == "none"


def test_pick_sync_small_lz4() -> None:
    c = cn.compressor()
    assert c.pick("sync", 200) == "lz4"


def test_pick_sync_large_zstd() -> None:
    c = cn.compressor()
    assert c.pick("sync", 50_000) == "zstd_balanced"


def test_pick_file_small_lz4() -> None:
    c = cn.compressor()
    assert c.pick("file", 100_000) == "lz4"


def test_pick_file_large_zstd() -> None:
    c = cn.compressor()
    assert c.pick("file", 5_000_000) == "zstd_balanced"


def test_pick_background_always_aggressive() -> None:
    c = cn.compressor()
    assert c.pick("background", 100) == "zstd_aggressive"
    assert c.pick("background", 5_000_000) == "zstd_aggressive"


def test_pick_precompressed_always_none() -> None:
    c = cn.compressor()
    for kind in ("msg", "file", "sync", "heartbeat", "background"):
        assert c.pick(kind, 5_000_000, precompressed=True) == "none"


def test_pick_unknown_kind_rejected() -> None:
    c = cn.compressor()
    with pytest.raises(ValueError):
        c.pick("supercritical", 100)


# ---------- compress / decompress round-trip ----------


def _round_trip(algo: str, payload: bytes) -> bytes:
    c = cn.compressor()
    compressed = c.compress(algo, payload)
    return c.decompress(compressed, 16 * 1024 * 1024)


def test_round_trip_none() -> None:
    assert _round_trip("none", b"hello") == b"hello"


def test_round_trip_lz4() -> None:
    p = b"hello hello hello hello hello world world world"
    assert _round_trip("lz4", p) == p


def test_round_trip_zstd_balanced() -> None:
    p = b"x" * 4096
    assert _round_trip("zstd_balanced", p) == p


def test_round_trip_zstd_aggressive() -> None:
    p = b"y" * 16_384
    assert _round_trip("zstd_aggressive", p) == p


def test_round_trip_empty() -> None:
    # An empty ALGORITHMS -- which is what a missing native backend looks like
    # -- would make every round-trip test below pass having compressed nothing.
    assert set(cn.ALGORITHMS) >= {"none", "lz4", "zstd_balanced"}, cn.ALGORITHMS
    for algo in cn.ALGORITHMS:
        assert _round_trip(algo, b"") == b""


def test_round_trip_random_payload() -> None:
    payload = bytes(range(256)) * 4  # non-trivial
    assert set(cn.ALGORITHMS) >= {"none", "lz4", "zstd_balanced"}, cn.ALGORITHMS
    for algo in cn.ALGORITHMS:
        assert _round_trip(algo, payload) == payload, f"algo={algo}"


# ---------- error paths ----------


def test_decompress_empty_rejected() -> None:
    c = cn.compressor()
    with pytest.raises(ValueError, match="too short"):
        c.decompress(b"", 1024)


def test_decompress_unknown_tag_rejected() -> None:
    c = cn.compressor()
    with pytest.raises(ValueError, match="unknown algorithm"):
        c.decompress(bytes([99]) + b"data", 1024)


def test_decompress_caps_oversize() -> None:
    c = cn.compressor()
    # Big repeating payload → zstd compresses tiny.
    compressed = c.compress("zstd_balanced", b"q" * 100_000)
    with pytest.raises(ValueError, match="exceeds"):
        c.decompress(compressed, 50_000)


def test_unknown_algo_rejected() -> None:
    c = cn.compressor()
    with pytest.raises(ValueError, match="unknown algo"):
        c.compress("supercritical", b"data")


# ---------- precompressed helper ----------


def test_is_precompressed_by_extension() -> None:
    assert cn.is_precompressed_by_extension("photo.jpg")
    assert cn.is_precompressed_by_extension("PHOTO.JPEG")
    assert cn.is_precompressed_by_extension("vid.mp4")
    assert cn.is_precompressed_by_extension("archive.zip")
    assert cn.is_precompressed_by_extension("doc.pdf")


def test_is_precompressed_negative_cases() -> None:
    assert not cn.is_precompressed_by_extension("doc.txt")
    assert not cn.is_precompressed_by_extension("data.json")
    assert not cn.is_precompressed_by_extension("notes")
    assert not cn.is_precompressed_by_extension("")
    assert not cn.is_precompressed_by_extension(None)
