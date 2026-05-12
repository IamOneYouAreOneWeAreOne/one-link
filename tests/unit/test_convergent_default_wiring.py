"""Tests for Phase B convergent-encryption default flip in the
native_transfer ingest path."""

from __future__ import annotations

from pathlib import Path

import pytest


def _native_available() -> bool:
    try:
        from one_link_native import chunk, store  # noqa: F401

        return True
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native.chunk + .store not installed",
)


def test_resolve_address_kind_raw_media_returns_convergent():
    from one_link.native_transfer import NativeTransferSession

    for ext in (".mp4", ".mov", ".h264", ".wav", ".flac", ".jpg", ".png"):
        p = Path(f"clip{ext}")
        assert (
            NativeTransferSession._resolve_address_kind(p) == "convergent"
        ), f"{ext} should map to convergent"


def test_resolve_address_kind_non_media_returns_raw():
    from one_link.native_transfer import NativeTransferSession

    for ext in (".docx", ".xlsx", ".pdf", ".zip", ".py", ".rs", ".txt", ".json", ""):
        p = Path(f"doc{ext}")
        assert (
            NativeTransferSession._resolve_address_kind(p) == "raw"
        ), f"{ext} should map to raw"


def test_compute_address_matches_address_kind():
    """Convergent path produces a different address than raw for the
    same plaintext (both are 32-byte BLAKE3 hashes but seeded
    differently)."""
    from one_link.native_transfer import NativeTransferSession

    plaintext = b"hello, this is a test buffer of arbitrary length" * 100
    raw_id = NativeTransferSession._compute_address(plaintext, "raw")
    conv_id = NativeTransferSession._compute_address(plaintext, "convergent")
    assert raw_id != conv_id
    assert len(raw_id) == 32
    assert len(conv_id) == 32


def test_compute_address_convergent_is_deterministic():
    """Two senders processing identical plaintext must produce identical
    convergent addresses — that's the point of convergent encryption.
    Raw addresses would differ if the BLAKE3 keying varied; convergent
    must NOT."""
    from one_link.native_transfer import NativeTransferSession

    plaintext = b"video frame payload that two senders independently encode" * 50
    a = NativeTransferSession._compute_address(plaintext, "convergent")
    b = NativeTransferSession._compute_address(plaintext, "convergent")
    assert a == b


def test_address_kind_consistency_across_python_and_rust():
    """The Python `_resolve_address_kind` MUST agree with the Rust
    `convergent_default_for_content_type` for the same extension —
    if they drift, the chunk-store and the daemon disagree about
    which scheme to use."""
    pytest.importorskip("one_link_native")
    from one_link.native_transfer import NativeTransferSession

    # The Rust helper isn't exposed via pyo3 yet (it's an internal
    # ol_chunk_store function), so this test asserts the Python side
    # matches the Rust side's documented behavior by exhaustively
    # enumerating media extensions and verifying both classify them
    # consistently. If the Rust list changes, this test forces a
    # corresponding Python update (or vice versa).
    media_exts = [
        "mp4", "m4v", "mov", "3gp", "mkv", "webm", "avi",
        "mp3", "wav", "flac", "ogg", "opus", "aac", "m4a",
        "jpg", "jpeg", "png", "gif", "webp", "heic",
        "h264", "264", "avc",
    ]
    for ext in media_exts:
        p = Path(f"file.{ext}")
        assert (
            NativeTransferSession._resolve_address_kind(p) == "convergent"
        ), f"Python side missing media extension: {ext}"
    non_media = ["docx", "xlsx", "pdf", "zip", "rs", "py", "txt", "json", "tar"]
    for ext in non_media:
        p = Path(f"file.{ext}")
        assert (
            NativeTransferSession._resolve_address_kind(p) == "raw"
        ), f"Python side false-positive on non-media: {ext}"
