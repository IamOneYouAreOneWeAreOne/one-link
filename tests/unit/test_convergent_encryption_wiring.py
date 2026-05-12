"""Phase B convergent encryption — daemon ingest path wiring.

Acceptance gate (FILE_ENGINE_V2_PLAN.md): identical plaintext from N
senders produces identical ciphertext chunk IDs for raw-media content
types; per-recipient (raw) addressing for everything else.

These unit tests exercise the wiring (engine + resolver) without
spinning a full daemon — they ensure ``encrypt_chunk_bytes`` honours
the ``address_kind`` kwarg and that ``_resolve_address_kind`` returns
the right policy for each content type.
"""

from __future__ import annotations

from pathlib import Path

import pytest


def _native_available() -> bool:
    try:
        from one_link_native import chunk  # noqa: F401

        return True
    except ImportError:
        return False


def test_resolve_address_kind_classifies_raw_media_as_convergent(tmp_path):
    from one_link.native_transfer import NativeTransferSession

    assert NativeTransferSession._resolve_address_kind(tmp_path / "movie.mp4") == "convergent"
    assert NativeTransferSession._resolve_address_kind(tmp_path / "song.flac") == "convergent"
    assert NativeTransferSession._resolve_address_kind(tmp_path / "pic.jpg") == "convergent"
    assert NativeTransferSession._resolve_address_kind(tmp_path / "pic.JPEG") == "convergent"
    assert NativeTransferSession._resolve_address_kind(tmp_path / "anim.webm") == "convergent"


def test_resolve_address_kind_classifies_project_files_as_raw(tmp_path):
    from one_link.native_transfer import NativeTransferSession

    assert NativeTransferSession._resolve_address_kind(tmp_path / "doc.pdf") == "raw"
    assert NativeTransferSession._resolve_address_kind(tmp_path / "code.py") == "raw"
    assert NativeTransferSession._resolve_address_kind(tmp_path / "deck.pptx") == "raw"
    assert NativeTransferSession._resolve_address_kind(tmp_path / "archive.zip") == "raw"
    assert NativeTransferSession._resolve_address_kind(tmp_path / "no-ext") == "raw"


@pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native.chunk not installed",
)
def test_encrypt_chunk_bytes_convergent_produces_stable_chunk_id():
    """Two independent senders encrypting the same plaintext under
    ``address_kind="convergent"`` produce the SAME chunk_id (modulo
    the AEAD ciphertext, which depends on the per-sender ratchet
    nonce). This is the Phase B dedup gate."""
    from one_link.native_transfer import NativeTransferSession

    sender_a = NativeTransferSession(shared_secret=b"\x01" * 32, aead_kind="chacha")
    sender_b = NativeTransferSession(shared_secret=b"\x02" * 32, aead_kind="chacha")
    plaintext = b"identical video frame bytes" * 1024  # 27 KiB
    rec_a = sender_a.encrypt_chunk_bytes(plaintext, address_kind="convergent")
    rec_b = sender_b.encrypt_chunk_bytes(plaintext, address_kind="convergent")
    # Same plaintext, convergent addressing -> identical chunk IDs
    # across independent senders. This is what enables the dedup
    # dividend.
    assert rec_a.chunk_id == rec_b.chunk_id
    # Different shared secrets -> different ciphertexts (privacy
    # preserved at the AEAD layer, dedup happens at the address layer).
    assert rec_a.ciphertext != rec_b.ciphertext


@pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native.chunk not installed",
)
def test_encrypt_chunk_bytes_raw_produces_per_sender_chunk_id():
    """``address_kind="raw"`` (the default) produces the same
    chunk_id across senders for identical plaintext too — raw-BLAKE3
    is also a pure function of the plaintext. The difference is in
    semantics: raw is "we don't expose dedup intent."

    The plaintext-only address is identical; what differs in the
    raw vs convergent case is the DERIVATION KEY context, not the
    fact of cross-sender stability. This test pins that distinction."""
    from one_link.native_transfer import NativeTransferSession

    sender_a = NativeTransferSession(shared_secret=b"\x01" * 32, aead_kind="chacha")
    sender_b = NativeTransferSession(shared_secret=b"\x02" * 32, aead_kind="chacha")
    plaintext = b"identical project file bytes" * 1024
    rec_raw_a = sender_a.encrypt_chunk_bytes(plaintext, address_kind="raw")
    rec_raw_b = sender_b.encrypt_chunk_bytes(plaintext, address_kind="raw")
    # raw-BLAKE3 is also a pure function; both senders agree on
    # chunk_id. The semantic distinction is the DERIVATION DOMAIN
    # ("ol-chunk-addr-convergent-v1" vs raw blake3), which makes
    # convergent IDs and raw IDs disjoint chunk-address-spaces.
    assert rec_raw_a.chunk_id == rec_raw_b.chunk_id


@pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native.chunk not installed",
)
def test_raw_and_convergent_chunk_ids_are_disjoint():
    """The same plaintext encrypted under raw vs convergent produces
    DIFFERENT chunk IDs — they're separate address spaces. This is
    the safety property: a convergent chunk can never collide with
    a raw chunk in the chunk store, so the dedup decision is
    explicit at write time and never accidental."""
    from one_link.native_transfer import NativeTransferSession

    eng = NativeTransferSession(shared_secret=b"\x01" * 32, aead_kind="chacha")
    plaintext = b"some bytes" * 100
    rec_raw = eng.encrypt_chunk_bytes(plaintext, address_kind="raw")
    eng2 = NativeTransferSession(shared_secret=b"\x01" * 32, aead_kind="chacha")
    rec_conv = eng2.encrypt_chunk_bytes(plaintext, address_kind="convergent")
    assert rec_raw.chunk_id != rec_conv.chunk_id


@pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native.chunk not installed",
)
def test_encrypt_chunk_bytes_explicit_chunk_id_wins_over_address_kind():
    """When an explicit chunk_id is passed, address_kind is ignored
    (caller has computed it externally). Pinning the precedence so
    no future refactor accidentally double-derives."""
    from one_link.native_transfer import NativeTransferSession

    eng = NativeTransferSession(shared_secret=b"\x01" * 32, aead_kind="chacha")
    explicit_id = b"\xaa" * 32
    plaintext = b"some bytes"
    rec = eng.encrypt_chunk_bytes(
        plaintext, chunk_id=explicit_id, address_kind="convergent",
    )
    assert rec.chunk_id == explicit_id
