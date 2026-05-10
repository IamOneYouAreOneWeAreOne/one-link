"""v0.20.7 (audit M30) — deterministic AES-SIV path-PII encryption.

The chunk_sources.path + file_index_cache.path columns reveal the
user's home-dir layout to a T4 attacker (lost device, at-rest
unlocked). We can't simply hash the path (kills the path → bytes
lookup) or store basename + folder root (breaks ad-hoc-send paths
not under any synced folder).

Outside-the-box fix: AES-SIV deterministic AEAD (RFC 5297). Same
plaintext + AAD → same ciphertext, so the existing PRIMARY KEY +
UNIQUE indexes still de-duplicate / look up correctly. Without the
seed-derived key the ciphertext is opaque.

These tests pin:

  - encrypt+decrypt round-trips correctly
  - same plaintext + AAD → same ciphertext (the property we need
    for indexing)
  - different AAD → different ciphertext (column separation)
  - different seed → different ciphertext (cross-install isolation)
  - tampered ciphertext fails (auth)
  - legacy cleartext (no marker) passes through unchanged
  - State lookups work end-to-end with the encryptor attached
  - State lookups still find legacy cleartext rows (rolling-upgrade
    safety net)
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from one_link import path_pii, state as state_mod
from one_link.path_pii import PathPIIEncryptor


def _seed():
    return os.urandom(32)


# ── primitive layer ─────────────────────────────────────────────────


def test_round_trip():
    enc = PathPIIEncryptor(_seed())
    p = "/Users/Alice/Documents/Confidential/payroll.xlsx"
    wrapped = enc.wrap(p, aad=b"col-A")
    assert wrapped.startswith(path_pii.PATH_PII_MARKER)
    assert path_pii.is_wrapped(wrapped)
    assert enc.unwrap(wrapped, aad=b"col-A") == p


def test_deterministic_same_input_same_output():
    """The defining AES-SIV property — same plaintext + AAD always
    encrypts to the same ciphertext under the same key. This is what
    makes indexed lookup work."""
    enc = PathPIIEncryptor(_seed())
    p = "C:/Users/Bob/Pictures/family.jpg"
    a = enc.wrap(p, aad=b"aad-x")
    b = enc.wrap(p, aad=b"aad-x")
    assert a == b


def test_different_aad_different_ciphertext():
    """A path encrypted under AAD-A must NOT match the same path
    encrypted under AAD-B; column separation prevents pivoting."""
    enc = PathPIIEncryptor(_seed())
    p = "/tmp/x.bin"
    a = enc.wrap(p, aad=b"AAD-1")
    b = enc.wrap(p, aad=b"AAD-2")
    assert a != b


def test_different_seed_different_ciphertext():
    """Cross-install: two daemons with different seeds wrap the same
    path to different ciphertext. Even a leaked path-PII column from
    one daemon is unintelligible against another's column."""
    e1 = PathPIIEncryptor(_seed())
    e2 = PathPIIEncryptor(_seed())
    p = "/etc/passwd"
    a = e1.wrap(p, aad=b"x")
    b = e2.wrap(p, aad=b"x")
    assert a != b
    # Cross-install unwrap fails (returns None per the API contract).
    assert e2.unwrap(a, aad=b"x") is None


def test_ciphertext_tamper_rejected():
    enc = PathPIIEncryptor(_seed())
    wrapped = enc.wrap("/path/to/file", aad=b"x")
    # Flip a byte in the body.
    body = list(wrapped)
    body[len(path_pii.PATH_PII_MARKER) + 4] = (
        "X" if body[len(path_pii.PATH_PII_MARKER) + 4] != "X" else "Y"
    )
    tampered = "".join(body)
    assert enc.unwrap(tampered, aad=b"x") is None


def test_legacy_cleartext_passes_through():
    """Rolling-upgrade hatch: rows written before this module landed
    are returned unchanged so old installs still hit their indexes
    while the data slowly migrates on natural rewrites."""
    enc = PathPIIEncryptor(_seed())
    # No marker prefix → treat as legacy cleartext.
    legacy = "/Users/Alice/legacy.bin"
    assert enc.unwrap(legacy, aad=b"x") == legacy


def test_empty_path_passthrough():
    enc = PathPIIEncryptor(_seed())
    assert enc.wrap("", aad=b"x") == ""
    assert enc.unwrap("", aad=b"x") == ""


def test_wrong_seed_length_rejected():
    with pytest.raises(ValueError, match="32 bytes"):
        path_pii.derive_path_pii_key(b"\x00" * 16)


# ── State integration ──────────────────────────────────────────────


def test_state_chunk_sources_round_trip_with_encryptor(tmp_path):
    """End-to-end: write a chunk source with a real path; the on-disk
    column is opaque ciphertext, the read API returns the original
    cleartext path."""
    db_path = tmp_path / "s.db"
    s = state_mod.State(db_path=db_path)
    seed = _seed()
    s.set_path_pii_encryptor(PathPIIEncryptor(seed))

    real_path = "/Users/Alice/Documents/secret.docx"
    s.record_chunk_source(
        chunk_hash="a" * 64,
        path=real_path,
        start=0, size=4096, mtime_ms=1, file_size=4096,
    )

    # The raw on-disk row must NOT contain the cleartext path.
    raw = s._conn.execute(
        "SELECT path FROM chunk_sources WHERE chunk_hash=?",
        ("a" * 64,),
    ).fetchone()
    assert raw is not None
    assert raw["path"].startswith(path_pii.PATH_PII_MARKER)
    assert real_path not in raw["path"]

    # The public read API decrypts back to cleartext.
    rows = s.get_chunk_sources("a" * 64)
    assert len(rows) == 1
    assert rows[0]["path"] == real_path
    s._conn.close()


def test_state_file_index_cache_lookup_with_encryptor(tmp_path):
    """The lookup path must wrap the query before SELECT WHERE — same
    plaintext + AAD → same ciphertext, so the row inserted under the
    same canonical path is still found."""
    db_path = tmp_path / "s.db"
    s = state_mod.State(db_path=db_path)
    seed = _seed()
    s.set_path_pii_encryptor(PathPIIEncryptor(seed))

    real_path = "/Users/Alice/big.iso"
    s.record_file_index_cache(
        path=real_path,
        size=1 << 30, mtime_ns=1, ctime_ns=1,
        blob_hash="b" * 64, index_kind="cdc",
        chunks=[],
    )

    out = s.get_file_index_cache(
        path=real_path, size=1 << 30, mtime_ns=1, ctime_ns=1,
    )
    assert out is not None
    assert out["path"] == real_path
    s._conn.close()


def test_state_legacy_cleartext_row_still_readable(tmp_path):
    """A row written without the encryptor (legacy cleartext) must
    still be readable AFTER the encryptor is attached. This is the
    rolling-upgrade safety net."""
    db_path = tmp_path / "s.db"
    s = state_mod.State(db_path=db_path)
    # Write WITHOUT encryptor (legacy state).
    legacy_path = "/Users/Alice/legacy.bin"
    s.record_chunk_source(
        chunk_hash="c" * 64,
        path=legacy_path,
        start=0, size=4096, mtime_ms=1, file_size=4096,
    )
    # Now attach an encryptor (post-upgrade boot).
    s.set_path_pii_encryptor(PathPIIEncryptor(_seed()))
    rows = s.get_chunk_sources("c" * 64)
    assert len(rows) == 1
    # Legacy cleartext returns unchanged; no decrypt-fail surface.
    assert rows[0]["path"] == legacy_path
    s._conn.close()


def test_state_no_encryptor_passthrough(tmp_path):
    """Without an encryptor attached, paths are stored cleartext —
    same posture as pre-v0.20.7."""
    db_path = tmp_path / "s.db"
    s = state_mod.State(db_path=db_path)
    s.record_chunk_source(
        chunk_hash="d" * 64,
        path="/some/path.bin",
        start=0, size=4096, mtime_ms=1, file_size=4096,
    )
    raw = s._conn.execute(
        "SELECT path FROM chunk_sources WHERE chunk_hash=?",
        ("d" * 64,),
    ).fetchone()
    assert raw["path"] == "/some/path.bin"
    s._conn.close()


def test_state_index_dedup_under_encryption(tmp_path):
    """Same plaintext path inserted twice must hit the ON CONFLICT
    branch — proves the deterministic property holds end-to-end."""
    db_path = tmp_path / "s.db"
    s = state_mod.State(db_path=db_path)
    s.set_path_pii_encryptor(PathPIIEncryptor(_seed()))

    p = "/Users/Alice/file.bin"
    s.record_chunk_source(
        chunk_hash="e" * 64, path=p,
        start=0, size=4096, mtime_ms=1, file_size=4096,
    )
    s.record_chunk_source(
        chunk_hash="e" * 64, path=p,
        start=0, size=8192, mtime_ms=2, file_size=8192,  # bumped fields
    )
    rows = s.get_chunk_sources("e" * 64)
    assert len(rows) == 1  # ON CONFLICT collapsed both writes
    assert rows[0]["size"] == 8192  # updated_ms=2 row won
    s._conn.close()
