"""Tests for at-rest capsule encryption — audit C5 closure.

Properties:
  - Round-trip preserves the plaintext.
  - Wrong master_seed fails decryption (no plaintext leakage).
  - Wrong call_id fails decryption.
  - Tampered ciphertext fails the AEAD tag.
  - Header can be inspected without the key.
  - Magic mismatch raises before any decryption attempt.
"""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest

from one_link.capsule_at_rest import (
    KEY_LEN,
    MAGIC,
    NONCE_LEN,
    SEAL_VERSION,
    derive_capsule_key,
    inspect_header,
    open_from_path,
    seal_to_path,
)


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def test_derive_capsule_key_returns_correct_length() -> None:
    key = derive_capsule_key(
        master_seed=secrets.token_bytes(32),
        call_id="abc",
        finalized_at_ms=1_700_000_000_000,
    )
    assert len(key) == KEY_LEN


def test_derive_capsule_key_is_deterministic() -> None:
    seed = secrets.token_bytes(32)
    k1 = derive_capsule_key(
        master_seed=seed, call_id="abc", finalized_at_ms=1000,
    )
    k2 = derive_capsule_key(
        master_seed=seed, call_id="abc", finalized_at_ms=1000,
    )
    assert k1 == k2


def test_derive_capsule_key_differs_per_call_id() -> None:
    seed = secrets.token_bytes(32)
    k1 = derive_capsule_key(master_seed=seed, call_id="a", finalized_at_ms=1000)
    k2 = derive_capsule_key(master_seed=seed, call_id="b", finalized_at_ms=1000)
    assert k1 != k2


def test_derive_capsule_key_differs_per_finalized_time() -> None:
    seed = secrets.token_bytes(32)
    k1 = derive_capsule_key(master_seed=seed, call_id="a", finalized_at_ms=1000)
    k2 = derive_capsule_key(master_seed=seed, call_id="a", finalized_at_ms=2000)
    assert k1 != k2


def test_derive_capsule_key_rejects_short_seed() -> None:
    with pytest.raises(ValueError):
        derive_capsule_key(
            master_seed=b"too-short", call_id="x", finalized_at_ms=0,
        )


def test_derive_capsule_key_rejects_empty_call_id() -> None:
    with pytest.raises(ValueError):
        derive_capsule_key(
            master_seed=secrets.token_bytes(32),
            call_id="", finalized_at_ms=0,
        )


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------

def test_seal_then_open_round_trip(tmp_path: Path) -> None:
    seed = secrets.token_bytes(32)
    plaintext = b"voice-note-audio-content-blob-" * 100
    p = tmp_path / "capsule.bin"
    seal_to_path(
        plaintext=plaintext, out_path=p,
        master_seed=seed, call_id="call-xyz", finalized_at_ms=1_700,
    )
    out = open_from_path(
        sealed_path=p,
        master_seed=seed, call_id="call-xyz", finalized_at_ms=1_700,
    )
    assert out == plaintext


def test_seal_writes_magic_header(tmp_path: Path) -> None:
    seed = secrets.token_bytes(32)
    p = tmp_path / "capsule.bin"
    seal_to_path(
        plaintext=b"x", out_path=p,
        master_seed=seed, call_id="c", finalized_at_ms=0,
    )
    raw = p.read_bytes()
    assert raw[:len(MAGIC)] == MAGIC


def test_seal_produces_atomic_write(tmp_path: Path) -> None:
    """No .tmp file should remain after successful sealing."""
    seed = secrets.token_bytes(32)
    p = tmp_path / "capsule.bin"
    seal_to_path(
        plaintext=b"x", out_path=p,
        master_seed=seed, call_id="c", finalized_at_ms=0,
    )
    leftover = list(tmp_path.glob("*.tmp"))
    assert leftover == []


def test_seal_creates_parent_directories(tmp_path: Path) -> None:
    seed = secrets.token_bytes(32)
    p = tmp_path / "deep" / "nested" / "capsule.bin"
    seal_to_path(
        plaintext=b"x", out_path=p,
        master_seed=seed, call_id="c", finalized_at_ms=0,
    )
    assert p.exists()


# ---------------------------------------------------------------------------
# Refusal paths
# ---------------------------------------------------------------------------

def test_wrong_master_seed_fails_decryption(tmp_path: Path) -> None:
    seed_real = secrets.token_bytes(32)
    seed_attacker = secrets.token_bytes(32)
    p = tmp_path / "capsule.bin"
    seal_to_path(
        plaintext=b"audio", out_path=p,
        master_seed=seed_real, call_id="c", finalized_at_ms=0,
    )
    with pytest.raises(Exception):
        open_from_path(
            sealed_path=p, master_seed=seed_attacker,
            call_id="c", finalized_at_ms=0,
        )


def test_wrong_call_id_fails_decryption(tmp_path: Path) -> None:
    seed = secrets.token_bytes(32)
    p = tmp_path / "capsule.bin"
    seal_to_path(
        plaintext=b"audio", out_path=p,
        master_seed=seed, call_id="alice", finalized_at_ms=0,
    )
    with pytest.raises(Exception):
        open_from_path(
            sealed_path=p, master_seed=seed,
            call_id="not-alice", finalized_at_ms=0,
        )


def test_wrong_finalized_time_fails_decryption(tmp_path: Path) -> None:
    seed = secrets.token_bytes(32)
    p = tmp_path / "capsule.bin"
    seal_to_path(
        plaintext=b"audio", out_path=p,
        master_seed=seed, call_id="c", finalized_at_ms=1000,
    )
    with pytest.raises(Exception):
        open_from_path(
            sealed_path=p, master_seed=seed,
            call_id="c", finalized_at_ms=2000,
        )


def test_tampered_ciphertext_fails_aead_tag(tmp_path: Path) -> None:
    seed = secrets.token_bytes(32)
    p = tmp_path / "capsule.bin"
    seal_to_path(
        plaintext=b"audio-content", out_path=p,
        master_seed=seed, call_id="c", finalized_at_ms=0,
    )
    raw = bytearray(p.read_bytes())
    # Flip one bit in the ciphertext (after the header).
    header_len = len(MAGIC) + 1 + NONCE_LEN + 8
    raw[header_len + 0] ^= 0x01
    p.write_bytes(raw)
    with pytest.raises(Exception):
        open_from_path(
            sealed_path=p, master_seed=seed,
            call_id="c", finalized_at_ms=0,
        )


def test_magic_mismatch_raises_before_any_key_use(tmp_path: Path) -> None:
    p = tmp_path / "not-a-capsule.bin"
    p.write_bytes(b"random nonsense bytes that aren't a sealed capsule")
    with pytest.raises(ValueError, match="bad magic|truncated"):
        open_from_path(
            sealed_path=p, master_seed=secrets.token_bytes(32),
            call_id="c", finalized_at_ms=0,
        )


def test_unsupported_version_raises(tmp_path: Path) -> None:
    p = tmp_path / "capsule.bin"
    raw = (
        MAGIC
        + bytes([99])  # unknown version
        + b"\x00" * NONCE_LEN
        + (0).to_bytes(8, "big")
    )
    p.write_bytes(raw)
    with pytest.raises(ValueError, match="unsupported sealed capsule version"):
        open_from_path(
            sealed_path=p, master_seed=secrets.token_bytes(32),
            call_id="c", finalized_at_ms=0,
        )


def test_truncated_body_raises(tmp_path: Path) -> None:
    seed = secrets.token_bytes(32)
    p = tmp_path / "capsule.bin"
    seal_to_path(
        plaintext=b"plenty of audio data here for testing",
        out_path=p,
        master_seed=seed, call_id="c", finalized_at_ms=0,
    )
    raw = p.read_bytes()
    # Chop off the last 5 bytes — body shorter than the declared length.
    p.write_bytes(raw[:-5])
    with pytest.raises(ValueError, match="truncated body"):
        open_from_path(
            sealed_path=p, master_seed=seed,
            call_id="c", finalized_at_ms=0,
        )


# ---------------------------------------------------------------------------
# Header inspection
# ---------------------------------------------------------------------------

def test_inspect_header_returns_metadata_without_key(tmp_path: Path) -> None:
    seed = secrets.token_bytes(32)
    nonce = b"\x42" * NONCE_LEN
    p = tmp_path / "capsule.bin"
    seal_to_path(
        plaintext=b"hello", out_path=p,
        master_seed=seed, call_id="c", finalized_at_ms=0,
        nonce=nonce,
    )
    header = inspect_header(p)
    assert header.magic == MAGIC
    assert header.version == SEAL_VERSION
    assert header.nonce == nonce
    # ciphertext_len = plaintext len (5) + tag (16) = 21
    assert header.ciphertext_len == 5 + 16


def test_inspect_header_rejects_truncated_file(tmp_path: Path) -> None:
    p = tmp_path / "tiny.bin"
    p.write_bytes(b"x" * 5)
    with pytest.raises(ValueError):
        inspect_header(p)


def test_sealed_paths_reject_symbolic_link_indirection(tmp_path: Path) -> None:
    target = tmp_path / "target.bin"
    seed = secrets.token_bytes(32)
    seal_to_path(
        plaintext=b"private capsule",
        out_path=target,
        master_seed=seed,
        call_id="call-link",
        finalized_at_ms=1,
    )
    link = tmp_path / "link.bin"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are unavailable for this test account")
    with pytest.raises(ValueError, match="not a regular file"):
        open_from_path(
            sealed_path=link,
            master_seed=seed,
            call_id="call-link",
            finalized_at_ms=1,
        )
    with pytest.raises(ValueError, match="not a regular file"):
        inspect_header(link)
    with pytest.raises(ValueError, match="destination is not a regular file"):
        seal_to_path(
            plaintext=b"replacement",
            out_path=link,
            master_seed=seed,
            call_id="call-link",
            finalized_at_ms=2,
        )


# ---------------------------------------------------------------------------
# Large blob
# ---------------------------------------------------------------------------

def test_round_trip_large_blob(tmp_path: Path) -> None:
    """1 MiB capsule — verify we can handle realistic voice-note sizes."""
    seed = secrets.token_bytes(32)
    plaintext = secrets.token_bytes(1024 * 1024)
    p = tmp_path / "capsule.bin"
    seal_to_path(
        plaintext=plaintext, out_path=p,
        master_seed=seed, call_id="c", finalized_at_ms=0,
    )
    out = open_from_path(
        sealed_path=p, master_seed=seed,
        call_id="c", finalized_at_ms=0,
    )
    assert out == plaintext
