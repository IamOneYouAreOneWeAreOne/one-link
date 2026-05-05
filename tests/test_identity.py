"""Identity module: keypair gen, persistence, fingerprint, verify."""

from __future__ import annotations

from pathlib import Path

import pytest

from one_link.identity import fingerprint_of, load_or_create, verify


def test_create_new_identity(tmp_path: Path):
    key = tmp_path / "id.key"
    me = load_or_create(key)
    assert key.exists()
    assert key.stat().st_size > 0
    assert len(me.public_bytes) == 32
    assert len(me.fingerprint) == 64  # blake3 hex (256-bit)
    assert me.short_id == me.fingerprint[:8]
    assert me.hostname  # whatever the OS thinks


def test_persistence_round_trip(tmp_path: Path):
    key = tmp_path / "id.key"
    a = load_or_create(key)
    b = load_or_create(key)
    assert a.fingerprint == b.fingerprint
    assert a.public_bytes == b.public_bytes


def test_two_fresh_keys_differ(tmp_path: Path):
    a = load_or_create(tmp_path / "a.key")
    b = load_or_create(tmp_path / "b.key")
    assert a.fingerprint != b.fingerprint


def test_sign_and_verify(tmp_path: Path):
    me = load_or_create(tmp_path / "id.key")
    payload = b"hello, world"
    sig = me.sign(payload)
    assert verify(me.public_bytes, sig, payload)


def test_verify_rejects_tampered_payload(tmp_path: Path):
    me = load_or_create(tmp_path / "id.key")
    sig = me.sign(b"hello")
    assert not verify(me.public_bytes, sig, b"hellp")


def test_verify_rejects_wrong_pubkey(tmp_path: Path):
    a = load_or_create(tmp_path / "a.key")
    b = load_or_create(tmp_path / "b.key")
    sig = a.sign(b"x")
    assert not verify(b.public_bytes, sig, b"x")


def test_verify_rejects_garbage_pubkey(tmp_path: Path):
    me = load_or_create(tmp_path / "id.key")
    sig = me.sign(b"x")
    assert not verify(b"\x00" * 32, sig, b"x")
    assert not verify(b"too short", sig, b"x")
    assert not verify(b"\x00" * 100, sig, b"x")


def test_verify_rejects_garbage_signature(tmp_path: Path):
    me = load_or_create(tmp_path / "id.key")
    assert not verify(me.public_bytes, b"\x00" * 64, b"x")
    assert not verify(me.public_bytes, b"short", b"x")


def test_fingerprint_is_deterministic():
    fp1 = fingerprint_of(b"\x42" * 32)
    fp2 = fingerprint_of(b"\x42" * 32)
    assert fp1 == fp2
    assert len(fp1) == 64


def test_fingerprint_changes_with_input():
    fp1 = fingerprint_of(b"\x42" * 32)
    fp2 = fingerprint_of(b"\x43" * 32)
    assert fp1 != fp2


def test_corrupt_keyfile_raises(tmp_path: Path):
    key = tmp_path / "id.key"
    key.write_bytes(b"this is not a PEM key")
    with pytest.raises(Exception):
        load_or_create(key)
