"""v0.20.7 lockbox: at-rest wrap of group chain_keys when
ONE_LINK_PASSPHRASE is set.

Pins the security audit H21 fix:
  - Cleartext writes survive when no lockbox is attached.
  - Wrapped writes round-trip via length-based detection.
  - Mid-life passphrase opt-in: legacy cleartext rows remain readable
    after a lockbox is attached.
  - Tag-mismatch on wrap fails the unwrap (no silent acceptance).
"""
from __future__ import annotations

import pytest

from one_link import lockbox as lb
from one_link.lockbox import LockBox, LockBoxError, is_wrapped, maybe_wrap, maybe_unwrap
from one_link.state import State


def _new_state(tmp_path) -> State:
    return State(db_path=tmp_path / "state.db")


def test_lockbox_wrap_unwrap_round_trip():
    box = LockBox.from_passphrase(b"hunter2", b"X" * 16)
    blob = box.wrap(b"\x00" * 32)
    assert is_wrapped(blob)
    assert len(blob) == 1 + 12 + 32 + 16
    assert box.unwrap(blob) == b"\x00" * 32


def test_lockbox_unwrap_tampered_fails():
    box = LockBox.from_passphrase(b"hunter2", b"X" * 16)
    blob = bytearray(box.wrap(b"the cat sat on the mat"))
    # Flip one byte of the ciphertext.
    blob[20] ^= 0xff
    with pytest.raises(LockBoxError):
        box.unwrap(bytes(blob))


def test_lockbox_unwrap_wrong_passphrase_fails():
    blob = LockBox.from_passphrase(b"correct", b"X" * 16).wrap(b"secret")
    other = LockBox.from_passphrase(b"wrong", b"X" * 16)
    with pytest.raises(LockBoxError):
        other.unwrap(blob)


def test_state_chain_key_cleartext_when_no_lockbox(tmp_path):
    """No lockbox attached → chain_key stored cleartext, read back
    byte-equal. Same posture as before this fix."""
    state = _new_state(tmp_path)
    try:
        secret = b"k" * 32
        state.upsert_sender_chain(
            group_id=b"g" * 16, sender_pub=b"s" * 32,
            direction="out", epoch=1, chain_key=secret, counter=0,
        )
        row = state.get_sender_chain(
            group_id=b"g" * 16, sender_pub=b"s" * 32, direction="out",
        )
        assert row["chain_key"] == secret
        # Verify it's actually cleartext on disk (32 bytes, no marker).
        raw = state._conn.execute(
            "SELECT chain_key FROM group_sender_chains LIMIT 1"
        ).fetchone()["chain_key"]
        assert len(raw) == 32
        assert raw == secret
    finally:
        state.close()


def test_state_chain_key_wrapped_when_lockbox_set(tmp_path):
    """Lockbox attached → chain_key on disk is AES-GCM wrapped, but
    reads back unwrapped value byte-equal."""
    state = _new_state(tmp_path)
    try:
        state.set_lockbox(LockBox.from_passphrase(b"hunter2", b"X" * 16))
        secret = bytes(range(32))
        state.upsert_sender_chain(
            group_id=b"g" * 16, sender_pub=b"s" * 32,
            direction="in", epoch=2, chain_key=secret, counter=5,
        )
        row = state.get_sender_chain(
            group_id=b"g" * 16, sender_pub=b"s" * 32, direction="in",
        )
        assert row["chain_key"] == secret
        # Disk is wrapped (61 bytes, marker prefix).
        raw = state._conn.execute(
            "SELECT chain_key FROM group_sender_chains LIMIT 1"
        ).fetchone()["chain_key"]
        assert len(raw) == 61
        assert raw[0:1] == lb.WRAP_MARKER
        assert raw != secret  # cleartext doesn't appear in storage
    finally:
        state.close()


def test_state_chain_key_legacy_cleartext_readable_after_lockbox_attached(tmp_path):
    """Mid-life passphrase opt-in: rows written before set_lockbox
    are still readable. The length-based detection path knows that
    a 32-byte stored value is cleartext regardless of lockbox state."""
    state = _new_state(tmp_path)
    try:
        # Phase 1: write cleartext (no lockbox).
        secret = b"\xaa" * 32
        state.upsert_sender_chain(
            group_id=b"g" * 16, sender_pub=b"s" * 32,
            direction="out", epoch=3, chain_key=secret, counter=0,
        )
        # Phase 2: attach a lockbox; legacy row stays readable.
        state.set_lockbox(LockBox.from_passphrase(b"hunter2", b"X" * 16))
        row = state.get_sender_chain(
            group_id=b"g" * 16, sender_pub=b"s" * 32, direction="out",
        )
        assert row["chain_key"] == secret
        # Phase 3: write a NEW chain — gets wrapped.
        secret2 = b"\xbb" * 32
        state.upsert_sender_chain(
            group_id=b"g" * 16, sender_pub=b"s" * 32,
            direction="in", epoch=4, chain_key=secret2, counter=1,
        )
        row2 = state.get_sender_chain(
            group_id=b"g" * 16, sender_pub=b"s" * 32, direction="in",
        )
        assert row2["chain_key"] == secret2
        # And the new chain on disk is the wrapped form.
        raw = state._conn.execute(
            "SELECT chain_key FROM group_sender_chains "
            "WHERE direction = 'in'"
        ).fetchone()["chain_key"]
        assert len(raw) == 61
    finally:
        state.close()


def test_state_chain_key_first_byte_collision_is_safe(tmp_path):
    """Defends the length-based detection rule: a cleartext chain_key
    that happens to start with the wrap-marker byte must not be
    misdetected as wrapped. Without length disambiguation a generic
    is_wrapped check would mis-fire here ~1/256 of the time."""
    state = _new_state(tmp_path)
    try:
        # Construct a cleartext 32-byte key starting with the wrap marker.
        secret = lb.WRAP_MARKER + b"x" * 31
        assert len(secret) == 32
        state.upsert_sender_chain(
            group_id=b"g" * 16, sender_pub=b"s" * 32,
            direction="out", epoch=5, chain_key=secret, counter=0,
        )
        row = state.get_sender_chain(
            group_id=b"g" * 16, sender_pub=b"s" * 32, direction="out",
        )
        assert row["chain_key"] == secret
    finally:
        state.close()


def test_lockbox_top_level_helpers_passthrough_when_none():
    assert maybe_wrap(b"hello", None) == b"hello"
    assert maybe_unwrap(b"hello", None) == b"hello"
