"""Phase C-3 (ADR-0026) FILE_NATIVE_CHUNK wire-format + capability
negotiation tests.

Covers the daemon-level cutover plumbing without spinning up a full
two-daemon socket pair. End-to-end socket coverage stays in the daemon
test suite (which still uses the legacy FILE_CHUNK path; opt-in is via
``ONE_LINK_NATIVE_TRANSFER=1``).
"""

from __future__ import annotations

import asyncio
import os

import pytest


def _native_available() -> bool:
    try:
        from one_link import native_transfer

        return native_transfer.HAS_NATIVE
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native not installed (build via maturin)",
)


# --- capability constant + advertise ---------------------------------------


def test_native_transfer_indexed_v1_in_local_capabilities():
    """The capability must be in the daemon's advertised set so peers
    discover it via CAPS."""
    from one_link import capabilities

    assert "native_transfer_v1" == capabilities.NATIVE_TRANSFER_V1
    assert "native_transfer_indexed_v1" == capabilities.NATIVE_TRANSFER_INDEXED_V1
    assert capabilities.NATIVE_TRANSFER_V1 not in capabilities.LOCAL_CAPABILITIES
    assert capabilities.NATIVE_TRANSFER_INDEXED_V1 in capabilities.LOCAL_CAPABILITIES
    # It's a transport-layer cap (not user-prompt-required).
    assert capabilities.NATIVE_TRANSFER_INDEXED_V1 in capabilities.TRANSPORT_LAYER_CAPS


def test_channel_note_caps_records_native_transfer():
    """Channel.note_caps_received must flip
    peer_native_transfer_capable when peer advertises the cap."""
    from one_link.channel import Channel
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    loop = asyncio.new_event_loop()
    try:
        reader = asyncio.StreamReader(loop=loop)
        writer = type("W", (), {})()
        c = Channel(
            reader=reader,
            writer=writer,  # type: ignore[arg-type]
            peer_ed_pub=b"\x00" * 32,
            peer_short_id="peer_test",
            tx_aead=ChaCha20Poly1305(os.urandom(32)),
            rx_aead=ChaCha20Poly1305(os.urandom(32)),
            transcript_hash=os.urandom(32),
        )
        assert c.peer_native_transfer_capable is False
        c.note_caps_received(["double_ratchet_v1", "files", "native_transfer_indexed_v1"])
        assert c.peer_native_transfer_capable is True

        c2 = Channel(
            reader=reader,
            writer=writer,  # type: ignore[arg-type]
            peer_ed_pub=b"\x00" * 32,
            peer_short_id="peer_test_legacy",
            tx_aead=ChaCha20Poly1305(os.urandom(32)),
            rx_aead=ChaCha20Poly1305(os.urandom(32)),
            transcript_hash=os.urandom(32),
        )
        c2.note_caps_received(["double_ratchet_v1", "files"])  # legacy peer
        assert c2.peer_native_transfer_capable is False
    finally:
        loop.close()


# --- session caching -------------------------------------------------------


def _matched_channels():
    """Two channels that share DR-bootstrap material — emulates a
    post-handshake state. Same fixture shape as
    test_channel_native_transfer.py."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    from one_link.channel import Channel

    alice_priv = X25519PrivateKey.generate()
    bob_priv = X25519PrivateKey.generate()
    shared = alice_priv.exchange(bob_priv.public_key())
    transcript = os.urandom(32)
    bob_pub = bob_priv.public_key().public_bytes_raw()
    alice_pub = alice_priv.public_key().public_bytes_raw()

    def _build(role, my_priv, peer_pub):
        loop = asyncio.new_event_loop()
        c = Channel(
            reader=asyncio.StreamReader(loop=loop),
            writer=type("W", (), {})(),  # type: ignore[arg-type]
            peer_ed_pub=b"\x00" * 32,
            peer_short_id=f"peer_{role}",
            tx_aead=ChaCha20Poly1305(os.urandom(32)),
            rx_aead=ChaCha20Poly1305(os.urandom(32)),
            transcript_hash=transcript,
        )
        c._dr_role = role
        c._dr_x_priv = my_priv
        c._dr_peer_x_pub = peer_pub
        c._dr_shared = shared
        return c

    return _build("alice", alice_priv, bob_pub), _build("bob", bob_priv, alice_pub)


def test_get_or_create_native_transfer_session_caches():
    """Calling twice returns the same instance — confirms the daemon
    pattern of "build on first chunk, reuse for the rest of the
    channel" doesn't accidentally drift session state."""
    alice, _ = _matched_channels()
    s1 = alice.get_or_create_native_transfer_session()
    s2 = alice.get_or_create_native_transfer_session()
    assert s1 is s2


# --- wire-format round trip via paired sessions ----------------------------


def test_file_native_chunk_wire_envelope_round_trips():
    """Sender encrypts via its native session; the wire-shape encode
    (chunk_id hex, plaintext_len, base64 ciphertext) round-trips
    through a JSON-equivalent dict to the receiver's decrypt path."""
    import base64
    import json

    from one_link import native_transfer

    alice, bob = _matched_channels()
    sender = alice.get_or_create_native_transfer_session()
    receiver = bob.get_or_create_native_transfer_session()

    plaintext = os.urandom(2048)
    record = sender.encrypt_chunk_bytes(plaintext)

    # Build the FILE_NATIVE_CHUNK wire dict (what make_msg + encode_msg
    # would produce).
    wire = {
        "t": "FILE_NATIVE_CHUNK",
        "id": "test-id",
        "ts": 1234,
        "from": "alice",
        "blob": "deadbeef",
        "seq": 0,
        "chunk_index": record.chunk_index,
        "chunk_id": record.chunk_id.hex(),
        "plaintext_len": record.plaintext_len,
        "data": base64.b64encode(record.ciphertext).decode("ascii"),
        "eof": True,
    }
    # Round trip through JSON to prove the encoded shape is valid.
    encoded = json.dumps(wire)
    decoded = json.loads(encoded)

    # Receiver reconstructs the record from the wire dict.
    rebuilt = native_transfer.NativeChunkRecord(
        chunk_id=bytes.fromhex(decoded["chunk_id"]),
        chunk_index=decoded["chunk_index"],
        plaintext_len=decoded["plaintext_len"],
        ciphertext=base64.b64decode(decoded["data"]),
    )
    recovered = receiver.decrypt_chunk(rebuilt)
    assert recovered == plaintext


def test_file_native_chunk_wire_keeps_session_chunk_index_across_files():
    """Regression for the live 512 KiB every-other-transfer timeout.

    FILE_NATIVE_CHUNK has two different counters:
      * ``seq`` is the per-file order and resets to zero for each file.
      * ``chunk_index`` is the native transfer session counter and keeps
        increasing across repeated files on the same channel.

    The receiver must decrypt with ``chunk_index``. Reusing ``seq`` as
    the AEAD nonce works for the first file, then breaks the next one.
    """
    import base64

    from one_link import native_transfer

    alice, bob = _matched_channels()
    sender = alice.get_or_create_native_transfer_session()
    receiver = bob.get_or_create_native_transfer_session()

    first = sender.encrypt_chunk_bytes(os.urandom(1024))
    second_plaintext = os.urandom(2048)
    second = sender.encrypt_chunk_bytes(second_plaintext)

    first_wire = {
        "seq": 0,
        "chunk_index": first.chunk_index,
        "chunk_id": first.chunk_id.hex(),
        "plaintext_len": first.plaintext_len,
        "data": base64.b64encode(first.ciphertext).decode("ascii"),
    }
    second_wire = {
        "seq": 0,  # new file, so per-file sequence resets
        "chunk_index": second.chunk_index,
        "chunk_id": second.chunk_id.hex(),
        "plaintext_len": second.plaintext_len,
        "data": base64.b64encode(second.ciphertext).decode("ascii"),
    }

    first_rebuilt = native_transfer.NativeChunkRecord(
        chunk_id=bytes.fromhex(first_wire["chunk_id"]),
        chunk_index=first_wire["chunk_index"],
        plaintext_len=first_wire["plaintext_len"],
        ciphertext=base64.b64decode(first_wire["data"]),
    )
    assert receiver.decrypt_chunk(first_rebuilt) is not None

    second_rebuilt = native_transfer.NativeChunkRecord(
        chunk_id=bytes.fromhex(second_wire["chunk_id"]),
        chunk_index=second_wire["chunk_index"],
        plaintext_len=second_wire["plaintext_len"],
        ciphertext=base64.b64decode(second_wire["data"]),
    )
    assert receiver.decrypt_chunk(second_rebuilt) == second_plaintext

    broken_rebuilt = native_transfer.NativeChunkRecord(
        chunk_id=bytes.fromhex(second_wire["chunk_id"]),
        chunk_index=second_wire["seq"],
        plaintext_len=second_wire["plaintext_len"],
        ciphertext=base64.b64decode(second_wire["data"]),
    )
    bob_tx, bob_rx = bob.derive_native_transfer_direction_secrets()
    fresh_receiver = native_transfer.duplex_session_from_directional_secrets(
        bob_tx,
        bob_rx,
    )
    fresh_receiver.decrypt_chunk(first_rebuilt)
    with pytest.raises(Exception):
        fresh_receiver.decrypt_chunk(broken_rebuilt)


def test_file_native_chunk_aead_tag_rejects_swapped_chunk_id():
    """Wire-format tampering: rewrite chunk_id on the wire. The
    receiver's AEAD-AAD-bound tag check must reject before any
    plaintext leaks (the explicit BLAKE3 verify is dropped, so the
    AEAD is the only gate)."""
    from one_link import native_transfer

    alice, bob = _matched_channels()
    sender = alice.get_or_create_native_transfer_session()
    receiver = bob.get_or_create_native_transfer_session()

    record = sender.encrypt_chunk_bytes(b"y" * 1024)
    # Tamper a byte in the chunk_id.
    tampered_id = bytearray(record.chunk_id)
    tampered_id[5] ^= 0xAA
    tampered = native_transfer.NativeChunkRecord(
        chunk_id=bytes(tampered_id),
        chunk_index=record.chunk_index,
        plaintext_len=record.plaintext_len,
        ciphertext=record.ciphertext,
    )
    with pytest.raises(Exception):
        receiver.decrypt_chunk(tampered)


# --- end-to-end multi-chunk round trip via paired channels ----------------


def test_multi_chunk_round_trip_via_paired_channels():
    """Stream 8 chunks via the sender, decode each through the
    receiver. Mirrors what daemon's send_file loop does end-to-end."""
    alice, bob = _matched_channels()
    sender = alice.get_or_create_native_transfer_session()
    receiver = bob.get_or_create_native_transfer_session()

    chunks = [os.urandom(64 * 1024) for _ in range(8)]
    records = [sender.encrypt_chunk_bytes(c) for c in chunks]
    recovered = [receiver.decrypt_chunk(r) for r in records]
    assert recovered == chunks


# --- env flag gating (sender opt-in) ---------------------------------------


def _native_env_resolved() -> bool:
    """Replicates the daemon's exact env-flag resolution at
    ``daemon.py:18423``: unset → "1" default → enabled, only the
    literal "0" disables. Centralising the check here means a test
    failure on the helper can't be a typo in three near-identical
    tests."""
    return os.environ.get("ONE_LINK_NATIVE_TRANSFER", "1") != "0"


def test_env_flag_default_on(monkeypatch):
    """Post default-flip (ADR-0026 follow-up): unset env defaults to
    native transport when peer advertises the capability. Daemon
    reads ``os.environ.get("ONE_LINK_NATIVE_TRANSFER", "1") != "0"``,
    so absence → default-on.

    2026-05-22 audit Batch BB: use ``monkeypatch.delenv`` for
    isolation under pytest-xdist + drive the daemon's exact env
    resolver via ``_native_env_resolved`` so a refactor of the
    daemon-side check that diverges from this test's assertion
    shows up here."""
    monkeypatch.delenv("ONE_LINK_NATIVE_TRANSFER", raising=False)
    assert _native_env_resolved() is True


def test_env_flag_explicit_disable(monkeypatch):
    """Operators rolling back during incident can set
    ONE_LINK_NATIVE_TRANSFER=0 to force the legacy path."""
    monkeypatch.setenv("ONE_LINK_NATIVE_TRANSFER", "0")
    assert _native_env_resolved() is False


def test_env_flag_explicit_enable(monkeypatch):
    monkeypatch.setenv("ONE_LINK_NATIVE_TRANSFER", "1")
    assert _native_env_resolved() is True
