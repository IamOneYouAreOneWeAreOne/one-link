"""Phase C-3 (ADR-0025) channel <-> native_transfer integration.

Verifies the new ``Channel.derive_native_transfer_secret()`` /
``Channel.establish_native_transfer()`` helpers wire the channel's
existing DR-bootstrap material through to a working
:class:`NativeTransferSession`.

These are unit tests against synthesized channels — no live socket /
peer pairing. End-to-end-with-real-socket coverage stays in the daemon
test suite (currently exercises legacy AEAD; native cutover lands in
a follow-up commit per ADR-0025's shadow-window gate).
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


def _matched_channels():
    """Build two channels that share DR bootstrap material — emulates a
    completed handshake where both peers ended up with the same
    ``_dr_shared`` and the same ``transcript_hash``."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    from one_link.channel import Channel

    # The "shared secret" both ends would compute via X25519 ECDH.
    alice_priv = X25519PrivateKey.generate()
    bob_priv = X25519PrivateKey.generate()
    alice_pub = alice_priv.public_key().public_bytes_raw()
    bob_pub = bob_priv.public_key().public_bytes_raw()
    shared = alice_priv.exchange(bob_priv.public_key())
    # Both sides also share an identical transcript_hash (the SHA-256
    # of HELLO || REPLY in the real flow).
    transcript = os.urandom(32)

    def _build_channel(role: str, my_priv, peer_pub) -> Channel:
        # Channel needs reader/writer/peer_ed_pub/peer_short_id/tx_aead
        # /rx_aead. We synthesize dummy versions because the helpers
        # under test don't touch them.
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

        loop = asyncio.new_event_loop()
        reader = asyncio.StreamReader(loop=loop)
        writer = type("W", (), {"drain": lambda self: None, "close": lambda self: None})()
        c = Channel(
            reader=reader,
            writer=writer,  # type: ignore[arg-type]
            peer_ed_pub=b"\x00" * 32,
            peer_short_id="peer_test",
            tx_aead=ChaCha20Poly1305(os.urandom(32)),
            rx_aead=ChaCha20Poly1305(os.urandom(32)),
            transcript_hash=transcript,
        )
        c._dr_role = role
        c._dr_x_priv = my_priv
        c._dr_peer_x_pub = peer_pub
        c._dr_shared = shared
        return c

    return _build_channel("alice", alice_priv, bob_pub), _build_channel(
        "bob", bob_priv, alice_pub
    )


def test_derive_native_transfer_secret_matched_across_peers():
    """Both peers, given the same DR-bootstrap material + transcript,
    must derive the same 32-byte native transfer secret. Otherwise
    sender + receiver wouldn't end up on the same ratchet."""
    alice, bob = _matched_channels()
    secret_a = alice.derive_native_transfer_secret()
    secret_b = bob.derive_native_transfer_secret()
    assert secret_a == secret_b
    assert len(secret_a) == 32


def test_derive_native_transfer_secret_rejects_pre_handshake():
    """Calling before the channel has a DR-bootstrap shared raises."""
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    from one_link.channel import Channel

    loop = asyncio.new_event_loop()
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
    # _dr_shared is None by default.
    with pytest.raises(RuntimeError, match="handshake incomplete"):
        c.derive_native_transfer_secret()


def test_establish_native_transfer_round_trips_via_paired_channels(tmp_path):
    """The full daemon-cutover shape: alice.establish_native_transfer()
    on the sender side produces a session whose chunks decrypt on the
    paired receiver session bob.establish_native_transfer()."""
    alice, bob = _matched_channels()
    sender = alice.establish_native_transfer()
    receiver = bob.establish_native_transfer()

    payload = os.urandom(100 * 1024)
    path = tmp_path / "f.bin"
    path.write_bytes(payload)
    records = list(sender.encrypt_file(path))
    recovered = receiver.decrypt_records_to_bytes(records)
    assert recovered == payload


def test_establish_native_transfer_supports_native_backend(tmp_path):
    """Selecting cipher_backend='native' routes through the ring-backed
    ol_aead.AeadCipher multi-frame path. Round trip must still work."""
    alice, bob = _matched_channels()
    sender = alice.establish_native_transfer(cipher_backend="native")
    receiver = bob.establish_native_transfer(cipher_backend="native")

    payload = os.urandom(50 * 1024)
    path = tmp_path / "f.bin"
    path.write_bytes(payload)
    records = list(sender.encrypt_file(path))
    recovered = receiver.decrypt_records_to_bytes(records)
    assert recovered == payload


def test_distinct_channels_produce_distinct_native_secrets():
    """Two independent channel pairs (different X25519 keypairs) must
    derive different native transfer secrets. Critical: a leak of one
    session must not compromise another."""
    a1, b1 = _matched_channels()
    a2, b2 = _matched_channels()
    s1 = a1.derive_native_transfer_secret()
    s2 = a2.derive_native_transfer_secret()
    assert s1 != s2
