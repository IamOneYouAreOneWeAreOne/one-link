"""Encrypted bidirectional channel between two peers.

Handshake (Noise-IK-flavored, simplified):
    1. Initiator -> Responder
       HELLO = init_pub_ed25519 || init_pub_x25519 || nonce_init || sig_init
       sig_init signs: "OL1|HELLO|" + init_pub_ed25519 + init_pub_x25519 + nonce_init
    2. Responder -> Initiator
       REPLY = resp_pub_ed25519 || resp_pub_x25519 || nonce_resp || sig_resp
       sig_resp signs: "OL1|REPLY|" + nonce_init + resp_pub_ed25519 + resp_pub_x25519 + nonce_resp

After both sides verify the other's signature, they:
    shared = X25519(my_x25519_priv, peer_x25519_pub)
    salt   = nonce_init || nonce_resp
    keys   = HKDF(shared, salt, info="OL1/keys", L=64)
    tx_key = keys[0:32]   # initiator -> responder
    rx_key = keys[32:64]  # responder -> initiator

Each side keeps a 64-bit send counter (starts at 0) used as the ChaCha20-Poly1305 nonce
(little-endian, padded to 12 bytes). AAD = "OL1/data".

This is a deliberately small, auditable handshake — not full Noise. Good enough for
LAN trust-on-first-use; we'll harden it (replay cache, rotation, full Noise pattern)
in a later pass.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from one_link.identity import Identity, fingerprint_of, verify
from one_link.wire import read_frame, write_frame

PROTO = b"OL1"
NONCE_LEN = 16
HELLO_TAG = b"OL1|HELLO|"
REPLY_TAG = b"OL1|REPLY|"
AAD = b"OL1/data"


@dataclass
class Channel:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    peer_ed_pub: bytes
    peer_short_id: str
    tx_aead: ChaCha20Poly1305
    rx_aead: ChaCha20Poly1305
    tx_seq: int = 0
    rx_seq: int = 0

    def _nonce(self, seq: int) -> bytes:
        return seq.to_bytes(12, "little")

    async def send(self, plaintext: bytes) -> None:
        nonce = self._nonce(self.tx_seq)
        self.tx_seq += 1
        ct = self.tx_aead.encrypt(nonce, plaintext, AAD)
        await write_frame(self.writer, ct)

    async def recv(self) -> bytes:
        ct = await read_frame(self.reader)
        nonce = self._nonce(self.rx_seq)
        self.rx_seq += 1
        return self.rx_aead.decrypt(nonce, ct, AAD)

    async def close(self) -> None:
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass


def _x25519_keypair() -> tuple[X25519PrivateKey, bytes]:
    priv = X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub


def _derive_keys(shared: bytes, salt: bytes) -> tuple[bytes, bytes]:
    out = HKDF(
        algorithm=hashes.SHA256(), length=64, salt=salt, info=b"OL1/keys"
    ).derive(shared)
    return out[:32], out[32:64]


async def initiate(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    me: Identity,
) -> Channel:
    x_priv, x_pub = _x25519_keypair()
    nonce_i = os.urandom(NONCE_LEN)
    sig_i = me.sign(HELLO_TAG + me.public_bytes + x_pub + nonce_i)
    hello = me.public_bytes + x_pub + nonce_i + sig_i
    await write_frame(writer, hello)

    reply = await read_frame(reader)
    if len(reply) != 32 + 32 + NONCE_LEN + 64:
        raise RuntimeError(f"bad REPLY length: {len(reply)}")
    r_ed = reply[0:32]
    r_x = reply[32:64]
    nonce_r = reply[64 : 64 + NONCE_LEN]
    sig_r = reply[64 + NONCE_LEN :]
    if not verify(r_ed, sig_r, REPLY_TAG + nonce_i + r_ed + r_x + nonce_r):
        raise RuntimeError("REPLY signature invalid")

    shared = x_priv.exchange(X25519PublicKey.from_public_bytes(r_x))
    k_i_to_r, k_r_to_i = _derive_keys(shared, nonce_i + nonce_r)
    return Channel(
        reader=reader,
        writer=writer,
        peer_ed_pub=r_ed,
        peer_short_id=fingerprint_of(r_ed)[:8],
        tx_aead=ChaCha20Poly1305(k_i_to_r),
        rx_aead=ChaCha20Poly1305(k_r_to_i),
    )


async def respond(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    me: Identity,
) -> Channel:
    hello = await read_frame(reader)
    if len(hello) != 32 + 32 + NONCE_LEN + 64:
        raise RuntimeError(f"bad HELLO length: {len(hello)}")
    i_ed = hello[0:32]
    i_x = hello[32:64]
    nonce_i = hello[64 : 64 + NONCE_LEN]
    sig_i = hello[64 + NONCE_LEN :]
    if not verify(i_ed, sig_i, HELLO_TAG + i_ed + i_x + nonce_i):
        raise RuntimeError("HELLO signature invalid")

    x_priv, x_pub = _x25519_keypair()
    nonce_r = os.urandom(NONCE_LEN)
    sig_r = me.sign(REPLY_TAG + nonce_i + me.public_bytes + x_pub + nonce_r)
    reply = me.public_bytes + x_pub + nonce_r + sig_r
    await write_frame(writer, reply)

    shared = x_priv.exchange(X25519PublicKey.from_public_bytes(i_x))
    k_i_to_r, k_r_to_i = _derive_keys(shared, nonce_i + nonce_r)
    return Channel(
        reader=reader,
        writer=writer,
        peer_ed_pub=i_ed,
        peer_short_id=fingerprint_of(i_ed)[:8],
        tx_aead=ChaCha20Poly1305(k_r_to_i),
        rx_aead=ChaCha20Poly1305(k_i_to_r),
    )
