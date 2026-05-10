"""Provably-deletable messages — the cryptographic delete button.

When a user clicks "delete" in most chat apps, the platform hides
the message from the UI but the bytes still exist: in backups, in
caches, on the recipient's device, in the audit log, in the
"Recently Deleted" folder. "Delete" is a soft-state contract.

We can do better. The Double Ratchet already gives forward secrecy
on chain advance — the previous key is unrecoverable. What's
missing is a **publicly-verifiable proof** that a party has
deleted: a signed commitment that says "I have applied this
specific HKDF advance, so K_n is gone from my state."

Bundle 42 ships that primitive. The model:

  - Each message is keyed by a 32-byte chain key K_n.
  - After encrypting / decrypting, the holder advances:
      K_{n+1} = HKDF(K_n, "OL-deletion-chain-advance|v1", 32)
  - The holder MAY retain K_n in a bounded cache for resend /
    retransmit. ``delete(n)`` drops K_n from the cache + emits
    a signed deletion proof bound to the chain identity, the
    deleted key index, the post-delete chain hash, and a
    timestamp.
  - Anyone with the chain's verification pubkey (typically the
    holder's Ed25519 identity) can verify the proof. They can't
    recover K_n; they CAN audit "this party did delete this
    message at this time."

This combines well with the existing channel ratchet: the channel
provides forward secrecy on receive; this primitive lets the
sender + receiver MUTUALLY commit to deletion AND prove it to a
third-party auditor (e.g. when a journalist source needs to prove
the message has been destroyed).

Threat note
-----------

This protects against post-deletion content recovery from the
party's own chain state. It does NOT defend against:

  - An attacker who captured K_n WHILE it was active. The
    ciphertext from that period remains decryptable to anyone
    holding the key from before the delete.
  - A party that lies about deleting — the proof says "I did the
    advance," but the proof can't force the party to actually
    forget K_n. (The proof is a commitment, not a coercion.)
    Trust here is anchored in the public nature of the commitment:
    a party that produces deletion proofs while secretly retaining
    K_n is detectable if any retained K_n leaks later.

Wire format for a deletion proof
--------------------------------

  [magic: b"OLDLP1"] (6 bytes)
  [version: 1 byte]
  [chain_id: 16 bytes]                # caller-chosen unique chain ID
  [deleted_key_index: 8 bytes BE]     # which K_n was deleted
  [post_delete_chain_hash: 32 bytes]  # SHA-256 of chain state after advance
  [timestamp_ms: 8 bytes BE]
  [signature: 64 bytes]               # Ed25519 over the above
"""
from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


CHAIN_KEY_LEN = 32
CHAIN_ID_LEN = 16
PROOF_MAGIC = b"OLDLP1"
PROOF_VERSION = 1
PROOF_LEN = (
    len(PROOF_MAGIC) + 1
    + CHAIN_ID_LEN + 8 + 32 + 8 + 64
)
HKDF_INFO_ADVANCE = b"OL-deletion-chain-advance|v1"
HKDF_INFO_MSG_KEY = b"OL-deletion-chain-msg-key|v1"


def _hkdf(material: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    ).derive(material)


def advance_chain(chain_key: bytes) -> bytes:
    if len(chain_key) != CHAIN_KEY_LEN:
        raise ValueError(f"chain_key must be {CHAIN_KEY_LEN} bytes")
    return _hkdf(chain_key, HKDF_INFO_ADVANCE, CHAIN_KEY_LEN)


def derive_msg_key(chain_key: bytes) -> bytes:
    if len(chain_key) != CHAIN_KEY_LEN:
        raise ValueError(f"chain_key must be {CHAIN_KEY_LEN} bytes")
    return _hkdf(chain_key, HKDF_INFO_MSG_KEY, CHAIN_KEY_LEN)


def chain_state_hash(chain_key: bytes, index: int) -> bytes:
    """Public commitment to chain state. SHA-256 over the
    chain key + index. The index is included so a party that
    advances out of order can't claim it's at index N+1 with the
    K_N key."""
    if len(chain_key) != CHAIN_KEY_LEN:
        raise ValueError("chain_key wrong length")
    h = hashlib.sha256()
    h.update(b"OL-chain-state|")
    h.update(struct.pack(">Q", index))
    h.update(chain_key)
    return h.digest()


# ── DeletionChain ──────────────────────────────────────────────────


@dataclass
class DeletionChain:
    """Holds the current chain state + a bounded cache of historical
    keys for replay / retransmit. ``delete(idx)`` removes a specific
    historical key + emits a signed deletion proof.

    Construction: pass an initial 32-byte chain key (typically
    derived from the channel handshake's transcript_hash + an HKDF
    domain tag) + the holder's Ed25519 identity for signing
    deletion proofs."""

    chain_id: bytes
    current_chain_key: bytes
    next_index: int = 0
    sign_priv: Optional[Ed25519PrivateKey] = None
    sign_pub: Optional[bytes] = None
    cache_window: int = 64
    _cache: dict[int, bytes] = field(default_factory=dict)

    def __post_init__(self):
        if len(self.chain_id) != CHAIN_ID_LEN:
            raise ValueError(f"chain_id must be {CHAIN_ID_LEN} bytes")
        if len(self.current_chain_key) != CHAIN_KEY_LEN:
            raise ValueError(
                f"current_chain_key must be {CHAIN_KEY_LEN} bytes"
            )

    def seal_msg_key(self) -> tuple[int, bytes]:
        """Reserve the next message-key in the chain. Returns
        ``(index, msg_key)``. Caller uses msg_key to encrypt the
        message body via their AEAD of choice. The chain advances
        AFTER reservation so the next call gets a fresh msg_key."""
        idx = self.next_index
        msg_key = derive_msg_key(self.current_chain_key)
        # Cache the chain key at this index so a delete-proof
        # later can attest to the specific state.
        self._cache[idx] = self.current_chain_key
        # Bound the cache: drop the oldest entry on overflow.
        while len(self._cache) > self.cache_window:
            oldest = min(self._cache)
            self._cache.pop(oldest, None)
        # Advance.
        self.current_chain_key = advance_chain(self.current_chain_key)
        self.next_index = idx + 1
        return idx, msg_key

    def get_msg_key(self, idx: int) -> Optional[bytes]:
        """Re-derive the message key at index ``idx`` if the
        underlying chain key is still cached. Returns None if the
        key has been deleted or evicted from the window."""
        ck = self._cache.get(idx)
        if ck is None:
            return None
        return derive_msg_key(ck)

    def delete(self, idx: int) -> bytes:
        """Drop the cached chain key at ``idx`` + emit a signed
        deletion proof.

        After this call, ``get_msg_key(idx)`` returns None
        permanently — the key is gone from local state. The proof
        can be shipped to the peer (or an auditor) to attest that
        the deletion happened.

        Raises if no signing key is configured (deletion proofs
        require a signature; an unsigned proof is meaningless)."""
        if self.sign_priv is None or self.sign_pub is None:
            raise ValueError(
                "DeletionChain has no signing key; can't emit deletion proof"
            )
        if idx not in self._cache:
            # Already deleted or never existed. Still emit a proof
            # so the peer learns of the (idempotent) deletion.
            post_hash = chain_state_hash(self.current_chain_key, self.next_index)
        else:
            ck = self._cache.pop(idx)
            # Best-effort overwrite of the local copy. (Python
            # bytes are immutable so we can't truly overwrite the
            # underlying memory; this is the standard caveat for
            # any pure-Python crypto. A C-extension impl could
            # explicit_bzero the buffer.)
            del ck
            post_hash = chain_state_hash(self.current_chain_key, self.next_index)
        ts = int(time.time() * 1000)
        body = (
            PROOF_MAGIC + bytes([PROOF_VERSION])
            + self.chain_id
            + struct.pack(">Q", idx)
            + post_hash
            + struct.pack(">Q", ts)
        )
        signature = self.sign_priv.sign(body)
        return body + signature


# ── deletion-proof verification ────────────────────────────────────


@dataclass(frozen=True)
class DeletionProof:
    chain_id: bytes
    deleted_index: int
    post_chain_hash: bytes
    timestamp_ms: int
    signature: bytes
    encoded: bytes


def parse_deletion_proof(blob: bytes) -> DeletionProof:
    if len(blob) != PROOF_LEN:
        raise ValueError(
            f"deletion proof must be {PROOF_LEN} bytes, got {len(blob)}"
        )
    if blob[:6] != PROOF_MAGIC:
        raise ValueError("not a One Link deletion proof (bad magic)")
    if blob[6] != PROOF_VERSION:
        raise ValueError(f"unsupported proof version {blob[6]}")
    off = 7
    chain_id = blob[off:off + CHAIN_ID_LEN]
    off += CHAIN_ID_LEN
    deleted_index = struct.unpack(">Q", blob[off:off + 8])[0]
    off += 8
    post_hash = blob[off:off + 32]
    off += 32
    ts = struct.unpack(">Q", blob[off:off + 8])[0]
    off += 8
    signature = blob[off:off + 64]
    return DeletionProof(
        chain_id=chain_id,
        deleted_index=deleted_index,
        post_chain_hash=post_hash,
        timestamp_ms=ts,
        signature=signature,
        encoded=blob,
    )


def verify_deletion_proof(blob: bytes, signer_pub: bytes) -> DeletionProof:
    """Verify a deletion proof's signature. Returns the parsed
    DeletionProof on success. Raises ValueError on tamper / bad
    signature / wrong signer."""
    proof = parse_deletion_proof(blob)
    body = blob[:PROOF_LEN - 64]
    try:
        Ed25519PublicKey.from_public_bytes(signer_pub).verify(
            proof.signature, body,
        )
    except InvalidSignature:
        raise ValueError("deletion-proof signature invalid") from None
    return proof
