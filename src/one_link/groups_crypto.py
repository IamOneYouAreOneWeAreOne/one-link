"""Sender-Keys group encryption — Signal-pattern, adapted for One Link.

Each member of a group maintains a per-group **sender chain**: a 32-byte
chain key that advances after every message they send. Messages are
encrypted with a fresh per-message key derived from the chain head;
the chain key itself never leaves the sender. Recipients who hold a
copy of the sender's current chain can re-derive each message's key
in lock-step.

Two cryptographic primitives compose the chain:

  msg_key   = HMAC-SHA256(chain_key, b"msg")
  next_key  = HMAC-SHA256(chain_key, b"next")

After a message is sent or received, the holder advances the chain:

  chain_key ← next_key, counter += 1

Forward secrecy (this primitive)
================================

Within a chain: an attacker who captures the chain key at counter=N
can decrypt message N onward but NOT N-1 or earlier — the previous
key was destroyed at advance.

This is "weak forward secrecy". Full FS + post-compromise security
arrives in v0.7 via the Double Ratchet, which folds in fresh
Diffie-Hellman material every message.

Sender authentication
=====================

AEAD with the chain-derived `msg_key` authenticates "whoever has the
chain key wrote this". That's NOT enough for a group: every current
group member holds every sender's chain key, so a malicious member
could forge messages purporting to come from any other member.

Defence: every encrypted group message is also Ed25519-signed by the
sender's device key. The pubkey is in the wire envelope; the
signature covers
`(group_id || sender_pubkey || epoch || counter || ciphertext)`.

Epoch & rotation
================

`epoch` is a monotone counter that bumps when membership changes.
The full session key state is `(group_id, sender_pubkey, epoch,
chain_key, counter)`. After a remove-member event, every remaining
member rotates their own chain to a fresh epoch and re-distributes
to the new member set. The removed member's old chain is now stale —
they can't decrypt the new epoch's messages.

For v0.6.1 the *primitive* is here. The *distribution* (sending the
new chain to peers over their 1-on-1 encrypted channels) lives in the
wire-protocol layer added in v0.6.2.

Replay defence
==============

Receivers track the highest `(sender, epoch, counter)` triple they've
seen. A duplicate or out-of-order replay is rejected. Note: out-of-
order delivery in normal use is rare for group chat; if needed we
can add a sliding window in v0.6.2.

Wire format
===========

  v0.20.7+ frames (PROTOCOL_VERSION = "OL-GROUP-MSG-2"):

  {
    "v": "OL-GROUP-MSG-2",
    "group_id_b64": ...,
    "sender_pubkey_b64": ...,
    "epoch": int,
    "counter": int,
    "nonce_salt_b64": ...,    # 4 bytes os.urandom (audit M3 defense)
    "ciphertext_b64": ...,
    "signature_b64": ...,
  }

  Pre-v0.20.7 frames (PROTOCOL_VERSION = "OL-GROUP-MSG-1") omit the
  ``nonce_salt_b64`` field and use a deterministic (epoch, counter)
  nonce. Receivers continue to accept v1 frames so a daemon upgrade
  on one side doesn't drop in-flight messages from the other; senders
  always emit v2.

Why the v2 salt (audit finding M3)
==================================

The v1 nonce was deterministic = ``(epoch || counter || zero4)``. The
chain_key advances in RAM after each send, but if the daemon crashes
and restarts before the new chain_key is fsynced to disk, the
restarted daemon reads the *previous* chain_key from disk, advances
it, and emits a frame at the same ``(epoch, counter)``. That is a
catastrophic AEAD nonce-reuse: ChaCha20 keystream is xored with both
plaintexts, leaking both messages.

v2 folds 4 bytes of fresh ``os.urandom`` into the nonce + AAD per
send. Even on the worst-case crash-replay scenario, the probability
of two frames at the same ``(key, nonce)`` is 2^-32 per pair (~1 in
4 billion). Not zero, but a probabilistic event practically
impossible in any realistic group lifetime — a structural class
upgrade vs. the deterministic v1 catastrophe.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
from dataclasses import dataclass, field
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

PROTOCOL_VERSION = "OL-GROUP-MSG-2"
LEGACY_PROTOCOL_VERSION = "OL-GROUP-MSG-1"
SUPPORTED_PROTOCOL_VERSIONS = (PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION)

# Cryptographic constants.
CHAIN_KEY_BYTES = 32              # HMAC-SHA256 output / ChaCha20Poly1305 key
COUNTER_BYTES = 4                 # u32 — wraps after ~4B msgs / chain
NONCE_BYTES = 12                  # ChaCha20-Poly1305 nonce
NONCE_SALT_BYTES = 4              # v0.20.7 (audit M3) random salt in nonce
TAG_BYTES = 16                    # Poly1305 auth tag
MAX_MESSAGE_PLAINTEXT_BYTES = 1024 * 1024  # 1 MB sanity cap


# ─── chain primitives ───────────────────────────────────────────────

def _hmac_sha256(key: bytes, info: bytes) -> bytes:
    """HMAC-SHA256(key, info). 32-byte output."""
    return hmac.new(key, info, hashlib.sha256).digest()


def derive_message_key(chain_key: bytes) -> bytes:
    """The encryption key for *this* message — the current chain head."""
    if len(chain_key) != CHAIN_KEY_BYTES:
        raise ValueError(
            f"chain_key must be {CHAIN_KEY_BYTES} bytes, got {len(chain_key)}"
        )
    return _hmac_sha256(chain_key, b"msg")


def advance_chain_key(chain_key: bytes) -> bytes:
    """Step the chain forward. The previous key MUST be destroyed
    after this returns — that's where forward secrecy comes from."""
    if len(chain_key) != CHAIN_KEY_BYTES:
        raise ValueError(
            f"chain_key must be {CHAIN_KEY_BYTES} bytes, got {len(chain_key)}"
        )
    return _hmac_sha256(chain_key, b"next")


def new_chain_key() -> bytes:
    """Cryptographically secure fresh chain key. Used at chain
    creation (new group, new epoch after member rotation)."""
    return os.urandom(CHAIN_KEY_BYTES)


# ─── per-message AEAD ───────────────────────────────────────────────

def _build_nonce_v1(epoch: int, counter: int) -> bytes:
    """Pre-v0.20.7 deterministic nonce. Read-only path for legacy frames.

    Vulnerable to (key, nonce) reuse on restart-after-crash with stale
    persisted chain_key state. Kept ONLY for accepting in-flight
    frames sent by older daemons; v0.20.7+ senders always use
    ``_build_nonce_v2``."""
    if not (0 <= epoch < 2**32):
        raise ValueError(f"epoch out of u32 range: {epoch}")
    if not (0 <= counter < 2**32):
        raise ValueError(f"counter out of u32 range: {counter}")
    return struct.pack(">II", epoch, counter) + b"\x00\x00\x00\x00"


def _build_nonce_v2(epoch: int, counter: int, nonce_salt: bytes) -> bytes:
    """v0.20.7+ nonce: 4 bytes epoch + 4 bytes counter + 4 bytes
    fresh os.urandom salt. Defends against (key, nonce) reuse on
    restart-after-crash even if persisted chain_key is stale: the
    salt is fresh per send so collision probability is 2^-32 per
    pair of frames sharing the same ``(epoch, counter)``."""
    if not (0 <= epoch < 2**32):
        raise ValueError(f"epoch out of u32 range: {epoch}")
    if not (0 <= counter < 2**32):
        raise ValueError(f"counter out of u32 range: {counter}")
    if len(nonce_salt) != NONCE_SALT_BYTES:
        raise ValueError(
            f"nonce_salt must be {NONCE_SALT_BYTES} bytes, got {len(nonce_salt)}"
        )
    return struct.pack(">II", epoch, counter) + bytes(nonce_salt)


def _aad_v1(
    group_id: bytes, sender_pubkey: bytes, epoch: int, counter: int
) -> bytes:
    """Associated data for legacy v1 frames."""
    if len(group_id) != 16:
        raise ValueError("group_id must be 16 bytes")
    if len(sender_pubkey) != 32:
        raise ValueError("sender_pubkey must be 32 bytes")
    return (
        b"OL-GROUP-MSG-1"
        + group_id
        + sender_pubkey
        + struct.pack(">II", epoch, counter)
    )


def _aad_v2(
    group_id: bytes,
    sender_pubkey: bytes,
    epoch: int,
    counter: int,
    nonce_salt: bytes,
) -> bytes:
    """Associated data for v0.20.7+ frames. Includes the nonce_salt
    so a flipped salt invalidates the Poly1305 tag."""
    if len(group_id) != 16:
        raise ValueError("group_id must be 16 bytes")
    if len(sender_pubkey) != 32:
        raise ValueError("sender_pubkey must be 32 bytes")
    if len(nonce_salt) != NONCE_SALT_BYTES:
        raise ValueError("nonce_salt wrong length")
    return (
        b"OL-GROUP-MSG-2"
        + group_id
        + sender_pubkey
        + struct.pack(">II", epoch, counter)
        + bytes(nonce_salt)
    )


def _encrypt_with_msg_key(
    msg_key: bytes,
    plaintext: bytes,
    group_id: bytes,
    sender_pubkey: bytes,
    epoch: int,
    counter: int,
    nonce_salt: bytes,
) -> bytes:
    """ChaCha20-Poly1305 with v0.20.7 salted nonce + AAD."""
    if len(msg_key) != CHAIN_KEY_BYTES:
        raise ValueError("msg_key wrong length")
    if len(plaintext) > MAX_MESSAGE_PLAINTEXT_BYTES:
        raise ValueError(
            f"plaintext too large: {len(plaintext)} > "
            f"{MAX_MESSAGE_PLAINTEXT_BYTES}"
        )
    aead = ChaCha20Poly1305(msg_key)
    nonce = _build_nonce_v2(epoch, counter, nonce_salt)
    aad = _aad_v2(group_id, sender_pubkey, epoch, counter, nonce_salt)
    return aead.encrypt(nonce, plaintext, aad)


def _decrypt_with_msg_key(
    msg_key: bytes,
    ciphertext: bytes,
    group_id: bytes,
    sender_pubkey: bytes,
    epoch: int,
    counter: int,
    *,
    wire_version: str,
    nonce_salt: Optional[bytes] = None,
) -> bytes:
    """Inverse. Dispatches on ``wire_version`` so a v1 or v2 frame
    is verified under the AAD/nonce shape it was sealed with.
    Raises ValueError on auth failure (Poly1305 tag mismatch); caller
    must NOT reveal which check failed."""
    aead = ChaCha20Poly1305(msg_key)
    if wire_version == PROTOCOL_VERSION:
        if nonce_salt is None or len(nonce_salt) != NONCE_SALT_BYTES:
            raise ValueError("v2 frame missing valid nonce_salt")
        nonce = _build_nonce_v2(epoch, counter, nonce_salt)
        aad = _aad_v2(group_id, sender_pubkey, epoch, counter, nonce_salt)
    elif wire_version == LEGACY_PROTOCOL_VERSION:
        nonce = _build_nonce_v1(epoch, counter)
        aad = _aad_v1(group_id, sender_pubkey, epoch, counter)
    else:
        raise ValueError(f"unsupported wire version: {wire_version!r}")
    try:
        return aead.decrypt(nonce, ciphertext, aad)
    except Exception as e:
        raise ValueError(f"AEAD decrypt failed: {e}") from None


# ─── SenderChain — per-(group, sender) sending state ───────────────

@dataclass
class SenderChain:
    """One member's outbound state for one group at one epoch."""
    group_id: bytes
    sender_pubkey: bytes
    epoch: int
    chain_key: bytes        # advanced after every send
    counter: int = 0        # number of messages already sent this epoch


@dataclass
class ReceivingChain:
    """The corresponding inbound state on the receiver side. Tracks
    the highest counter seen + a sliding-window cache for out-of-
    order frames so a single dropped or reordered message doesn't
    brick the chain."""
    group_id: bytes
    sender_pubkey: bytes
    epoch: int
    chain_key: bytes
    counter: int = 0  # next-expected; advances past every consumed counter
    seen_counters: set[int] = field(default_factory=set)
    # v0.20.7 (security audit M4): sliding-window cache of message
    # keys for counters that we advanced past (because a higher
    # counter arrived first) but haven't yet decrypted. When the
    # missing counter eventually arrives, we pop its msg_key here
    # and decrypt the OOO frame instead of bricking the chain.
    # Bounded at MAX_SKIP_KEYS_GROUP entries; oldest evicted on
    # overflow.
    skipped: dict[int, bytes] = field(default_factory=dict)


# v0.20.7 (security audit M4): receive-side sliding-window cap. A
# legitimate sender shouldn't get more than this many messages
# ahead of the receiver under any normal delivery pattern. Beyond
# this, we treat the gap as "the sender is racing us into a forged-
# state condition" and abort. 64 is comfortable for typical chat
# / wire reordering; under heavy file-transfer-style bursts groups
# don't ride this code path (group-msg flow is text + small).
MAX_SKIP_KEYS_GROUP = 64


def encrypt_message(
    *,
    plaintext: bytes,
    chain: SenderChain,
    private_key: Ed25519PrivateKey,
) -> tuple[dict, SenderChain]:
    """Encrypt a single group message. Returns the wire dict + the
    *new* SenderChain (chain key advanced, counter += 1).

    The caller should treat the returned chain as the canonical
    sender state from this point. The previous chain_key is no
    longer usable (forward secrecy).

    v0.20.7 (audit M3): emits a v2 wire frame with a 4-byte fresh
    random ``nonce_salt``, eliminating the deterministic-nonce
    catastrophic-reuse class on crash-restart.
    """
    if len(plaintext) == 0:
        raise ValueError("empty plaintext not allowed")
    if len(plaintext) > MAX_MESSAGE_PLAINTEXT_BYTES:
        raise ValueError("plaintext too large")
    nonce_salt = os.urandom(NONCE_SALT_BYTES)
    msg_key = derive_message_key(chain.chain_key)
    ciphertext = _encrypt_with_msg_key(
        msg_key=msg_key,
        plaintext=plaintext,
        group_id=chain.group_id,
        sender_pubkey=chain.sender_pubkey,
        epoch=chain.epoch,
        counter=chain.counter,
        nonce_salt=nonce_salt,
    )
    # Sign (group_id || sender_pubkey || epoch || counter || nonce_salt
    # || ciphertext) so a member who holds the chain key can't forge
    # as somebody else, and so the salt itself is sender-authenticated
    # (a relay can't substitute a different salt to force a collision).
    sig_input = (
        chain.group_id
        + chain.sender_pubkey
        + struct.pack(">II", chain.epoch, chain.counter)
        + nonce_salt
        + ciphertext
    )
    signature = private_key.sign(sig_input)

    wire = {
        "v": PROTOCOL_VERSION,
        "group_id_b64": _b64(chain.group_id),
        "sender_pubkey_b64": _b64(chain.sender_pubkey),
        "epoch": chain.epoch,
        "counter": chain.counter,
        "nonce_salt_b64": _b64(nonce_salt),
        "ciphertext_b64": _b64(ciphertext),
        "signature_b64": _b64(signature),
    }
    next_chain = SenderChain(
        group_id=chain.group_id,
        sender_pubkey=chain.sender_pubkey,
        epoch=chain.epoch,
        chain_key=advance_chain_key(chain.chain_key),
        counter=chain.counter + 1,
    )
    return wire, next_chain


def decrypt_message(
    *,
    wire: dict,
    chain: ReceivingChain,
) -> tuple[bytes, ReceivingChain]:
    """Decrypt + verify a group message. Returns plaintext + advanced
    receiving chain.

    v0.20.7 (security audit M4): supports out-of-order delivery via a
    sliding-window cache (MAX_SKIP_KEYS_GROUP entries). When a higher
    counter arrives first we derive + stash msg_keys for the gap so
    the missing counters can decrypt later. When an OOO frame arrives
    after we've advanced past it we look up its key in the cache.
    Pre-v0.20.7 this code rejected ANY out-of-order frame, which
    meant a single dropped message bricked the entire chain — a real
    DoS primitive over the relay path.

    Raises ValueError on:
      - protocol version mismatch
      - signature verification failure (forged sender)
      - AEAD decrypt failure (tampered ciphertext or wrong key)
      - replay (counter already seen this epoch)
      - epoch mismatch (expected fresh-epoch rotation)
      - out-of-window OOO (counter below chain.counter and not in
        the sliding-window cache)
      - too-large jump forward (counter > chain.counter +
        MAX_SKIP_KEYS_GROUP).
    """
    if not isinstance(wire, dict):
        raise ValueError("wire must be a dict")
    wire_version = wire.get("v")
    if wire_version not in SUPPORTED_PROTOCOL_VERSIONS:
        raise ValueError(f"unsupported version: {wire_version!r}")

    # Parse + validate fields.
    group_id = _b64d(_require_str(wire.get("group_id_b64"), "group_id_b64"))
    if group_id != chain.group_id:
        raise ValueError("group_id does not match chain")
    sender_pubkey = _b64d(_require_str(
        wire.get("sender_pubkey_b64"), "sender_pubkey_b64"
    ))
    if sender_pubkey != chain.sender_pubkey:
        raise ValueError("sender_pubkey does not match chain")
    epoch = _require_int(wire.get("epoch"), "epoch")
    counter = _require_int(wire.get("counter"), "counter")
    ciphertext = _b64d(_require_str(wire.get("ciphertext_b64"), "ciphertext_b64"))
    signature = _b64d(_require_str(wire.get("signature_b64"), "signature_b64"))
    if len(signature) != 64:
        raise ValueError("signature must be 64 bytes")

    nonce_salt: Optional[bytes] = None
    if wire_version == PROTOCOL_VERSION:
        nonce_salt = _b64d(_require_str(
            wire.get("nonce_salt_b64"), "nonce_salt_b64"
        ))
        if len(nonce_salt) != NONCE_SALT_BYTES:
            raise ValueError(
                f"nonce_salt must be {NONCE_SALT_BYTES} bytes, "
                f"got {len(nonce_salt)}"
            )

    if epoch != chain.epoch:
        raise ValueError(
            f"epoch mismatch: chain at {chain.epoch}, message claims {epoch}"
        )
    if counter in chain.seen_counters:
        raise ValueError(f"replay: counter {counter} already seen")
    if counter < 0:
        raise ValueError(f"counter must be non-negative: {counter}")

    # Verify Ed25519 signature BEFORE deriving keys / mutating chain
    # state so a malformed-but-counter-ahead frame can't push us
    # past legitimate intermediates. v2 binds the nonce_salt into the
    # signed input so a relay can't substitute a different salt to
    # force a collision.
    if wire_version == PROTOCOL_VERSION:
        sig_input = (
            group_id + sender_pubkey
            + struct.pack(">II", epoch, counter)
            + nonce_salt
            + ciphertext
        )
    else:
        sig_input = (
            group_id + sender_pubkey
            + struct.pack(">II", epoch, counter)
            + ciphertext
        )
    try:
        Ed25519PublicKey.from_public_bytes(sender_pubkey).verify(
            signature, sig_input
        )
    except InvalidSignature:
        raise ValueError("signature does not verify")

    # Three relations to chain.counter:
    #   counter < chain.counter — late OOO arrival (must be in
    #     skipped cache, else out-of-window)
    #   counter == chain.counter — in-order delivery (the common
    #     path)
    #   counter > chain.counter — forward jump (gap must fit in
    #     the sliding window)
    skipped = dict(chain.skipped)
    if counter < chain.counter:
        msg_key = skipped.pop(counter, None)
        if msg_key is None:
            raise ValueError(
                f"out-of-window: counter {counter} is below chain "
                f"counter {chain.counter} and not in the sliding "
                f"window cache"
            )
        plaintext = _decrypt_with_msg_key(
            msg_key=msg_key,
            ciphertext=ciphertext,
            group_id=group_id,
            sender_pubkey=sender_pubkey,
            epoch=epoch,
            counter=counter,
            wire_version=wire_version,
            nonce_salt=nonce_salt,
        )
        # No chain advancement on OOO arrival; we just consumed a
        # cached key.
        next_chain_key = chain.chain_key
        next_counter = chain.counter
    else:
        # counter >= chain.counter
        gap = counter - chain.counter
        if gap > MAX_SKIP_KEYS_GROUP:
            raise ValueError(
                f"too many skipped messages: gap {gap} > "
                f"{MAX_SKIP_KEYS_GROUP}"
            )
        # Derive intermediate msg_keys for the [chain.counter, counter)
        # range and stash them in skipped, then derive the key for
        # this counter and decrypt.
        cur_chain_key = chain.chain_key
        for c in range(chain.counter, counter):
            stashed = derive_message_key(cur_chain_key)
            skipped[c] = stashed
            cur_chain_key = advance_chain_key(cur_chain_key)
        # cur_chain_key is now at step `counter`.
        msg_key = derive_message_key(cur_chain_key)
        plaintext = _decrypt_with_msg_key(
            msg_key=msg_key,
            ciphertext=ciphertext,
            group_id=group_id,
            sender_pubkey=sender_pubkey,
            epoch=epoch,
            counter=counter,
            wire_version=wire_version,
            nonce_salt=nonce_salt,
        )
        next_chain_key = advance_chain_key(cur_chain_key)
        next_counter = counter + 1

    # Bound the skipped cache. FIFO eviction (lowest counter first)
    # keeps the window centered on recent sender state.
    while len(skipped) > MAX_SKIP_KEYS_GROUP:
        oldest = min(skipped)
        skipped.pop(oldest, None)

    next_seen = set(chain.seen_counters)
    next_seen.add(counter)
    next_chain = ReceivingChain(
        group_id=chain.group_id,
        sender_pubkey=chain.sender_pubkey,
        epoch=chain.epoch,
        chain_key=next_chain_key,
        counter=next_counter,
        seen_counters=next_seen,
        skipped=skipped,
    )
    return plaintext, next_chain


# ─── epoch rotation ────────────────────────────────────────────────

def begin_new_epoch(
    *,
    group_id: bytes,
    sender_pubkey: bytes,
    new_epoch: int,
) -> SenderChain:
    """Start a fresh sending chain at a new epoch. Called when group
    membership changes (someone added or removed). The chain key is
    fresh from the OS RNG so neither the previous epoch nor any
    departed member can derive it.

    The caller must distribute the resulting `chain_key` to the
    current group members over their 1-on-1 encrypted channels.
    That distribution happens at the wire-protocol layer (v0.6.2).
    """
    if new_epoch <= 0:
        raise ValueError("epoch must be positive")
    return SenderChain(
        group_id=group_id,
        sender_pubkey=sender_pubkey,
        epoch=new_epoch,
        chain_key=new_chain_key(),
        counter=0,
    )


def receive_new_epoch(
    *,
    group_id: bytes,
    sender_pubkey: bytes,
    epoch: int,
    chain_key: bytes,
) -> ReceivingChain:
    """Materialize an incoming epoch's receiving chain. Called when
    we receive someone's new chain key over a 1-on-1 encrypted
    channel after a membership change."""
    if len(chain_key) != CHAIN_KEY_BYTES:
        raise ValueError("chain_key wrong length")
    if len(group_id) != 16:
        raise ValueError("group_id must be 16 bytes")
    if len(sender_pubkey) != 32:
        raise ValueError("sender_pubkey must be 32 bytes")
    return ReceivingChain(
        group_id=group_id,
        sender_pubkey=sender_pubkey,
        epoch=epoch,
        chain_key=chain_key,
        counter=0,
    )


# ─── helpers ────────────────────────────────────────────────────────

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def _require_str(v, name: str) -> str:
    if not isinstance(v, str):
        raise ValueError(f"{name} must be a string")
    return v


def _require_int(v, name: str) -> int:
    if not isinstance(v, int) or isinstance(v, bool):
        raise ValueError(f"{name} must be an integer")
    return v
