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

  Current frames (PROTOCOL_VERSION = "OL-GROUP-MSG-3"):

  {
    "v": "OL-GROUP-MSG-3",
    "group_id_b64": ...,
    "sender_pubkey_b64": ...,
    "epoch": int,
    "counter": int,
    "nonce_salt_b64": ...,    # full 12-byte random ChaCha20 nonce
    "ciphertext_b64": ...,
    "signature_b64": ...,
  }

  v2 frames use ``epoch || counter || random32`` as their nonce. v1
  frames omit ``nonce_salt_b64`` and use a deterministic
  ``epoch || counter`` nonce. Receivers retain read-only v1/v2 support
  for rolling upgrades; senders always emit v3.

Why v3 uses a full-entropy nonce
================================

The v1 nonce was deterministic = ``(epoch || counter || zero4)``. The
chain_key advances in RAM after each send, but if the daemon crashes
and restarts before the new chain_key is fsynced to disk, the
restarted daemon reads the *previous* chain_key from disk, advances
it, and emits a frame at the same ``(epoch, counter)``. That is a
catastrophic AEAD nonce-reuse: ChaCha20 keystream is xored with both
plaintexts, leaking both messages.

v2 improved this with four random bytes, but only provided 32 bits of
collision resistance for repeated stale-state sends. v3 makes all 96
nonce bits fresh randomness while keeping epoch/counter authenticated in
AAD and the Ed25519 transcript. Its signature also has an explicit v3
domain separator. This removes the small v2 nonce suffix as a practical
collision ceiling without dropping in-flight legacy messages.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
import struct
from dataclasses import dataclass, field
from typing import Optional

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

PROTOCOL_VERSION = "OL-GROUP-MSG-3"
SALTED_LEGACY_PROTOCOL_VERSION = "OL-GROUP-MSG-2"
LEGACY_PROTOCOL_VERSION = "OL-GROUP-MSG-1"
SUPPORTED_PROTOCOL_VERSIONS = (
    PROTOCOL_VERSION,
    SALTED_LEGACY_PROTOCOL_VERSION,
    LEGACY_PROTOCOL_VERSION,
)

# Cryptographic constants.
CHAIN_KEY_BYTES = 32              # HMAC-SHA256 output / ChaCha20Poly1305 key
COUNTER_BYTES = 4                 # u32 — wraps after ~4B msgs / chain
NONCE_BYTES = 12                  # ChaCha20-Poly1305 nonce
NONCE_SALT_BYTES = NONCE_BYTES    # v3: full-entropy random nonce
LEGACY_NONCE_SALT_BYTES = 4       # v2 rolling-upgrade decoder only
TAG_BYTES = 16                    # Poly1305 auth tag
MAX_MESSAGE_PLAINTEXT_BYTES = 1024 * 1024  # 1 MB sanity cap
MAX_MESSAGE_CIPHERTEXT_BYTES = MAX_MESSAGE_PLAINTEXT_BYTES + TAG_BYTES
UINT32_MAX = 2**32 - 1

_V1_WIRE_FIELDS = frozenset({
    "v",
    "group_id_b64",
    "sender_pubkey_b64",
    "epoch",
    "counter",
    "ciphertext_b64",
    "signature_b64",
})
_SALTED_WIRE_FIELDS = _V1_WIRE_FIELDS | {"nonce_salt_b64"}
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")
_V3_SIGNATURE_DOMAIN = b"OL-GROUP-SIG-3"


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
    frames sent by older daemons; current senders use v3."""
    if not (0 <= epoch < 2**32):
        raise ValueError(f"epoch out of u32 range: {epoch}")
    if not (0 <= counter < 2**32):
        raise ValueError(f"counter out of u32 range: {counter}")
    return struct.pack(">II", epoch, counter) + b"\x00\x00\x00\x00"


def _build_nonce_v2(epoch: int, counter: int, nonce_salt: bytes) -> bytes:
    """Legacy v2 nonce retained for rolling-upgrade decryption only."""
    if not (0 <= epoch < 2**32):
        raise ValueError(f"epoch out of u32 range: {epoch}")
    if not (0 <= counter < 2**32):
        raise ValueError(f"counter out of u32 range: {counter}")
    if len(nonce_salt) != LEGACY_NONCE_SALT_BYTES:
        raise ValueError(
            "legacy nonce_salt must be "
            f"{LEGACY_NONCE_SALT_BYTES} bytes, got {len(nonce_salt)}"
        )
    return struct.pack(">II", epoch, counter) + bytes(nonce_salt)


def _build_nonce_v3(nonce_salt: bytes) -> bytes:
    """Current nonce: 96 fresh random bits, the full ChaCha20 nonce.

    v2 devoted eight nonce bytes to epoch/counter and left only 32 random
    bits for crash-replay uniqueness. That made collisions plausible under
    repeated stale-state recovery. v3 retains epoch/counter in signed AAD
    while using the entire nonce for fresh entropy.
    """
    if len(nonce_salt) != NONCE_SALT_BYTES:
        raise ValueError(
            f"nonce_salt must be {NONCE_SALT_BYTES} bytes, got {len(nonce_salt)}"
        )
    return bytes(nonce_salt)


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
    """Associated data for legacy v2 frames. Includes the nonce_salt
    so a flipped salt invalidates the Poly1305 tag."""
    if len(group_id) != 16:
        raise ValueError("group_id must be 16 bytes")
    if len(sender_pubkey) != 32:
        raise ValueError("sender_pubkey must be 32 bytes")
    if len(nonce_salt) != LEGACY_NONCE_SALT_BYTES:
        raise ValueError("nonce_salt wrong length")
    return (
        b"OL-GROUP-MSG-2"
        + group_id
        + sender_pubkey
        + struct.pack(">II", epoch, counter)
        + bytes(nonce_salt)
    )


def _aad_v3(
    group_id: bytes,
    sender_pubkey: bytes,
    epoch: int,
    counter: int,
    nonce_salt: bytes,
) -> bytes:
    if len(group_id) != 16:
        raise ValueError("group_id must be 16 bytes")
    if len(sender_pubkey) != 32:
        raise ValueError("sender_pubkey must be 32 bytes")
    if len(nonce_salt) != NONCE_SALT_BYTES:
        raise ValueError("nonce_salt wrong length")
    return (
        b"OL-GROUP-MSG-3"
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
    """ChaCha20-Poly1305 with the v3 full-entropy nonce and AAD."""
    if len(msg_key) != CHAIN_KEY_BYTES:
        raise ValueError("msg_key wrong length")
    if len(plaintext) > MAX_MESSAGE_PLAINTEXT_BYTES:
        raise ValueError(
            f"plaintext too large: {len(plaintext)} > "
            f"{MAX_MESSAGE_PLAINTEXT_BYTES}"
        )
    aead = ChaCha20Poly1305(msg_key)
    nonce = _build_nonce_v3(nonce_salt)
    aad = _aad_v3(group_id, sender_pubkey, epoch, counter, nonce_salt)
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
    """Inverse. Dispatches on ``wire_version`` so v1/v2/v3 frames
    is verified under the AAD/nonce shape it was sealed with.
    Raises ValueError on auth failure (Poly1305 tag mismatch); caller
    must NOT reveal which check failed."""
    aead = ChaCha20Poly1305(msg_key)
    if wire_version == PROTOCOL_VERSION:
        if nonce_salt is None or len(nonce_salt) != NONCE_SALT_BYTES:
            raise ValueError("v3 frame missing valid nonce_salt")
        nonce = _build_nonce_v3(nonce_salt)
        aad = _aad_v3(group_id, sender_pubkey, epoch, counter, nonce_salt)
    elif wire_version == SALTED_LEGACY_PROTOCOL_VERSION:
        if nonce_salt is None or len(nonce_salt) != LEGACY_NONCE_SALT_BYTES:
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
    except InvalidTag:
        raise ValueError("message authentication failed") from None


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

    Emits a v3 frame with a fresh 12-byte nonce. v1/v2 are decode-only.
    """
    if len(plaintext) == 0:
        raise ValueError("empty plaintext not allowed")
    if len(plaintext) > MAX_MESSAGE_PLAINTEXT_BYTES:
        raise ValueError("plaintext too large")
    _validate_chain_coordinates(chain)
    if private_key.public_key().public_bytes_raw() != chain.sender_pubkey:
        raise ValueError("private_key does not match sender_pubkey")
    if chain.counter == UINT32_MAX:
        raise ValueError("sender counter exhausted; rotate to a new epoch")
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
    sig_input = _V3_SIGNATURE_DOMAIN + (
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
    _validate_receiving_chain(chain)
    wire_version = wire.get("v")
    if wire_version not in SUPPORTED_PROTOCOL_VERSIONS:
        raise ValueError(f"unsupported version: {wire_version!r}")
    expected_fields = (
        _V1_WIRE_FIELDS
        if wire_version == LEGACY_PROTOCOL_VERSION
        else _SALTED_WIRE_FIELDS
    )
    keys = frozenset(wire)
    missing = expected_fields - keys
    extra = keys - expected_fields
    if missing:
        raise ValueError(f"wire missing fields: {', '.join(sorted(missing))}")
    if extra:
        raise ValueError(f"wire has unknown fields: {', '.join(sorted(extra))}")

    # Parse + validate fields.
    group_id = _decode_exact_b64(
        wire.get("group_id_b64"), name="group_id_b64", size=16
    )
    if group_id != chain.group_id:
        raise ValueError("group_id does not match chain")
    sender_pubkey = _decode_exact_b64(
        wire.get("sender_pubkey_b64"), name="sender_pubkey_b64", size=32
    )
    if sender_pubkey != chain.sender_pubkey:
        raise ValueError("sender_pubkey does not match chain")
    epoch = _require_int(wire.get("epoch"), "epoch")
    counter = _require_int(wire.get("counter"), "counter")
    if not 0 < epoch <= UINT32_MAX:
        raise ValueError("epoch must be a positive u32")
    if not 0 <= counter <= UINT32_MAX:
        raise ValueError("counter must be a u32")
    ciphertext = _b64d(
        _require_str(wire.get("ciphertext_b64"), "ciphertext_b64"),
        name="ciphertext_b64",
        max_decoded_bytes=MAX_MESSAGE_CIPHERTEXT_BYTES,
    )
    if not TAG_BYTES < len(ciphertext) <= MAX_MESSAGE_CIPHERTEXT_BYTES:
        raise ValueError("ciphertext length is out of range")
    signature = _decode_exact_b64(
        wire.get("signature_b64"), name="signature_b64", size=64
    )

    nonce_salt: Optional[bytes] = None
    if wire_version in (PROTOCOL_VERSION, SALTED_LEGACY_PROTOCOL_VERSION):
        salt_size = (
            NONCE_SALT_BYTES
            if wire_version == PROTOCOL_VERSION
            else LEGACY_NONCE_SALT_BYTES
        )
        nonce_salt = _decode_exact_b64(
            wire.get("nonce_salt_b64"), name="nonce_salt_b64", size=salt_size
        )

    if epoch != chain.epoch:
        raise ValueError(
            f"epoch mismatch: chain at {chain.epoch}, message claims {epoch}"
        )
    if counter in chain.seen_counters:
        raise ValueError(f"replay: counter {counter} already seen")
    # Verify Ed25519 signature BEFORE deriving keys / mutating chain
    # state so a malformed-but-counter-ahead frame can't push us
    # past legitimate intermediates. Salted versions bind nonce_salt into the
    # signed input so a relay can't substitute a different salt to
    # force a collision.
    if wire_version in (PROTOCOL_VERSION, SALTED_LEGACY_PROTOCOL_VERSION):
        # ES-18: explicit raise, not assert. Salted wire-frame invariant
        # protects the AEAD nonce derivation; under python -O the
        # assert would strip and a malformed frame could feed a
        # None into the BLAKE3 derive that follows.
        if nonce_salt is None:
            raise RuntimeError("salted wire frame must carry nonce_salt")
        sig_input = (
            group_id + sender_pubkey
            + struct.pack(">II", epoch, counter)
            + nonce_salt
            + ciphertext
        )
        if wire_version == PROTOCOL_VERSION:
            sig_input = _V3_SIGNATURE_DOMAIN + sig_input
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

    oldest_replay_counter = max(0, next_counter - MAX_SKIP_KEYS_GROUP)
    next_seen = {
        seen
        for seen in chain.seen_counters
        if oldest_replay_counter <= seen < next_counter
    }
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
    if (
        not isinstance(new_epoch, int)
        or isinstance(new_epoch, bool)
        or not 0 < new_epoch <= UINT32_MAX
    ):
        raise ValueError("epoch must be a positive u32")
    _validate_group_and_sender(group_id, sender_pubkey)
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
    _validate_group_and_sender(group_id, sender_pubkey)
    if (
        not isinstance(epoch, int)
        or isinstance(epoch, bool)
        or not 0 < epoch <= UINT32_MAX
    ):
        raise ValueError("epoch must be a positive u32")
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


def _b64d(
    s: str,
    *,
    name: str = "base64url value",
    max_decoded_bytes: int = MAX_MESSAGE_CIPHERTEXT_BYTES,
) -> bytes:
    """Strict canonical decoder.

    The defaults preserve the small internal compatibility surface used by
    the group key-offer handler. Security-sensitive wire parsers always pass
    their exact field bound explicitly.
    """
    max_encoded = (max_decoded_bytes * 4 + 2) // 3
    if len(s) > max_encoded:
        raise ValueError(f"{name} is too large")
    if len(s) % 4 == 1 or _B64URL_RE.fullmatch(s) is None:
        raise ValueError(f"{name} must be canonical base64url")
    pad = "=" * ((4 - len(s) % 4) % 4)
    try:
        decoded = base64.b64decode(
            (s + pad).encode("ascii"), altchars=b"-_", validate=True
        )
    except (binascii.Error, ValueError, UnicodeEncodeError):
        raise ValueError(f"{name} must be canonical base64url") from None
    if len(decoded) > max_decoded_bytes or _b64(decoded) != s:
        raise ValueError(f"{name} must be canonical base64url")
    return decoded


def _decode_exact_b64(v: object, *, name: str, size: int) -> bytes:
    decoded = _b64d(
        _require_str(v, name), name=name, max_decoded_bytes=size
    )
    if len(decoded) != size:
        raise ValueError(f"{name} must decode to {size} bytes")
    return decoded


def _validate_group_and_sender(group_id: bytes, sender_pubkey: bytes) -> None:
    if len(group_id) != 16:
        raise ValueError("group_id must be 16 bytes")
    if len(sender_pubkey) != 32:
        raise ValueError("sender_pubkey must be 32 bytes")


def _validate_chain_coordinates(chain: SenderChain) -> None:
    _validate_group_and_sender(chain.group_id, chain.sender_pubkey)
    if (
        not isinstance(chain.epoch, int)
        or isinstance(chain.epoch, bool)
        or not 0 < chain.epoch <= UINT32_MAX
    ):
        raise ValueError("epoch must be a positive u32")
    if (
        not isinstance(chain.counter, int)
        or isinstance(chain.counter, bool)
        or not 0 <= chain.counter <= UINT32_MAX
    ):
        raise ValueError("counter must be a u32")


def _validate_receiving_chain(chain: ReceivingChain) -> None:
    _validate_group_and_sender(chain.group_id, chain.sender_pubkey)
    if len(chain.chain_key) != CHAIN_KEY_BYTES:
        raise ValueError("chain_key wrong length")
    if (
        not isinstance(chain.epoch, int)
        or isinstance(chain.epoch, bool)
        or not 0 < chain.epoch <= UINT32_MAX
    ):
        raise ValueError("epoch must be a positive u32")
    if (
        not isinstance(chain.counter, int)
        or isinstance(chain.counter, bool)
        or not 0 <= chain.counter <= UINT32_MAX
    ):
        raise ValueError("counter must be a u32")
    if len(chain.seen_counters) > MAX_SKIP_KEYS_GROUP:
        raise ValueError("seen counter window exceeds its bound")
    if len(chain.skipped) > MAX_SKIP_KEYS_GROUP:
        raise ValueError("skipped-key window exceeds its bound")
    for counter in chain.seen_counters:
        if (
            not isinstance(counter, int)
            or isinstance(counter, bool)
            or not 0 <= counter < chain.counter
        ):
            raise ValueError("seen counter window is malformed")
    for counter, message_key in chain.skipped.items():
        if (
            not isinstance(counter, int)
            or isinstance(counter, bool)
            or not 0 <= counter < chain.counter
            or len(message_key) != CHAIN_KEY_BYTES
        ):
            raise ValueError("skipped-key window is malformed")


def _require_str(v, name: str) -> str:
    if not isinstance(v, str):
        raise ValueError(f"{name} must be a string")
    return v


def _require_int(v, name: str) -> int:
    if not isinstance(v, int) or isinstance(v, bool):
        raise ValueError(f"{name} must be an integer")
    return v
