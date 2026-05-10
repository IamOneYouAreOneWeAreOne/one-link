"""Rendezvous blinding — the lookup itself reveals nothing.

Today the rendezvous /lookup endpoint takes a peer's Ed25519
pubkey and returns their registered endpoints. The rendezvous
operator learns:

  1. The set of peers registered (from /register frames)
  2. The set of peers being LOOKED UP, by who, when (from /lookup
     frames)

Combined, that's a complete social graph of conversation
intentions, even if the actual messages are sealed-sender onion-
routed end-to-end-encrypted. Metadata is the substance.

Standard mitigation: **blinded lookups**. Each peer registers under
a deterministic-but-unlinkable TOKEN derived from their pubkey + a
per-time-period epoch tag::

  register_token = HKDF(peer_pub, "OL/rdz/blind|v1", epoch_id)

A peer wanting to find someone computes the same HKDF over the
same inputs and queries by register_token. Rendezvous sees only
opaque 32-byte tokens. The token rotates with the epoch so logging
the token stream doesn't build a long-term graph either: a 1-hour
epoch means a previously-leaked log goes stale within an hour.

Properties
----------

  - **Forward-unlinkability**: epoch N+1 tokens are unrelated to
    epoch N tokens (HKDF one-wayness on the epoch input).
  - **Lookup-equality**: two parties who know the same peer pubkey
    + same epoch derive the same token, so /lookup matches /register.
  - **Pubkey-hiding**: HKDF output reveals nothing about the input
    pubkey beyond "someone with knowledge of pubkey P could have
    produced this token at this epoch".
  - **No correlation across pubkeys**: tokens for distinct pubkeys
    at the same epoch are uncorrelated.

Combined with the existing Tor proxy support (Bundle 22), the
rendezvous sees only:
  - Opaque tokens (not pubkeys)
  - Tor exit IPs (not real client IPs)

Threat caveats
--------------

This blinds WHICH PEER is being looked up. It does NOT blind
"someone is looking up someone" (the rendezvous still sees the
total query volume). It also does NOT defend against a rendezvous
that records ALL tokens it ever sees and waits for a future
deanonymization event — the user's protection is the rotation
window.

A future bundle can add a more advanced "private set intersection"
or "oblivious transfer" lookup where the rendezvous can't even
tell which token in its set you queried — out of scope here.

Wire format for a registered token
----------------------------------

  [magic: b"OLBT1"] (5 bytes)
  [version: 1 byte]
  [epoch_id: 8 bytes BE]
  [token: 32 bytes]
  [signature: 64 bytes]               # Ed25519 over (magic|version|epoch_id|token|peer_pub)

Note: the signed message includes peer_pub. The signature proves
that the SAME peer who owns peer_pub minted this token, which
prevents an attacker from registering an arbitrary token to
hijack lookups. The peer_pub itself is NOT on the wire — the
rendezvous receives the registration with peer_pub in the body
once at first contact (in a sealed channel), records the binding
internally, and verifies subsequent renewals against the recorded
key. Subsequent registrations and lookups carry only the token
+ signature.
"""
from __future__ import annotations

import struct
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


TOKEN_LEN = 32
HKDF_INFO_BLIND = b"OL/rdz/blind|v1"
RECORD_MAGIC = b"OLBT1"
RECORD_VERSION = 1
SIG_LEN = 64
RECORD_LEN = (
    len(RECORD_MAGIC) + 1
    + 8 + TOKEN_LEN + SIG_LEN
)
DEFAULT_EPOCH_SECONDS = 60 * 60  # 1-hour rotation


def current_epoch_id(*, now_ms: int | None = None,
                     epoch_seconds: int = DEFAULT_EPOCH_SECONDS) -> int:
    """Compute the epoch ID for the wall-clock NOW (or supplied
    timestamp). Both peers MUST agree on epoch_seconds; the
    canonical value is 3600 = 1-hour rotation."""
    if epoch_seconds <= 0:
        raise ValueError("epoch_seconds must be positive")
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    return now_ms // (epoch_seconds * 1000)


def derive_blinded_token(*, peer_pub: bytes, epoch_id: int) -> bytes:
    """Deterministically derive a 32-byte blinded lookup token.

    Both the peer (during /register) and a looker (during /lookup)
    compute this with the same inputs. The rendezvous server stores
    + matches by token; it never sees peer_pub on the wire."""
    if len(peer_pub) != 32:
        raise ValueError("peer_pub must be 32 bytes")
    if epoch_id < 0:
        raise ValueError("epoch_id must be non-negative")
    epoch_bytes = struct.pack(">Q", epoch_id)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=TOKEN_LEN,
        salt=None,
        info=HKDF_INFO_BLIND + b"|" + epoch_bytes,
    ).derive(bytes(peer_pub))


def _record_signing_input(
    epoch_id: int, token: bytes, peer_pub: bytes,
) -> bytes:
    return (
        RECORD_MAGIC + bytes([RECORD_VERSION])
        + struct.pack(">Q", epoch_id)
        + token + peer_pub
    )


def encode_registration(
    *,
    peer_priv_seed: bytes,
    peer_pub: bytes,
    epoch_id: int,
) -> bytes:
    """Encode a self-signed registration record.

    The record carries:
      - magic + version
      - epoch_id (so the rendezvous can detect stale records)
      - token (the lookup key for this epoch)
      - signature over (magic|version|epoch|token|peer_pub)

    The peer's pub key is NOT on the wire of subsequent
    registrations; it's bound to the record's token via the
    signature so a rendezvous that has previously seen + recorded
    peer_pub can verify renewals without storing the key in cleartext.

    Use ``encode_initial_registration`` for the very first
    registration (which DOES carry peer_pub for the bind-once
    flow)."""
    if len(peer_priv_seed) != 32:
        raise ValueError("peer_priv_seed must be 32 bytes")
    if len(peer_pub) != 32:
        raise ValueError("peer_pub must be 32 bytes")
    token = derive_blinded_token(peer_pub=peer_pub, epoch_id=epoch_id)
    body = (
        RECORD_MAGIC + bytes([RECORD_VERSION])
        + struct.pack(">Q", epoch_id)
        + token
    )
    sign_input = _record_signing_input(epoch_id, token, peer_pub)
    sig = Ed25519PrivateKey.from_private_bytes(peer_priv_seed).sign(sign_input)
    return body + sig


@dataclass(frozen=True)
class ParsedRegistration:
    epoch_id: int
    token: bytes
    signature: bytes
    encoded: bytes


def parse_registration(blob: bytes) -> ParsedRegistration:
    if len(blob) != RECORD_LEN:
        raise ValueError(
            f"registration must be {RECORD_LEN} bytes, got {len(blob)}"
        )
    if blob[:5] != RECORD_MAGIC:
        raise ValueError("not a One Link blinded registration (bad magic)")
    if blob[5] != RECORD_VERSION:
        raise ValueError(f"unsupported version {blob[5]}")
    epoch_id = struct.unpack(">Q", blob[6:14])[0]
    token = blob[14:14 + TOKEN_LEN]
    sig = blob[14 + TOKEN_LEN:14 + TOKEN_LEN + SIG_LEN]
    return ParsedRegistration(
        epoch_id=epoch_id, token=token, signature=sig, encoded=blob,
    )


def verify_registration(
    *, blob: bytes, peer_pub: bytes,
) -> ParsedRegistration:
    """The rendezvous verifies a registration against the peer_pub
    it has on file from the initial bind-once flow.

    Returns the parsed registration on success. Raises ValueError
    on tamper, bad signature, or wrong peer_pub."""
    parsed = parse_registration(blob)
    expected_token = derive_blinded_token(
        peer_pub=peer_pub, epoch_id=parsed.epoch_id,
    )
    if parsed.token != expected_token:
        raise ValueError(
            "registration token doesn't match HKDF(peer_pub, epoch); "
            "peer_pub may be wrong or the epoch_id was tampered"
        )
    sign_input = _record_signing_input(
        parsed.epoch_id, parsed.token, peer_pub,
    )
    try:
        Ed25519PublicKey.from_public_bytes(peer_pub).verify(
            parsed.signature, sign_input,
        )
    except InvalidSignature:
        raise ValueError("registration signature invalid") from None
    return parsed
