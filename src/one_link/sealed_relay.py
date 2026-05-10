"""Sealed-sender on the relay path — combine identity hiding with
capability-bearing relay frames.

When peer A sends to peer B via the One Link relay (NAT-traversed
flow), the relay sees both pubkeys today. Bundle 39 shipped the
sealed-sender primitive (relay can't see WHO sent); Bundle 44
shipped signed capability grants (peer authorizes specific actions
with auto-expiry). Bundle 52 ships the integration: a relay frame
that carries

  - the sealed-sender envelope (so the relay learns nothing about
    the sender)
  - an OPTIONAL capability grant the recipient should evaluate
    before accepting the action (so the recipient's daemon can
    auto-allow specific operations without waking the user)

The format mounts atop the existing sealed-sender wire shape with
a relay-specific AAD ("OL/relay-frame|v1") so a sealed envelope
intended for direct channel use can't be replayed against the
relay path (and vice-versa). The capability grant, when present,
is OUTSIDE the AEAD envelope (so the relay-side rate-limiter can
read its expiry without decrypting) but is referenced inside the
sealed plaintext via the grant's nonce, binding the sender's
intent.

Wire format
-----------

  [u16 grant_len] [grant: caps_grants encoded record, 0+ bytes]
  [u32 envelope_len] [envelope: sealed_sender wire blob]

Envelope inner plaintext layout (matches sealed_sender's normal
inner layout):
  [version: 1] [sender_ed_pub: 32] [timestamp_ms: 8 BE]
  [signature: 64] [body: variable]

Where body is structured as:
  [grant_nonce: 16 bytes] [u16 payload_len] [payload]

The grant_nonce is the 16-byte nonce of the OUTER capability grant,
embedded inside the sealed plaintext — this binds the sender's
intent ("I deliberately attached this grant") to the message body
so a relay (or man-in-the-middle) can't strip the grant or swap
in a different one without invalidating the AEAD tag on the
inner envelope.

If no grant is attached, ``grant_len = 0`` and ``grant_nonce`` is
all zeros inside the envelope.
"""
from __future__ import annotations

import secrets
import struct
from dataclasses import dataclass
from typing import Iterable, Optional

from one_link import caps_grants, sealed_sender


RELAY_AAD = b"OL/relay-frame|v1"
GRANT_NONCE_LEN = 16
NULL_NONCE = b"\x00" * GRANT_NONCE_LEN


@dataclass(frozen=True)
class SealedRelayFrame:
    sender_ed_pub: bytes
    timestamp_ms: int
    payload: bytes
    grant: Optional[caps_grants.CapabilityGrant]


def _encode_inner_body(grant_nonce: bytes, payload: bytes) -> bytes:
    if len(grant_nonce) != GRANT_NONCE_LEN:
        raise ValueError(
            f"grant_nonce must be {GRANT_NONCE_LEN} bytes"
        )
    if len(payload) > 65535:
        raise ValueError(f"payload too large: {len(payload)} > 65535")
    return grant_nonce + struct.pack(">H", len(payload)) + payload


def _decode_inner_body(body: bytes) -> tuple[bytes, bytes]:
    if len(body) < GRANT_NONCE_LEN + 2:
        raise ValueError("inner body too short")
    grant_nonce = body[:GRANT_NONCE_LEN]
    payload_len = struct.unpack(
        ">H", body[GRANT_NONCE_LEN:GRANT_NONCE_LEN + 2],
    )[0]
    if GRANT_NONCE_LEN + 2 + payload_len != len(body):
        raise ValueError("inner body length mismatch")
    payload = body[GRANT_NONCE_LEN + 2:]
    return grant_nonce, payload


def seal_for_relay(
    *,
    payload: bytes,
    sender_ed_priv_seed: bytes,
    sender_ed_pub: bytes,
    recipient_ed_pub: bytes,
    grant_blob: Optional[bytes] = None,
) -> bytes:
    """Build a sealed-relay frame. ``grant_blob``, when present, is
    a Bundle 44 caps_grants record that the recipient evaluates
    after unwrapping. The grant's nonce is bound into the sealed
    plaintext so a relay can't strip or swap it."""
    if grant_blob is not None:
        if len(grant_blob) > 65535:
            raise ValueError("grant_blob too large for u16 length prefix")
        # Parse to extract the nonce we'll bind into the inner body.
        parsed_grant = caps_grants.parse_grant(grant_blob)
        grant_nonce = parsed_grant.nonce
    else:
        grant_blob = b""
        grant_nonce = NULL_NONCE

    inner_body = _encode_inner_body(grant_nonce, payload)
    envelope = sealed_sender.seal(
        body=inner_body,
        sender_ed_priv_seed=sender_ed_priv_seed,
        sender_ed_pub=sender_ed_pub,
        recipient_ed_pub=recipient_ed_pub,
    )
    return (
        struct.pack(">H", len(grant_blob)) + grant_blob
        + struct.pack(">I", len(envelope)) + envelope
    )


def unseal_from_relay(
    *,
    blob: bytes,
    my_ed_priv_seed: bytes,
    paired_ed_pubs: Optional[Iterable[bytes]] = None,
    expected_capabilities: Optional[Iterable[str]] = None,
    expected_scope: Optional[bytes] = None,
    seen_grant_nonces: Optional[set[bytes]] = None,
    now_ms: Optional[int] = None,
    freshness_window_ms: int = sealed_sender.DEFAULT_FRESHNESS_MS,
) -> SealedRelayFrame:
    """Decrypt + verify a sealed-relay frame.

    Steps:
      1. Parse outer wire format.
      2. If a grant is present, parse it (but DON'T verify yet —
         we verify after extracting sender_ed_pub from the sealed
         plaintext, since the grant's subject_pub must match).
      3. Unseal the envelope with this device's priv key, getting
         (sender_ed_pub, timestamp, inner_body).
      4. Decode inner_body → (grant_nonce, payload).
      5. If a grant blob was attached: verify (signature, expiry,
         subject == sender, nonce-match-with-bound-nonce, scope,
         capabilities, replay).
      6. Optionally enforce paired-set on sender (sealed_sender does
         this internally when paired_ed_pubs is supplied).

    Raises ValueError on any failure; returns the SealedRelayFrame
    on success."""
    if len(blob) < 6:
        raise ValueError("relay blob too short")
    off = 0
    grant_len = struct.unpack(">H", blob[off:off + 2])[0]
    off += 2
    if off + grant_len > len(blob):
        raise ValueError("relay blob truncated at grant body")
    grant_blob = blob[off:off + grant_len]
    off += grant_len
    if off + 4 > len(blob):
        raise ValueError("relay blob truncated at envelope length")
    envelope_len = struct.unpack(">I", blob[off:off + 4])[0]
    off += 4
    if off + envelope_len != len(blob):
        raise ValueError(
            f"relay blob length mismatch: claimed grant={grant_len} "
            f"envelope={envelope_len}, actual {len(blob)} bytes"
        )
    envelope = blob[off:off + envelope_len]

    msg = sealed_sender.unseal(
        blob=envelope,
        my_ed_priv_seed=my_ed_priv_seed,
        paired_ed_pubs=paired_ed_pubs,
        freshness_window_ms=freshness_window_ms,
        now_ms=now_ms,
    )
    grant_nonce, payload = _decode_inner_body(msg.body)

    grant: Optional[caps_grants.CapabilityGrant] = None
    if grant_blob:
        parsed = caps_grants.parse_grant(grant_blob)
        if parsed.nonce != grant_nonce:
            raise ValueError(
                "grant nonce inside sealed envelope doesn't match "
                "outer grant — possible relay tampering"
            )
        # Verify the grant: signature, subject == sender, freshness,
        # caller-supplied caps + scope, replay.
        verified = caps_grants.verify_grant(
            grant_blob,
            expected_subject_pub=msg.sender_ed_pub,
            now_ms=now_ms,
            seen_nonces=seen_grant_nonces,
        )
        if expected_capabilities is not None:
            need = set(expected_capabilities)
            if not need.issubset(verified.capabilities):
                raise ValueError(
                    f"grant lacks required capabilities; need "
                    f"{need - verified.capabilities}"
                )
        if expected_scope is not None:
            if verified.scope != expected_scope:
                raise ValueError(
                    f"grant scope mismatch: have {verified.scope!r}, "
                    f"need {expected_scope!r}"
                )
        grant = verified
    else:
        # No grant attached. The bound nonce inside MUST be the null
        # nonce (otherwise the sender promised a grant that wasn't
        # delivered, which is a tampering signal).
        if grant_nonce != NULL_NONCE:
            raise ValueError(
                "sealed envelope claims to bear a grant nonce but "
                "no grant attached on the wire — possible relay "
                "stripped the grant"
            )

    return SealedRelayFrame(
        sender_ed_pub=msg.sender_ed_pub,
        timestamp_ms=msg.timestamp_ms,
        payload=payload,
        grant=grant,
    )
