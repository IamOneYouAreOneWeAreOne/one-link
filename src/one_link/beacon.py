"""Coherence Beacon — UDP multicast discovery that works across LAN segments.

mDNS (the existing discovery layer) reaches only the local link —
the same broadcast domain as the daemon. Many real Wi-Fi setups
break that:

  - **Guest networks**: phone on guest, laptop on main; same
    house, but different VLANs, mDNS doesn't cross.
  - **Apartment-buildings + shared Wi-Fi**: each unit has its own
    isolated SSID even though packets traverse a shared upstream.
  - **Office Wi-Fi with client isolation enabled**: peer-to-peer
    traffic is blocked at L2.

The Coherence Beacon is a complementary, opt-in discovery layer
that uses link-local IPv6 multicast (FF02::OL — the All-Coherence-
Daemons group) and a periodic 1-Hz announcement. Where IPv6 link-
local actually works (most modern routers do forward IPv6 LL
multicast across VLAN trunk ports), peers discover each other even
when mDNS is sandboxed.

The beacon is **noise-light** by design:
  - 1-Hz tick (one announcement per second per active daemon)
  - 192-byte payload max (fits one IPv6 MTU comfortably)
  - Only emits when explicitly enabled via beacon_enable() — off
    by default to preserve the "no surprise broadcasts" privacy
    posture.

Wire format (UDP payload)
-------------------------

  [magic: b"OL-BEACON\\x01"] (10 bytes)
  [u16 short_id_len] [short_id: <= 16 bytes ascii]
  [u16 endpoint_len] [endpoint: e.g. "[fe80::dead:beef]:7117" — opaque]
  [u16 ed_pub_len: 0 or 32] [ed_pub: 32 bytes when present]
  [u64 announce_ms BE]                    # daemon's clock at emit
  [signature: 64 bytes when ed_pub present, else 0 bytes]

When ed_pub is present, the signature covers
``(magic || short_id || endpoint || announce_ms)`` under that
ed_pub. Receivers can pin a peer's beacon-pub in their trust
store after first sight + verify subsequent beacons.

A beacon WITHOUT a signature is acceptable but treated as
unverified TOFU; the daemon's pair flow + channel handshake do
the actual identity binding. The beacon is only a hint.

Threat caveats
--------------

  - **Spoofing**: anyone on the L2 segment can mint a beacon. The
    beacon is informational ("a daemon claims to be at endpoint
    X"); the channel handshake is what proves identity. With a
    signature, the receiver can pin and detect later spoofing.
  - **Tracking**: emitting beacons reveals daemon presence to
    every L2 listener. Privacy-conscious users keep beacon off
    (the default) and rely on direct mDNS / pair-by-QR.
  - **Amplification**: beacon emit is 1-Hz with bounded payload;
    rate-limiting by emit-side is built in. Receive-side
    rate-limiting is the caller's responsibility (we only
    parse + validate).

This module ships the wire-format primitive + the validation
logic. Hooking the actual UDP socket in is the next layer
(the daemon's discovery loop integrates beacon as a sibling
to mDNS).
"""
from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)


BEACON_MAGIC = b"OL-BEACON\x01"
MAX_SHORT_ID_LEN = 16
MAX_ENDPOINT_LEN = 96
MAX_BEACON_LEN = 256  # UDP-friendly cap; one MTU
SIG_LEN = 64
ED_PUB_LEN = 32

# IANA-compatible link-local multicast group for One Link beacons.
# FF02::/16 is permanently link-local; the group ID 0xCAFE is
# arbitrary but distinct (the canonical One Link "OL" 4-letter
# encoded as UTF-16 would be 0x4F4C — collides with no IANA-
# assigned LL group). 5354 is the UDP port (mirrors mDNS 5353 +1).
BEACON_GROUP = "ff02::cafe"
BEACON_PORT = 5354
BEACON_TICK_HZ = 1  # one emit per second per active daemon


def encode_beacon(
    *,
    short_id: str,
    endpoint: str,
    announce_ms: int | None = None,
    priv_seed: bytes | None = None,
) -> bytes:
    """Encode a beacon frame. Pass ``priv_seed`` to sign + bind the
    daemon's Ed25519 identity into the announcement; omit for an
    unsigned (TOFU) beacon."""
    sid_bytes = short_id.encode("ascii")
    if len(sid_bytes) == 0 or len(sid_bytes) > MAX_SHORT_ID_LEN:
        raise ValueError(
            f"short_id must be 1..{MAX_SHORT_ID_LEN} bytes, "
            f"got {len(sid_bytes)}"
        )
    ep_bytes = endpoint.encode("ascii")
    if len(ep_bytes) == 0 or len(ep_bytes) > MAX_ENDPOINT_LEN:
        raise ValueError(
            f"endpoint must be 1..{MAX_ENDPOINT_LEN} bytes, "
            f"got {len(ep_bytes)}"
        )
    if announce_ms is None:
        announce_ms = int(time.time() * 1000)
    if not (0 <= announce_ms <= 2**63 - 1):
        raise ValueError("announce_ms out of range")

    if priv_seed is not None:
        if len(priv_seed) != 32:
            raise ValueError("priv_seed must be 32 bytes")
        priv_obj = Ed25519PrivateKey.from_private_bytes(priv_seed)
        pub = priv_obj.public_key().public_bytes_raw()
    else:
        pub = b""
        priv_obj = None

    body = (
        BEACON_MAGIC
        + struct.pack(">H", len(sid_bytes)) + sid_bytes
        + struct.pack(">H", len(ep_bytes)) + ep_bytes
        + struct.pack(">H", len(pub)) + pub
        + struct.pack(">Q", announce_ms)
    )
    if priv_obj is not None:
        sig = priv_obj.sign(body)
        body += sig
    if len(body) > MAX_BEACON_LEN:
        raise ValueError(
            f"beacon exceeds {MAX_BEACON_LEN} bytes; trim short_id "
            "or endpoint"
        )
    return body


@dataclass(frozen=True)
class Beacon:
    short_id: str
    endpoint: str
    announce_ms: int
    ed_pub: Optional[bytes]   # None when unsigned
    signed: bool
    encoded: bytes


def parse_beacon(blob: bytes) -> Beacon:
    if len(blob) < len(BEACON_MAGIC) + 6 + 8:
        raise ValueError("beacon too short")
    if blob[:len(BEACON_MAGIC)] != BEACON_MAGIC:
        raise ValueError("not a One Link beacon (bad magic)")
    off = len(BEACON_MAGIC)
    sid_len = struct.unpack(">H", blob[off:off + 2])[0]
    off += 2
    if sid_len > MAX_SHORT_ID_LEN or off + sid_len > len(blob):
        raise ValueError("beacon truncated at short_id")
    short_id = blob[off:off + sid_len].decode("ascii")
    off += sid_len
    if off + 2 > len(blob):
        raise ValueError("beacon truncated at endpoint length")
    ep_len = struct.unpack(">H", blob[off:off + 2])[0]
    off += 2
    if ep_len > MAX_ENDPOINT_LEN or off + ep_len > len(blob):
        raise ValueError("beacon truncated at endpoint")
    endpoint = blob[off:off + ep_len].decode("ascii")
    off += ep_len
    if off + 2 > len(blob):
        raise ValueError("beacon truncated at ed_pub length")
    pub_len = struct.unpack(">H", blob[off:off + 2])[0]
    off += 2
    if pub_len not in (0, ED_PUB_LEN):
        raise ValueError(
            f"beacon ed_pub_len must be 0 or 32, got {pub_len}"
        )
    if off + pub_len > len(blob):
        raise ValueError("beacon truncated at ed_pub")
    ed_pub = blob[off:off + pub_len] if pub_len > 0 else None
    off += pub_len
    if off + 8 > len(blob):
        raise ValueError("beacon truncated at announce_ms")
    announce_ms = struct.unpack(">Q", blob[off:off + 8])[0]
    off += 8
    expected_remaining = SIG_LEN if ed_pub else 0
    if off + expected_remaining != len(blob):
        raise ValueError(
            f"beacon length mismatch: expected {off + expected_remaining}, "
            f"got {len(blob)}"
        )
    signed = ed_pub is not None
    return Beacon(
        short_id=short_id,
        endpoint=endpoint,
        announce_ms=announce_ms,
        ed_pub=ed_pub,
        signed=signed,
        encoded=blob,
    )


def verify_beacon(
    blob: bytes,
    *,
    expected_pub: bytes | None = None,
    max_age_ms: int = 30_000,
    now_ms: int | None = None,
) -> Beacon:
    """Verify + parse a beacon. If signed, the signature is checked.
    If ``expected_pub`` is set, the signed beacon's ed_pub must
    match (peer-pin enforcement). Beacons older than ``max_age_ms``
    are rejected to prevent replay of captured beacons.

    Raises ValueError on any failure; returns the parsed Beacon
    on success."""
    parsed = parse_beacon(blob)
    if parsed.signed:
        # Body is everything except the trailing 64-byte sig.
        body = blob[:-SIG_LEN]
        sig = blob[-SIG_LEN:]
        if parsed.ed_pub is None:
            raise ValueError("signed beacon missing ed_pub")
        try:
            Ed25519PublicKey.from_public_bytes(parsed.ed_pub).verify(sig, body)
        except InvalidSignature:
            raise ValueError("beacon signature invalid") from None
        if expected_pub is not None and parsed.ed_pub != expected_pub:
            raise ValueError(
                f"beacon ed_pub doesn't match expected "
                f"{expected_pub.hex()[:16]}…"
            )
    else:
        if expected_pub is not None:
            raise ValueError(
                "beacon is unsigned but expected_pub was supplied; "
                "TOFU mode does not support pin enforcement"
            )
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    age = now_ms - parsed.announce_ms
    if age > max_age_ms:
        raise ValueError(
            f"beacon stale: {age}ms old > max_age {max_age_ms}ms "
            "(possible replay)"
        )
    if age < -max_age_ms:  # future-dated beacon = clock skew abuse
        raise ValueError(
            f"beacon dated in the future ({-age}ms); refusing"
        )
    return parsed
