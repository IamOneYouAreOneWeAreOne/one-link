"""v0.20.7 — Coherence Beacon (UDP multicast discovery for cross-LAN).

mDNS only reaches the local broadcast domain. Coherence Beacon uses
IPv6 link-local multicast at FF02::CAFE:5354 to reach across VLAN
trunk ports where mDNS sandboxes (guest networks, apartment Wi-Fi
with SSID isolation, office client-isolation enabled).

These tests pin:
  - Encode + parse round-trip preserves every field
  - Unsigned beacon (TOFU mode) round-trips
  - Signed beacon verifies under the embedded ed_pub
  - Tampered signature / body / ed_pub rejected
  - expected_pub enforcement: pinned receiver rejects a different pub
  - Stale beacon rejected (replay defense)
  - Future-dated beacon rejected (clock-skew abuse)
  - Length caps enforced on short_id + endpoint
  - Multicast group + port constants exposed
"""
from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import beacon


def _gen_ed25519():
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes_raw()
    pub = priv.public_key().public_bytes_raw()
    return seed, pub


def _now_ms():
    return int(time.time() * 1000)


# ── encode / parse ─────────────────────────────────────────────────


def test_unsigned_beacon_round_trip():
    blob = beacon.encode_beacon(
        short_id="abc12345",
        endpoint="[fe80::1]:7117",
    )
    parsed = beacon.parse_beacon(blob)
    assert parsed.short_id == "abc12345"
    assert parsed.endpoint == "[fe80::1]:7117"
    assert parsed.signed is False
    assert parsed.ed_pub is None


def test_signed_beacon_round_trip():
    seed, pub = _gen_ed25519()
    blob = beacon.encode_beacon(
        short_id="signed42",
        endpoint="[fe80::2]:7118",
        priv_seed=seed,
    )
    parsed = beacon.parse_beacon(blob)
    assert parsed.signed is True
    assert parsed.ed_pub == pub


def test_signed_beacon_verifies():
    seed, pub = _gen_ed25519()
    blob = beacon.encode_beacon(
        short_id="x", endpoint="[::1]:7117", priv_seed=seed,
    )
    parsed = beacon.verify_beacon(blob)
    assert parsed.short_id == "x"


def test_signed_beacon_pin_match():
    seed, pub = _gen_ed25519()
    blob = beacon.encode_beacon(
        short_id="x", endpoint="[::1]:7117", priv_seed=seed,
    )
    beacon.verify_beacon(blob, expected_pub=pub)  # OK
    other_pub = _gen_ed25519()[1]
    with pytest.raises(ValueError, match="ed_pub"):
        beacon.verify_beacon(blob, expected_pub=other_pub)


def test_unsigned_beacon_with_expected_pub_rejected():
    """Pin enforcement requires a signed beacon."""
    blob = beacon.encode_beacon(short_id="x", endpoint="[::1]:7117")
    _, pub = _gen_ed25519()
    with pytest.raises(ValueError, match="TOFU mode"):
        beacon.verify_beacon(blob, expected_pub=pub)


def test_tampered_signature_rejected():
    seed, _ = _gen_ed25519()
    blob = bytearray(beacon.encode_beacon(
        short_id="x", endpoint="[::1]:7117", priv_seed=seed,
    ))
    blob[-1] ^= 0xff
    with pytest.raises(ValueError, match="signature"):
        beacon.verify_beacon(bytes(blob))


def test_tampered_body_rejected():
    seed, _ = _gen_ed25519()
    blob = bytearray(beacon.encode_beacon(
        short_id="x", endpoint="[::1]:7117", priv_seed=seed,
    ))
    # Flip a byte inside the endpoint region.
    blob[20] ^= 0xff
    with pytest.raises(ValueError):
        beacon.verify_beacon(bytes(blob))


def test_stale_beacon_rejected():
    seed, _ = _gen_ed25519()
    past = _now_ms() - 60_000  # 1 min ago
    blob = beacon.encode_beacon(
        short_id="x", endpoint="[::1]:7117",
        announce_ms=past, priv_seed=seed,
    )
    with pytest.raises(ValueError, match="stale"):
        beacon.verify_beacon(blob, max_age_ms=30_000)


def test_future_dated_beacon_rejected():
    seed, _ = _gen_ed25519()
    future = _now_ms() + 60_000
    blob = beacon.encode_beacon(
        short_id="x", endpoint="[::1]:7117",
        announce_ms=future, priv_seed=seed,
    )
    with pytest.raises(ValueError, match="future"):
        beacon.verify_beacon(blob, max_age_ms=30_000)


def test_fresh_beacon_accepted():
    seed, _ = _gen_ed25519()
    blob = beacon.encode_beacon(
        short_id="x", endpoint="[::1]:7117", priv_seed=seed,
    )
    parsed = beacon.verify_beacon(blob, max_age_ms=30_000)
    assert parsed.short_id == "x"


# ── input bounds ───────────────────────────────────────────────────


def test_short_id_too_long_rejected():
    with pytest.raises(ValueError, match="short_id"):
        beacon.encode_beacon(
            short_id="x" * (beacon.MAX_SHORT_ID_LEN + 1),
            endpoint="[::1]:7117",
        )


def test_endpoint_too_long_rejected():
    with pytest.raises(ValueError, match="endpoint"):
        beacon.encode_beacon(
            short_id="x",
            endpoint="x" * (beacon.MAX_ENDPOINT_LEN + 1),
        )


def test_empty_short_id_rejected():
    with pytest.raises(ValueError, match="short_id"):
        beacon.encode_beacon(short_id="", endpoint="[::1]:7117")


def test_empty_endpoint_rejected():
    with pytest.raises(ValueError, match="endpoint"):
        beacon.encode_beacon(short_id="x", endpoint="")


# ── parse failure modes ──────────────────────────────────────────


def test_parse_too_short():
    with pytest.raises(ValueError, match="too short"):
        beacon.parse_beacon(b"\x00" * 5)


def test_parse_bad_magic():
    blob = bytearray(beacon.encode_beacon(
        short_id="x", endpoint="[::1]:7117",
    ))
    blob[0:5] = b"NOTOL"
    with pytest.raises(ValueError, match="bad magic"):
        beacon.parse_beacon(bytes(blob))


def test_parse_invalid_pub_len():
    """A beacon claiming a non-{0,32} ed_pub_len is rejected."""
    seed, _ = _gen_ed25519()
    blob = bytearray(beacon.encode_beacon(
        short_id="x", endpoint="[::1]:7117", priv_seed=seed,
    ))
    # Find the ed_pub_len field — fixed offset:
    #   magic (10) + sid_len (2) + sid (1) + ep_len (2) + ep (13)
    #   = 28; then ed_pub_len at offset 28 (2 bytes).
    pub_len_off = 10 + 2 + 1 + 2 + 13
    # Force pub_len = 16 (invalid). Actual blob layout: short_id="x"
    # so sid is 1 byte, endpoint="[::1]:7117" is 13 bytes. Sanity-
    # check the offset against the actual pub_len bytes.
    import struct as _s
    # Locate it dynamically: scan for the pattern (\x00\x20 = 32) that
    # marks the SIGNED case's ed_pub_len.
    needle = _s.pack(">H", 32)
    idx = bytes(blob).find(needle)
    blob[idx:idx + 2] = _s.pack(">H", 16)
    with pytest.raises(ValueError, match="ed_pub_len"):
        beacon.parse_beacon(bytes(blob))


def test_constants_sane():
    assert beacon.BEACON_GROUP == "ff02::cafe"
    assert beacon.BEACON_PORT == 5354
    assert beacon.BEACON_TICK_HZ == 1
    assert beacon.MAX_BEACON_LEN == 256
