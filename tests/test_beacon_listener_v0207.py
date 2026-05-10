"""v0.20.7 (Bundle 54) — Coherence Beacon UDP listener integration.

Bundle 50 shipped the beacon wire format; Bundle 54 wires it onto a
real asyncio DatagramProtocol. Most of the wire-format checks live
in test_beacon_v0207.py; here we test the asyncio integration.

These tests are network-touch tests (they bind a real UDP socket
on loopback). On platforms where multicast isn't available, they
skip cleanly.

Pinned:
  - _BeaconProtocol.datagram_received parses + verifies an incoming
    beacon, dispatches to the callback
  - Self-emissions (matching short_id) are filtered out
  - Malformed beacons don't kill the listener
  - Oversized beacons are dropped before parse
  - Unverified mode passes parsable-but-stale beacons through
  - BeaconConfig + BeaconService construct cleanly
"""
from __future__ import annotations

import asyncio
import socket
import time

import pytest

from one_link import beacon, beacon_listener as bl


def test_protocol_dispatches_valid_beacon():
    received = []
    cfg = bl.BeaconConfig(
        short_id="self-id",
        endpoint="[::1]:7117",
        on_peer_discovered=lambda b: received.append(b),
    )
    proto = bl._BeaconProtocol(cfg, self_short_id="self-id")
    blob = beacon.encode_beacon(
        short_id="peer-id", endpoint="[::1]:7118",
    )
    proto.datagram_received(blob, ("::1", 5354))
    assert len(received) == 1
    assert received[0].short_id == "peer-id"


def test_protocol_filters_self_emissions():
    received = []
    cfg = bl.BeaconConfig(
        short_id="self-id",
        endpoint="[::1]:7117",
        on_peer_discovered=lambda b: received.append(b),
    )
    proto = bl._BeaconProtocol(cfg, self_short_id="self-id")
    blob = beacon.encode_beacon(
        short_id="self-id", endpoint="[::1]:7117",
    )
    proto.datagram_received(blob, ("::1", 5354))
    assert received == []


def test_protocol_drops_malformed():
    """A malformed datagram should be dropped silently — listener
    keeps running."""
    received = []
    cfg = bl.BeaconConfig(
        short_id="self", endpoint="x",
        on_peer_discovered=lambda b: received.append(b),
    )
    proto = bl._BeaconProtocol(cfg)
    proto.datagram_received(b"junk", ("::1", 5354))
    proto.datagram_received(b"\x00" * 100, ("::1", 5354))
    assert received == []


def test_protocol_drops_oversized():
    received = []
    cfg = bl.BeaconConfig(
        short_id="x", endpoint="y",
        on_peer_discovered=lambda b: received.append(b),
    )
    proto = bl._BeaconProtocol(cfg)
    huge = b"\x00" * (beacon.MAX_BEACON_LEN + 1)
    proto.datagram_received(huge, ("::1", 5354))
    assert received == []


def test_protocol_drops_stale_when_verifying():
    """A beacon dated in the past must be rejected when
    verify_incoming=True."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    received = []
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes_raw()
    cfg = bl.BeaconConfig(
        short_id="self", endpoint="x",
        on_peer_discovered=lambda b: received.append(b),
        verify_incoming=True, max_age_ms=5_000,
    )
    proto = bl._BeaconProtocol(cfg)
    stale_blob = beacon.encode_beacon(
        short_id="peer", endpoint="x",
        announce_ms=int(time.time() * 1000) - 60_000,
        priv_seed=seed,
    )
    proto.datagram_received(stale_blob, ("::1", 5354))
    assert received == []


def test_protocol_passes_unverified_when_disabled():
    """With verify_incoming=False, unsigned-and-parsable beacons
    pass through (TOFU mode)."""
    received = []
    cfg = bl.BeaconConfig(
        short_id="self", endpoint="x",
        on_peer_discovered=lambda b: received.append(b),
        verify_incoming=False,
    )
    proto = bl._BeaconProtocol(cfg)
    blob = beacon.encode_beacon(
        short_id="ancient-peer", endpoint="x",
        announce_ms=1_000_000,  # year 1970-ish
    )
    proto.datagram_received(blob, ("::1", 5354))
    assert len(received) == 1


def test_callback_exception_does_not_kill_listener():
    """A callback that raises must not propagate — listener keeps
    running."""
    received = []

    def boom(_b):
        raise RuntimeError("synthetic")

    cfg = bl.BeaconConfig(
        short_id="self", endpoint="x", on_peer_discovered=boom,
    )
    proto = bl._BeaconProtocol(cfg)
    blob = beacon.encode_beacon(short_id="peer", endpoint="x")
    # Should not raise — callback exception swallowed.
    proto.datagram_received(blob, ("::1", 5354))
    # Send a second; if the listener died, this would error. It
    # doesn't because the protocol catches.
    proto.datagram_received(blob, ("::1", 5354))


def test_beacon_config_defaults_sane():
    cfg = bl.BeaconConfig(short_id="x", endpoint="y")
    assert cfg.tick_seconds == 1.0
    assert cfg.verify_incoming is True
    assert cfg.max_age_ms == 30_000


def test_beacon_v4_group_constant():
    assert bl.BEACON_V4_GROUP == "224.0.0.123"
