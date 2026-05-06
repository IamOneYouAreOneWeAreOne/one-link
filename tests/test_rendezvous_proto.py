"""Tests for the rendezvous wire protocol (`one_link.rendezvous_proto`).

These exercise the pure-data layer — signing, canonicalization,
verification, replay-window math, parsing of malformed input.
The on-the-wire HTTP server is tested separately."""
from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.rendezvous_proto import (
    MAX_ADVERTISED_ENDPOINTS,
    MAX_REGISTRATION_TTL_S,
    PROTOCOL_VERSION,
    REPLAY_WINDOW_MS,
    Endpoint,
    LookupAck,
    RegisterAck,
    RegisterReq,
    RevokeReq,
    now_ms,
    sign_register,
    sign_revoke,
    timestamp_within_replay_window,
)


def _new_key() -> tuple[Ed25519PrivateKey, bytes]:
    sk = Ed25519PrivateKey.generate()
    pk_bytes = sk.public_key().public_bytes_raw()
    return sk, pk_bytes


# ─── sign / verify round-trip ───────────────────────────────────────

def test_register_sign_then_verify_round_trips():
    sk, pk = _new_key()
    req = sign_register(
        private_key=sk,
        pubkey=pk,
        ttl_s=300,
        advertised_endpoints=[Endpoint("192.168.1.10", 51234)],
    )
    req.verify()  # must not raise


def test_register_verify_rejects_tampered_endpoint():
    sk, pk = _new_key()
    req = sign_register(
        private_key=sk,
        pubkey=pk,
        ttl_s=300,
        advertised_endpoints=[Endpoint("192.168.1.10", 51234)],
    )
    # Tamper with endpoint after signing.
    req.advertised_endpoints = [Endpoint("10.0.0.1", 51234)]
    with pytest.raises(ValueError, match="signature"):
        req.verify()


def test_register_verify_rejects_tampered_ttl():
    sk, pk = _new_key()
    req = sign_register(
        private_key=sk, pubkey=pk, ttl_s=300,
        advertised_endpoints=[Endpoint("h", 1)],
    )
    req.ttl_s = 86400
    with pytest.raises(ValueError, match="signature"):
        req.verify()


def test_register_verify_rejects_swapped_pubkey():
    sk1, pk1 = _new_key()
    _,   pk2 = _new_key()
    req = sign_register(
        private_key=sk1, pubkey=pk1, ttl_s=300,
        advertised_endpoints=[Endpoint("h", 1)],
    )
    # Trying to claim a different pubkey while keeping the same signature
    # — must fail.
    req.pubkey = pk2
    with pytest.raises(ValueError, match="signature"):
        req.verify()


def test_revoke_sign_then_verify_round_trips():
    sk, pk = _new_key()
    req = sign_revoke(private_key=sk, pubkey=pk)
    req.verify()


def test_revoke_verify_rejects_tampered_timestamp():
    sk, pk = _new_key()
    req = sign_revoke(private_key=sk, pubkey=pk, timestamp_ms=1_700_000_000_000)
    req.timestamp_ms = 1_800_000_000_000
    with pytest.raises(ValueError, match="signature"):
        req.verify()


# ─── wire round-trip ────────────────────────────────────────────────

def test_register_to_wire_and_back():
    sk, pk = _new_key()
    req = sign_register(
        private_key=sk, pubkey=pk, ttl_s=600,
        advertised_endpoints=[Endpoint("a.example", 7117), Endpoint("10.0.0.5", 51000)],
        nat_type="restricted",
        capabilities=["chat", "files"],
    )
    on_wire = json.loads(json.dumps(req.to_wire()))  # round-trip JSON
    parsed = RegisterReq.from_wire(on_wire)
    parsed.verify()
    assert parsed.pubkey == pk
    assert parsed.ttl_s == 600
    assert parsed.nat_type == "restricted"
    assert parsed.capabilities == ["chat", "files"]
    assert [(e.host, e.port) for e in parsed.advertised_endpoints] == [
        ("a.example", 7117), ("10.0.0.5", 51000),
    ]


def test_register_ack_round_trip():
    ack = RegisterAck(
        observed_host="203.0.113.7",
        observed_port=44321,
        server_time_ms=1_700_000_000_000,
        expires_at_ms=1_700_000_300_000,
    )
    parsed = RegisterAck.from_wire(json.loads(json.dumps(ack.to_wire())))
    assert parsed == ack


def test_lookup_ack_round_trip_with_observed_endpoint():
    _, pk = _new_key()
    ack = LookupAck(
        pubkey=pk,
        observed_endpoint=Endpoint("203.0.113.7", 44321),
        advertised_endpoints=[Endpoint("192.168.1.10", 51234)],
        nat_type="open",
        capabilities=["chat"],
        expires_at_ms=1_700_000_300_000,
        server_time_ms=1_700_000_000_000,
    )
    parsed = LookupAck.from_wire(json.loads(json.dumps(ack.to_wire())))
    assert parsed.pubkey == pk
    assert parsed.observed_endpoint == Endpoint("203.0.113.7", 44321)
    assert parsed.advertised_endpoints == [Endpoint("192.168.1.10", 51234)]
    assert parsed.nat_type == "open"


def test_lookup_ack_round_trip_without_observed_endpoint():
    _, pk = _new_key()
    ack = LookupAck(
        pubkey=pk, observed_endpoint=None,
        advertised_endpoints=[],
        nat_type="unknown",
        capabilities=[],
        expires_at_ms=1_700_000_300_000,
        server_time_ms=1_700_000_000_000,
    )
    parsed = LookupAck.from_wire(json.loads(json.dumps(ack.to_wire())))
    assert parsed.observed_endpoint is None


def test_revoke_to_wire_and_back():
    sk, pk = _new_key()
    req = sign_revoke(private_key=sk, pubkey=pk)
    parsed = RevokeReq.from_wire(json.loads(json.dumps(req.to_wire())))
    parsed.verify()
    assert parsed.pubkey == pk


# ─── replay window ──────────────────────────────────────────────────

def test_replay_window_accepts_recent():
    now = 1_700_000_000_000
    assert timestamp_within_replay_window(now - 5_000, server_now_ms=now)
    assert timestamp_within_replay_window(now + 5_000, server_now_ms=now)


def test_replay_window_rejects_old():
    now = 1_700_000_000_000
    assert not timestamp_within_replay_window(
        now - REPLAY_WINDOW_MS - 1, server_now_ms=now
    )


def test_replay_window_rejects_future():
    now = 1_700_000_000_000
    assert not timestamp_within_replay_window(
        now + REPLAY_WINDOW_MS + 1, server_now_ms=now
    )


# ─── input validation ───────────────────────────────────────────────

def test_register_rejects_wrong_protocol_version():
    sk, pk = _new_key()
    req = sign_register(
        private_key=sk, pubkey=pk, ttl_s=60,
        advertised_endpoints=[Endpoint("h", 1)],
    )
    wire = req.to_wire()
    wire["v"] = "OL-RDZ-99"
    with pytest.raises(ValueError, match="protocol version"):
        RegisterReq.from_wire(wire)


def test_register_rejects_wrong_type_field():
    sk, pk = _new_key()
    req = sign_register(
        private_key=sk, pubkey=pk, ttl_s=60,
        advertised_endpoints=[Endpoint("h", 1)],
    )
    wire = req.to_wire()
    wire["type"] = "lookup"
    with pytest.raises(ValueError, match="type"):
        RegisterReq.from_wire(wire)


def test_register_rejects_pubkey_wrong_length():
    sk, _pk = _new_key()
    req = sign_register(
        private_key=sk, pubkey=b"\x00" * 32, ttl_s=60,
        advertised_endpoints=[Endpoint("h", 1)],
    )
    wire = req.to_wire()
    # Truncate to 16 bytes' worth before re-encoding
    wire["pubkey_b64"] = wire["pubkey_b64"][:22]  # malformed
    with pytest.raises(ValueError):
        RegisterReq.from_wire(wire)


def test_register_rejects_signature_wrong_length():
    sk, pk = _new_key()
    req = sign_register(
        private_key=sk, pubkey=pk, ttl_s=60,
        advertised_endpoints=[Endpoint("h", 1)],
    )
    wire = req.to_wire()
    wire["signature"] = "AAAA"  # decodes to 3 bytes — too short
    with pytest.raises(ValueError, match="signature"):
        RegisterReq.from_wire(wire)


def test_register_rejects_ttl_zero():
    sk, pk = _new_key()
    req = sign_register(
        private_key=sk, pubkey=pk, ttl_s=60,
        advertised_endpoints=[Endpoint("h", 1)],
    )
    wire = req.to_wire()
    wire["ttl_s"] = 0
    with pytest.raises(ValueError, match="ttl_s"):
        RegisterReq.from_wire(wire)


def test_register_rejects_ttl_too_large():
    sk, pk = _new_key()
    req = sign_register(
        private_key=sk, pubkey=pk, ttl_s=60,
        advertised_endpoints=[Endpoint("h", 1)],
    )
    wire = req.to_wire()
    wire["ttl_s"] = MAX_REGISTRATION_TTL_S + 1
    with pytest.raises(ValueError, match="ttl_s"):
        RegisterReq.from_wire(wire)


def test_register_rejects_too_many_endpoints():
    sk, pk = _new_key()
    req = sign_register(
        private_key=sk, pubkey=pk, ttl_s=60,
        advertised_endpoints=[Endpoint(f"h{i}", 1) for i in range(MAX_ADVERTISED_ENDPOINTS)],
    )
    wire = req.to_wire()
    wire["advertised_endpoints"].append({"host": "extra", "port": 1})
    with pytest.raises(ValueError, match="advertised_endpoints"):
        RegisterReq.from_wire(wire)


def test_register_rejects_bad_nat_type():
    sk, pk = _new_key()
    req = sign_register(
        private_key=sk, pubkey=pk, ttl_s=60,
        advertised_endpoints=[Endpoint("h", 1)],
    )
    wire = req.to_wire()
    wire["nat_type"] = "weird"
    with pytest.raises(ValueError, match="nat_type"):
        RegisterReq.from_wire(wire)


def test_endpoint_rejects_invalid_port():
    with pytest.raises(ValueError, match="port"):
        Endpoint.from_json({"host": "h", "port": 0})
    with pytest.raises(ValueError, match="port"):
        Endpoint.from_json({"host": "h", "port": 70000})


def test_endpoint_rejects_empty_host():
    with pytest.raises(ValueError, match="host"):
        Endpoint.from_json({"host": "", "port": 80})


# ─── canonical-form determinism ─────────────────────────────────────

def test_canonical_signing_is_deterministic_across_field_order():
    """Signing must not depend on Python dict iteration order: two
    requests with the same logical content must produce byte-identical
    canonical bytes regardless of how the fields were inserted."""
    sk, pk = _new_key()
    req_a = RegisterReq(
        pubkey=pk, timestamp_ms=1, ttl_s=60,
        advertised_endpoints=[Endpoint("h", 1)],
        nat_type="open", capabilities=["a", "b"],
    )
    req_b = RegisterReq(
        pubkey=pk, timestamp_ms=1, ttl_s=60,
        advertised_endpoints=[Endpoint("h", 1)],
        nat_type="open", capabilities=["a", "b"],
    )
    from one_link.rendezvous_proto import _canonical_bytes  # type: ignore
    assert _canonical_bytes(req_a.to_signing_dict()) == _canonical_bytes(req_b.to_signing_dict())
