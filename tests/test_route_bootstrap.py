import json
import socket

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.identity import Identity, fingerprint_of
from one_link.route_bootstrap import (
    RouteEndpointHint,
    decode_bootstrap,
    encode_bootstrap,
    encode_bootstrap_compact,
    make_route_bootstrap,
    verify_bootstrap,
)
from one_link import route_bootstrap as rb


def _identity() -> Identity:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=priv,
        public=pub,
        public_bytes=pub_bytes,
        fingerprint=fp,
        short_id=fp[:8],
        hostname=socket.gethostname(),
    )


def test_route_bootstrap_round_trips_and_verifies():
    ident = _identity()
    payload = make_route_bootstrap(
        identity=ident,
        endpoints=[
            RouteEndpointHint(
                kind="lan",
                address="192.168.1.20",
                port=17117,
                priority=1,
                route="lan",
            )
        ],
        capabilities=["files", "chat", "files"],
        route_truth={"kind": "Local network", "state": "Ready"},
        ttl_s=120,
        now_ms=1_000_000,
        nonce_hex="00" * 16,
    )

    token = encode_bootstrap(payload)
    decoded = decode_bootstrap(token, now_ms=1_001_000)

    assert decoded.issuer_fp == ident.fingerprint
    assert decoded.endpoints[0]["address"] == "192.168.1.20"
    assert decoded.body["capabilities"] == ["chat", "files"]
    verify_bootstrap(decoded, now_ms=1_001_000, expected_issuer_fp=ident.fingerprint)


def test_route_bootstrap_rejects_tampering():
    ident = _identity()
    payload = make_route_bootstrap(
        identity=ident,
        endpoints=[RouteEndpointHint(kind="lan", address="10.0.0.4", port=17117)],
        now_ms=1_000_000,
    )
    tampered = payload.to_dict()
    tampered["body"]["endpoints"][0]["port"] = 9

    token = encode_bootstrap(type(payload)(body=tampered["body"], signature_hex=tampered["signature"]))

    with pytest.raises(ValueError, match="body hash|signature"):
        decode_bootstrap(token, now_ms=1_001_000)


def test_route_bootstrap_compact_token_round_trips_for_qr():
    ident = _identity()
    payload = make_route_bootstrap(
        identity=ident,
        endpoints=[
            RouteEndpointHint(
                kind="lan",
                route="lan",
                address="192.168.1.20",
                port=17117,
            )
        ],
        capabilities=[f"capability_{i}" for i in range(24)],
        route_truth={
            "kind": "Local network",
            "state": "Ready",
            "reason": "route truth that compresses well for QR transport",
        },
        now_ms=1_000_000,
    )

    compact = encode_bootstrap_compact(payload)
    decoded = decode_bootstrap(compact, now_ms=1_001_000)

    assert compact.startswith("OLRZ1.")
    assert len(compact) < len(encode_bootstrap(payload))
    assert decoded.issuer_fp == ident.fingerprint
    assert decoded.endpoints[0]["address"] == "192.168.1.20"


def test_route_bootstrap_rejects_expired_payload():
    ident = _identity()
    payload = make_route_bootstrap(
        identity=ident,
        endpoints=[RouteEndpointHint(kind="lan", address="10.0.0.4", port=17117)],
        now_ms=1_000_000,
        ttl_s=5,
    )

    with pytest.raises(ValueError, match="expired"):
        verify_bootstrap(payload, now_ms=1_006_001)


def test_route_bootstrap_clamps_and_rejects_oversized_endpoint_sets():
    ident = _identity()
    endpoints = [
        RouteEndpointHint(kind="lan", address=f"10.0.0.{i}", port=17117)
        for i in range(9)
    ]

    with pytest.raises(ValueError, match="too many endpoint"):
        make_route_bootstrap(identity=ident, endpoints=endpoints)


def test_route_bootstrap_rejects_bad_ports_before_signing():
    ident = _identity()

    with pytest.raises(ValueError, match="port"):
        make_route_bootstrap(
            identity=ident,
            endpoints=[RouteEndpointHint(kind="lan", address="10.0.0.4", port=70000)],
        )


def test_route_bootstrap_rejects_wrong_expected_issuer():
    ident = _identity()
    payload = make_route_bootstrap(
        identity=ident,
        endpoints=[RouteEndpointHint(kind="lan", address="10.0.0.4", port=17117)],
    )

    with pytest.raises(ValueError, match="unexpected"):
        verify_bootstrap(payload, expected_issuer_fp="bb" * 32)


def test_route_bootstrap_rejects_loopback_or_multicast_network_hints():
    ident = _identity()

    with pytest.raises(ValueError, match="safe routable target"):
        make_route_bootstrap(
            identity=ident,
            endpoints=[RouteEndpointHint(kind="lan", address="127.0.0.1", port=17117)],
        )

    with pytest.raises(ValueError, match="safe routable target"):
        make_route_bootstrap(
            identity=ident,
            endpoints=[RouteEndpointHint(kind="lan", address="224.0.0.1", port=17117)],
        )


def test_route_bootstrap_allows_explicit_loopback_hint_only_as_loopback():
    ident = _identity()

    payload = make_route_bootstrap(
        identity=ident,
        endpoints=[
            RouteEndpointHint(
                kind="loopback",
                route="loopback",
                address="127.0.0.1",
                port=17117,
            )
        ],
    )

    assert payload.endpoints[0]["route"] == "loopback"
    assert payload.endpoints[0]["kind"] == "loopback"


def test_route_bootstrap_rejects_non_loopback_address_on_loopback_route():
    ident = _identity()

    with pytest.raises(ValueError, match="loopback route"):
        make_route_bootstrap(
            identity=ident,
            endpoints=[
                RouteEndpointHint(
                    kind="loopback",
                    route="loopback",
                    address="10.0.0.4",
                    port=17117,
                )
            ],
        )


def test_route_bootstrap_rejects_local_route_to_public_ip():
    ident = _identity()

    with pytest.raises(ValueError, match="local route"):
        make_route_bootstrap(
            identity=ident,
            endpoints=[RouteEndpointHint(kind="lan", address="8.8.8.8", port=17117)],
        )


def test_route_bootstrap_control_paths_cannot_smuggle_tcp_ports():
    ident = _identity()

    with pytest.raises(ValueError, match="control-only"):
        make_route_bootstrap(
            identity=ident,
            endpoints=[
                RouteEndpointHint(
                    kind="ble_control",
                    address="peer-nearby",
                    port=17117,
                    route="ble_control",
                    transport="tcp",
                )
            ],
        )


def _sample_payload():
    return make_route_bootstrap(
        identity=_identity(),
        endpoints=[RouteEndpointHint(kind="lan", address="10.0.0.4", port=17117)],
        capabilities=["chat", "files"],
        now_ms=1_000_000,
        nonce_hex="01" * 16,
    )


def test_route_bootstrap_rejects_unknown_outer_body_and_endpoint_fields():
    payload = _sample_payload()
    outer = payload.to_dict()
    outer["ignored"] = "parser-confusion"
    raw = rb._canonical_bytes(outer)
    with pytest.raises(ValueError, match="fields invalid"):
        decode_bootstrap("OLRB1." + rb._b64u(raw), now_ms=1_001_000)

    body = json.loads(json.dumps(payload.body))
    body["ignored"] = "parser-confusion"
    with pytest.raises(ValueError, match="fields invalid"):
        verify_bootstrap(
            type(payload)(body=body, signature_hex=payload.signature_hex),
            now_ms=1_001_000,
        )

    body = json.loads(json.dumps(payload.body))
    body["endpoints"][0]["ignored"] = True
    with pytest.raises(ValueError, match="fields invalid"):
        verify_bootstrap(
            type(payload)(body=body, signature_hex=payload.signature_hex),
            now_ms=1_001_000,
        )


def test_route_bootstrap_rejects_coercive_scalars_and_malformed_capabilities():
    payload = _sample_payload()
    for field, value in (
        ("version", True),
        ("issued_ms", "1000000"),
        ("expires_ms", False),
    ):
        body = json.loads(json.dumps(payload.body))
        body[field] = value
        with pytest.raises(ValueError, match=field if field != "version" else "version"):
            verify_bootstrap(
                type(payload)(body=body, signature_hex=payload.signature_hex),
                now_ms=1_001_000,
            )

    body = json.loads(json.dumps(payload.body))
    body["endpoints"][0]["port"] = True
    with pytest.raises(ValueError, match="port"):
        verify_bootstrap(
            type(payload)(body=body, signature_hex=payload.signature_hex),
            now_ms=1_001_000,
        )

    for capabilities in (["bad token"], ["chat", "chat"], [7]):
        body = json.loads(json.dumps(payload.body))
        body["capabilities"] = capabilities
        with pytest.raises(ValueError, match="capability"):
            verify_bootstrap(
                type(payload)(body=body, signature_hex=payload.signature_hex),
                now_ms=1_001_000,
            )


def test_route_bootstrap_rejects_noncanonical_json_base64_and_duplicate_fields():
    payload = _sample_payload()
    noncanonical = json.dumps(payload.to_dict()).encode("utf-8")
    with pytest.raises(ValueError, match="canonical encoding"):
        decode_bootstrap("OLRB1." + rb._b64u(noncanonical), now_ms=1_001_000)

    with pytest.raises(ValueError, match="base64url"):
        decode_bootstrap(encode_bootstrap(payload) + "=", now_ms=1_001_000)

    duplicate = b'{"body":{},"body":{},"signature":""}'
    with pytest.raises(ValueError, match="invalid bootstrap JSON"):
        decode_bootstrap("OLRB1." + rb._b64u(duplicate), now_ms=1_001_000)


def test_route_bootstrap_rejects_truncated_or_trailed_compressed_streams():
    payload = _sample_payload()
    compact = encode_bootstrap_compact(payload)
    assert compact.startswith("OLRZ1.")
    compressed = rb._b64u_decode(compact.split(".", 1)[1])

    with pytest.raises(ValueError, match="compressed"):
        decode_bootstrap(
            "OLRZ1." + rb._b64u(compressed[:-1]),
            now_ms=1_001_000,
        )
    with pytest.raises(ValueError, match="compressed"):
        decode_bootstrap(
            "OLRZ1." + rb._b64u(compressed + b"trailing"),
            now_ms=1_001_000,
        )


def test_route_bootstrap_rejects_noncanonical_hex_and_nonfinite_metadata():
    payload = _sample_payload()
    with pytest.raises(ValueError, match="lowercase hex"):
        verify_bootstrap(
            type(payload)(body=payload.body, signature_hex=payload.signature_hex.upper()),
            now_ms=1_001_000,
        )
    with pytest.raises(ValueError, match="finite"):
        make_route_bootstrap(
            identity=_identity(),
            endpoints=[
                RouteEndpointHint(
                    kind="lan",
                    address="10.0.0.4",
                    port=17117,
                    metadata={"metric": float("nan")},
                )
            ],
        )
