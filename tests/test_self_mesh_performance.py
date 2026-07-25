from __future__ import annotations

import json
import time

import pytest

from one_link.personal_device_mesh import (
    DeliveryIntent,
    DevicePresence,
    MeshDevice,
    PresenceBook,
    choose_self_mesh_target,
)
from one_link.self_mesh_enrollment import (
    MAX_ENROLLMENT_INVITE_CHARS,
    MeshRoot,
    b64u,
    b64u_decode,
    build_enrollment_invite,
    mint_device_cert,
    parse_enrollment_invite,
)


def test_self_mesh_route_selection_stays_sub_millisecond_scale():
    root = b"r" * 32
    devices = [
        MeshDevice(
            root_pub=root,
            device_pub=i.to_bytes(2, "big") + b"d" * 30,
            device_kind="laptop",
            label=f"Device {i}",
        )
        for i in range(256)
    ]
    presence = PresenceBook(
        DevicePresence(
            device_pub=d.device_pub,
            state="awake" if i % 3 else "asleep",
            sequence=i,
            updated_ms=10_000 + i,
            network="ethernet" if i % 5 else "wifi",
            free_bytes=10_000_000 + i,
            latency_ms=float(i % 40),
            bandwidth_bps=100_000_000 + i,
        )
        for i, d in enumerate(devices)
    )

    started = time.perf_counter()
    for _ in range(100):
        decision = choose_self_mesh_target(
            devices,
            presence,
            DeliveryIntent(kind="send", size_bytes=4096),
            now_ms=20_000,
        )
        assert decision.ready
    elapsed = time.perf_counter() - started
    assert elapsed < 0.25


def test_self_mesh_enrollment_invite_round_trips():
    root = MeshRoot.create()
    device_pub = b"d" * 32
    cert = mint_device_cert(
        root_seed=root.root_seed,
        root_pub=root.root_pub,
        device_pub=device_pub,
        device_kind="phone",
    )
    invite = build_enrollment_invite(cert=cert, label="Phone")
    parsed = parse_enrollment_invite(invite["token"])

    assert invite["deep_link"].startswith("one-link://self-mesh/enroll?")
    assert parsed["label"] == "Phone"
    assert parsed["device_kind"] == "phone"


def _enrollment_invite() -> dict:
    root = MeshRoot.create()
    cert = mint_device_cert(
        root_seed=root.root_seed,
        root_pub=root.root_pub,
        device_pub=b"p" * 32,
        device_kind="phone",
    )
    return build_enrollment_invite(cert=cert, label="Phone")


def test_enrollment_invite_rejects_mutable_security_fields():
    invite = _enrollment_invite()
    body = json.loads(b64u_decode(invite["token"]).decode("utf-8"))
    body["device_kind"] = "controller"
    tampered = b64u(json.dumps(body, separators=(",", ":")).encode("utf-8"))

    with pytest.raises(ValueError, match="device kind"):
        parse_enrollment_invite(tampered)


def test_enrollment_invite_rejects_aliases_duplicates_and_oversize():
    invite = _enrollment_invite()
    with pytest.raises(ValueError, match="canonical"):
        parse_enrollment_invite(invite["token"] + "=")

    raw = b64u_decode(invite["token"]).decode("utf-8")
    duplicate = b64u(("{\"v\":1," + raw[1:]).encode("utf-8"))
    with pytest.raises(ValueError, match="duplicate invite field"):
        parse_enrollment_invite(duplicate)

    with pytest.raises(ValueError, match="size limit"):
        parse_enrollment_invite("A" * (MAX_ENROLLMENT_INVITE_CHARS + 1))


def test_enrollment_invite_rejects_ambiguous_metadata():
    invite = _enrollment_invite()
    body = json.loads(b64u_decode(invite["token"]).decode("utf-8"))

    body["created_ms"] = True
    token = b64u(json.dumps(body, separators=(",", ":")).encode("utf-8"))
    with pytest.raises(ValueError, match="created_ms"):
        parse_enrollment_invite(token)

    body["created_ms"] = 1
    body["label"] = "Phone\nspoof"
    token = b64u(json.dumps(body, separators=(",", ":")).encode("utf-8"))
    with pytest.raises(ValueError, match="control character"):
        parse_enrollment_invite(token)
