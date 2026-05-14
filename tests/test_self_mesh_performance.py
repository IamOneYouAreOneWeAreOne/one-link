from __future__ import annotations

import time

from one_link.personal_device_mesh import (
    DeliveryIntent,
    DevicePresence,
    MeshDevice,
    PresenceBook,
    choose_self_mesh_target,
)
from one_link.self_mesh_enrollment import (
    MeshRoot,
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
