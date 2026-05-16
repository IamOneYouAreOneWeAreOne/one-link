from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import identity_dag as idag
from one_link import personal_device_mesh as pdm


def _gen_ed25519():
    priv = Ed25519PrivateKey.generate()
    return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()


def _device(root_seed: bytes, root_pub: bytes, kind: str, label: str):
    seed, pub = _gen_ed25519()
    cert = idag.encode_device_cert(
        root_priv_seed=root_seed,
        root_pub=root_pub,
        device_pub=pub,
        device_kind=kind,
        added_ms=1000,
    )
    return seed, pdm.MeshDevice(
        root_pub=root_pub,
        device_pub=pub,
        device_kind=kind,
        label=label,
        cert=cert,
    )


def test_presence_book_converges_by_sequence_then_timestamp():
    _, pub = _gen_ed25519()
    book = pdm.PresenceBook()
    older = pdm.DevicePresence(pub, "awake", updated_ms=200, sequence=1)
    newer_seq = pdm.DevicePresence(pub, "asleep", updated_ms=100, sequence=2)
    stale = pdm.DevicePresence(pub, "dormant", updated_ms=999, sequence=1)

    book.merge(older)
    book.merge(newer_seq)
    book.merge(stale)

    assert book.get(pub) == newer_seq


def test_choose_self_mesh_prefers_awake_high_quality_device():
    root_seed, root_pub = _gen_ed25519()
    _, phone = _device(root_seed, root_pub, "phone-ios", "Phone")
    _, laptop = _device(root_seed, root_pub, "laptop-windows", "Laptop")
    now = 1_000_000
    presence = [
        pdm.DevicePresence(
            phone.device_pub,
            "asleep",
            updated_ms=now - 2_000,
            sequence=4,
            battery_pct=80,
            network="wifi",
            free_bytes=200_000_000,
            route="self_wifi_phone",
        ),
        pdm.DevicePresence(
            laptop.device_pub,
            "awake",
            updated_ms=now - 1_000,
            sequence=5,
            battery_pct=70,
            network="ethernet",
            free_bytes=900_000_000,
            bandwidth_bps=700_000_000,
            latency_ms=15,
            route="self_lan_laptop",
        ),
    ]

    decision = pdm.choose_self_mesh_target(
        [phone, laptop],
        presence,
        pdm.DeliveryIntent(kind="receive_friend_message", size_bytes=10_000),
        now_ms=now,
    )

    assert decision.ready
    assert decision.target == laptop
    assert decision.route == "self_lan_laptop"
    assert any("awake" in fact for fact in decision.facts)


def test_choose_self_mesh_rejects_revoked_and_storage_starved_devices():
    root_seed, root_pub = _gen_ed25519()
    _, phone = _device(root_seed, root_pub, "phone-ios", "Phone")
    _, laptop = _device(root_seed, root_pub, "laptop-windows", "Laptop")
    phone = pdm.MeshDevice(
        root_pub=phone.root_pub,
        device_pub=phone.device_pub,
        device_kind=phone.device_kind,
        label=phone.label,
        cert=phone.cert,
        revoked=True,
    )
    now = 2_000_000
    decision = pdm.choose_self_mesh_target(
        [phone, laptop],
        [
            pdm.DevicePresence(
                phone.device_pub,
                "awake",
                updated_ms=now,
                free_bytes=10_000_000_000,
                network="ethernet",
            ),
            pdm.DevicePresence(
                laptop.device_pub,
                "awake",
                updated_ms=now,
                free_bytes=10,
                network="ethernet",
            ),
        ],
        pdm.DeliveryIntent(
            kind="remote_send_file",
            size_bytes=50_000_000,
            require_awake=True,
        ),
        now_ms=now,
    )

    assert not decision.ready
    reasons = {r["label"]: r["reason"] for r in decision.rejected}
    assert reasons["Phone"] == "revoked"
    assert reasons["Laptop"] == "insufficient_storage"


def test_choose_self_mesh_rejects_guardian_frozen_device():
    root_seed, root_pub = _gen_ed25519()
    _, phone = _device(root_seed, root_pub, "phone-ios", "Phone")
    phone = pdm.MeshDevice(
        root_pub=phone.root_pub,
        device_pub=phone.device_pub,
        device_kind=phone.device_kind,
        label=phone.label,
        cert=phone.cert,
        safety_state="frozen",
    )
    now = 2_500_000
    decision = pdm.choose_self_mesh_target(
        [phone],
        [pdm.DevicePresence(phone.device_pub, "awake", updated_ms=now, network="wifi")],
        pdm.DeliveryIntent(kind="remote_send_file"),
        now_ms=now,
    )

    assert not decision.ready
    assert decision.rejected[0]["reason"] == "guardian_frozen"


def test_choose_specific_target_ignores_better_non_target():
    root_seed, root_pub = _gen_ed25519()
    _, phone = _device(root_seed, root_pub, "phone-ios", "Phone")
    _, laptop = _device(root_seed, root_pub, "laptop-windows", "Laptop")
    now = 3_000_000

    decision = pdm.choose_self_mesh_target(
        [phone, laptop],
        [
            pdm.DevicePresence(phone.device_pub, "awake", updated_ms=now, network="wifi"),
            pdm.DevicePresence(
                laptop.device_pub,
                "awake",
                updated_ms=now,
                network="ethernet",
                bandwidth_bps=1_000_000_000,
            ),
        ],
        pdm.DeliveryIntent(
            kind="pull_manifest",
            target_device_pub=phone.device_pub,
        ),
        now_ms=now,
    )

    assert decision.ready
    assert decision.target == phone
    assert any(r["reason"] == "not_requested_target" for r in decision.rejected)


def test_remote_instruction_sign_verify_round_trip():
    root_seed, root_pub = _gen_ed25519()
    phone_seed, phone = _device(root_seed, root_pub, "phone-ios", "Phone")
    _, laptop = _device(root_seed, root_pub, "laptop-windows", "Laptop")
    wire = pdm.sign_remote_instruction(
        controller_device_seed=phone_seed,
        controller_cert=phone.cert or b"",
        target_device_pub=laptop.device_pub,
        action="send_file_from_device",
        scope={
            "recipient_fp": "abc123",
            "path_hash": "sha256:deadbeef",
            "max_bytes": 100_000,
        },
        created_ms=10_000,
        expires_ms=20_000,
        nonce=b"0" * 16,
    )

    parsed = pdm.verify_remote_instruction(
        wire,
        expected_root_pub=root_pub,
        expected_target_device_pub=laptop.device_pub,
        now_ms=15_000,
    )

    assert parsed.controller_device_pub == phone.device_pub
    assert parsed.target_device_pub == laptop.device_pub
    assert parsed.action == "send_file_from_device"
    assert parsed.scope["max_bytes"] == 100_000


def test_remote_instruction_rejects_tampered_scope():
    root_seed, root_pub = _gen_ed25519()
    phone_seed, phone = _device(root_seed, root_pub, "phone-ios", "Phone")
    _, laptop = _device(root_seed, root_pub, "laptop-windows", "Laptop")
    body = json.loads(pdm.sign_remote_instruction(
        controller_device_seed=phone_seed,
        controller_cert=phone.cert or b"",
        target_device_pub=laptop.device_pub,
        action="send_file_from_device",
        scope={"max_bytes": 100},
        created_ms=10_000,
        expires_ms=20_000,
        nonce=b"1" * 16,
    ).decode("utf-8"))
    body["scope"]["max_bytes"] = 999_999

    with pytest.raises(ValueError, match="command_id|signature"):
        pdm.verify_remote_instruction(
            body,
            expected_root_pub=root_pub,
            expected_target_device_pub=laptop.device_pub,
            now_ms=15_000,
        )


def test_remote_instruction_rejects_wrong_target_expiry_and_replay():
    root_seed, root_pub = _gen_ed25519()
    phone_seed, phone = _device(root_seed, root_pub, "phone-ios", "Phone")
    _, laptop = _device(root_seed, root_pub, "laptop-windows", "Laptop")
    _, tablet = _device(root_seed, root_pub, "tablet-android", "Tablet")
    wire = pdm.sign_remote_instruction(
        controller_device_seed=phone_seed,
        controller_cert=phone.cert or b"",
        target_device_pub=laptop.device_pub,
        action="pull_file_manifest",
        scope={"path_hash": "sha256:cafe"},
        created_ms=10_000,
        expires_ms=20_000,
        nonce=b"2" * 16,
    )

    with pytest.raises(ValueError, match="target"):
        pdm.verify_remote_instruction(
            wire,
            expected_root_pub=root_pub,
            expected_target_device_pub=tablet.device_pub,
            now_ms=15_000,
        )

    with pytest.raises(ValueError, match="expired"):
        pdm.verify_remote_instruction(
            wire,
            expected_root_pub=root_pub,
            expected_target_device_pub=laptop.device_pub,
            now_ms=20_001,
        )

    seen: set[str] = set()
    pdm.verify_remote_instruction(
        wire,
        expected_root_pub=root_pub,
        expected_target_device_pub=laptop.device_pub,
        now_ms=15_000,
        seen_command_ids=seen,
    )
    with pytest.raises(ValueError, match="replayed"):
        pdm.verify_remote_instruction(
            wire,
            expected_root_pub=root_pub,
            expected_target_device_pub=laptop.device_pub,
            now_ms=15_000,
            seen_command_ids=seen,
        )


def test_remote_instruction_rejects_foreign_root():
    root_seed, root_pub = _gen_ed25519()
    other_root_pub = _gen_ed25519()[1]
    phone_seed, phone = _device(root_seed, root_pub, "phone-ios", "Phone")
    _, laptop = _device(root_seed, root_pub, "laptop-windows", "Laptop")
    wire = pdm.sign_remote_instruction(
        controller_device_seed=phone_seed,
        controller_cert=phone.cert or b"",
        target_device_pub=laptop.device_pub,
        action="pull_file_manifest",
        scope={"path_hash": "sha256:cafe"},
        created_ms=10_000,
        expires_ms=20_000,
        nonce=b"3" * 16,
    )

    with pytest.raises(ValueError, match="root"):
        pdm.verify_remote_instruction(
            wire,
            expected_root_pub=other_root_pub,
            expected_target_device_pub=laptop.device_pub,
            now_ms=15_000,
        )
