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
    body = json.loads(
        pdm.sign_remote_instruction(
            controller_device_seed=phone_seed,
            controller_cert=phone.cert or b"",
            target_device_pub=laptop.device_pub,
            action="send_file_from_device",
            scope={"max_bytes": 100},
            created_ms=10_000,
            expires_ms=20_000,
            nonce=b"1" * 16,
        ).decode("utf-8")
    )
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


def _remote_instruction_fixture():
    root_seed, root_pub = _gen_ed25519()
    controller_seed, controller = _device(
        root_seed,
        root_pub,
        "phone-ios",
        "Phone",
    )
    _, target = _device(root_seed, root_pub, "laptop-windows", "Laptop")
    wire = pdm.sign_remote_instruction(
        controller_device_seed=controller_seed,
        controller_cert=controller.cert or b"",
        target_device_pub=target.device_pub,
        action="pull_file_manifest",
        scope={"path": "C:/safe/file.txt", "max_bytes": 1234},
        created_ms=10_000,
        expires_ms=20_000,
        nonce=b"n" * 16,
    )
    return root_pub, controller_seed, controller, target, wire


def test_remote_instruction_signer_binds_private_key_to_certificate():
    root_pub, _, controller, target, _ = _remote_instruction_fixture()
    unrelated_seed, _ = _gen_ed25519()

    with pytest.raises(ValueError, match="does not match controller_cert"):
        pdm.sign_remote_instruction(
            controller_device_seed=unrelated_seed,
            controller_cert=controller.cert or b"",
            target_device_pub=target.device_pub,
            action="pull_file_manifest",
            scope={"path": "C:/safe/file.txt"},
            created_ms=10_000,
            expires_ms=20_000,
            nonce=b"n" * 16,
        )

    assert len(root_pub) == 32


def test_remote_instruction_lifetime_is_contained_by_controller_certificate():
    root_seed, root_pub = _gen_ed25519()
    controller_seed, controller_pub = _gen_ed25519()
    _, target_pub = _gen_ed25519()
    future_cert = idag.encode_device_cert(
        root_priv_seed=root_seed,
        root_pub=root_pub,
        device_pub=controller_pub,
        device_kind="phone",
        added_ms=12_000,
    )
    with pytest.raises(ValueError, match="predates controller cert"):
        pdm.sign_remote_instruction(
            controller_device_seed=controller_seed,
            controller_cert=future_cert,
            target_device_pub=target_pub,
            action="pull_file_manifest",
            scope={"path": "C:/safe/file.txt"},
            created_ms=10_000,
            expires_ms=20_000,
            nonce=b"n" * 16,
        )

    now = pdm._now_ms()
    expiring_cert = idag.encode_device_cert(
        root_priv_seed=root_seed,
        root_pub=root_pub,
        device_pub=controller_pub,
        device_kind="phone",
        added_ms=now - 1_000,
        expires_ms=now + 5_000,
    )
    with pytest.raises(ValueError, match="outlives controller cert"):
        pdm.sign_remote_instruction(
            controller_device_seed=controller_seed,
            controller_cert=expiring_cert,
            target_device_pub=target_pub,
            action="pull_file_manifest",
            scope={"path": "C:/safe/file.txt"},
            created_ms=now,
            expires_ms=now + 10_000,
            nonce=b"n" * 16,
        )


@pytest.mark.parametrize(
    ("override", "match"),
    [
        ({"action": "Pull_File"}, "action"),
        ({"created_ms": True}, "created_ms"),
        ({"expires_ms": "20000"}, "expires_ms"),
        ({"nonce": b"short"}, "nonce"),
        ({"scope": {"ratio": 1.5}}, "floating-point"),
        ({"scope": {"bad": "line\nbreak"}}, "control character"),
        (
            {"scope": {"huge": "x" * 4096}},
            "character limit|byte limit|too large",
        ),
    ],
)
def test_remote_instruction_signer_rejects_ambiguous_or_unbounded_values(
    override,
    match,
):
    _, controller_seed, controller, target, _ = _remote_instruction_fixture()
    kwargs = {
        "controller_device_seed": controller_seed,
        "controller_cert": controller.cert or b"",
        "target_device_pub": target.device_pub,
        "action": "pull_file_manifest",
        "scope": {"path": "C:/safe/file.txt"},
        "created_ms": 10_000,
        "expires_ms": 20_000,
        "nonce": b"n" * 16,
    }
    kwargs.update(override)

    with pytest.raises(ValueError, match=match):
        pdm.sign_remote_instruction(**kwargs)


def test_remote_instruction_wire_is_exact_bounded_canonical_json():
    root_pub, _, _, target, wire = _remote_instruction_fixture()
    body = json.loads(wire)

    with pytest.raises(ValueError, match="schema|field count"):
        pdm.verify_remote_instruction(
            {**body, "unexpected": True},
            expected_root_pub=root_pub,
            expected_target_device_pub=target.device_pub,
            now_ms=15_000,
        )
    missing = dict(body)
    missing.pop("nonce_b64")
    with pytest.raises(ValueError, match="schema|field count"):
        pdm.verify_remote_instruction(
            missing,
            expected_root_pub=root_pub,
            expected_target_device_pub=target.device_pub,
            now_ms=15_000,
        )
    noncanonical = json.dumps(body, indent=2).encode()
    with pytest.raises(ValueError, match="JSON is not canonical"):
        pdm.verify_remote_instruction(
            noncanonical,
            expected_root_pub=root_pub,
            expected_target_device_pub=target.device_pub,
            now_ms=15_000,
        )
    duplicate = b'{"action":"duplicate",' + wire[1:]
    with pytest.raises(ValueError, match="duplicate JSON field"):
        pdm.verify_remote_instruction(
            duplicate,
            expected_root_pub=root_pub,
            expected_target_device_pub=target.device_pub,
            now_ms=15_000,
        )
    with pytest.raises(ValueError, match="wire size limit"):
        pdm.verify_remote_instruction(
            b"{" + b" " * pdm.MAX_REMOTE_INSTRUCTION_BYTES,
            expected_root_pub=root_pub,
            expected_target_device_pub=target.device_pub,
            now_ms=15_000,
        )


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("v", True, "version must be an integer"),
        ("created_ms", "10000", "created_ms must be an integer"),
        ("root_pub_b64", "A" * 43 + "=", "canonical base64url|size limit"),
        ("root_pub_b64", "AA", "decode to 32 bytes"),
        ("nonce_b64", "AA", "decode to 16 bytes"),
        ("signature_b64", "AA", "decode to 64 bytes"),
        ("command_id", "A" * 64, "lowercase SHA-256"),
    ],
)
def test_remote_instruction_rejects_type_length_and_encoding_aliases(
    field,
    value,
    match,
):
    root_pub, _, _, target, wire = _remote_instruction_fixture()
    body = json.loads(wire)
    body[field] = value

    with pytest.raises(ValueError, match=match):
        pdm.verify_remote_instruction(
            body,
            expected_root_pub=root_pub,
            expected_target_device_pub=target.device_pub,
            now_ms=15_000,
        )


def test_invalid_signature_never_consumes_replay_capacity(monkeypatch):
    root_pub, _, _, target, wire = _remote_instruction_fixture()
    body = json.loads(wire)
    invalid_signature = b"x" * 64
    body["signature_b64"] = pdm._b64u(invalid_signature)
    unsigned = {
        key: value for key, value in body.items() if key not in {"signature_b64", "command_id"}
    }
    body["command_id"] = pdm._stable_command_id(unsigned, invalid_signature)
    seen: set[str] = set()

    with pytest.raises(ValueError, match="signature invalid"):
        pdm.verify_remote_instruction(
            body,
            expected_root_pub=root_pub,
            expected_target_device_pub=target.device_pub,
            now_ms=15_000,
            seen_command_ids=seen,
        )
    assert seen == set()

    monkeypatch.setattr(pdm, "MAX_IN_MEMORY_REPLAY_IDS", 0)
    with pytest.raises(ValueError, match="replay cache is full"):
        pdm.verify_remote_instruction(
            wire,
            expected_root_pub=root_pub,
            expected_target_device_pub=target.device_pub,
            now_ms=15_000,
            seen_command_ids=seen,
        )
    assert seen == set()


def test_remote_instruction_expiry_boundary_is_exclusive():
    root_pub, _, _, target, wire = _remote_instruction_fixture()

    with pytest.raises(ValueError, match="expired"):
        pdm.verify_remote_instruction(
            wire,
            expected_root_pub=root_pub,
            expected_target_device_pub=target.device_pub,
            now_ms=20_000,
        )


def test_presence_equal_clock_tie_converges_independently_of_merge_order():
    _, pub = _gen_ed25519()
    awake = pdm.DevicePresence(pub, "awake", updated_ms=100, sequence=7)
    asleep = pdm.DevicePresence(pub, "asleep", updated_ms=100, sequence=7)
    first = pdm.PresenceBook([awake, asleep]).get(pub)
    second = pdm.PresenceBook([asleep, awake]).get(pub)

    assert first == second


def test_presence_rejects_non_finite_metrics_and_stale_or_future_facts():
    root_seed, root_pub = _gen_ed25519()
    _, device = _device(root_seed, root_pub, "laptop-windows", "Laptop")
    with pytest.raises(ValueError, match="finite"):
        pdm.DevicePresence(
            device.device_pub,
            "awake",
            updated_ms=100,
            latency_ms=float("nan"),
        )
    with pytest.raises(ValueError, match="finite"):
        pdm.DevicePresence(
            device.device_pub,
            "awake",
            updated_ms=100,
            bandwidth_bps=-1,
        )

    stale = pdm.choose_self_mesh_target(
        [device],
        [pdm.DevicePresence(device.device_pub, "awake", updated_ms=1)],
        pdm.DeliveryIntent(kind="send"),
        now_ms=pdm.MAX_PRESENCE_AGE_MS + 2,
    )
    assert stale.rejected[0]["reason"] == "presence_stale"
    future = pdm.choose_self_mesh_target(
        [device],
        [
            pdm.DevicePresence(
                device.device_pub,
                "awake",
                updated_ms=100_000,
            )
        ],
        pdm.DeliveryIntent(kind="send"),
        now_ms=1,
    )
    assert future.rejected[0]["reason"] == "presence_from_future"
    disconnected = pdm.choose_self_mesh_target(
        [device],
        [
            pdm.DevicePresence(
                device.device_pub,
                "awake",
                updated_ms=100,
                network="offline",
            )
        ],
        pdm.DeliveryIntent(kind="send"),
        now_ms=100,
    )
    assert disconnected.rejected[0]["reason"] == "network_offline"


def test_mesh_router_rejects_mixed_roots_and_duplicate_devices():
    root_seed, root_pub = _gen_ed25519()
    _, first = _device(root_seed, root_pub, "laptop", "First")
    other_seed, other_pub = _gen_ed25519()
    _, second = _device(other_seed, other_pub, "phone", "Second")
    facts = [
        pdm.DevicePresence(first.device_pub, "awake", updated_ms=100),
        pdm.DevicePresence(second.device_pub, "awake", updated_ms=100),
    ]

    with pytest.raises(ValueError, match="mix identity roots"):
        pdm.choose_self_mesh_target(
            [first, second],
            facts,
            pdm.DeliveryIntent(kind="send"),
            now_ms=100,
        )
    with pytest.raises(ValueError, match="duplicate device"):
        pdm.choose_self_mesh_target(
            [first, first],
            facts,
            pdm.DeliveryIntent(kind="send"),
            now_ms=100,
        )


def test_mesh_models_reject_type_confusion_and_certificate_metadata_aliases():
    root_seed, root_pub = _gen_ed25519()
    _, device = _device(root_seed, root_pub, "laptop", "Laptop")

    with pytest.raises(ValueError, match="state must be text"):
        pdm.DevicePresence(device.device_pub, [], updated_ms=100)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="updated_ms must be an integer"):
        pdm.DevicePresence(device.device_pub, "awake", updated_ms=True)
    with pytest.raises(ValueError, match="finite"):
        pdm.DevicePresence(
            device.device_pub,
            "awake",
            updated_ms=100,
            bandwidth_bps=10**10_000,
        )
    with pytest.raises(ValueError, match="size_bytes must be an integer"):
        pdm.DeliveryIntent(kind="send", size_bytes=True)
    with pytest.raises(ValueError, match="device_kind does not match"):
        pdm.MeshDevice(
            root_pub=root_pub,
            device_pub=device.device_pub,
            device_kind="forged-kind",
            cert=device.cert,
        )


def test_presence_book_fails_closed_at_resource_capacity(monkeypatch):
    _, first_pub = _gen_ed25519()
    _, second_pub = _gen_ed25519()
    monkeypatch.setattr(pdm, "MAX_MESH_DEVICES", 1)
    book = pdm.PresenceBook([pdm.DevicePresence(first_pub, "awake", updated_ms=100)])

    with pytest.raises(ValueError, match="device limit"):
        book.merge(pdm.DevicePresence(second_pub, "awake", updated_ms=100))
