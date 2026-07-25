"""Adversarial durability, restart, and replay tests for capsule storage."""

from __future__ import annotations

import struct
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.async_capsule import AsyncCapsule, CapsuleKind
from one_link.capsule_store import (
    CapsuleConflictError,
    CapsuleRepository,
    CapsuleStoreError,
    deserialize_capsule,
    load_or_create_capsule_master_seed,
)
from one_link.frame_provenance import (
    FrameKind,
    PathClass,
    RecordingState,
    make_segment_hash,
    sign_provenance,
)
from one_link.lockbox import LockBox


ALICE = "a" * 64
MOM = "b" * 64


def _capsule(
    *,
    capsule_id: str = "capsule-durable-1",
    payload: bytes = b"opus",
    sender: str = ALICE,
    recipient: str = MOM,
    kind: CapsuleKind = CapsuleKind.VOICE_NOTE_OUTGOING,
) -> AsyncCapsule:
    provenance = sign_provenance(
        segment_hash=make_segment_hash(payload),
        device_id=sender[:8],
        frame_kind=FrameKind.REAL,
        path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
        timestamp_us=10_000_000,
        produce_confidence=1.0,
        signing_key=Ed25519PrivateKey.from_private_bytes(b"\x01" * 32),
    )
    return AsyncCapsule(
        capsule_id=capsule_id,
        call_id="call-durable-1",
        kind=kind,
        sender_master_vk_hex=sender,
        recipient_master_vk_hex=recipient,
        started_at_ms=10_000,
        finalized_at_ms=11_000,
        duration_ms=900,
        audio_payload=payload,
        audio_codec="opus",
        sample_rate_hz=48_000,
        provenance_chain=(provenance,),
        provenance_segment_sizes=(len(payload),),
        recording_state_at_conversion=RecordingState.NOT_RECORDING,
        resumable_until_ms=611_000,
        payload_hash=make_segment_hash(payload).hex(),
    )


def test_capsule_key_is_wrapped_stable_and_corruption_fails_closed(tmp_path: Path) -> None:
    lockbox = LockBox(b"k" * 32)
    first = load_or_create_capsule_master_seed(tmp_path, lockbox)
    second = load_or_create_capsule_master_seed(tmp_path, lockbox)
    assert first == second
    assert first not in (tmp_path / "capsule-master-key.bin").read_bytes()

    with pytest.raises(CapsuleStoreError, match="could not be opened"):
        load_or_create_capsule_master_seed(tmp_path, LockBox(b"x" * 32))


def test_capsule_key_loader_rejects_symbolic_link(tmp_path: Path) -> None:
    outside = tmp_path / "outside-key"
    outside.write_bytes(b"not-a-key")
    key_path = tmp_path / "capsule-master-key.bin"
    try:
        key_path.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are unavailable for this test account")
    with pytest.raises(CapsuleStoreError, match="not a regular file"):
        load_or_create_capsule_master_seed(tmp_path, LockBox(b"k" * 32))


def test_outbox_survives_restart_and_requires_exact_receipt(tmp_path: Path) -> None:
    seed = b"s" * 32
    cap = _capsule()
    first = CapsuleRepository(tmp_path / "capsules", master_seed=seed)
    stored = first.store_capsule(cap, peer_fp=MOM, direction="outbound", now_ms=100)
    assert stored.status == "pending"
    assert first.due_outbound(now_ms=100) == (stored,)
    sealed = first.sealed_root / stored.sealed_name
    raw = sealed.read_bytes()
    assert cap.audio_payload not in raw
    assert cap.capsule_id.encode() not in raw
    first.close()

    restarted = CapsuleRepository(tmp_path / "capsules", master_seed=seed)
    pending = restarted.due_outbound(now_ms=100)
    assert len(pending) == 1
    assert restarted.load_capsule(pending[0]) == cap
    with pytest.raises(CapsuleConflictError):
        restarted.mark_delivered(
            cap.capsule_id,
            peer_fp=ALICE,
            payload_hash=cap.payload_hash,
        )
    with pytest.raises(CapsuleConflictError):
        restarted.mark_delivered(
            cap.capsule_id,
            peer_fp=MOM,
            payload_hash="0" * 64,
        )
    delivered = restarted.mark_delivered(
        cap.capsule_id,
        peer_fp=MOM,
        payload_hash=cap.payload_hash,
        now_ms=200,
    )
    assert delivered.status == "delivered"
    assert restarted.mark_delivered(
        cap.capsule_id,
        peer_fp=MOM,
        payload_hash=cap.payload_hash,
        now_ms=300,
    ) == delivered
    assert restarted.due_outbound(now_ms=10_000) == ()
    restarted.close()


def test_capsule_id_replay_is_exactly_idempotent_or_rejected(tmp_path: Path) -> None:
    repo = CapsuleRepository(tmp_path / "capsules", master_seed=b"z" * 32)
    cap = _capsule()
    original = repo.store_capsule(cap, peer_fp=MOM, direction="outbound")
    assert repo.store_capsule(cap, peer_fp=MOM, direction="outbound") == original

    changed_payload = b"different"
    conflicting = _capsule(
        capsule_id=cap.capsule_id,
        payload=changed_payload,
    )
    with pytest.raises(CapsuleConflictError):
        repo.store_capsule(conflicting, peer_fp=MOM, direction="outbound")
    with pytest.raises(CapsuleConflictError):
        repo.store_capsule(cap, peer_fp=ALICE, direction="outbound")
    with pytest.raises(CapsuleConflictError):
        repo.store_capsule(cap, peer_fp=MOM, direction="inbound")
    repo.close()


def test_inbound_commit_and_staging_recovery_are_restart_safe(tmp_path: Path) -> None:
    root = tmp_path / "capsules"
    seed = b"r" * 32
    cap = _capsule(
        kind=CapsuleKind.VOICE_NOTE_INCOMING,
        sender=MOM,
        recipient=ALICE,
    )
    repo = CapsuleRepository(root, master_seed=seed)
    received = repo.store_capsule(cap, peer_fp=MOM, direction="inbound")
    assert received.status == "received"
    # Model a crash after the sealed rename and before the final status write.
    repo._db.execute(  # noqa: SLF001 - precise crash-window regression
        "UPDATE capsule_records SET status = 'staging' WHERE capsule_id = ?",
        (cap.capsule_id,),
    )
    repo.close()

    recovered = CapsuleRepository(root, master_seed=seed)
    row = recovered.get(cap.capsule_id)
    assert row is not None and row.status == "received"
    assert recovered.load_capsule(row) == cap
    recovered.close()


def test_failed_attempt_backoff_is_bounded_and_persistent(tmp_path: Path) -> None:
    repo = CapsuleRepository(tmp_path / "capsules", master_seed=b"q" * 32)
    cap = _capsule()
    repo.store_capsule(cap, peer_fp=MOM, direction="outbound", now_ms=1_000)
    failed = repo.mark_attempt_failed(
        cap.capsule_id,
        peer_fp=MOM,
        error="offline" * 200,
        now_ms=1_000,
    )
    assert failed.attempts == 1
    assert failed.next_attempt_ms == 2_000
    assert len(failed.last_error) <= 320
    assert repo.due_outbound(now_ms=1_999) == ()
    assert len(repo.due_outbound(now_ms=2_000)) == 1
    repo.close()


def test_concurrent_duplicate_save_collapses_to_one_record(tmp_path: Path) -> None:
    repo = CapsuleRepository(tmp_path / "capsules", master_seed=b"c" * 32)
    cap = _capsule()
    with ThreadPoolExecutor(max_workers=8) as pool:
        records = list(pool.map(
            lambda _: repo.store_capsule(cap, peer_fp=MOM, direction="outbound"),
            range(32),
        ))
    assert len({record.content_hash for record in records}) == 1
    assert len(repo.list_records()) == 1
    repo.close()


def test_deserializer_rejects_forged_lengths_before_body_allocation() -> None:
    with pytest.raises(ValueError, match="header length exceeds"):
        deserialize_capsule(struct.pack("!I", 0xFFFFFFFF))


def test_index_metadata_cannot_redirect_authentic_capsule_to_another_peer(
    tmp_path: Path,
) -> None:
    repo = CapsuleRepository(tmp_path / "capsules", master_seed=b"i" * 32)
    cap = _capsule(capsule_id="capsule-index-binding")
    record = repo.store_capsule(
        cap,
        peer_fp=MOM,
        direction="outbound",
    )

    # Model a same-user filesystem attacker changing only the plaintext
    # scheduler index.  The encrypted body is still authentic, but it is
    # addressed to MOM and must never be released to ALICE.
    repo._db.execute(  # noqa: SLF001 - adversarial index-corruption fixture
        "UPDATE capsule_records SET peer_fp = ? WHERE capsule_id = ?",
        (ALICE, cap.capsule_id),
    )
    redirected = repo.get(cap.capsule_id)
    assert redirected is not None and redirected.peer_fp == ALICE
    with pytest.raises(CapsuleConflictError, match="peer binding"):
        repo.load_capsule(redirected)

    # A caller also cannot create that mismatch through the public API.
    fresh = CapsuleRepository(tmp_path / "fresh", master_seed=b"j" * 32)
    with pytest.raises(CapsuleConflictError, match="peer binding"):
        fresh.store_capsule(
            cap,
            peer_fp=ALICE,
            direction="outbound",
        )
    fresh.close()
    # Restore solely so close/reopen recovery is not part of this test.
    repo._db.execute(  # noqa: SLF001
        "UPDATE capsule_records SET peer_fp = ? WHERE capsule_id = ?",
        (record.peer_fp, cap.capsule_id),
    )
    repo.close()


def test_repository_control_values_reject_type_confusion_and_overflow(
    tmp_path: Path,
) -> None:
    repo = CapsuleRepository(tmp_path / "capsules", master_seed=b"t" * 32)
    cap = _capsule(capsule_id="capsule-control-bounds")
    for invalid_now in (True, -1, 2**63, 1.5):
        with pytest.raises(ValueError, match="63-bit integer"):
            repo.store_capsule(
                cap,
                peer_fp=MOM,
                direction="outbound",
                now_ms=invalid_now,  # type: ignore[arg-type]
            )
    repo.store_capsule(cap, peer_fp=MOM, direction="outbound", now_ms=2**63 - 1)
    saturated = repo.mark_attempt_failed(
        cap.capsule_id,
        peer_fp=MOM,
        error="offline",
        now_ms=2**63 - 1,
    )
    assert saturated.next_attempt_ms == 2**63 - 1
    for invalid_limit in (True, 1.5, 0, 65):
        with pytest.raises(ValueError, match="limit"):
            repo.due_outbound(limit=invalid_limit)  # type: ignore[arg-type]
    repo.close()
