from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from one_link.transfer_safety import (
    InboundTransferReservationLedger,
    TIB,
    TransferAdmissionContext,
    TransferAdmissionPolicy,
    _disk_free_bytes,
    classify_file_risk,
    evaluate_transfer_admission,
    is_active_content_file,
    known_bytes_from_chunks,
    same_storage_volume,
)


def test_admission_rejects_absurd_declared_size(tmp_path: Path):
    decision = evaluate_transfer_admission(
        name="impossible.bin",
        size=10_000 * TIB,
        peer_fp="aa" * 32,
        policy=TransferAdmissionPolicy(max_declared_bytes=16 * TIB),
        context=TransferAdmissionContext(incoming_dir=tmp_path),
    )

    assert decision.ok is False
    assert decision.reason == "declared_size_too_large"


def test_admission_rejects_when_disk_cannot_keep_reserve(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("one_link.transfer_safety._disk_free_bytes", lambda _p: 100)

    decision = evaluate_transfer_admission(
        name="large.mov",
        size=1_000,
        peer_fp="aa" * 32,
        policy=TransferAdmissionPolicy(
            max_declared_bytes=16 * TIB,
            min_free_reserve_bytes=50,
            free_reserve_ratio=0,
        ),
        context=TransferAdmissionContext(incoming_dir=tmp_path),
    )

    assert decision.ok is False
    assert decision.reason == "insufficient_disk_space"
    assert decision.required_free_bytes == 1050


def test_admission_does_not_treat_cache_hits_as_destination_allocation(
    tmp_path: Path, monkeypatch,
):
    monkeypatch.setattr("one_link.transfer_safety._disk_free_bytes", lambda _p: 2_000)

    decision = evaluate_transfer_admission(
        name="mostly-known.mov",
        size=1_000,
        peer_fp="aa" * 32,
        policy=TransferAdmissionPolicy(
            max_declared_bytes=16 * TIB,
            min_free_reserve_bytes=50,
            free_reserve_ratio=0,
        ),
        context=TransferAdmissionContext(
            incoming_dir=tmp_path,
            already_known_bytes=900,
        ),
    )

    assert decision.ok is True
    assert decision.reserve_bytes == 1_000
    assert decision.already_known_bytes == 900


def test_admission_only_deducts_verified_destination_allocation(
    tmp_path: Path, monkeypatch,
):
    monkeypatch.setattr("one_link.transfer_safety._disk_free_bytes", lambda _p: 200)

    decision = evaluate_transfer_admission(
        name="resumed.mov",
        size=1_000,
        peer_fp="aa" * 32,
        policy=TransferAdmissionPolicy(
            min_free_reserve_bytes=50,
            free_reserve_ratio=0,
        ),
        context=TransferAdmissionContext(
            incoming_dir=tmp_path,
            already_allocated_bytes=900,
        ),
    )

    assert decision.ok is True
    assert decision.reserve_bytes == 100


def test_admission_reserves_destination_and_missing_cache_copies(
    tmp_path: Path, monkeypatch,
):
    monkeypatch.setattr("one_link.transfer_safety._disk_free_bytes", lambda _p: 2_000)

    decision = evaluate_transfer_admission(
        name="dual-materialization.bin",
        size=1_000,
        peer_fp="aa" * 32,
        policy=TransferAdmissionPolicy(
            min_free_reserve_bytes=100,
            free_reserve_ratio=0,
        ),
        context=TransferAdmissionContext(
            incoming_dir=tmp_path,
            already_allocated_bytes=200,
            additional_storage_bytes=600,
        ),
    )

    assert decision.ok is True
    assert decision.reserve_bytes == 1_400
    assert decision.additional_storage_bytes == 600


def test_admission_subtracts_all_prior_disk_promises(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("one_link.transfer_safety._disk_free_bytes", lambda _p: 1_000)

    decision = evaluate_transfer_admission(
        name="second.bin",
        size=400,
        peer_fp="aa" * 32,
        policy=TransferAdmissionPolicy(
            min_free_reserve_bytes=100,
            free_reserve_ratio=0,
        ),
        context=TransferAdmissionContext(
            incoming_dir=tmp_path,
            reserved_disk_bytes=600,
        ),
    )

    assert decision.ok is False
    assert decision.reason == "insufficient_disk_space"
    assert decision.required_free_bytes == 1_100


def test_admission_rejects_per_peer_transfer_quota(tmp_path: Path):
    decision = evaluate_transfer_admission(
        name="another.bin",
        size=1,
        peer_fp="aa" * 32,
        policy=TransferAdmissionPolicy(max_active_inbound_transfers_per_peer=2),
        context=TransferAdmissionContext(
            incoming_dir=tmp_path,
            active_inbound_count_for_peer=2,
        ),
    )

    assert decision.ok is False
    assert decision.reason == "peer_inbound_transfer_quota"


def test_admission_rejects_global_transfer_and_byte_quotas(tmp_path: Path):
    transfer_limit = evaluate_transfer_admission(
        name="busy.bin",
        size=1,
        peer_fp="aa" * 32,
        policy=TransferAdmissionPolicy(max_active_inbound_transfers=2),
        context=TransferAdmissionContext(
            incoming_dir=tmp_path,
            active_inbound_count=2,
        ),
    )
    byte_limit = evaluate_transfer_admission(
        name="full.bin",
        size=60,
        peer_fp="bb" * 32,
        policy=TransferAdmissionPolicy(max_active_inbound_bytes=100),
        context=TransferAdmissionContext(
            incoming_dir=tmp_path,
            active_inbound_bytes=50,
        ),
    )

    assert transfer_limit.reason == "global_inbound_transfer_quota"
    assert byte_limit.reason == "global_inbound_byte_quota"


def test_admission_requires_exact_json_integer_sizes(tmp_path: Path):
    policy = TransferAdmissionPolicy()
    context = TransferAdmissionContext(incoming_dir=tmp_path)

    for spoofed in (True, False, 1.5, "1024"):
        decision = evaluate_transfer_admission(
            name="spoof.bin",
            size=spoofed,
            peer_fp="aa" * 32,
            policy=policy,
            context=context,
        )
        assert decision.reason == "invalid_size", spoofed


def test_reservation_ledger_is_atomic_idempotent_and_owner_bound(
    tmp_path: Path, monkeypatch,
):
    monkeypatch.setattr("one_link.transfer_safety._disk_free_bytes", lambda _p: 2_000)
    ledger = InboundTransferReservationLedger(tmp_path)
    policy = TransferAdmissionPolicy(
        min_free_reserve_bytes=100,
        free_reserve_ratio=0,
        max_active_inbound_transfers_per_peer=2,
        max_active_inbound_transfers=2,
    )

    first = ledger.reserve(
        reservation_id="in:one",
        name="one.bin",
        size=700,
        peer_fp="aa",
        policy=policy,
    )
    retry = ledger.reserve(
        reservation_id="in:one",
        name="renamed.bin",
        size=700,
        peer_fp="aa",
        policy=policy,
    )
    conflict = ledger.reserve(
        reservation_id="in:one",
        name="one.bin",
        size=700,
        peer_fp="bb",
        policy=policy,
    )
    second = ledger.reserve(
        reservation_id="in:two",
        name="two.bin",
        size=700,
        peer_fp="bb",
        policy=policy,
    )
    third = ledger.reserve(
        reservation_id="in:three",
        name="three.bin",
        size=1,
        peer_fp="cc",
        policy=policy,
    )

    assert first.ok and not first.reservation_reused
    assert retry.ok and retry.reservation_reused
    assert conflict.reason == "reservation_conflict"
    assert second.ok
    assert third.reason == "global_inbound_transfer_quota"
    assert len(ledger.snapshot()) == 2


def test_reservation_ledger_consumes_and_releases_disk_promises(
    tmp_path: Path, monkeypatch,
):
    monkeypatch.setattr("one_link.transfer_safety._disk_free_bytes", lambda _p: 1_000)
    ledger = InboundTransferReservationLedger(tmp_path)
    policy = TransferAdmissionPolicy(
        min_free_reserve_bytes=100,
        free_reserve_ratio=0,
    )
    assert ledger.reserve(
        reservation_id="in:one",
        name="one.bin",
        size=700,
        peer_fp="aa",
        policy=policy,
    ).ok
    blocked = ledger.reserve(
        reservation_id="in:two",
        name="two.bin",
        size=300,
        peer_fp="bb",
        policy=policy,
    )
    assert blocked.reason == "insufficient_disk_space"

    assert ledger.consume("in:one", 400) == 300
    admitted = ledger.reserve(
        reservation_id="in:two",
        name="two.bin",
        size=300,
        peer_fp="bb",
        policy=policy,
    )
    assert admitted.ok
    assert ledger.release("in:one", peer_fp="bb") is False
    assert ledger.release("in:one", peer_fp="aa") is True
    assert {item.reservation_id for item in ledger.snapshot()} == {"in:two"}


def test_reservation_ledger_closes_parallel_check_then_act_race(
    tmp_path: Path, monkeypatch,
):
    monkeypatch.setattr("one_link.transfer_safety._disk_free_bytes", lambda _p: 10_000)
    ledger = InboundTransferReservationLedger(tmp_path)
    policy = TransferAdmissionPolicy(
        min_free_reserve_bytes=0,
        free_reserve_ratio=0,
        max_active_inbound_transfers_per_peer=10,
        max_active_inbound_transfers=1,
    )
    barrier = threading.Barrier(3)

    def _race(index: int):
        barrier.wait()
        return ledger.reserve(
            reservation_id=f"in:{index}",
            name=f"{index}.bin",
            size=100,
            peer_fp=f"peer:{index}",
            policy=policy,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_race, index) for index in range(2)]
        barrier.wait()
        decisions = [future.result(timeout=5) for future in futures]

    assert sum(decision.ok for decision in decisions) == 1
    assert {decision.reason for decision in decisions if not decision.ok} == {
        "global_inbound_transfer_quota",
    }
    assert len(ledger.snapshot()) == 1


def test_reservation_resize_is_atomic_and_preserves_logical_size(
    tmp_path: Path, monkeypatch,
):
    free = 1_000
    monkeypatch.setattr(
        "one_link.transfer_safety._disk_free_bytes",
        lambda _p: free,
    )
    ledger = InboundTransferReservationLedger(tmp_path)
    policy = TransferAdmissionPolicy(
        min_free_reserve_bytes=100,
        free_reserve_ratio=0,
    )
    assert ledger.reserve(
        reservation_id="in:adaptive",
        name="adaptive.bin",
        size=800,
        peer_fp="aa",
        policy=policy,
    ).ok
    ledger.consume("in:adaptive", 400)

    shrunk = ledger.resize_remaining(
        reservation_id="in:adaptive",
        remaining_bytes=200,
        peer_fp="aa",
        policy=policy,
    )
    grown = ledger.resize_remaining(
        reservation_id="in:adaptive",
        remaining_bytes=700,
        peer_fp="aa",
        policy=policy,
    )
    denied = ledger.resize_remaining(
        reservation_id="in:adaptive",
        remaining_bytes=950,
        peer_fp="aa",
        policy=policy,
    )

    assert shrunk.ok and shrunk.reserve_bytes == 200
    assert grown.ok and grown.reserve_bytes == 700
    assert denied.reason == "insufficient_disk_space"
    current = ledger.snapshot()[0]
    assert current.declared_size == 800
    assert current.remaining_bytes == 700


def test_same_storage_volume_matches_sibling_directories(tmp_path: Path):
    assert same_storage_volume(tmp_path / "inbox", tmp_path / "uploads")


def test_disk_probe_fails_closed_for_os_errors_but_surfaces_programming_errors(
    tmp_path: Path, monkeypatch,
):
    monkeypatch.setattr(
        "one_link.transfer_safety.shutil.disk_usage",
        lambda _path: (_ for _ in ()).throw(OSError("volume unavailable")),
    )
    assert _disk_free_bytes(tmp_path) == 0

    monkeypatch.setattr(
        "one_link.transfer_safety.shutil.disk_usage",
        lambda _path: (_ for _ in ()).throw(RuntimeError("probe defect")),
    )
    with pytest.raises(RuntimeError, match="probe defect"):
        _disk_free_bytes(tmp_path)


def test_known_chunk_accounting_never_executes_untrusted_coercion_hooks():
    class HostileDict(dict):
        def get(self, *_args, **_kwargs):
            raise RuntimeError("custom get executed")

    known = {"aa" * 32}
    chunks = [
        HostileDict(hash="aa" * 32, size=10),
        {"hash": "aa" * 32, "size": True},
        {"hash": "aa" * 32, "size": 10},
    ]

    assert known_bytes_from_chunks(chunks, known) == 10


def test_file_risk_marks_executables_reveal_only():
    risk = classify_file_risk("invoice.pdf.exe")

    assert risk["level"] == "high"
    assert risk["reason"] == "executable_or_script"
    assert risk["open_policy"] == "reveal_only"


def test_file_risk_marks_archives_cautious_but_allows_transfer():
    risk = classify_file_risk("family-video.zip")

    assert risk["level"] == "medium"
    assert risk["reason"] == "archive_or_macro_document"
    assert risk["open_policy"] == "cautious"


def test_file_risk_marks_active_documents_download_only():
    for name in (
        "page.html",
        "vector.svg",
        "feed.xml",
        "mail.mhtml",
        "archive.webarchive",
        "misleading.svg.txt",
    ):
        risk = classify_file_risk(name)
        assert risk["level"] == "high", name
        assert risk["reason"] == "active_web_content", name
        assert risk["open_policy"] == "download_only", name


def test_active_content_detection_honors_parameterized_mime():
    assert is_active_content_file("opaque.bin", "text/html; charset=utf-8")
    assert is_active_content_file("opaque.bin", "image/svg+xml")
    assert not is_active_content_file("photo.png", "image/png")
