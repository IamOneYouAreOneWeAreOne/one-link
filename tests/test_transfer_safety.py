from __future__ import annotations

from pathlib import Path

from one_link.transfer_safety import (
    TIB,
    TransferAdmissionContext,
    TransferAdmissionPolicy,
    classify_file_risk,
    evaluate_transfer_admission,
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


def test_admission_counts_known_bytes_against_disk_reserve(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("one_link.transfer_safety._disk_free_bytes", lambda _p: 200)

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
    assert decision.reserve_bytes == 100


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
