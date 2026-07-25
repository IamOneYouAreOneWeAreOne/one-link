"""Safety contract for the retired FILE_OFFER_BATCH_V1 send path.

The public collection helper now delegates every item to send_file so stable
per-delivery nonces, fail-stop markers, durable FILE_COMMIT receipts, and the
full transfer pipeline remain mandatory. Actual multi-file receipt behavior,
including identical blobs at different paths, is covered by the commit receipt
test module.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from one_link.daemon import Daemon


def _daemon() -> Daemon:
    return Daemon.__new__(Daemon)


@pytest.mark.asyncio
async def test_collection_delegates_every_file_to_canonical_send_file(
    tmp_path: Path,
) -> None:
    daemon = _daemon()
    peer = SimpleNamespace(short_id="peer")
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"
    first.write_bytes(b"same")
    second.write_bytes(b"same")
    calls: list[dict] = []

    async def _send_file(_peer, path, **kwargs):
        index = len(calls)
        calls.append({"path": Path(path), **kwargs})
        return {
            "confirmed": True,
            "transfer_id": f"out-{index}",
            "offer": {"delivery_id": f"{index + 1:032x}"},
            "size": Path(path).stat().st_size,
            "total_chunks": 1,
            "cdc_skipped": 0,
        }

    daemon.send_file = _send_file  # type: ignore[method-assign]
    result = await daemon.send_files_batched(
        peer,  # type: ignore[arg-type]
        [(first, "tree/first.bin"), (second, "tree/second.bin")],
        extra_metadata={"folder_send_group": "group-1"},
    )

    assert result["ok"] is True
    assert result["sent"] == 2
    assert result["failed"] == 0
    assert [call["rel_path"] for call in calls] == [
        "tree/first.bin",
        "tree/second.bin",
    ]
    assert all(
        call["extra_metadata"] == {
            "folder_send_group": "group-1",
            "batch_fallback": "individual_commit_protocol",
        }
        for call in calls
    )
    assert len({
        item["delivery_id"] for item in result["results"]
    }) == 2


@pytest.mark.asyncio
async def test_collection_never_claims_unconfirmed_delivery() -> None:
    daemon = _daemon()
    daemon.send_file = AsyncMock(return_value={
        "confirmed": False,
        "status": "sent_unconfirmed",
    })
    result = await daemon.send_files_batched(
        SimpleNamespace(short_id="legacy"),  # type: ignore[arg-type]
        [(Path("legacy.bin"), "legacy.bin")],
    )

    assert result["ok"] is False
    assert result["sent"] == 0
    assert result["failed"] == 1
    assert result["results"][0]["error"] == "delivery was not commit-confirmed"


@pytest.mark.asyncio
async def test_collection_negative_or_exception_outcomes_remain_per_file() -> None:
    daemon = _daemon()
    outcomes = iter([
        RuntimeError("receiver rejected"),
        {
            "confirmed": True,
            "transfer_id": "out-good",
            "offer": {"delivery_id": "ab" * 16},
            "size": 3,
            "total_chunks": 1,
            "cdc_skipped": 1,
        },
    ])

    async def _send_file(*_args, **_kwargs):
        outcome = next(outcomes)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    daemon.send_file = _send_file  # type: ignore[method-assign]
    result = await daemon.send_files_batched(
        SimpleNamespace(short_id="peer"),  # type: ignore[arg-type]
        [(Path("bad.bin"), "bad.bin"), (Path("good.bin"), "good.bin")],
    )

    assert result["ok"] is False
    assert result["sent"] == 1
    assert result["failed"] == 1
    assert result["dedup_files"] == 1
    assert result["dedup_bytes"] == 3
    assert result["results"][0]["error_class"] == "RuntimeError"


@pytest.mark.asyncio
async def test_collection_rejects_unsafe_relative_path_before_send() -> None:
    daemon = _daemon()
    daemon.send_file = AsyncMock()
    result = await daemon.send_files_batched(
        SimpleNamespace(short_id="peer"),  # type: ignore[arg-type]
        [(Path("escape.bin"), "../escape.bin")],
    )

    assert result["ok"] is False
    assert result["failed"] == 1
    daemon.send_file.assert_not_awaited()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_collection_propagates_cancellation() -> None:
    daemon = _daemon()
    daemon.send_file = AsyncMock(side_effect=asyncio.CancelledError())
    with pytest.raises(asyncio.CancelledError):
        await daemon.send_files_batched(
            SimpleNamespace(short_id="peer"),  # type: ignore[arg-type]
            [(Path("cancel.bin"), "cancel.bin")],
        )


@pytest.mark.asyncio
async def test_collection_empty_input_has_no_side_effects() -> None:
    daemon = _daemon()
    daemon.send_file = AsyncMock()
    result = await daemon.send_files_batched(
        SimpleNamespace(short_id="peer"),  # type: ignore[arg-type]
        [],
    )

    assert result == {
        "ok": True,
        "sent": 0,
        "failed": 0,
        "dedup_files": 0,
        "dedup_bytes": 0,
        "results": [],
    }
    daemon.send_file.assert_not_awaited()  # type: ignore[attr-defined]
