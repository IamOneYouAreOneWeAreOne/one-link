from __future__ import annotations

import asyncio
import aiohttp
import base64
import hashlib
from pathlib import Path
import json
import sqlite3
import threading
import time
from types import SimpleNamespace

import pytest

from one_link.peer_rtc import BrowserPeerManager
from one_link.ui_delivery_idempotency import (
    UIDeliveryContract,
    UIDeliveryContractConflict,
    UIDeliveryIdempotencyStore,
    UIDeliveryStoreUnavailable,
)


_STORE_KEY = bytes.fromhex("91" * 32)


@pytest.fixture(autouse=True)
def _isolate_delivery_behavior_from_browser_roster_admission(monkeypatch):
    """Synthetic delivery peers start after the separately-tested auth gate."""

    monkeypatch.setattr(
        BrowserPeerManager,
        "peer_authorization_is_live",
        lambda _manager, _peer: True,
    )


def _contract(**changes) -> UIDeliveryContract:
    values = {
        "peer_fp": "bb" * 32,
        "blob_hash": "aa" * 32,
        "size": 123,
        "display_name": "proof.bin",
        "rel_path": "folder/proof.bin",
        "chat_inline": True,
    }
    values.update(changes)
    return UIDeliveryContract(**values)


def test_full_sync_binding_replays_response_after_store_reconstruction(
    tmp_path: Path,
) -> None:
    db = tmp_path / "ui-deliveries.sqlite3"
    key = "12" * 16
    first = UIDeliveryIdempotencyStore(
        db, contract_key=_STORE_KEY, owner_epoch="01" * 16
    )
    binding = first.bind(
        principal_scope="session:" + "34" * 32,
        client_delivery_id=key,
        contract=_contract(),
    )
    assert binding.owns_attempt is True
    assert binding.transfer_id.startswith(f"out:{'aa' * 32}:")
    queued = first.mark_queued(binding, delivery_id="56" * 16)
    dispatching = first.mark_dispatching(queued)
    expected = {
        "ok": True,
        "transfer_id": binding.transfer_id,
        "delivery_id": "56" * 16,
        "result": {"transfer_id": binding.transfer_id, "delivery_id": "56" * 16},
    }
    first.record_response(dispatching, status=200, body=expected)
    first.close()

    reconstructed = UIDeliveryIdempotencyStore(
        db, contract_key=_STORE_KEY, owner_epoch="02" * 16
    )
    replay = reconstructed.bind(
        principal_scope="session:" + "34" * 32,
        client_delivery_id=key,
        contract=_contract(),
    )
    assert replay.is_replay is True
    assert replay.owns_attempt is False
    assert replay.transfer_id == binding.transfer_id
    assert replay.delivery_id == "56" * 16
    assert replay.response_status == 200
    assert replay.response_body == expected
    reconstructed.close()


@pytest.mark.parametrize(
    "change",
    [
        {"peer_fp": "cc" * 32},
        {"blob_hash": "dd" * 32},
        {"size": 124},
        {"display_name": "renamed.bin"},
        {"rel_path": "elsewhere/proof.bin"},
        {"chat_inline": False},
    ],
)
def test_reusing_key_with_any_changed_contract_fails_closed(
    tmp_path: Path,
    change: dict,
) -> None:
    store = UIDeliveryIdempotencyStore(
        tmp_path / "ui-deliveries.sqlite3", contract_key=_STORE_KEY
    )
    store.bind(
        principal_scope="local-ui:test",
        client_delivery_id="ab" * 16,
        contract=_contract(),
    )
    with pytest.raises(UIDeliveryContractConflict, match="different file send"):
        store.bind(
            principal_scope="local-ui:test",
            client_delivery_id="ab" * 16,
            contract=_contract(**change),
        )
    store.close()


def test_same_client_id_cannot_cross_authenticated_principals(
    tmp_path: Path,
) -> None:
    store = UIDeliveryIdempotencyStore(
        tmp_path / "ui-deliveries.sqlite3",
        contract_key=_STORE_KEY,
    )
    key = "ae" * 16
    original = store.bind(
        principal_scope="session:" + "01" * 32,
        client_delivery_id=key,
        contract=_contract(),
    )
    with pytest.raises(
        UIDeliveryContractConflict,
        match="another authenticated principal",
    ):
        store.bind(
            principal_scope="token:" + "02" * 32,
            client_delivery_id=key,
            contract=_contract(),
        )
    replay = store.bind(
        principal_scope="session:" + "01" * 32,
        client_delivery_id=key,
        contract=_contract(),
    )
    assert replay.transfer_id == original.transfer_id
    assert replay.owns_attempt is False
    store.close()


def test_dispatching_row_is_never_reclaimed_after_restart(tmp_path: Path) -> None:
    db = tmp_path / "ui-deliveries.sqlite3"
    first = UIDeliveryIdempotencyStore(
        db, contract_key=_STORE_KEY, owner_epoch="11" * 16
    )
    bound = first.bind(
        principal_scope="local-ui:test",
        client_delivery_id="22" * 16,
        contract=_contract(),
    )
    queued = first.mark_queued(bound, delivery_id="33" * 16)
    first.mark_dispatching(queued)
    first.close()

    second = UIDeliveryIdempotencyStore(
        db, contract_key=_STORE_KEY, owner_epoch="44" * 16
    )
    ambiguous = second.bind(
        principal_scope="local-ui:test",
        client_delivery_id="22" * 16,
        contract=_contract(),
    )
    assert ambiguous.is_outcome_ambiguous is True
    assert ambiguous.owns_attempt is False
    assert ambiguous.transfer_id == bound.transfer_id
    assert ambiguous.delivery_id == "33" * 16
    second.close()


def test_predispatch_row_can_be_reclaimed_by_reconstructed_server(
    tmp_path: Path,
) -> None:
    db = tmp_path / "ui-deliveries.sqlite3"
    first = UIDeliveryIdempotencyStore(
        db, contract_key=_STORE_KEY, owner_epoch="55" * 16
    )
    bound = first.bind(
        principal_scope="local-ui:test",
        client_delivery_id="66" * 16,
        contract=_contract(),
    )
    first.close()

    second = UIDeliveryIdempotencyStore(
        db, contract_key=_STORE_KEY, owner_epoch="77" * 16
    )
    reclaimed = second.bind(
        principal_scope="local-ui:test",
        client_delivery_id="66" * 16,
        contract=_contract(),
    )
    assert reclaimed.owns_attempt is True
    assert reclaimed.phase == "bound"
    assert reclaimed.reclaimable_before_dispatch is False
    assert reclaimed.transfer_id == bound.transfer_id
    second.close()


def test_probe_distinguishes_live_owner_from_restart_reclaim(
    tmp_path: Path,
) -> None:
    db = tmp_path / "ui-deliveries.sqlite3"
    key = "67" * 16
    first = UIDeliveryIdempotencyStore(
        db, contract_key=_STORE_KEY, owner_epoch="68" * 16
    )
    first.bind(
        principal_scope="local-ui:test",
        client_delivery_id=key,
        contract=_contract(),
    )
    live = first.probe(
        principal_scope="local-ui:test",
        client_delivery_id=key,
    )
    assert live is not None
    assert live.reclaimable_before_dispatch is False
    first.close()

    second = UIDeliveryIdempotencyStore(
        db, contract_key=_STORE_KEY, owner_epoch="69" * 16
    )
    abandoned = second.probe(
        principal_scope="local-ui:test",
        client_delivery_id=key,
    )
    assert abandoned is not None
    assert abandoned.phase == "bound"
    assert abandoned.reclaimable_before_dispatch is True
    assert abandoned.recoverable_after_restart is False
    second.close()


def test_probe_is_read_only_and_skips_durable_path_sync(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = UIDeliveryIdempotencyStore(
        tmp_path / "ui-deliveries.sqlite3",
        contract_key=_STORE_KEY,
    )
    key = "6a" * 16
    store.bind(
        principal_scope="local-ui:test",
        client_delivery_id=key,
        contract=_contract(),
    )
    sync_calls = 0

    def _unexpected_path_sync() -> None:
        nonlocal sync_calls
        sync_calls += 1

    monkeypatch.setattr(store, "_harden_and_sync_paths", _unexpected_path_sync)
    result = store.probe(
        principal_scope="local-ui:test",
        client_delivery_id=key,
    )
    assert result is not None
    assert result.transfer_id.startswith(f"out:{'aa' * 32}:")
    assert sync_calls == 0
    store.close()


@pytest.mark.parametrize("invalid_size", [True, 1.5, "123", None])
def test_contract_refuses_non_integer_size(invalid_size) -> None:
    with pytest.raises(ValueError, match="non-negative integer"):
        _contract(size=invalid_size).validate()


def test_contract_and_response_presentation_never_reach_sqlite_plaintext(
    tmp_path: Path,
) -> None:
    db = tmp_path / "ui-deliveries.sqlite3"
    store = UIDeliveryIdempotencyStore(db, contract_key=_STORE_KEY)
    binding = store.bind(
        principal_scope="session:private-browser-principal",
        client_delivery_id="91" * 16,
        contract=_contract(),
    )
    queued = store.mark_queued(binding, delivery_id="92" * 16)
    dispatching = store.mark_dispatching(queued)
    store.record_response(
        dispatching,
        status=200,
        body={
            "ok": True,
            "private_response": "proof.bin folder/proof.bin receiver-alias",
        },
    )
    store._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    store.close()

    disk = b"".join(
        candidate.read_bytes()
        for candidate in (db, Path(f"{db}-wal"), Path(f"{db}-shm"))
        if candidate.exists()
    )
    for secret in (
        binding.transfer_id.encode("ascii"),
        binding.contract.blob_hash.encode("ascii"),
        binding.contract.peer_fp.encode("ascii"),
        ("92" * 16).encode("ascii"),
        b"proof.bin",
        b"folder/proof.bin",
        b"receiver-alias",
        b"private-browser-principal",
        b"private_response",
    ):
        assert secret not in disk


def test_wrong_store_key_and_commit_failure_both_fail_closed(tmp_path: Path) -> None:
    db = tmp_path / "ui-deliveries.sqlite3"
    initial = UIDeliveryIdempotencyStore(db, contract_key=_STORE_KEY)
    initial.close()
    with pytest.raises(UIDeliveryStoreUnavailable, match="key does not match"):
        UIDeliveryIdempotencyStore(db, contract_key=b"wrong-key" * 4)

    store = UIDeliveryIdempotencyStore(db, contract_key=_STORE_KEY)
    real_connection = store._conn

    class _CommitFailure:
        def execute(self, sql, parameters=()):
            if sql == "COMMIT":
                raise sqlite3.OperationalError("simulated durable commit failure")
            return real_connection.execute(sql, parameters)

        def close(self):
            return real_connection.close()

    store._conn = _CommitFailure()
    with pytest.raises(UIDeliveryStoreUnavailable, match="commit failed"):
        store.bind(
            principal_scope="local-ui:test",
            client_delivery_id="93" * 16,
            contract=_contract(),
        )
    with pytest.raises(UIDeliveryStoreUnavailable, match="fail-closed"):
        store.bind(
            principal_scope="local-ui:test",
            client_delivery_id="94" * 16,
            contract=_contract(),
        )
    store.close()


def test_preexisting_sqlite_sidecar_link_is_rejected_before_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import one_link.ui_delivery_idempotency as idempotency_module

    db = tmp_path / "ui-deliveries.sqlite3"
    sidecar = Path(f"{db}-wal")
    sidecar.write_bytes(b"must not be opened by sqlite")
    real_check = idempotency_module._is_link_or_reparse

    def _mark_sidecar_as_reparse(path, value) -> bool:
        return path == sidecar or real_check(path, value)

    monkeypatch.setattr(
        idempotency_module,
        "_is_link_or_reparse",
        _mark_sidecar_as_reparse,
    )
    with pytest.raises(UIDeliveryStoreUnavailable, match="cannot be a link"):
        UIDeliveryIdempotencyStore(db, contract_key=_STORE_KEY)
    assert sidecar.read_bytes() == b"must not be opened by sqlite"
    assert not db.exists()


def test_transaction_body_database_fault_is_normalized_and_poisons_store(
    tmp_path: Path,
) -> None:
    store = UIDeliveryIdempotencyStore(
        tmp_path / "ui-deliveries.sqlite3",
        contract_key=_STORE_KEY,
    )
    real_connection = store._conn

    class _BodyDatabaseFailure:
        failed = False

        def execute(self, sql, parameters=()):
            if not self.failed and sql.startswith(
                "SELECT * FROM ui_file_deliveries"
            ):
                self.failed = True
                raise sqlite3.DatabaseError("simulated corrupt page")
            return real_connection.execute(sql, parameters)

        def close(self):
            return real_connection.close()

    store._conn = _BodyDatabaseFailure()
    with pytest.raises(
        UIDeliveryStoreUnavailable,
        match="operation failed; store is fail-closed",
    ):
        store.bind(
            principal_scope="local-ui:test",
            client_delivery_id="95" * 16,
            contract=_contract(),
        )
    with pytest.raises(UIDeliveryStoreUnavailable, match="fail-closed"):
        store.bind(
            principal_scope="local-ui:test",
            client_delivery_id="96" * 16,
            contract=_contract(),
        )
    store.close()


def test_authenticated_identity_corruption_poisons_store(tmp_path: Path) -> None:
    store = UIDeliveryIdempotencyStore(
        tmp_path / "ui-deliveries.sqlite3",
        contract_key=_STORE_KEY,
    )
    store.bind(
        principal_scope="local-ui:test",
        client_delivery_id="99" * 16,
        contract=_contract(),
    )
    store._conn.execute(
        "UPDATE ui_file_deliveries "
        "SET identity_ciphertext = zeroblob(length(identity_ciphertext))"
    )
    with pytest.raises(
        UIDeliveryStoreUnavailable,
        match="integrity failed; store is fail-closed",
    ):
        store.bind(
            principal_scope="local-ui:test",
            client_delivery_id="99" * 16,
            contract=_contract(),
        )
    with pytest.raises(UIDeliveryStoreUnavailable, match="fail-closed"):
        store.bind(
            principal_scope="local-ui:test",
            client_delivery_id="9a" * 16,
            contract=_contract(),
        )
    store.close()


@pytest.mark.parametrize(
    ("column", "replacement"),
    [
        ("phase", "queued"),
        ("owner_epoch", "fe" * 16),
    ],
)
def test_delivery_phase_and_owner_are_authenticated_authority(
    tmp_path: Path,
    column: str,
    replacement: str,
) -> None:
    store = UIDeliveryIdempotencyStore(
        tmp_path / "ui-deliveries.sqlite3",
        contract_key=_STORE_KEY,
        owner_epoch="fd" * 16,
    )
    binding = store.bind(
        principal_scope="local-ui:test",
        client_delivery_id="9d" * 16,
        contract=_contract(),
    )
    queued = store.mark_queued(binding, delivery_id="9e" * 16)
    store.mark_dispatching(queued)
    assert column in {"phase", "owner_epoch"}
    store._conn.execute(
        f"UPDATE ui_file_deliveries SET {column} = ?",  # noqa: S608 - fixed test whitelist
        (replacement,),
    )

    with pytest.raises(
        UIDeliveryStoreUnavailable,
        match="integrity failed; store is fail-closed",
    ):
        store.probe(
            principal_scope="local-ui:test",
            client_delivery_id="9d" * 16,
        )
    with pytest.raises(UIDeliveryStoreUnavailable, match="fail-closed"):
        store.bind(
            principal_scope="local-ui:test",
            client_delivery_id="9f" * 16,
            contract=_contract(),
        )
    store.close()


def test_v3_rows_migrate_phase_owner_and_response_without_losing_replay(
    tmp_path: Path,
) -> None:
    db = tmp_path / "ui-deliveries.sqlite3"
    key = "a1" * 16
    first = UIDeliveryIdempotencyStore(
        db,
        contract_key=_STORE_KEY,
        owner_epoch="a2" * 16,
    )
    binding = first.bind(
        principal_scope="local-ui:test",
        client_delivery_id=key,
        contract=_contract(),
    )
    queued = first.mark_queued(binding, delivery_id="a3" * 16)
    expected = {
        "ok": True,
        "transfer_id": binding.transfer_id,
        "delivery_id": "a3" * 16,
    }
    first.record_response(queued, status=202, body=expected)

    # Reconstruct the exact v3 envelope shape: identity/contract/response were
    # authenticated, but phase and owner were not yet present in the payload.
    row = first._conn.execute("SELECT * FROM ui_file_deliveries").fetchone()
    assert row is not None
    identity = json.loads(
        first._identity_aead.decrypt(
            bytes(row["identity_nonce"]),
            bytes(row["identity_ciphertext"]),
            first._identity_aad(row),
        ).decode("utf-8")
    )
    identity.pop("phase")
    identity.pop("owner_epoch")
    old_identity_nonce = b"\x31" * 12
    old_identity_ciphertext = first._identity_aead.encrypt(
        old_identity_nonce,
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("ascii"),
        first._identity_aad(row),
    )
    first._conn.execute(
        "UPDATE ui_file_deliveries SET identity_nonce = ?, identity_ciphertext = ?",
        (old_identity_nonce, old_identity_ciphertext),
    )
    old_row = first._conn.execute("SELECT * FROM ui_file_deliveries").fetchone()
    assert old_row is not None
    old_response_nonce = b"\x32" * 12
    old_response_ciphertext = first._response_aead.encrypt(
        old_response_nonce,
        json.dumps(
            expected,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8"),
        first._response_aad(old_row, status=202),
    )
    first._conn.execute(
        "UPDATE ui_file_deliveries SET response_nonce = ?, response_ciphertext = ?",
        (old_response_nonce, old_response_ciphertext),
    )
    first._conn.execute("PRAGMA user_version = 3")
    first.close()

    upgraded = UIDeliveryIdempotencyStore(
        db,
        contract_key=_STORE_KEY,
        owner_epoch="a4" * 16,
    )
    replay = upgraded.bind(
        principal_scope="local-ui:test",
        client_delivery_id=key,
        contract=_contract(),
    )
    assert replay.response_status == 202
    assert replay.response_body == expected
    assert replay.phase == "result"
    assert upgraded._conn.execute("PRAGMA user_version").fetchone()[0] == 4
    upgraded.close()


def test_post_commit_path_sync_failure_is_normalized_and_poisons_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = UIDeliveryIdempotencyStore(
        tmp_path / "ui-deliveries.sqlite3",
        contract_key=_STORE_KEY,
    )

    def _fail_path_sync() -> None:
        raise OSError("simulated directory fsync failure")

    monkeypatch.setattr(store, "_harden_and_sync_paths", _fail_path_sync)
    with pytest.raises(UIDeliveryStoreUnavailable, match="path sync failed"):
        store.bind(
            principal_scope="local-ui:test",
            client_delivery_id="9b" * 16,
            contract=_contract(),
        )
    with pytest.raises(UIDeliveryStoreUnavailable, match="fail-closed"):
        store.bind(
            principal_scope="local-ui:test",
            client_delivery_id="9c" * 16,
            contract=_contract(),
        )
    store.close()


def test_capacity_fails_closed_without_pruning_replay_authority(
    tmp_path: Path,
) -> None:
    store = UIDeliveryIdempotencyStore(
        tmp_path / "ui-deliveries.sqlite3",
        contract_key=_STORE_KEY,
        max_records=1,
    )
    original = store.bind(
        principal_scope="local-ui:test",
        client_delivery_id="97" * 16,
        contract=_contract(),
    )
    expected = {"ok": True, "admitted": True}
    store.record_response(original, status=202, body=expected)

    with pytest.raises(UIDeliveryStoreUnavailable, match="capacity is exhausted"):
        store.bind(
            principal_scope="local-ui:test",
            client_delivery_id="98" * 16,
            contract=_contract(display_name="another.bin"),
        )

    replay = store.bind(
        principal_scope="local-ui:test",
        client_delivery_id="97" * 16,
        contract=_contract(),
    )
    assert replay.response_status == 202
    assert replay.response_body == expected
    count = store._conn.execute(
        "SELECT count(*) FROM ui_file_deliveries"
    ).fetchone()
    assert count is not None and int(count[0]) == 1
    store.close()


class _MultipartPart:
    def __init__(
        self,
        name: str,
        *,
        text: str | None = None,
        data: bytes = b"",
        filename: str | None = None,
    ) -> None:
        self.name = name
        self.filename = filename
        self._text = text
        self._data = data
        self._offset = 0
        self.read_calls = 0

    async def text(self) -> str:
        return self._text or ""

    async def read_chunk(self, size: int = 8192) -> bytes:
        self.read_calls += 1
        chunk = self._data[self._offset:self._offset + size]
        self._offset += len(chunk)
        return chunk


class _StalledMultipartPart(_MultipartPart):
    async def read_chunk(self, size: int = 8192) -> bytes:
        del size
        self.read_calls += 1
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


class _Multipart:
    def __init__(self, parts: list[_MultipartPart]) -> None:
        self.parts = iter(parts)

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return next(self.parts)
        except StopIteration as exc:
            raise StopAsyncIteration from exc


class _MultipartRequest:
    content_type = "multipart/form-data; boundary=idempotency-test"

    def __init__(self, parts: list[_MultipartPart]) -> None:
        self.parts = parts
        self.content_length = 1024 + sum(
            len(part._data) + len((part._text or "").encode()) for part in parts
        )
        self.cookies: dict[str, str] = {}
        self.headers: dict[str, str] = {}

    async def multipart(self) -> _Multipart:
        return _Multipart(self.parts)


def _file_request(
    *,
    key: str,
    payload: bytes = b"one durable browser intent",
    filename: str = "intent.bin",
    rel_path: str | None = "proof/intent.bin",
    chat_inline: bool = True,
) -> _MultipartRequest:
    parts = [
        _MultipartPart("peer", text="bbbbbbbb"),
        _MultipartPart("client_delivery_id", text=key),
    ]
    if rel_path is not None:
        parts.append(_MultipartPart("rel_path", text=rel_path))
    if chat_inline:
        parts.append(_MultipartPart("chat_inline", text="1"))
    parts.append(_MultipartPart("file_size", text=str(len(payload))))
    parts.append(_MultipartPart("intent_metadata_complete", text="1"))
    parts.append(
        _MultipartPart("file", data=payload, filename=filename)
    )
    return _MultipartRequest(parts)


class _CrashRecoveryDaemon:
    """Exact transfer-ledger double for process-boundary crash tests."""

    me = SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa")

    def __init__(self, state, *, root: Path) -> None:
        self.state = state
        self.root = root
        self.queue_calls: list[str] = []
        self.wire_sends: list[str] = []
        self.resume_tasks: list[asyncio.Task] = []
        self._scheduled_ids: set[str] = set()

    async def resolve_for_send(self, _needle):
        return SimpleNamespace(
            short_id="bbbbbbbb",
            ed_pub_hex=(b"\xbb" * 32).hex(),
        )

    @staticmethod
    def _safe_transfer_rel_path(value):
        return value if value == "proof/intent.bin" else None

    def _remote_commit_failstop_path(self, transfer_id: str) -> Path:
        digest = hashlib.sha256(transfer_id.encode("ascii")).hexdigest()
        return self.root / "transfer_commit_failstop" / f"{digest}.json"

    def _remote_commit_is_failstopped(self, transfer_id: str) -> bool:
        return self._remote_commit_failstop_path(transfer_id).exists()

    def _schedule_resume_paused(self, peer_fp: str, *, force: bool = False) -> None:
        del force
        candidates = [
            rec
            for rec in self.state.list_transfers(peer_fp=peer_fp, limit=100)
            if rec.direction == "out" and rec.status in {"paused", "queued"}
        ]
        for rec in candidates:
            if rec.id in self._scheduled_ids:
                continue
            self._scheduled_ids.add(rec.id)
            metadata = dict(rec.metadata or {})
            peer = SimpleNamespace(
                short_id="bbbbbbbb",
                ed_pub_hex=(b"\xbb" * 32).hex(),
            )
            task = asyncio.create_task(
                self.send_file(
                    peer,
                    Path(metadata["path"]),
                    transfer_id=rec.id,
                    rel_path=metadata.get("delivery_rel_path"),
                    display_name=metadata.get("delivery_name"),
                    chat_inline=bool(metadata.get("chat_inline")),
                )
            )
            self.resume_tasks.append(task)

    def queue_file_transfer(
        self,
        *,
        peer_fp,
        path,
        reason="peer offline",
        schedule_resume=True,
        display_name=None,
        chat_inline=False,
        rel_path=None,
        transfer_id=None,
    ):
        from one_link.cdc import hash_path

        del reason
        source = Path(path)
        blob = hash_path(source)
        name = display_name or source.name
        assert transfer_id is not None
        assert transfer_id.startswith(f"out:{blob}:")
        self.queue_calls.append(transfer_id)
        existing = self.state.get_transfer(transfer_id)
        if existing is not None:
            metadata = dict(existing.metadata or {})
            assert existing.peer_fp == peer_fp
            assert existing.name == name
            assert existing.blob_hash == blob
            assert existing.size == source.stat().st_size
            assert metadata["display_name"] == name
            assert metadata["chat_inline"] is bool(chat_inline)
            assert str(metadata.get("rel_path") or "") == str(rel_path or "")
            assert hash_path(Path(metadata["path"])) == blob
            if schedule_resume:
                self._schedule_resume_paused(peer_fp)
            return existing
        delivery_id = "cd" * 16
        queued = self.state.upsert_transfer(
            id=transfer_id,
            direction="out",
            peer_fp=peer_fp,
            kind="file",
            name=name,
            size=source.stat().st_size,
            blob_hash=blob,
            status="paused",
            total_bytes=source.stat().st_size,
            chunks_total=1,
            metadata={
                "mode": "cdc",
                "path": str(source),
                "display_name": name,
                "chat_inline": bool(chat_inline),
                "rel_path": rel_path,
                "delivery_id": delivery_id,
                "delivery_name": name,
                "delivery_rel_path": str(rel_path or ""),
                "delivery_kind": "file",
                "delivery_state": "waiting_for_device",
                "attempts": 0,
                "last_attempt_ms": None,
            },
        )
        if schedule_resume:
            self._schedule_resume_paused(peer_fp)
        return queued

    async def send_file(
        self,
        _peer,
        path,
        *,
        transfer_id=None,
        rel_path=None,
        display_name=None,
        chat_inline=False,
    ):
        from one_link.cdc import hash_path
        from one_link.daemon import FILE_COMMIT_RECEIPT_VERSION

        assert transfer_id is not None
        rec = self.state.get_transfer(transfer_id)
        assert rec is not None
        metadata = dict(rec.metadata or {})
        source = Path(path)
        blob = hash_path(source)
        assert blob == rec.blob_hash
        assert str(rel_path or "") == str(metadata.get("delivery_rel_path") or "")
        assert (display_name or source.name) == rec.name
        assert bool(chat_inline) is bool(metadata.get("chat_inline"))
        self.wire_sends.append(transfer_id)
        size = source.stat().st_size
        receipt = {
            "t": "FILE_COMMIT",
            "receipt_version": FILE_COMMIT_RECEIPT_VERSION,
            "of": "ab" * 16,
            "blob": blob,
            "size": size,
            "mode": "stream",
            "delivery_id": metadata["delivery_id"],
            "delivery_name": rec.name,
            "delivery_rel_path": str(metadata.get("delivery_rel_path") or ""),
            "delivery_kind": metadata["delivery_kind"],
            "ok": True,
            "retryable": False,
            "committed_bytes": size,
            "durable": True,
            "verified_hash": blob,
        }
        completed = self.state.update_transfer(
            transfer_id,
            status="complete",
            progress_bytes=size,
            total_bytes=size,
            chunks_done=1,
            chunks_total=1,
            raw_bytes=size,
            wire_bytes=size,
            metadata={
                **metadata,
                "mode": "stream",
                "delivery_state": "done",
                "commit_confirmed": True,
                "commit_receipt": receipt,
            },
        )
        assert completed is not None
        return {
            "transfer_id": transfer_id,
            "delivery_id": metadata["delivery_id"],
            "blob": blob,
            "size": size,
            "confirmed": True,
            "status": "done",
        }


def _prepare_dispatch_boundary(server, daemon, source: Path, *, key: str):
    from one_link.cdc import hash_path

    contract = UIDeliveryContract(
        peer_fp="bb" * 32,
        blob_hash=hash_path(source),
        size=source.stat().st_size,
        display_name="intent.bin",
        rel_path="proof/intent.bin",
        chat_inline=True,
    )
    binding = server._ui_delivery_idempotency.bind(
        principal_scope="daemon:" + "aa" * 32,
        client_delivery_id=key,
        contract=contract,
    )
    rec = daemon.queue_file_transfer(
        peer_fp=contract.peer_fp,
        path=source,
        display_name=contract.display_name,
        chat_inline=contract.chat_inline,
        rel_path=contract.rel_path,
        schedule_resume=False,
        transfer_id=binding.transfer_id,
    )
    queued = server._ui_delivery_idempotency.mark_queued(
        binding,
        delivery_id=rec.metadata["delivery_id"],
    )
    dispatching = server._ui_delivery_idempotency.mark_dispatching(queued)
    return dispatching, rec


def test_revoked_session_cannot_fall_through_to_daemon_delivery_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link.server import SESSION_COOKIE_NAME, UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    server = UIServer(daemon)
    monkeypatch.setattr(server, "_request_uses_tls", lambda _request: True)
    request = SimpleNamespace(
        cookies={SESSION_COOKIE_NAME: "revoked-session-token"},
        headers={},
    )

    with pytest.raises(
        UIDeliveryStoreUnavailable,
        match="session is no longer active",
    ):
        server._ui_delivery_principal_scope(request)

    asyncio.run(server.stop())
    state.close()


@pytest.mark.asyncio
async def test_lost_http_response_replays_same_ids_and_one_wire_send_after_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link.cdc import hash_path
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    peer_fp = "bb" * 32
    state.upsert_peer(
        fingerprint=peer_fp,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="Receiver",
        trust_default="pinned",
    )
    queue_calls: list[str] = []
    wire_sends: list[str] = []

    class _Daemon:
        me = SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa")

        def __init__(self) -> None:
            self.state = state
            self.resume_tasks: list[asyncio.Task] = []
            self._scheduled_ids: set[str] = set()

        async def resolve_for_send(self, _needle):
            return SimpleNamespace(
                short_id="bbbbbbbb",
                ed_pub_hex=(b"\xbb" * 32).hex(),
            )

        def _peer_fp_from_peer(self, _peer):
            return peer_fp

        def _schedule_resume_paused(self, scheduled_peer_fp, *, force=False):
            del force
            assert scheduled_peer_fp == peer_fp
            recs = [
                rec
                for rec in state.list_transfers(peer_fp=peer_fp, limit=100)
                if rec.direction == "out" and rec.status in {"paused", "queued"}
            ]
            for rec in recs:
                if rec.id in self._scheduled_ids:
                    continue
                self._scheduled_ids.add(rec.id)
                metadata = dict(rec.metadata or {})
                task = asyncio.create_task(
                    self.send_file(
                        SimpleNamespace(short_id="bbbbbbbb"),
                        Path(metadata["path"]),
                        transfer_id=rec.id,
                        rel_path=metadata.get("delivery_rel_path"),
                        display_name=metadata.get("delivery_name"),
                        chat_inline=bool(metadata.get("chat_inline")),
                    )
                )
                self.resume_tasks.append(task)

        @staticmethod
        def _safe_transfer_rel_path(value):
            return value if value == "proof/intent.bin" else None

        def queue_file_transfer(
            self,
            *,
            peer_fp,
            path,
            reason="peer offline",
            schedule_resume=True,
            display_name=None,
            chat_inline=False,
            rel_path=None,
            transfer_id=None,
        ):
            del reason
            assert transfer_id is not None
            queue_calls.append(transfer_id)
            source = Path(path)
            blob = hash_path(source)
            assert transfer_id.startswith(f"out:{blob}:")
            delivery_id = "cd" * 16
            rec = state.upsert_transfer(
                id=transfer_id,
                direction="out",
                peer_fp=peer_fp,
                kind="file",
                name=display_name or source.name,
                size=source.stat().st_size,
                blob_hash=blob,
                status="paused",
                total_bytes=source.stat().st_size,
                chunks_total=1,
                metadata={
                    "path": str(source),
                    "display_name": display_name,
                    "chat_inline": chat_inline,
                    "rel_path": rel_path,
                    "delivery_id": delivery_id,
                    "delivery_name": display_name,
                    "delivery_rel_path": rel_path or "",
                    "delivery_kind": "file",
                },
            )
            if schedule_resume:
                self._schedule_resume_paused(peer_fp)
            return rec

        async def send_file(
            self,
            _peer,
            path,
            *,
            transfer_id=None,
            rel_path=None,
            display_name=None,
            chat_inline=False,
        ):
            del rel_path, display_name, chat_inline
            assert transfer_id is not None
            wire_sends.append(transfer_id)
            state.update_transfer(
                transfer_id,
                status="complete",
                progress_bytes=Path(path).stat().st_size,
            )
            return {
                "ok": True,
                "transfer_id": transfer_id,
                "delivery_id": "cd" * 16,
            }

    key = "ef" * 16
    first_daemon = _Daemon()
    first_server = UIServer(first_daemon)
    first_response = await first_server.api_send_file(_file_request(key=key))
    first_body = json.loads(first_response.text)
    assert first_response.status == 202
    assert first_body["accepted"] is True
    assert first_body["background"] is True
    assert first_body["transfer_id"] == queue_calls[0]
    assert first_body["delivery_id"] == "cd" * 16
    assert first_body["client_delivery_id"] == key
    await asyncio.gather(*first_daemon.resume_tasks)
    # Simulate response loss: discard the response and reconstruct the entire
    # HTTP server/idempotency connection from the same durable home.
    await first_server.stop()

    reconstructed = UIServer(_Daemon())

    def _reservation_must_not_run(**_kwargs):
        raise AssertionError("replay attempted to reserve upload capacity")

    monkeypatch.setattr(
        reconstructed._upload_reservations,
        "reserve",
        _reservation_must_not_run,
    )
    replay_request = _file_request(key=key)
    replay_file_part = next(
        part for part in replay_request.parts if part.name == "file"
    )
    replay_response = await reconstructed.api_send_file(replay_request)
    replay_body = json.loads(replay_response.text)
    assert replay_response.status == 202
    assert replay_body == first_body
    assert queue_calls == [first_body["transfer_id"]]
    assert wire_sends == [first_body["transfer_id"]]
    assert replay_file_part.read_calls == 0
    assert replay_file_part._offset == 0

    # Any contract change under the same key is a conflict, even after the
    # original response became replayable, and cannot reach the wire.
    conflict_request = _file_request(key=key, filename="renamed.bin")
    conflict_file_part = next(
        part for part in conflict_request.parts if part.name == "file"
    )
    conflict = await reconstructed.api_send_file(conflict_request)
    assert conflict.status == 409
    assert json.loads(conflict.text)["code"] == "client_delivery_contract_conflict"
    assert len(queue_calls) == 1
    assert len(wire_sends) == 1
    assert conflict_file_part.read_calls == 0
    await reconstructed.stop()
    state.close()


@pytest.mark.asyncio
async def test_http_admission_does_not_wait_for_long_remote_transfer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint="bb" * 32,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="Receiver",
        trust_default="pinned",
    )
    send_started = asyncio.Event()
    release_send = asyncio.Event()

    class _SlowDaemon(_CrashRecoveryDaemon):
        async def send_file(
            self,
            _peer,
            path,
            *,
            transfer_id=None,
            rel_path=None,
            display_name=None,
            chat_inline=False,
        ):
            del path, rel_path, display_name, chat_inline
            assert transfer_id is not None
            self.wire_sends.append(transfer_id)
            send_started.set()
            await release_send.wait()
            return {"transfer_id": transfer_id, "status": "done"}

    daemon = _SlowDaemon(state, root=tmp_path)
    server = UIServer(daemon)
    key = "fa" * 16
    response = await asyncio.wait_for(
        server.api_send_file(_file_request(key=key)),
        timeout=1.0,
    )
    body = json.loads(response.text)
    assert response.status == 202
    assert body["accepted"] is True
    assert body["background"] is True

    await asyncio.wait_for(send_started.wait(), timeout=1.0)
    assert daemon.resume_tasks and not daemon.resume_tasks[0].done()
    replay = await asyncio.wait_for(
        server.api_send_file(_file_request(key=key)),
        timeout=1.0,
    )
    assert replay.status == 202
    assert json.loads(replay.text) == body
    assert daemon.queue_calls == [body["transfer_id"]]
    assert daemon.wire_sends == [body["transfer_id"]]

    release_send.set()
    await asyncio.gather(*daemon.resume_tasks)
    await server.stop()
    state.close()


@pytest.mark.asyncio
async def test_large_file_preparation_never_blocks_http_event_loop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link.cdc import hash_path
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint="bb" * 32,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="Receiver",
        trust_default="pinned",
    )

    class _SlowPreparationDaemon(_CrashRecoveryDaemon):
        def prepare_file_for_transfer(self, path, *, peer_fp=None):
            assert peer_fp == "bb" * 32
            # Model the CPU/disk time of indexing a 385 MiB upload. If the
            # server invokes this directly, the heartbeat below is delayed by
            # the full interval; asyncio.to_thread keeps HTTP/WS traffic live.
            time.sleep(0.25)
            return SimpleNamespace(
                file_index=SimpleNamespace(blob_hash=hash_path(Path(path)))
            )

    daemon = _SlowPreparationDaemon(state, root=tmp_path)
    server = UIServer(daemon)
    send_task = asyncio.create_task(
        server.api_send_file(_file_request(key="fc" * 16))
    )
    loop = asyncio.get_running_loop()
    started = loop.time()
    await asyncio.sleep(0.03)
    heartbeat_delay = loop.time() - started

    assert heartbeat_delay < 0.12
    assert not send_task.done(), "slow preparation did not run in the worker"
    response = await asyncio.wait_for(send_task, timeout=1.0)
    assert response.status == 202
    await asyncio.gather(*daemon.resume_tasks)
    await server.stop()
    state.close()


@pytest.mark.asyncio
async def test_durable_queue_admission_never_blocks_http_event_loop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint="bb" * 32,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="Receiver",
        trust_default="pinned",
    )
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    original_queue = daemon.queue_file_transfer
    queue_started = threading.Event()

    def _slow_queue(**kwargs):
        queue_started.set()
        time.sleep(0.25)
        return original_queue(**kwargs)

    monkeypatch.setattr(daemon, "queue_file_transfer", _slow_queue)
    server = UIServer(daemon)
    send_task = asyncio.create_task(
        server.api_send_file(_file_request(key="fb" * 16))
    )
    assert await asyncio.to_thread(queue_started.wait, 1.0)
    loop = asyncio.get_running_loop()
    started = loop.time()
    await asyncio.sleep(0.03)
    heartbeat_delay = loop.time() - started

    assert heartbeat_delay < 0.12
    assert not send_task.done(), "durable queue admission did not run in a worker"
    response = await asyncio.wait_for(send_task, timeout=1.0)
    assert response.status == 202
    await asyncio.gather(*daemon.resume_tasks)
    await server.stop()
    state.close()


@pytest.mark.asyncio
async def test_full_sync_idempotency_transactions_never_block_event_loop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint="bb" * 32,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="Receiver",
        trust_default="pinned",
    )
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    server = UIServer(daemon)
    original_sync = server._ui_delivery_idempotency._harden_and_sync_paths

    def _slow_full_sync() -> None:
        # Model an antivirus/filesystem flush stall at each FULL-sync boundary.
        time.sleep(0.15)
        original_sync()

    monkeypatch.setattr(
        server._ui_delivery_idempotency,
        "_harden_and_sync_paths",
        _slow_full_sync,
    )
    send_task = asyncio.create_task(
        server.api_send_file(_file_request(key="fd" * 16))
    )
    loop = asyncio.get_running_loop()
    started = loop.time()
    await asyncio.sleep(0.03)
    heartbeat_delay = loop.time() - started

    assert heartbeat_delay < 0.12
    assert not send_task.done(), "FULL-sync accounting did not run in a worker"
    response = await asyncio.wait_for(send_task, timeout=2.0)
    assert response.status == 202
    await asyncio.gather(*daemon.resume_tasks)
    await server.stop()
    state.close()


@pytest.mark.asyncio
async def test_stalled_multipart_file_times_out_cleans_file_and_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import one_link.server as server_module
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    monkeypatch.setattr(server_module, "UI_UPLOAD_IDLE_TIMEOUT_SECONDS", 0.02)
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint="bb" * 32,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="Receiver",
        trust_default="pinned",
    )
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    server = UIServer(daemon)
    request = _file_request(
        key="fb" * 16,
        payload=b"stalled upload",
        filename="stalled.bin",
    )
    for index, part in enumerate(request.parts):
        if part.name == "file":
            request.parts[index] = _StalledMultipartPart(
                "file",
                data=part._data,
                filename=part.filename,
            )
            break

    response = await asyncio.wait_for(server.api_send_file(request), timeout=1.0)
    assert response.status == 408
    assert json.loads(response.text)["code"] == "upload_idle_timeout"
    assert server._upload_reservations.snapshot() == ()
    uploads = tmp_path / "uploads"
    if uploads.exists():
        assert not list(uploads.glob("*stalled.bin"))
    await server.stop()
    state.close()


@pytest.mark.asyncio
async def test_real_aiohttp_multipart_boundary_and_utf8_metadata_round_trip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aiohttp import web
    from aiohttp.test_utils import TestClient, TestServer
    from one_link.server import UI_UPLOAD_REQUEST_MAX_BYTES, UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint="bb" * 32,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="Receiver",
        trust_default="pinned",
    )
    rel_path = "資料/über/intent.bin"

    class _Utf8Daemon(_CrashRecoveryDaemon):
        @staticmethod
        def _safe_transfer_rel_path(value):
            return value if value == rel_path else None

    daemon = _Utf8Daemon(state, root=tmp_path)
    server = UIServer(daemon)
    app = web.Application(client_max_size=UI_UPLOAD_REQUEST_MAX_BYTES)
    app.router.add_post("/api/send-file", server.api_send_file)
    client = TestClient(TestServer(app))
    await client.start_server()
    payload = b"real BodyPartReader browser-boundary proof"
    form = aiohttp.FormData()
    form.add_field("peer", "bbbbbbbb")
    form.add_field("client_delivery_id", "ac" * 16)
    form.add_field("rel_path", rel_path)
    form.add_field("chat_inline", "1")
    form.add_field("file_size", str(len(payload)))
    # The historical bug requested max_bytes+1 from read_chunk; this one-byte
    # part is shorter than an ordinary browser boundary and triggered aiohttp's
    # boundary-size assertion before the fixed 8192-byte read buffer.
    form.add_field("intent_metadata_complete", "1")
    form.add_field(
        "file",
        payload,
        filename="intent.bin",
        content_type="application/octet-stream",
    )
    try:
        response = await client.post("/api/send-file", data=form)
        body = await response.json()
        assert response.status == 202, body
        assert body["accepted"] is True
        rec = state.get_transfer(body["transfer_id"])
        assert rec is not None
        assert rec.metadata["delivery_rel_path"] == rel_path
        await asyncio.gather(*daemon.resume_tasks)
    finally:
        await client.close()
        await server.stop()
        state.close()


@pytest.mark.asyncio
async def test_real_aiohttp_oversized_metadata_stops_before_file_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aiohttp import web
    from aiohttp.test_utils import TestClient, TestServer
    from one_link.server import (
        UI_UPLOAD_METADATA_LIMITS,
        UI_UPLOAD_REQUEST_MAX_BYTES,
        UIServer,
    )
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    server = UIServer(daemon)
    app = web.Application(client_max_size=UI_UPLOAD_REQUEST_MAX_BYTES)
    app.router.add_post("/api/send-file", server.api_send_file)
    client = TestClient(TestServer(app))
    await client.start_server()
    form = aiohttp.FormData()
    form.add_field("peer", "x" * (UI_UPLOAD_METADATA_LIMITS["peer"] + 1))
    form.add_field(
        "file",
        b"must never reach server-side staging",
        filename="must-not-stage.bin",
        content_type="application/octet-stream",
    )
    try:
        response = await client.post("/api/send-file", data=form)
        assert response.status == 400
        assert daemon.queue_calls == []
        assert daemon.wire_sends == []
        assert server._upload_reservations.snapshot() == ()
        uploads = tmp_path / "uploads"
        assert not [
            path for path in uploads.rglob("*") if path.is_file()
        ]
    finally:
        await client.close()
        await server.stop()
        state.close()


@pytest.mark.asyncio
async def test_streaming_request_captures_one_principal_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint="bb" * 32,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="Receiver",
        trust_default="pinned",
    )
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    server = UIServer(daemon)
    scopes = ["session:" + "41" * 32, "token:" + "42" * 32]
    scope_calls: list[str] = []

    def _changing_scope(_request) -> str:
        value = scopes[len(scope_calls)]
        scope_calls.append(value)
        return value

    monkeypatch.setattr(server, "_ui_delivery_principal_scope", _changing_scope)
    key = "ad" * 16
    response = await server.api_send_file(_file_request(key=key))
    assert response.status == 202
    assert scope_calls == [scopes[0]]
    under_session = server._ui_delivery_idempotency.probe(
        principal_scope=scopes[0],
        client_delivery_id=key,
    )
    under_rotated_token = server._ui_delivery_idempotency.probe(
        principal_scope=scopes[1],
        client_delivery_id=key,
    )
    assert under_session is not None and under_session.is_replay
    assert under_rotated_token is None
    await asyncio.gather(*daemon.resume_tasks)
    await server.stop()
    state.close()


@pytest.mark.asyncio
async def test_upload_filename_is_wire_normalized_and_never_enters_staging_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint="bb" * 32,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="Receiver",
        trust_default="pinned",
    )
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    server = UIServer(daemon)
    key = "af" * 16

    response = await server.api_send_file(
        _file_request(
            key=key,
            filename=r"..\report.pdf:hidden.exe",
        )
    )
    body = json.loads(response.text)
    assert response.status == 202
    binding = server._ui_delivery_idempotency.probe(
        principal_scope="daemon:" + "aa" * 32,
        client_delivery_id=key,
    )
    assert binding is not None
    assert binding.contract.display_name == "report.pdf_hidden.exe"
    rec = state.get_transfer(body["transfer_id"])
    assert rec is not None
    assert rec.name == "report.pdf_hidden.exe"
    staging_name = Path(rec.metadata["path"]).name
    assert staging_name.endswith(".upload")
    assert "report" not in staging_name
    assert ":" not in staging_name

    await asyncio.gather(*daemon.resume_tasks)
    await server.stop()
    state.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("queued_before_crash", [False, True])
async def test_restart_reclaims_predispatch_http_intent_instead_of_stalling_forever(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    queued_before_crash: bool,
) -> None:
    from one_link.cdc import hash_path
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint="bb" * 32,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="Receiver",
        trust_default="pinned",
    )
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    payload = b"one durable browser intent"
    source = tmp_path / "intent.bin"
    source.write_bytes(payload)
    key = ("b1" if queued_before_crash else "b0") * 16

    first = UIServer(daemon)
    contract = UIDeliveryContract(
        peer_fp="bb" * 32,
        blob_hash=hash_path(source),
        size=len(payload),
        display_name="intent.bin",
        rel_path="proof/intent.bin",
        chat_inline=True,
    )
    abandoned = first._ui_delivery_idempotency.bind(
        principal_scope="daemon:" + "aa" * 32,
        client_delivery_id=key,
        contract=contract,
    )
    if queued_before_crash:
        rec = daemon.queue_file_transfer(
            peer_fp=contract.peer_fp,
            path=source,
            display_name=contract.display_name,
            chat_inline=contract.chat_inline,
            rel_path=contract.rel_path,
            schedule_resume=False,
            transfer_id=abandoned.transfer_id,
        )
        first._ui_delivery_idempotency.mark_queued(
            abandoned,
            delivery_id=rec.metadata["delivery_id"],
        )
    await first.stop()

    reconstructed = UIServer(daemon)
    retry_request = _file_request(key=key, payload=payload)
    retry_file_part = next(
        part for part in retry_request.parts if part.name == "file"
    )
    response = await reconstructed.api_send_file(retry_request)
    body = json.loads(response.text)

    assert response.status == 202
    assert body["accepted"] is True
    assert body["transfer_id"] == abandoned.transfer_id
    # An old pre-dispatch owner must consume and authenticate the retry body;
    # only a live same-process owner may use the zero-byte early shortcut.
    assert retry_file_part.read_calls > 0
    expected_queue_calls = 2 if queued_before_crash else 1
    assert daemon.queue_calls == [abandoned.transfer_id] * expected_queue_calls
    if queued_before_crash:
        assert not [
            path for path in (tmp_path / "uploads").glob("*") if path.is_file()
        ], "restart retry left a second complete staging copy"
    await asyncio.gather(*daemon.resume_tasks)
    assert daemon.wire_sends == [abandoned.transfer_id]
    await reconstructed.stop()
    state.close()


@pytest.mark.asyncio
async def test_cancellation_during_peer_resolution_removes_unowned_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint="bb" * 32,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="Receiver",
        trust_default="pinned",
    )
    started = asyncio.Event()

    class _BlockedResolver(_CrashRecoveryDaemon):
        async def resolve_for_send(self, _needle):
            started.set()
            await asyncio.Event().wait()

    daemon = _BlockedResolver(state, root=tmp_path)
    server = UIServer(daemon)
    task = asyncio.create_task(
        server.api_send_file(_file_request(key="b2" * 16))
    )
    await asyncio.wait_for(started.wait(), timeout=1.0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert server._upload_reservations.snapshot() == ()
    assert not [path for path in (tmp_path / "uploads").glob("*") if path.is_file()]
    await server.stop()
    state.close()


@pytest.mark.asyncio
async def test_cancellation_waits_for_preparation_worker_before_staging_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link.cdc import hash_path
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint="bb" * 32,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="Receiver",
        trust_default="pinned",
    )
    worker_started = threading.Event()
    release_worker = threading.Event()

    class _BlockedPreparation(_CrashRecoveryDaemon):
        def prepare_file_for_transfer(self, path, *, peer_fp=None):
            assert peer_fp == "bb" * 32
            worker_started.set()
            assert release_worker.wait(timeout=2.0)
            return SimpleNamespace(
                file_index=SimpleNamespace(blob_hash=hash_path(Path(path)))
            )

    daemon = _BlockedPreparation(state, root=tmp_path)
    server = UIServer(daemon)
    task = asyncio.create_task(
        server.api_send_file(_file_request(key="b3" * 16))
    )
    assert await asyncio.to_thread(worker_started.wait, 1.0)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done(), "cancellation escaped while the worker still read staging"
    release_worker.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=1.0)

    assert not [path for path in (tmp_path / "uploads").glob("*") if path.is_file()]
    await server.stop()
    state.close()


@pytest.mark.asyncio
async def test_cancellation_after_bind_commit_releases_only_completed_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint="bb" * 32,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="Receiver",
        trust_default="pinned",
    )
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    server = UIServer(daemon)
    original_bind = server._ui_delivery_idempotency.bind
    sync_finished = threading.Event()
    release_worker = threading.Event()

    def _bind_then_block(*, principal_scope, client_delivery_id, contract):
        result = original_bind(
            principal_scope=principal_scope,
            client_delivery_id=client_delivery_id,
            contract=contract,
        )
        sync_finished.set()
        assert release_worker.wait(timeout=2.0)
        return result

    monkeypatch.setattr(
        server._ui_delivery_idempotency,
        "bind",
        _bind_then_block,
    )
    key = "b5" * 16
    first_task = asyncio.create_task(
        server.api_send_file(_file_request(key=key))
    )
    assert await asyncio.to_thread(sync_finished.wait, 1.0)
    first_task.cancel()
    # Exercise the real double-cancellation shutdown/client-disconnect race.
    first_task.cancel()
    await asyncio.sleep(0)
    assert not first_task.done()
    release_worker.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(first_task, timeout=1.0)

    abandoned = server._ui_delivery_idempotency.probe(
        principal_scope="daemon:" + "aa" * 32,
        client_delivery_id=key,
    )
    assert abandoned is not None
    assert abandoned.phase == "bound"
    assert abandoned.reclaimable_before_dispatch is True
    assert not [path for path in (tmp_path / "uploads").glob("*") if path.is_file()]

    monkeypatch.setattr(
        server._ui_delivery_idempotency,
        "bind",
        original_bind,
    )
    retry = await server.api_send_file(_file_request(key=key))
    retry_body = json.loads(retry.text)
    assert retry.status == 202
    assert retry_body["accepted"] is True
    assert retry_body["transfer_id"] == abandoned.transfer_id
    assert daemon.queue_calls == [abandoned.transfer_id]
    await asyncio.gather(*daemon.resume_tasks)
    assert daemon.wire_sends == [abandoned.transfer_id]
    await server.stop()
    state.close()


@pytest.mark.asyncio
async def test_cancelled_duplicate_bind_never_releases_live_original_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint="bb" * 32,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="Receiver",
        trust_default="pinned",
    )
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    server = UIServer(daemon)
    original_bind = server._ui_delivery_idempotency.bind
    original_bound = threading.Event()
    duplicate_bound = threading.Event()
    release_original = threading.Event()
    release_duplicate = threading.Event()

    def _bind_then_block(*, principal_scope, client_delivery_id, contract):
        result = original_bind(
            principal_scope=principal_scope,
            client_delivery_id=client_delivery_id,
            contract=contract,
        )
        if result.owns_attempt:
            original_bound.set()
            assert release_original.wait(timeout=3.0)
        else:
            duplicate_bound.set()
            assert release_duplicate.wait(timeout=3.0)
        return result

    monkeypatch.setattr(
        server._ui_delivery_idempotency,
        "bind",
        _bind_then_block,
    )
    key = "b6" * 16

    def _legacy_request() -> _MultipartRequest:
        # Omitting the metadata-complete marker intentionally exercises the
        # full-body bind path for both concurrent requests.  The shipped UI's
        # prefix probe normally rejects the duplicate before reading bytes.
        return _MultipartRequest(
            [
                _MultipartPart("peer", text="bbbbbbbb"),
                _MultipartPart("client_delivery_id", text=key),
                _MultipartPart("rel_path", text="proof/intent.bin"),
                _MultipartPart("chat_inline", text="1"),
                _MultipartPart(
                    "file",
                    data=b"one durable browser intent",
                    filename="intent.bin",
                ),
            ]
        )

    original_task = asyncio.create_task(server.api_send_file(_legacy_request()))
    assert await asyncio.to_thread(original_bound.wait, 1.0)
    duplicate_task = asyncio.create_task(server.api_send_file(_legacy_request()))
    assert await asyncio.to_thread(duplicate_bound.wait, 1.0)
    duplicate_task.cancel()
    release_duplicate.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(duplicate_task, timeout=1.0)

    still_owned = server._ui_delivery_idempotency.probe(
        principal_scope="daemon:" + "aa" * 32,
        client_delivery_id=key,
    )
    assert still_owned is not None
    assert still_owned.phase == "bound"
    assert still_owned.reclaimable_before_dispatch is False

    release_original.set()
    response = await asyncio.wait_for(original_task, timeout=2.0)
    assert response.status == 202
    await asyncio.gather(*daemon.resume_tasks)
    assert daemon.queue_calls == [still_owned.transfer_id]
    assert daemon.wire_sends == [still_owned.transfer_id]
    await server.stop()
    state.close()


@pytest.mark.asyncio
async def test_cancellation_after_queued_full_sync_releases_owner_for_exact_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint="bb" * 32,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="Receiver",
        trust_default="pinned",
    )
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    server = UIServer(daemon)
    original_mark_queued = server._ui_delivery_idempotency.mark_queued
    sync_finished = threading.Event()
    release_worker = threading.Event()

    def _mark_then_block(binding, *, delivery_id):
        result = original_mark_queued(binding, delivery_id=delivery_id)
        sync_finished.set()
        assert release_worker.wait(timeout=2.0)
        return result

    monkeypatch.setattr(
        server._ui_delivery_idempotency,
        "mark_queued",
        _mark_then_block,
    )
    key = "b4" * 16
    first_task = asyncio.create_task(
        server.api_send_file(_file_request(key=key))
    )
    assert await asyncio.to_thread(sync_finished.wait, 1.0)
    first_task.cancel()
    await asyncio.sleep(0)
    assert not first_task.done()
    release_worker.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(first_task, timeout=1.0)

    abandoned = server._ui_delivery_idempotency.probe(
        principal_scope="daemon:" + "aa" * 32,
        client_delivery_id=key,
    )
    assert abandoned is not None
    assert abandoned.phase == "queued"
    assert abandoned.reclaimable_before_dispatch is True

    monkeypatch.setattr(
        server._ui_delivery_idempotency,
        "mark_queued",
        original_mark_queued,
    )
    retry = await server.api_send_file(_file_request(key=key))
    retry_body = json.loads(retry.text)
    assert retry.status == 202
    assert retry_body["accepted"] is True
    assert daemon.queue_calls == [abandoned.transfer_id, abandoned.transfer_id]
    await asyncio.gather(*daemon.resume_tasks)
    assert daemon.wire_sends == [abandoned.transfer_id]
    await server.stop()
    state.close()


@pytest.mark.asyncio
async def test_crash_after_dispatch_boundary_before_offer_reclaims_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint="bb" * 32,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="Receiver",
        trust_default="pinned",
    )
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    source = tmp_path / "intent.bin"
    payload = b"one durable browser intent"
    source.write_bytes(payload)
    key = "d1" * 16

    first = UIServer(daemon)
    dispatching, _rec = _prepare_dispatch_boundary(first, daemon, source, key=key)
    transfer_id = dispatching.transfer_id
    delivery_id = dispatching.delivery_id
    await first.stop()

    reconstructed = UIServer(daemon)
    response = await reconstructed.api_send_file(_file_request(key=key, payload=payload))
    body = json.loads(response.text)
    assert response.status == 202
    assert body["accepted"] is True
    assert body["background"] is True
    assert body["transfer_id"] == transfer_id
    assert body["delivery_id"] == delivery_id
    assert daemon.queue_calls == [transfer_id, transfer_id]
    await asyncio.gather(*daemon.resume_tasks)
    assert daemon.wire_sends == [transfer_id]

    replay = await reconstructed.api_send_file(_file_request(key=key, payload=payload))
    assert replay.status == 202
    assert json.loads(replay.text) == body
    assert daemon.wire_sends == [transfer_id]
    await reconstructed.stop()
    state.close()


@pytest.mark.asyncio
async def test_crash_after_commit_receipt_before_http_response_reconciles_and_replays(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint="bb" * 32,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="Receiver",
        trust_default="pinned",
    )
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    source = tmp_path / "intent.bin"
    payload = b"one durable browser intent"
    source.write_bytes(payload)
    key = "d2" * 16

    first = UIServer(daemon)
    dispatching, _rec = _prepare_dispatch_boundary(first, daemon, source, key=key)
    peer = await daemon.resolve_for_send("bbbbbbbb")
    await daemon.send_file(
        peer,
        source,
        transfer_id=dispatching.transfer_id,
        rel_path=dispatching.contract.rel_path,
        display_name=dispatching.contract.display_name,
        chat_inline=dispatching.contract.chat_inline,
    )
    assert daemon.wire_sends == [dispatching.transfer_id]
    await first.stop()

    reconstructed = UIServer(daemon)
    response = await reconstructed.api_send_file(_file_request(key=key, payload=payload))
    recovered = json.loads(response.text)
    assert response.status == 200
    assert recovered["transfer_id"] == dispatching.transfer_id
    assert recovered["delivery_id"] == dispatching.delivery_id
    assert recovered["result"]["confirmed"] is True
    assert recovered["result"]["recovered_from_ledger"] is True
    assert daemon.queue_calls == [dispatching.transfer_id]
    assert daemon.wire_sends == [dispatching.transfer_id]
    await reconstructed.stop()

    replay_server = UIServer(daemon)
    replay = await replay_server.api_send_file(_file_request(key=key, payload=payload))
    assert replay.status == 200
    assert json.loads(replay.text) == recovered
    assert daemon.queue_calls == [dispatching.transfer_id]
    assert daemon.wire_sends == [dispatching.transfer_id]
    await replay_server.stop()
    state.close()


@pytest.mark.asyncio
async def test_restart_reconciliation_rejects_changed_transfer_ledger_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint="bb" * 32,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="Receiver",
        trust_default="pinned",
    )
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    source = tmp_path / "intent.bin"
    payload = b"one durable browser intent"
    source.write_bytes(payload)
    key = "d3" * 16

    first = UIServer(daemon)
    dispatching, rec = _prepare_dispatch_boundary(first, daemon, source, key=key)
    changed_metadata = dict(rec.metadata)
    changed_metadata["delivery_id"] = "ee" * 16
    state.update_transfer(rec.id, metadata=changed_metadata)
    await first.stop()

    reconstructed = UIServer(daemon)
    response = await reconstructed.api_send_file(_file_request(key=key, payload=payload))
    assert response.status == 409
    assert json.loads(response.text)["code"] == "delivery_ledger_contract_conflict"
    assert daemon.queue_calls == [dispatching.transfer_id]
    assert daemon.wire_sends == []
    await reconstructed.stop()
    state.close()


@pytest.mark.asyncio
async def test_restart_reconciliation_state_failure_is_fail_closed_and_cleans_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint="bb" * 32,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="Receiver",
        trust_default="pinned",
    )
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    source = tmp_path / "intent.bin"
    payload = b"one durable browser intent"
    source.write_bytes(payload)
    key = "d4" * 16

    first = UIServer(daemon)
    dispatching, _rec = _prepare_dispatch_boundary(first, daemon, source, key=key)
    await first.stop()

    reconstructed = UIServer(daemon)
    original_get_transfer = state.get_transfer

    def _unavailable_transfer_ledger(_transfer_id):
        raise OSError("simulated state read failure")

    monkeypatch.setattr(state, "get_transfer", _unavailable_transfer_ledger)
    response = await reconstructed.api_send_file(
        _file_request(key=key, payload=payload)
    )
    body = json.loads(response.text)
    assert response.status == 503
    assert body["code"] == "delivery_outcome_unknown"
    assert body["outcome_unknown"] is True
    assert body["transfer_id"] == dispatching.transfer_id
    assert body["delivery_id"] == dispatching.delivery_id
    assert daemon.queue_calls == [dispatching.transfer_id]
    assert daemon.wire_sends == []
    assert not [path for path in (tmp_path / "uploads").glob("*") if path.is_file()]

    monkeypatch.setattr(state, "get_transfer", original_get_transfer)
    await reconstructed.stop()
    state.close()


@pytest.mark.asyncio
async def test_phone_client_msg_id_replays_lost_result_without_second_wire_send(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link.peer_rtc import BrowserPeer, PEER_DC_PROTOCOL_VERSION
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint="bb" * 32,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="Receiver",
        trust_default="pinned",
    )
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    server = UIServer(daemon)
    captured: list[dict] = []

    class _StubChannel:
        def send(self, data):
            captured.append(json.loads(data))

    phone = BrowserPeer(fingerprint="sha256:phone", pubkey_bytes=b"\x00" * 32)
    phone.control_dc = _StubChannel()
    server.peer_rtc.register_peer(phone)
    payload = b"phone idempotency proof"
    client_msg_id = "facefeed" * 4

    async def _upload_once(suffix: str, content: bytes = payload) -> dict:
        encoded = base64.urlsafe_b64encode(content).decode().rstrip("=")
        await server._handle_browser_peer_request(
            phone,
            "control",
            "send_file_init",
            {
                "v": PEER_DC_PROTOCOL_VERSION,
                "t": "send_file_init",
                "rid": f"init-{suffix}",
                "peer_fp": "bbbbbbbb",
                "filename": "intent.bin",
                "mime": "application/octet-stream",
                "size_bytes": len(content),
                "client_msg_id": client_msg_id,
            },
        )
        init_reply = dict(captured[-1])
        if init_reply.get("t") == "send_file_result":
            return init_reply
        upload_id = init_reply["upload_id"]
        await server._handle_browser_peer_request(
            phone,
            "control",
            "send_file_chunk",
            {
                "v": PEER_DC_PROTOCOL_VERSION,
                "t": "send_file_chunk",
                "rid": f"chunk-{suffix}",
                "upload_id": upload_id,
                "offset": 0,
                "data_b64": encoded,
            },
        )
        await server._handle_browser_peer_request(
            phone,
            "control",
            "send_file_complete",
            {
                "v": PEER_DC_PROTOCOL_VERSION,
                "t": "send_file_complete",
                "rid": f"complete-{suffix}",
                "upload_id": upload_id,
            },
        )
        return dict(captured[-1])

    first = await _upload_once("first")
    second = await _upload_once("retry")
    assert first["t"] == second["t"] == "send_file_result"
    assert first["transfer_id"] == second["transfer_id"]
    assert first["delivery_id"] == second["delivery_id"]
    assert first["client_msg_id"] == second["client_msg_id"] == client_msg_id
    assert first["rid"] == "complete-first"
    # A completed retry is re-staged until its content hash is known.  Only
    # then may the durable response be replayed; init metadata alone is not a
    # content identity.
    assert second["rid"] == "complete-retry"

    conflicting = await _upload_once("different-content", b"X" * len(payload))
    assert conflicting["t"] == "error"
    assert conflicting["code"] == "client_delivery_contract_conflict"
    await asyncio.gather(*daemon.resume_tasks)
    assert daemon.queue_calls == [first["transfer_id"]]
    assert daemon.wire_sends == [first["transfer_id"]]
    await server.stop()
    state.close()


@pytest.mark.asyncio
async def test_phone_upload_names_block_ads_reserved_devices_and_long_components(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link.peer_rtc import BrowserPeer, PEER_DC_PROTOCOL_VERSION
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint="bb" * 32,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="Receiver",
        trust_default="pinned",
    )
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    server = UIServer(daemon)
    captured: list[dict] = []

    class _StubChannel:
        def send(self, data):
            captured.append(json.loads(data))

    phone = BrowserPeer(fingerprint="sha256:name-audit", pubkey_bytes=b"\x01" * 32)
    phone.control_dc = _StubChannel()
    server.peer_rtc.register_peer(phone)
    cases = [
        (r"..\report.pdf:hidden.exe", "report.pdf_hidden.exe"),
        ("CON.txt", "_CON.txt"),
        ("CON.backup.txt", "_CON.backup.txt"),
        ("CLOCK$.trace", "_CLOCK$.trace"),
        ("COM¹.txt", "_COM¹.txt"),
        ('bad<>:"|?*.txt', "bad_______.txt"),
        ("report.\x01   ", "report"),
        ("\u202ereport.exe", "report.exe"),
        ("re\u0301sume\u0301.txt", "résumé.txt"),
        ("trailing-name...   ", "trailing-name"),
        ("x" * 1000 + ".archive.zip", None),
    ]
    for index, (filename, expected) in enumerate(cases):
        await server._handle_browser_peer_request(
            phone,
            "control",
            "send_file_init",
            {
                "v": PEER_DC_PROTOCOL_VERSION,
                "t": "send_file_init",
                "rid": f"name-{index}",
                "peer_fp": "bbbbbbbb",
                "filename": filename,
                "mime": "application/octet-stream",
                "size_bytes": 1,
                "client_msg_id": f"deadbeef{index:08x}",
            },
        )
        reply = captured[-1]
        assert reply["t"] == "send_file_init_ack"
        upload_id = str(reply["upload_id"])
        rec = server._phone_uploads[upload_id]
        normalized = str(rec["filename"])
        if expected is not None:
            assert normalized == expected
        else:
            assert normalized.endswith(".zip")
            assert len(normalized.encode("utf-8")) <= 240
        staging_name = Path(rec["path"]).name
        assert staging_name.endswith(".upload")
        assert ":" not in staging_name
        assert normalized not in staging_name
        assert await server._discard_phone_upload(upload_id)
    assert server._upload_reservations.snapshot() == ()
    await server.stop()
    state.close()


@pytest.mark.asyncio
async def test_phone_invalid_client_message_ids_fail_before_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link.peer_rtc import BrowserPeer, PEER_DC_PROTOCOL_VERSION
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    server = UIServer(daemon)
    captured: list[dict] = []

    class _StubChannel:
        def send(self, data):
            captured.append(json.loads(data))

    phone = BrowserPeer(fingerprint="sha256:invalid-id", pubkey_bytes=b"\x03" * 32)
    phone.control_dc = _StubChannel()
    server.peer_rtc.register_peer(phone)
    invalid_ids: list[object] = [
        True,
        12345678,
        "",
        "       ",
        "abcdefg",
        "g" * 32,
        "deadbeef!",
        "a" * 65,
    ]

    for index, invalid_id in enumerate(invalid_ids):
        await server._handle_browser_peer_request(
            phone,
            "control",
            "send_file_init",
            {
                "v": PEER_DC_PROTOCOL_VERSION,
                "t": "send_file_init",
                "rid": f"invalid-{index}",
                "peer_fp": "bbbbbbbb",
                "filename": "never-staged.bin",
                "mime": "application/octet-stream",
                "size_bytes": 1,
                "client_msg_id": invalid_id,
            },
        )
        assert captured[-1]["t"] == "error"
        assert captured[-1]["code"] == "bad_client_msg_id"

    invalid_names: list[object] = [
        {"not": "text"},
        ["not", "text"],
        "\ud800",
        "mixed\udfff.txt",
    ]
    for index, invalid_name in enumerate(invalid_names):
        await server._handle_browser_peer_request(
            phone,
            "control",
            "send_file_init",
            {
                "v": PEER_DC_PROTOCOL_VERSION,
                "t": "send_file_init",
                "rid": f"invalid-name-{index}",
                "peer_fp": "bbbbbbbb",
                "filename": invalid_name,
                "mime": "application/octet-stream",
                "size_bytes": 1,
                "client_msg_id": f"cafebabe{index:08x}",
            },
        )
        assert captured[-1]["t"] == "error"
        assert captured[-1]["code"] == "bad_filename"

    assert server._phone_uploads == {}
    assert server._upload_reservations.snapshot() == ()
    assert not list(tmp_path.rglob("*.upload"))
    await server.stop()
    state.close()


@pytest.mark.asyncio
async def test_phone_init_cancellation_closes_worker_opened_handle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link import server as server_module
    from one_link.peer_rtc import BrowserPeer, PEER_DC_PROTOCOL_VERSION
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    server = UIServer(daemon)
    captured: list[dict] = []

    class _StubChannel:
        def send(self, data):
            captured.append(json.loads(data))

    phone = BrowserPeer(fingerprint="sha256:init-cancel", pubkey_bytes=b"\x05" * 32)
    phone.control_dc = _StubChannel()
    server.peer_rtc.register_peer(phone)
    original_open = server_module._open_private_ui_upload
    open_started = threading.Event()
    release_open = threading.Event()
    opened_handles: list[object] = []

    def _blocked_open(*args, **kwargs):
        open_started.set()
        if not release_open.wait(timeout=2):
            raise TimeoutError("test did not release phone staging open")
        opened = original_open(*args, **kwargs)
        opened_handles.append(opened)
        return opened

    monkeypatch.setattr(server_module, "_open_private_ui_upload", _blocked_open)
    init_task = asyncio.create_task(
        server._handle_browser_peer_request(
            phone,
            "control",
            "send_file_init",
            {
                "v": PEER_DC_PROTOCOL_VERSION,
                "t": "send_file_init",
                "rid": "cancel-open",
                "peer_fp": "bbbbbbbb",
                "filename": "cancel-open.bin",
                "size_bytes": 32,
            },
        )
    )
    assert await asyncio.to_thread(open_started.wait, 1.0)
    init_task.cancel()
    init_task.cancel()
    release_open.set()
    with pytest.raises(asyncio.CancelledError):
        await init_task

    assert len(opened_handles) == 1
    assert bool(getattr(opened_handles[0], "closed", False))
    assert server._phone_uploads == {}
    assert server._upload_reservations.snapshot() == ()
    assert not list(tmp_path.rglob("*.upload"))
    assert captured == []
    await server.stop()
    state.close()


@pytest.mark.asyncio
async def test_concurrent_phone_init_reuses_one_staging_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link import server as server_module
    from one_link.peer_rtc import BrowserPeer, PEER_DC_PROTOCOL_VERSION
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint="bb" * 32,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="Receiver",
        trust_default="pinned",
    )
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    server = UIServer(daemon)
    captured: list[dict] = []

    class _StubChannel:
        def send(self, data):
            captured.append(json.loads(data))

    phone = BrowserPeer(fingerprint="sha256:init-race", pubkey_bytes=b"\x06" * 32)
    phone.control_dc = _StubChannel()
    server.peer_rtc.register_peer(phone)
    original_open = server_module._open_private_ui_upload
    open_started = threading.Event()
    release_open = threading.Event()
    open_calls = 0

    def _blocked_open(*args, **kwargs):
        nonlocal open_calls
        open_calls += 1
        open_started.set()
        if not release_open.wait(timeout=2):
            raise TimeoutError("test did not release phone staging open")
        return original_open(*args, **kwargs)

    monkeypatch.setattr(server_module, "_open_private_ui_upload", _blocked_open)
    stable_id = "9999aaaabbbbccccddddeeeeffff0000"

    def _envelope(rid: str, filename: str = "single.bin") -> dict:
        return {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "send_file_init",
            "rid": rid,
            "peer_fp": "bbbbbbbb",
            "filename": filename,
            "size_bytes": 64,
            "client_msg_id": stable_id,
        }

    first = asyncio.create_task(
        server._handle_browser_peer_request(
            phone, "control", "send_file_init", _envelope("first")
        )
    )
    assert await asyncio.to_thread(open_started.wait, 1.0)
    second = asyncio.create_task(
        server._handle_browser_peer_request(
            phone, "control", "send_file_init", _envelope("second")
        )
    )
    await asyncio.sleep(0.03)
    assert open_calls == 1
    assert len(server._upload_reservations.snapshot()) == 1
    release_open.set()
    await asyncio.gather(first, second)

    replies = {reply["rid"]: reply for reply in captured}
    assert replies["first"]["t"] == replies["second"]["t"] == "send_file_init_ack"
    assert replies["first"]["upload_id"] == replies["second"]["upload_id"]
    assert replies["second"]["resumed"] is True
    assert open_calls == 1
    assert len(server._phone_uploads) == 1
    assert len(list(tmp_path.rglob("*.upload"))) == 1

    captured.clear()
    await server._handle_browser_peer_request(
        phone,
        "control",
        "send_file_init",
        _envelope("conflict", filename="different.bin"),
    )
    assert captured[-1]["code"] == "client_delivery_contract_conflict"
    upload_id = replies["first"]["upload_id"]
    assert await server._discard_phone_upload(upload_id)
    await server.stop()
    state.close()


@pytest.mark.asyncio
async def test_phone_chunk_cancelled_after_write_replays_ack_without_duplication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link.peer_rtc import BrowserPeer, PEER_DC_PROTOCOL_VERSION
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    server = UIServer(daemon)
    captured: list[dict] = []

    class _StubChannel:
        def send(self, data):
            captured.append(json.loads(data))

    phone = BrowserPeer(fingerprint="sha256:chunk-replay", pubkey_bytes=b"\x04" * 32)
    phone.control_dc = _StubChannel()
    server.peer_rtc.register_peer(phone)
    payload = b"lost chunk acknowledgement must not duplicate bytes"
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    await server._handle_browser_peer_request(
        phone,
        "control",
        "send_file_init",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "send_file_init",
            "rid": "chunk-init",
            "peer_fp": "bbbbbbbb",
            "filename": "chunk.bin",
            "size_bytes": len(payload),
        },
    )
    upload_id = str(captured[-1]["upload_id"])
    rec = server._phone_uploads[upload_id]
    original_handle = rec["fh"]
    write_started = threading.Event()
    release_write = threading.Event()

    class _BlockingHandle:
        def __init__(self) -> None:
            self.write_calls = 0

        def write(self, data: bytes) -> int:
            self.write_calls += 1
            write_started.set()
            if not release_write.wait(timeout=2):
                raise TimeoutError("test did not release the phone chunk write")
            return int(original_handle.write(data))

        def __getattr__(self, name: str):
            return getattr(original_handle, name)

    blocking_handle = _BlockingHandle()
    rec["fh"] = blocking_handle
    chunk_envelope = {
        "v": PEER_DC_PROTOCOL_VERSION,
        "t": "send_file_chunk",
        "rid": "chunk-first",
        "upload_id": upload_id,
        "offset": 0,
        "data_b64": encoded,
    }
    chunk_task = asyncio.create_task(
        server._handle_browser_peer_request(
            phone,
            "control",
            "send_file_chunk",
            chunk_envelope,
        )
    )
    assert await asyncio.to_thread(write_started.wait, 1.0)

    loop = asyncio.get_running_loop()
    heartbeat_started = loop.time()
    await asyncio.sleep(0.03)
    assert loop.time() - heartbeat_started < 0.12
    assert not chunk_task.done(), "phone chunk write blocked the event loop"
    chunk_task.cancel()
    release_write.set()
    with pytest.raises(asyncio.CancelledError):
        await chunk_task

    assert rec["received_size"] == len(payload)
    assert blocking_handle.write_calls == 1
    captured.clear()
    await server._handle_browser_peer_request(
        phone,
        "control",
        "send_file_chunk",
        {**chunk_envelope, "rid": "chunk-retry"},
    )
    assert captured[-1]["t"] == "send_file_chunk_ack"
    assert captured[-1]["received_size"] == len(payload)
    assert captured[-1]["replayed"] is True
    assert blocking_handle.write_calls == 1

    # Reusing the accepted offset with different bytes is never treated as a
    # retry and cannot mutate the staged payload.
    captured.clear()
    conflicting = base64.urlsafe_b64encode(b"x" * len(payload)).decode().rstrip("=")
    await server._handle_browser_peer_request(
        phone,
        "control",
        "send_file_chunk",
        {
            **chunk_envelope,
            "rid": "chunk-conflict",
            "data_b64": conflicting,
        },
    )
    assert captured[-1]["t"] == "error"
    assert captured[-1]["code"] == "offset_mismatch"
    assert blocking_handle.write_calls == 1
    assert await server._discard_phone_upload(upload_id)
    await server.stop()
    state.close()


@pytest.mark.asyncio
async def test_phone_chunk_receipt_window_replays_non_tail_ack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link.peer_rtc import BrowserPeer, PEER_DC_PROTOCOL_VERSION
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    server = UIServer(daemon)
    captured: list[dict] = []

    class _StubChannel:
        def send(self, data):
            captured.append(json.loads(data))

    phone = BrowserPeer(fingerprint="sha256:receipt-window", pubkey_bytes=b"\x07" * 32)
    phone.control_dc = _StubChannel()
    server.peer_rtc.register_peer(phone)
    chunks = [b"a" * 32, b"b" * 32, b"c" * 32]
    await server._handle_browser_peer_request(
        phone,
        "control",
        "send_file_init",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "send_file_init",
            "rid": "window-init",
            "peer_fp": "bbbbbbbb",
            "filename": "window.bin",
            "size_bytes": sum(map(len, chunks)),
        },
    )
    upload_id = captured[-1]["upload_id"]
    offset = 0
    for index, chunk in enumerate(chunks):
        await server._handle_browser_peer_request(
            phone,
            "control",
            "send_file_chunk",
            {
                "v": PEER_DC_PROTOCOL_VERSION,
                "t": "send_file_chunk",
                "rid": f"window-{index}",
                "upload_id": upload_id,
                "offset": offset,
                "data_b64": base64.urlsafe_b64encode(chunk).decode().rstrip("="),
            },
        )
        offset += len(chunk)

    captured.clear()
    await server._handle_browser_peer_request(
        phone,
        "control",
        "send_file_chunk",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "send_file_chunk",
            "rid": "lost-first-ack-retry",
            "upload_id": upload_id,
            "offset": 0,
            "data_b64": base64.urlsafe_b64encode(chunks[0]).decode().rstrip("="),
        },
    )
    assert captured[-1]["t"] == "send_file_chunk_ack"
    assert captured[-1]["replayed"] is True
    assert captured[-1]["received_size"] == sum(map(len, chunks))
    rec = server._phone_uploads[upload_id]
    assert rec["received_size"] == sum(map(len, chunks))
    assert rec["fh"].tell() == sum(map(len, chunks))
    assert await server._discard_phone_upload(upload_id)
    await server.stop()
    state.close()


@pytest.mark.asyncio
async def test_phone_cancel_during_finalization_returns_explicit_too_late(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link import server as server_module
    from one_link.peer_rtc import BrowserPeer, PEER_DC_PROTOCOL_VERSION
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    server = UIServer(daemon)
    captured: list[dict] = []

    class _StubChannel:
        def send(self, data):
            captured.append(json.loads(data))

    phone = BrowserPeer(fingerprint="sha256:finalizing", pubkey_bytes=b"\x08" * 32)
    phone.control_dc = _StubChannel()
    server.peer_rtc.register_peer(phone)
    payload = b"explicit cancellation boundary"
    await server._handle_browser_peer_request(
        phone,
        "control",
        "send_file_init",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "send_file_init",
            "rid": "final-init",
            "peer_fp": "bbbbbbbb",
            "filename": "final.bin",
            "size_bytes": len(payload),
        },
    )
    upload_id = captured[-1]["upload_id"]
    await server._handle_browser_peer_request(
        phone,
        "control",
        "send_file_chunk",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "send_file_chunk",
            "rid": "final-chunk",
            "upload_id": upload_id,
            "offset": 0,
            "data_b64": base64.urlsafe_b64encode(payload).decode().rstrip("="),
        },
    )
    original_flush = server_module._durably_flush_ui_upload
    flush_started = threading.Event()
    release_flush = threading.Event()

    def _blocked_flush(handle, path):
        flush_started.set()
        if not release_flush.wait(timeout=2):
            raise TimeoutError("test did not release finalization")
        return original_flush(handle, path)

    monkeypatch.setattr(server_module, "_durably_flush_ui_upload", _blocked_flush)
    complete_task = asyncio.create_task(
        server._handle_browser_peer_request(
            phone,
            "control",
            "send_file_complete",
            {
                "v": PEER_DC_PROTOCOL_VERSION,
                "t": "send_file_complete",
                "rid": "final-complete",
                "upload_id": upload_id,
            },
        )
    )
    assert await asyncio.to_thread(flush_started.wait, 1.0)
    await server._handle_browser_peer_request(
        phone,
        "control",
        "send_file_cancel",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "send_file_cancel",
            "rid": "final-cancel",
            "upload_id": upload_id,
        },
    )
    cancel_reply = next(reply for reply in captured if reply.get("rid") == "final-cancel")
    assert cancel_reply["code"] == "upload_finalizing"
    assert cancel_reply["too_late"] is True
    assert upload_id in server._phone_finalizing_uploads
    release_flush.set()
    await complete_task
    assert upload_id not in server._phone_finalizing_uploads
    await server.stop()
    state.close()


@pytest.mark.asyncio
async def test_phone_periodic_sweeper_reclaims_idle_upload_without_new_traffic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link import server as server_module
    from one_link.peer_rtc import BrowserPeer, PEER_DC_PROTOCOL_VERSION
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    monkeypatch.setattr(server_module, "PHONE_UPLOAD_SWEEP_INTERVAL_SECONDS", 0.01)
    state = State(db_path=tmp_path / "state.db")
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    server = UIServer(daemon)
    captured: list[dict] = []

    class _StubChannel:
        def send(self, data):
            captured.append(json.loads(data))

    phone = BrowserPeer(fingerprint="sha256:periodic", pubkey_bytes=b"\x09" * 32)
    phone.control_dc = _StubChannel()
    server.peer_rtc.register_peer(phone)
    await server._handle_browser_peer_request(
        phone,
        "control",
        "send_file_init",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "send_file_init",
            "rid": "periodic-init",
            "peer_fp": "bbbbbbbb",
            "filename": "abandoned.bin",
            "size_bytes": 128,
        },
    )
    upload_id = captured[-1]["upload_id"]
    path = Path(server._phone_uploads[upload_id]["path"])
    server._phone_uploads[upload_id]["last_chunk_ms"] = 0
    server._phone_upload_sweeper_task = asyncio.create_task(
        server._phone_upload_sweeper_loop()
    )
    for _ in range(50):
        if (
            upload_id not in server._phone_uploads
            and not path.exists()
            and server._upload_reservations.snapshot() == ()
        ):
            break
        await asyncio.sleep(0.01)
    assert upload_id not in server._phone_uploads
    assert not path.exists()
    assert server._upload_reservations.snapshot() == ()
    await server.stop()
    state.close()


@pytest.mark.asyncio
async def test_server_stop_cancels_and_awaits_phone_ingress_before_store_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link import server as server_module
    from one_link.peer_rtc import BrowserPeer, PEER_DC_PROTOCOL_VERSION
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    server = UIServer(daemon)

    class _StubChannel:
        def send(self, _data):
            return None

    phone = BrowserPeer(fingerprint="sha256:shutdown", pubkey_bytes=b"\x0a" * 32)
    phone.control_dc = _StubChannel()
    server.peer_rtc.register_peer(phone)
    original_open = server_module._open_private_ui_upload
    open_started = threading.Event()
    release_open = threading.Event()

    def _blocked_open(*args, **kwargs):
        open_started.set()
        if not release_open.wait(timeout=2):
            raise TimeoutError("test did not release shutdown staging open")
        return original_open(*args, **kwargs)

    monkeypatch.setattr(server_module, "_open_private_ui_upload", _blocked_open)
    server._schedule_peer_dc_dispatch(
        phone,
        "control",
        json.dumps({
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "send_file_init",
            "rid": "shutdown-init",
            "peer_fp": "bbbbbbbb",
            "filename": "shutdown.bin",
            "size_bytes": 64,
        }),
    )
    assert await asyncio.to_thread(open_started.wait, 1.0)
    stop_task = asyncio.create_task(server.stop())
    await asyncio.sleep(0.03)
    assert not stop_task.done(), "stop did not await the ingress worker ownership barrier"
    release_open.set()
    await asyncio.wait_for(stop_task, timeout=2.0)

    assert server._peer_dc_tasks == set()
    assert server._phone_uploads == {}
    assert server._phone_upload_intents == {}
    assert server._upload_reservations.snapshot() == ()
    assert not list(tmp_path.rglob("*.upload"))
    state.close()


@pytest.mark.asyncio
async def test_same_phone_client_id_is_separated_by_authenticated_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link.peer_rtc import BrowserPeer, PEER_DC_PROTOCOL_VERSION
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint="bb" * 32,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="Receiver",
        trust_default="pinned",
    )
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    server = UIServer(daemon)
    captures: dict[str, list[dict]] = {"a": [], "b": []}

    class _StubChannel:
        def __init__(self, bucket: list[dict]) -> None:
            self.bucket = bucket

        def send(self, data) -> None:
            self.bucket.append(json.loads(data))

    phones = {
        "a": BrowserPeer(fingerprint="sha256:phone-a", pubkey_bytes=b"\x0a" * 32),
        "b": BrowserPeer(fingerprint="sha256:phone-b", pubkey_bytes=b"\x0b" * 32),
    }
    for label, phone in phones.items():
        phone.control_dc = _StubChannel(captures[label])
        server.peer_rtc.register_peer(phone)

    payload = b"same counter on two authenticated phones"
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    client_msg_id = "01234567-89ab-cdef-0123-456789abcdef"

    async def _upload(label: str) -> dict:
        phone = phones[label]
        captured = captures[label]
        await server._handle_browser_peer_request(
            phone,
            "control",
            "send_file_init",
            {
                "v": PEER_DC_PROTOCOL_VERSION,
                "t": "send_file_init",
                "rid": f"init-{label}",
                "peer_fp": "bbbbbbbb",
                "filename": "same.bin",
                "mime": "application/octet-stream",
                "size_bytes": len(payload),
                "client_msg_id": client_msg_id,
            },
        )
        upload_id = captured[-1]["upload_id"]
        await server._handle_browser_peer_request(
            phone,
            "control",
            "send_file_chunk",
            {
                "v": PEER_DC_PROTOCOL_VERSION,
                "t": "send_file_chunk",
                "rid": f"chunk-{label}",
                "upload_id": upload_id,
                "offset": 0,
                "data_b64": encoded,
            },
        )
        await server._handle_browser_peer_request(
            phone,
            "control",
            "send_file_complete",
            {
                "v": PEER_DC_PROTOCOL_VERSION,
                "t": "send_file_complete",
                "rid": f"complete-{label}",
                "upload_id": upload_id,
            },
        )
        return dict(captured[-1])

    first = await _upload("a")
    second = await _upload("b")
    await asyncio.gather(*daemon.resume_tasks)
    assert first["t"] == second["t"] == "send_file_result"
    assert first["transfer_id"] != second["transfer_id"]
    assert daemon.queue_calls == [first["transfer_id"], second["transfer_id"]]
    assert daemon.wire_sends == [first["transfer_id"], second["transfer_id"]]
    await server.stop()
    state.close()


@pytest.mark.asyncio
async def test_phone_cancellation_after_bind_commit_releases_and_cleans_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link.peer_rtc import BrowserPeer, PEER_DC_PROTOCOL_VERSION
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint="bb" * 32,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="Receiver",
        trust_default="pinned",
    )
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    server = UIServer(daemon)
    captured: list[dict] = []

    class _StubChannel:
        def send(self, data) -> None:
            captured.append(json.loads(data))

    source_fp = "sha256:phone-cancel"
    phone = BrowserPeer(fingerprint=source_fp, pubkey_bytes=b"\x0c" * 32)
    phone.control_dc = _StubChannel()
    server.peer_rtc.register_peer(phone)
    payload = b"phone cancellation durability proof"
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    client_msg_id = "cafebabecafebabecafebabecafebabe"

    async def _stage(suffix: str) -> str:
        await server._handle_browser_peer_request(
            phone,
            "control",
            "send_file_init",
            {
                "v": PEER_DC_PROTOCOL_VERSION,
                "t": "send_file_init",
                "rid": f"init-{suffix}",
                "peer_fp": "bbbbbbbb",
                "filename": "cancel.bin",
                "mime": "application/octet-stream",
                "size_bytes": len(payload),
                "client_msg_id": client_msg_id,
            },
        )
        upload_id = str(captured[-1]["upload_id"])
        await server._handle_browser_peer_request(
            phone,
            "control",
            "send_file_chunk",
            {
                "v": PEER_DC_PROTOCOL_VERSION,
                "t": "send_file_chunk",
                "rid": f"chunk-{suffix}",
                "upload_id": upload_id,
                "offset": 0,
                "data_b64": encoded,
            },
        )
        return upload_id

    first_upload_id = await _stage("first")
    original_bind = server._ui_delivery_idempotency.bind
    bind_committed = threading.Event()
    release_bind = threading.Event()

    def _bind_then_block(*, principal_scope, client_delivery_id, contract):
        binding = original_bind(
            principal_scope=principal_scope,
            client_delivery_id=client_delivery_id,
            contract=contract,
        )
        bind_committed.set()
        assert release_bind.wait(timeout=2.0)
        return binding

    monkeypatch.setattr(server._ui_delivery_idempotency, "bind", _bind_then_block)
    complete_task = asyncio.create_task(
        server._handle_browser_peer_request(
            phone,
            "control",
            "send_file_complete",
            {
                "v": PEER_DC_PROTOCOL_VERSION,
                "t": "send_file_complete",
                "rid": "complete-first",
                "upload_id": first_upload_id,
            },
        )
    )
    assert await asyncio.to_thread(bind_committed.wait, 1.0)
    complete_task.cancel()
    complete_task.cancel()
    await asyncio.sleep(0)
    assert not complete_task.done()
    release_bind.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(complete_task, timeout=1.0)

    mapped_id = server._ui_delivery_idempotency.derive_client_delivery_id(
        namespace=(
            "phone-file:" + hashlib.sha256(source_fp.encode("utf-8")).hexdigest()
        ),
        value=client_msg_id,
    )
    abandoned = server._ui_delivery_idempotency.probe(
        principal_scope=f"phone:{source_fp}",
        client_delivery_id=mapped_id,
    )
    assert abandoned is not None
    assert abandoned.phase == "bound"
    assert abandoned.reclaimable_before_dispatch is True
    assert server._upload_reservations.snapshot() == ()
    assert not [path for path in (tmp_path / "uploads").glob("*") if path.is_file()]
    assert daemon.queue_calls == []

    monkeypatch.setattr(server._ui_delivery_idempotency, "bind", original_bind)
    retry_upload_id = await _stage("retry")
    await server._handle_browser_peer_request(
        phone,
        "control",
        "send_file_complete",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "send_file_complete",
            "rid": "complete-retry",
            "upload_id": retry_upload_id,
        },
    )
    result = captured[-1]
    assert result["t"] == "send_file_result"
    assert result["transfer_id"] == abandoned.transfer_id
    await asyncio.gather(*daemon.resume_tasks)
    assert daemon.queue_calls == [abandoned.transfer_id]
    assert daemon.wire_sends == [abandoned.transfer_id]
    await server.stop()
    state.close()


@pytest.mark.asyncio
async def test_phone_complete_slow_queue_never_blocks_event_loop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link.peer_rtc import BrowserPeer, PEER_DC_PROTOCOL_VERSION
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint="bb" * 32,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="Receiver",
        trust_default="pinned",
    )
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    original_queue = daemon.queue_file_transfer
    queue_started = threading.Event()

    def _slow_queue(**kwargs):
        queue_started.set()
        time.sleep(0.25)
        return original_queue(**kwargs)

    monkeypatch.setattr(daemon, "queue_file_transfer", _slow_queue)
    server = UIServer(daemon)
    captured: list[dict] = []

    class _StubChannel:
        def send(self, data) -> None:
            captured.append(json.loads(data))

    phone = BrowserPeer(fingerprint="sha256:phone-slow", pubkey_bytes=b"\x0d" * 32)
    phone.control_dc = _StubChannel()
    server.peer_rtc.register_peer(phone)
    payload = b"event loop heartbeat"
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    await server._handle_browser_peer_request(
        phone,
        "control",
        "send_file_init",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "send_file_init",
            "rid": "init",
            "peer_fp": "bbbbbbbb",
            "filename": "heartbeat.bin",
            "mime": "application/octet-stream",
            "size_bytes": len(payload),
            "client_msg_id": "abcdabcdabcdabcdabcdabcdabcdabcd",
        },
    )
    upload_id = captured[-1]["upload_id"]
    await server._handle_browser_peer_request(
        phone,
        "control",
        "send_file_chunk",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "send_file_chunk",
            "rid": "chunk",
            "upload_id": upload_id,
            "offset": 0,
            "data_b64": encoded,
        },
    )
    complete_task = asyncio.create_task(
        server._handle_browser_peer_request(
            phone,
            "control",
            "send_file_complete",
            {
                "v": PEER_DC_PROTOCOL_VERSION,
                "t": "send_file_complete",
                "rid": "complete",
                "upload_id": upload_id,
            },
        )
    )
    assert await asyncio.to_thread(queue_started.wait, 1.0)
    loop = asyncio.get_running_loop()
    started = loop.time()
    await asyncio.sleep(0.03)
    heartbeat_delay = loop.time() - started

    assert heartbeat_delay < 0.12
    assert not complete_task.done(), "phone queue admission did not run in a worker"
    await asyncio.wait_for(complete_task, timeout=1.0)
    assert captured[-1]["t"] == "send_file_result"
    await asyncio.gather(*daemon.resume_tasks)
    await server.stop()
    state.close()


@pytest.mark.asyncio
async def test_phone_restart_reconciles_commit_receipt_without_second_wire_send(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link.cdc import hash_path
    from one_link.peer_rtc import BrowserPeer, PEER_DC_PROTOCOL_VERSION
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint="bb" * 32,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="Receiver",
        trust_default="pinned",
    )
    daemon = _CrashRecoveryDaemon(state, root=tmp_path)
    source_fp = "sha256:phone-restart"
    client_msg_id = "eeeeffffeeeeffffeeeeffffeeeeffff"
    payload = b"phone commit receipt crash recovery"
    source = tmp_path / "phone-original.upload"
    source.write_bytes(payload)

    first = UIServer(daemon)
    mapped_id = first._ui_delivery_idempotency.derive_client_delivery_id(
        namespace=(
            "phone-file:" + hashlib.sha256(source_fp.encode("utf-8")).hexdigest()
        ),
        value=client_msg_id,
    )
    contract = UIDeliveryContract(
        peer_fp="bb" * 32,
        blob_hash=hash_path(source),
        size=len(payload),
        display_name="phone-proof.bin",
        rel_path="",
        chat_inline=False,
    )
    binding = first._ui_delivery_idempotency.bind(
        principal_scope=f"phone:{source_fp}",
        client_delivery_id=mapped_id,
        contract=contract,
    )
    rec = daemon.queue_file_transfer(
        peer_fp=contract.peer_fp,
        path=source,
        display_name=contract.display_name,
        chat_inline=contract.chat_inline,
        rel_path=contract.rel_path,
        schedule_resume=False,
        transfer_id=binding.transfer_id,
    )
    queued = first._ui_delivery_idempotency.mark_queued(
        binding,
        delivery_id=rec.metadata["delivery_id"],
    )
    dispatching = first._ui_delivery_idempotency.mark_dispatching(queued)
    peer = await daemon.resolve_for_send("bbbbbbbb")
    await daemon.send_file(
        peer,
        source,
        transfer_id=dispatching.transfer_id,
        rel_path=dispatching.contract.rel_path,
        display_name=dispatching.contract.display_name,
        chat_inline=dispatching.contract.chat_inline,
    )
    assert daemon.wire_sends == [dispatching.transfer_id]
    await first.stop()

    reconstructed = UIServer(daemon)
    captured: list[dict] = []

    class _StubChannel:
        def send(self, data) -> None:
            captured.append(json.loads(data))

    phone = BrowserPeer(fingerprint=source_fp, pubkey_bytes=b"\x0e" * 32)
    phone.control_dc = _StubChannel()
    reconstructed.peer_rtc.register_peer(phone)
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")

    async def _retry(suffix: str) -> dict:
        await reconstructed._handle_browser_peer_request(
            phone,
            "control",
            "send_file_init",
            {
                "v": PEER_DC_PROTOCOL_VERSION,
                "t": "send_file_init",
                "rid": f"init-{suffix}",
                "peer_fp": "bbbbbbbb",
                "filename": contract.display_name,
                "mime": "application/octet-stream",
                "size_bytes": len(payload),
                "client_msg_id": client_msg_id,
            },
        )
        init_reply = dict(captured[-1])
        if init_reply.get("t") == "send_file_result":
            return init_reply
        upload_id = init_reply["upload_id"]
        await reconstructed._handle_browser_peer_request(
            phone,
            "control",
            "send_file_chunk",
            {
                "v": PEER_DC_PROTOCOL_VERSION,
                "t": "send_file_chunk",
                "rid": f"chunk-{suffix}",
                "upload_id": upload_id,
                "offset": 0,
                "data_b64": encoded,
            },
        )
        await reconstructed._handle_browser_peer_request(
            phone,
            "control",
            "send_file_complete",
            {
                "v": PEER_DC_PROTOCOL_VERSION,
                "t": "send_file_complete",
                "rid": f"complete-{suffix}",
                "upload_id": upload_id,
            },
        )
        return dict(captured[-1])

    recovered = await _retry("recovery")
    assert recovered["t"] == "send_file_result"
    assert recovered["transfer_id"] == dispatching.transfer_id
    assert recovered["delivery_id"] == dispatching.delivery_id
    assert recovered["result"]["confirmed"] is True
    assert recovered["result"]["recovered_from_ledger"] is True
    assert daemon.queue_calls == [dispatching.transfer_id]
    assert daemon.wire_sends == [dispatching.transfer_id]

    replay = await _retry("replay")
    assert replay["transfer_id"] == recovered["transfer_id"]
    assert replay["result"] == recovered["result"]
    assert daemon.queue_calls == [dispatching.transfer_id]
    assert daemon.wire_sends == [dispatching.transfer_id]
    await reconstructed.stop()
    state.close()
