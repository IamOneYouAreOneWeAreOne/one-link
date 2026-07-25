"""Adversarial proofs for upload ownership and offline CAS collection."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from one_link.blobstore import BlobStore
from one_link.state import State
from one_link import storage_lifecycle as lifecycle
from scripts import storage_gc


def _state(tmp_path: Path) -> State:
    data = tmp_path / "data"
    data.mkdir()
    return State(data / "state.db")


def _upload(state: State, name: str, body: bytes = b"upload") -> Path:
    path = Path(state.db_path).parent / "uploads" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    return path


def _transfer(
    state: State,
    transfer_id: str,
    path: Path,
    *,
    status: str = "complete",
    blob_hash: str | None = None,
) -> None:
    state.upsert_transfer(
        id=transfer_id,
        direction="out",
        peer_fp="peer",
        kind="file",
        name=path.name,
        size=path.stat().st_size,
        blob_hash=blob_hash,
        status=status,
        metadata={"path": str(path)},
    )


def _blob(store: BlobStore, body: bytes) -> tuple[str, Path]:
    digest = store.put_bytes(body)
    return digest, store.path(digest)


def _manifest(state: State, store: BlobStore, *, batch_limit: int = 100) -> dict:
    return lifecycle.build_cas_gc_manifest(
        state,
        store.root,
        now_ms=int(time.time() * 1000) + 10_000,
        grace_ms=0,
        batch_limit=batch_limit,
    )


def test_delete_last_terminal_reference_reclaims_owned_upload(tmp_path: Path) -> None:
    state = _state(tmp_path)
    try:
        path = _upload(state, "only.bin")
        _transfer(state, "out:only", path)

        assert state.delete_transfer("out:only") is True
        assert not path.exists()
    finally:
        state.close()


def test_shared_upload_survives_until_last_terminal_reference(tmp_path: Path) -> None:
    state = _state(tmp_path)
    try:
        path = _upload(state, "shared.bin")
        _transfer(state, "out:a", path)
        _transfer(state, "out:b", path)

        assert state.delete_transfer("out:a") is True
        assert path.is_file()
        assert state.delete_transfer("out:b") is True
        assert not path.exists()
    finally:
        state.close()


def test_startup_reclaims_only_aged_unreferenced_phone_staging(tmp_path: Path) -> None:
    state = _state(tmp_path)
    try:
        now_ms = 2_000_000_000_000
        old = _upload(
            state,
            "1999999000000_11111111111111111111111111111111.upload",
            b"old orphan",
        )
        recent = _upload(
            state,
            "2000000000000_22222222222222222222222222222222.upload",
            b"recent staging",
        )
        durable = _upload(
            state,
            "1999999000000_33333333333333333333333333333333.upload",
            b"durable queue source",
        )
        unrelated = _upload(state, "user-file.upload", b"not server minted")
        old_seconds = (now_ms - 10 * 60 * 1000) / 1000
        recent_seconds = (now_ms - 10 * 1000) / 1000
        os.utime(old, (old_seconds, old_seconds))
        os.utime(durable, (old_seconds, old_seconds))
        os.utime(recent, (recent_seconds, recent_seconds))
        _transfer(state, "out:durable-phone-source", durable, status="queued")

        result = lifecycle.reclaim_stale_unreferenced_phone_uploads(
            state,
            grace_ms=5 * 60 * 1000,
            now_ms=now_ms,
        )

        assert result.errors == ()
        assert result.removed == (str(old),)
        assert not old.exists()
        assert recent.is_file()
        assert durable.is_file()
        assert unrelated.is_file()
    finally:
        state.close()


@pytest.mark.parametrize("status", ["queued", "offered", "active", "paused"])
def test_nonterminal_transfer_is_not_deletable_or_reclaimed(
    tmp_path: Path,
    status: str,
) -> None:
    state = _state(tmp_path)
    try:
        path = _upload(state, f"{status}.bin")
        _transfer(state, f"out:{status}", path, status=status)

        assert state.delete_transfer(f"out:{status}") is False
        assert state.get_transfer(f"out:{status}") is not None
        assert path.is_file()
    finally:
        state.close()


@pytest.mark.parametrize("placement", ["outside", "inbox", "traversal"])
def test_transfer_cleanup_never_unlinks_unowned_paths(
    tmp_path: Path,
    placement: str,
) -> None:
    state = _state(tmp_path)
    try:
        data = Path(state.db_path).parent
        if placement == "outside":
            path = tmp_path / "user-original.bin"
        elif placement == "inbox":
            path = data / "inbox" / "received.bin"
        else:
            path = data / "uploads" / ".." / "escaped.bin"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"preserve me")
        _transfer(state, f"out:{placement}", path)

        assert state.delete_transfer(f"out:{placement}") is True
        assert path.is_file()
    finally:
        state.close()


def test_symlink_upload_is_never_followed_or_removed(tmp_path: Path) -> None:
    state = _state(tmp_path)
    try:
        target = tmp_path / "user-original.bin"
        target.write_bytes(b"preserve me")
        link = Path(state.db_path).parent / "uploads" / "link.bin"
        link.parent.mkdir(parents=True, exist_ok=True)
        try:
            link.symlink_to(target)
        except OSError:
            pytest.skip("symlink creation is not available")
        state.upsert_transfer(
            id="out:link",
            direction="out",
            peer_fp="peer",
            kind="file",
            name="link.bin",
            size=target.stat().st_size,
            status="complete",
            metadata={"path": str(link)},
        )

        assert state.delete_transfer("out:link") is True
        assert link.is_symlink()
        assert target.read_bytes() == b"preserve me"
    finally:
        state.close()


def test_unreadable_remaining_transfer_metadata_blocks_cleanup(tmp_path: Path) -> None:
    state = _state(tmp_path)
    try:
        path = _upload(state, "blocked.bin")
        _transfer(state, "out:remove", path)
        _transfer(state, "out:corrupt", path)
        state._conn.execute(
            "UPDATE transfers SET metadata_json='{' WHERE id='out:corrupt'"
        )

        assert state.delete_transfer("out:remove") is True
        assert path.is_file()
    finally:
        state.close()


def test_unreadable_target_metadata_is_not_deleted_or_pruned(tmp_path: Path) -> None:
    state = _state(tmp_path)
    try:
        path = _upload(state, "corrupt-target.bin")
        _transfer(state, "out:corrupt-target", path)
        state._conn.execute(
            "UPDATE transfers SET metadata_json='{' WHERE id='out:corrupt-target'"
        )

        assert state.delete_transfer("out:corrupt-target") is False
        assert state.prune_transfers(keep_latest=0) == 0
        assert state.get_transfer("out:corrupt-target") is not None
        assert path.is_file()
    finally:
        state.close()


@pytest.mark.parametrize("delivery_state", ["sent_unconfirmed", "outcome_unknown"])
def test_outbound_ambiguous_delivery_tombstone_is_never_pruned(
    tmp_path: Path,
    delivery_state: str,
) -> None:
    state = _state(tmp_path)
    try:
        path = _upload(state, f"{delivery_state}.bin")
        state.upsert_transfer(
            id=f"out:{delivery_state}",
            direction="out",
            peer_fp="peer",
            kind="file",
            name=path.name,
            size=path.stat().st_size,
            blob_hash="a" * 64,
            status="failed",
            metadata={
                "path": str(path),
                "delivery_state": delivery_state,
                "delivery_id": "b" * 32,
                "offer_boundary_contract": {"delivery_id": "b" * 32},
                "commit_confirmed": False,
            },
        )

        assert state.delete_transfer(f"out:{delivery_state}") is False
        assert state.prune_transfers(keep_latest=0) == 0
        assert state.get_transfer(f"out:{delivery_state}") is not None
        assert path.is_file()
    finally:
        state.close()


def test_prune_is_bounded_and_shared_reference_safe(tmp_path: Path) -> None:
    state = _state(tmp_path)
    try:
        path = _upload(state, "batch-shared.bin")
        _transfer(state, "out:a", path)
        _transfer(state, "out:b", path)

        assert state.prune_transfers(keep_latest=0, max_remove=1) == 1
        assert path.is_file()
        assert state.prune_transfers(keep_latest=0, max_remove=1) == 1
        assert not path.exists()
    finally:
        state.close()


def test_fail_closed_old_rows_do_not_starve_later_prunable_history(tmp_path: Path) -> None:
    state = _state(tmp_path)
    try:
        protected = _upload(state, "protected.bin")
        removable = _upload(state, "removable.bin")
        _transfer(state, "a-protected", protected)
        _transfer(state, "z-removable", removable)
        state._conn.execute(
            "UPDATE transfers SET metadata_json='{', updated_ms=1 WHERE id='a-protected'"
        )
        state._conn.execute(
            "UPDATE transfers SET updated_ms=2 WHERE id='z-removable'"
        )

        assert state.prune_transfers(keep_latest=0, max_remove=1) == 1
        assert state.get_transfer("a-protected") is not None
        assert protected.is_file()
        assert state.get_transfer("z-removable") is None
        # The ledger can make bounded progress, but filesystem reclamation is
        # globally fail-closed while any remaining path reference is corrupt.
        assert removable.is_file()
    finally:
        state.close()


def test_identity_race_fails_closed_without_unlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state(tmp_path)
    try:
        path = _upload(state, "raced.bin", b"before")
        _transfer(state, "out:race", path)
        original = lifecycle._unlink_identity_bound

        def mutate_then_unlink(candidate: Path, expected: lifecycle.FileIdentity) -> None:
            candidate.write_bytes(b"after mutation")
            original(candidate, expected)

        monkeypatch.setattr(lifecycle, "_unlink_identity_bound", mutate_then_unlink)
        assert state.delete_transfer("out:race") is True
        assert path.read_bytes() == b"after mutation"
    finally:
        state.close()


def test_every_durable_protocol_and_history_source_roots_blob(tmp_path: Path) -> None:
    state = _state(tmp_path)
    store = BlobStore(Path(state.db_path).parent / "blobs")
    try:
        digests = [_blob(store, f"blob-{index}".encode())[0] for index in range(11)]
        state._conn.execute(
            "INSERT INTO folder_manifest VALUES(?,?,?,?,?,?,?)",
            ("f", "a", digests[0], 1, 1, "{}", 1),
        )
        state._conn.execute(
            "INSERT INTO folder_audit(ts_ms,folder_name,root_id,peer_fp,action,"
            "file_path,blob_hash,size,note) VALUES(1,'f','r','p','write','a',?,1,'')",
            (digests[1],),
        )
        state.record_manifest_conflict(
            folder_name="f",
            file_path="a",
            peer_fp="p",
            local_blob_hash=digests[2],
            local_size=1,
            local_mtime_ms=1,
            local_vclock={"a": 1},
            remote_blob_hash=digests[3],
            remote_size=1,
            remote_mtime_ms=1,
            remote_vclock={"b": 1},
            applied_choice="local",
        )
        upload = _upload(state, "root.bin")
        _transfer(state, "out:root", upload, blob_hash=digests[4])
        state.record_chunk_available("f" * 64, 1, blob_hash=digests[5])
        state._conn.execute(
            "INSERT INTO file_index_cache(path,size,mtime_ns,ctime_ns,blob_hash,index_kind,"
            "chunks_json,updated_ms) VALUES('p',1,1,1,?,'fixed','[]',1)",
            (digests[6],),
        )
        state._conn.execute(
            "INSERT INTO pending_folder_offers(peer_fp,folder_name,merkle_root,entries_json,"
            "entry_count,total_bytes,offered_ms,state) VALUES('p','f','m',?,1,1,1,'pending')",
            (json.dumps([{"blob_hash": digests[7]}]),),
        )
        state._conn.execute(
            "INSERT INTO messages(id,ts_ms,direction,peer_fp,msg_type,metadata_json) "
            "VALUES('m',1,'in','p','FILE_OFFER',?)",
            (json.dumps({"blob": digests[8]}),),
        )
        state._conn.execute(
            "INSERT INTO outbox(peer_fp,msg_id,msg_kind,msg_body_json,enqueued_ms,attempts) "
            "VALUES('p','o','FILE',?,1,0)",
            (json.dumps({"verified_hash": digests[9]}),),
        )
        state.record_folder_lifecycle_event(
            event="send_complete",
            direction="out",
            folder_name="f",
            metadata={"blob": digests[10]},
        )

        roots = lifecycle.collect_durable_blob_roots(state)
        assert roots.complete
        assert set(digests) <= roots.roots
        manifest = _manifest(state, store)
        assert manifest["candidate_count"] == 0
    finally:
        state.close()


def test_malformed_json_and_noncanonical_hash_make_manifest_non_executable(
    tmp_path: Path,
) -> None:
    state = _state(tmp_path)
    store = BlobStore(Path(state.db_path).parent / "blobs")
    try:
        digest, _ = _blob(store, b"orphan")
        state.record_blob(digest, 6)
        state._conn.execute(
            "INSERT INTO messages(id,ts_ms,direction,peer_fp,msg_type,metadata_json) "
            "VALUES('bad',1,'in','p','FILE_OFFER','{')"
        )
        state._conn.execute(
            "INSERT INTO folder_manifest VALUES('f','a','NOT-A-HASH',1,1,'{}',1)"
        )

        manifest = _manifest(state, store)
        assert manifest["safe_to_execute"] is False
        assert any("malformed JSON" in error for error in manifest["errors"])
        assert any("non-canonical hash" in error for error in manifest["errors"])
        output = tmp_path / "unsafe.json"
        assert lifecycle.write_cas_gc_manifest(output, manifest) == manifest["manifest_blake3"]
        with pytest.raises(lifecycle.StorageLifecycleError):
            lifecycle.validate_cas_gc_manifest(json.loads(output.read_text()))
    finally:
        state.close()


def test_age_grace_and_batch_limit_are_enforced(tmp_path: Path) -> None:
    state = _state(tmp_path)
    store = BlobStore(Path(state.db_path).parent / "blobs")
    try:
        for index in range(4):
            _blob(store, f"orphan-{index}".encode())
        now_ms = int(time.time() * 1000)
        grace = lifecycle.build_cas_gc_manifest(
            state,
            store.root,
            now_ms=now_ms,
            grace_ms=60_000,
            batch_limit=2,
        )
        assert grace["candidate_count"] == 0
        assert grace["recent_unreferenced_count"] == 4

        collectible = lifecycle.build_cas_gc_manifest(
            state,
            store.root,
            now_ms=now_ms + 10_000,
            grace_ms=0,
            batch_limit=2,
        )
        assert collectible["candidate_total"] == 4
        assert collectible["candidate_count"] == 2
        assert collectible["deferred_candidate_count"] == 2
        assert [row["hash"] for row in collectible["candidates"]] == sorted(
            row["hash"] for row in collectible["candidates"]
        )

        repeated = lifecycle.build_cas_gc_manifest(
            state,
            store.root,
            now_ms=now_ms + 10_000,
            grace_ms=0,
            batch_limit=2,
        )
        assert repeated == collectible
        assert repeated["manifest_blake3"] == collectible["manifest_blake3"]
    finally:
        state.close()


def test_index_disk_divergence_is_reported_without_treating_index_as_root(
    tmp_path: Path,
) -> None:
    state = _state(tmp_path)
    store = BlobStore(Path(state.db_path).parent / "blobs")
    try:
        orphan, _ = _blob(store, b"unindexed")
        stale = "a" * 64 if orphan != "a" * 64 else "b" * 64
        state.record_blob(stale, 123)

        manifest = _manifest(state, store, batch_limit=2)
        assert manifest["candidate_total"] == 1
        assert manifest["unindexed_disk_total"] == 1
        assert manifest["stale_index_total"] == 1
        assert manifest["root_count"] == 0
    finally:
        state.close()


def test_chunk_cache_addresses_are_not_mistaken_for_blob_cas_roots(
    tmp_path: Path,
) -> None:
    """Chunk hashes address file_chunks; only their parent blob hash roots CAS."""

    state = _state(tmp_path)
    store = BlobStore(Path(state.db_path).parent / "blobs")
    try:
        digest, path = _blob(store, b"same digest happens to appear in chunk cache")
        state.record_chunk_available(digest, path.stat().st_size, blob_hash=None)
        state._conn.execute(
            "INSERT INTO chunk_sources(chunk_hash,path,start,size,mtime_ms,file_size,"
            "source,updated_ms) VALUES(?,?,0,1,1,1,'prior',1)",
            (digest, str(tmp_path / "separate-chunk-source")),
        )

        roots = lifecycle.collect_durable_blob_roots(state)
        assert roots.complete
        assert digest not in roots.roots
        manifest = _manifest(state, store)
        assert [row["hash"] for row in manifest["candidates"]] == [digest]
    finally:
        state.close()


def test_audit_cli_never_opens_or_mutates_production_state_files(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data = tmp_path / "data"
    data.mkdir()
    state = State(data / "state.db")
    try:
        BlobStore(data / "blobs")
        state.set_setting("snapshot-proof", "unchanged")
        (data / "daemon.lock").write_text("424242", encoding="ascii")
        state_artifacts = sorted(data.glob("state.db*"))
        assert state_artifacts

        def evidence(path: Path) -> tuple[bytes, int, int]:
            info = path.stat()
            return path.read_bytes(), int(info.st_mtime_ns), int(info.st_size)

        before = {path.name: evidence(path) for path in state_artifacts}
        output = tmp_path / "audit.json"
        return_code = storage_gc.main(
            [
                "--data-root",
                str(data),
                "audit",
                "--manifest",
                str(output),
                "--grace-ms",
                "0",
            ]
        )
        captured = json.loads(capsys.readouterr().out)

        assert return_code == 0
        assert captured["mode"] == "audit_only"
        assert output.is_file()
        after_paths = sorted(data.glob("state.db*"))
        assert [path.name for path in after_paths] == list(before)
        assert {path.name: evidence(path) for path in after_paths} == before
    finally:
        state.close()


def test_audit_refuses_instead_of_creating_missing_daemon_lock(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data = tmp_path / "data"
    data.mkdir()
    state = State(data / "state.db")
    try:
        BlobStore(data / "blobs")
        manifest = tmp_path / "must-not-exist.json"

        return_code = storage_gc.main(
            ["--data-root", str(data), "audit", "--manifest", str(manifest)]
        )
        error = json.loads(capsys.readouterr().err)

        assert return_code == 2
        assert error["ok"] is False
        assert not (data / "daemon.lock").exists()
        assert not manifest.exists()
    finally:
        state.close()


def test_symlink_inside_cas_is_an_error_and_never_a_candidate(tmp_path: Path) -> None:
    state = _state(tmp_path)
    store = BlobStore(Path(state.db_path).parent / "blobs")
    try:
        target = tmp_path / "outside"
        target.write_bytes(b"outside")
        digest = "a" * 64
        link = store.path(digest)
        link.parent.mkdir(parents=True, exist_ok=True)
        try:
            link.symlink_to(target)
        except OSError:
            pytest.skip("symlink creation is not available")

        manifest = _manifest(state, store)
        assert manifest["safe_to_execute"] is False
        assert manifest["candidate_count"] == 0
        assert target.read_bytes() == b"outside"
    finally:
        state.close()


def test_quarantine_then_rollback_preserves_bytes_and_reconciles_index(
    tmp_path: Path,
) -> None:
    state = _state(tmp_path)
    store = BlobStore(Path(state.db_path).parent / "blobs")
    try:
        digest, source = _blob(store, b"recoverable orphan")
        state.record_blob(digest, source.stat().st_size)
        manifest = _manifest(state, store)
        quarantine = tmp_path / "quarantine"

        result = lifecycle.quarantine_cas_orphans(
            state,
            manifest,
            quarantine,
            expected_manifest_blake3=manifest["manifest_blake3"],
        )
        quarantined = quarantine / "objects" / digest[:2] / digest[2:]
        assert result["quarantined"] == [digest]
        assert not source.exists()
        assert quarantined.read_bytes() == b"recoverable orphan"
        assert state.has_blob(digest) is False

        rollback = lifecycle.rollback_cas_quarantine(
            state,
            quarantine,
            expected_manifest_blake3=manifest["manifest_blake3"],
        )
        assert rollback["restored"] == [digest]
        assert source.read_bytes() == b"recoverable orphan"
        assert state.has_blob(digest) is True
    finally:
        state.close()


def test_purge_requires_grace_then_deletes_in_resumable_bounded_batches(
    tmp_path: Path,
) -> None:
    state = _state(tmp_path)
    store = BlobStore(Path(state.db_path).parent / "blobs")
    try:
        first, _ = _blob(store, b"purge one")
        second, _ = _blob(store, b"purge two")
        manifest = _manifest(state, store)
        quarantine = tmp_path / "quarantine"
        completion = lifecycle.quarantine_cas_orphans(
            state,
            manifest,
            quarantine,
            expected_manifest_blake3=manifest["manifest_blake3"],
        )
        with pytest.raises(lifecycle.StorageLifecycleError, match="grace"):
            lifecycle.purge_cas_quarantine(
                state,
                quarantine,
                expected_manifest_blake3=manifest["manifest_blake3"],
            )

        future = int(completion["completed_ms"]) + lifecycle.DEFAULT_QUARANTINE_GRACE_MS + 1
        first_batch = lifecycle.purge_cas_quarantine(
            state,
            quarantine,
            expected_manifest_blake3=manifest["manifest_blake3"],
            now_ms=future,
            batch_limit=1,
        )
        assert len(first_batch["purged"]) == 1
        assert first_batch["remaining"] == 1

        second_batch = lifecycle.purge_cas_quarantine(
            state,
            quarantine,
            expected_manifest_blake3=manifest["manifest_blake3"],
            now_ms=future,
            batch_limit=1,
        )
        assert len(second_batch["purged"]) == 1
        assert len(second_batch["recovered_prior_purges"]) == 1
        assert second_batch["remaining"] == 0
        assert (quarantine / "purge-complete.json").is_file()
        for digest in (first, second):
            assert not (quarantine / "objects" / digest[:2] / digest[2:]).exists()
    finally:
        state.close()


def test_purge_refuses_blob_that_became_a_durable_root(tmp_path: Path) -> None:
    state = _state(tmp_path)
    store = BlobStore(Path(state.db_path).parent / "blobs")
    try:
        digest, _ = _blob(store, b"needed again")
        manifest = _manifest(state, store)
        quarantine = tmp_path / "quarantine"
        completion = lifecycle.quarantine_cas_orphans(
            state,
            manifest,
            quarantine,
            expected_manifest_blake3=manifest["manifest_blake3"],
        )
        state.upsert_manifest_entry(
            folder_name="restored",
            file_path="needed.bin",
            blob_hash=digest,
            size=12,
            mtime_ms=1,
            vclock={"local": 1},
        )

        with pytest.raises(lifecycle.StorageLifecycleError, match="became a durable root"):
            lifecycle.purge_cas_quarantine(
                state,
                quarantine,
                expected_manifest_blake3=manifest["manifest_blake3"],
                now_ms=int(completion["completed_ms"]) + 1,
                quarantine_grace_ms=0,
            )
        assert (quarantine / "objects" / digest[:2] / digest[2:]).is_file()
    finally:
        state.close()


def test_interrupted_purge_recovers_from_durable_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state(tmp_path)
    store = BlobStore(Path(state.db_path).parent / "blobs")
    try:
        digest, _ = _blob(store, b"purge crash")
        manifest = _manifest(state, store)
        quarantine = tmp_path / "quarantine"
        completion = lifecycle.quarantine_cas_orphans(
            state,
            manifest,
            quarantine,
            expected_manifest_blake3=manifest["manifest_blake3"],
        )
        real_append = lifecycle._append_journal

        def crash_after_unlink(path: Path, event: dict) -> None:
            if event.get("event") == "purged":
                raise OSError("simulated purge crash")
            real_append(path, event)

        monkeypatch.setattr(lifecycle, "_append_journal", crash_after_unlink)
        with pytest.raises(OSError, match="simulated purge crash"):
            lifecycle.purge_cas_quarantine(
                state,
                quarantine,
                expected_manifest_blake3=manifest["manifest_blake3"],
                now_ms=int(completion["completed_ms"]) + 1,
                quarantine_grace_ms=0,
            )
        monkeypatch.setattr(lifecycle, "_append_journal", real_append)

        resumed = lifecycle.purge_cas_quarantine(
            state,
            quarantine,
            expected_manifest_blake3=manifest["manifest_blake3"],
            now_ms=int(completion["completed_ms"]) + 1,
            quarantine_grace_ms=0,
        )
        assert resumed["purged"] == []
        assert resumed["recovered_prior_purges"] == [digest]
        assert resumed["remaining"] == 0
    finally:
        state.close()


def test_interrupted_quarantine_resumes_from_destination_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state(tmp_path)
    store = BlobStore(Path(state.db_path).parent / "blobs")
    try:
        first, _ = _blob(store, b"first orphan")
        second, _ = _blob(store, b"second orphan")
        manifest = _manifest(state, store)
        quarantine = tmp_path / "quarantine"
        real_replace = lifecycle.os.replace
        move_count = 0

        def fail_second_object_move(source: os.PathLike[str], target: os.PathLike[str]) -> None:
            nonlocal move_count
            source_path = Path(source)
            target_path = Path(target)
            if source_path.parent.parent == store.root and "objects" in target_path.parts:
                move_count += 1
                if move_count == 2:
                    raise OSError("simulated power loss")
            real_replace(source, target)

        monkeypatch.setattr(lifecycle.os, "replace", fail_second_object_move)
        with pytest.raises(OSError, match="simulated power loss"):
            lifecycle.quarantine_cas_orphans(
                state,
                manifest,
                quarantine,
                expected_manifest_blake3=manifest["manifest_blake3"],
            )
        monkeypatch.setattr(lifecycle.os, "replace", real_replace)

        result = lifecycle.quarantine_cas_orphans(
            state,
            manifest,
            quarantine,
            expected_manifest_blake3=manifest["manifest_blake3"],
        )
        assert set(result["quarantined"]) == {first, second}
        assert len(result["resumed"]) == 1
        assert len(result["moved"]) == 1
    finally:
        state.close()


def test_new_durable_reference_invalidates_old_manifest(tmp_path: Path) -> None:
    state = _state(tmp_path)
    store = BlobStore(Path(state.db_path).parent / "blobs")
    try:
        digest, source = _blob(store, b"becomes live")
        manifest = _manifest(state, store)
        state.upsert_manifest_entry(
            folder_name="f",
            file_path="live.bin",
            blob_hash=digest,
            size=source.stat().st_size,
            mtime_ms=1,
            vclock={"local": 1},
        )

        with pytest.raises(lifecycle.StorageLifecycleError, match="root set changed"):
            lifecycle.quarantine_cas_orphans(
                state,
                manifest,
                tmp_path / "quarantine",
                expected_manifest_blake3=manifest["manifest_blake3"],
            )
        assert source.is_file()
    finally:
        state.close()


def test_quarantine_refuses_redirected_destination_chain(tmp_path: Path) -> None:
    state = _state(tmp_path)
    store = BlobStore(Path(state.db_path).parent / "blobs")
    try:
        _digest, source = _blob(store, b"must remain live")
        manifest = _manifest(state, store)
        quarantine = tmp_path / "quarantine"
        quarantine.mkdir()
        outside = tmp_path / "outside-quarantine"
        outside.mkdir()
        try:
            (quarantine / "objects").symlink_to(outside, target_is_directory=True)
        except OSError:
            pytest.skip("directory symlink creation is not available")

        with pytest.raises(lifecycle.StorageLifecycleError, match="redirected"):
            lifecycle.quarantine_cas_orphans(
                state,
                manifest,
                quarantine,
                expected_manifest_blake3=manifest["manifest_blake3"],
            )
        assert source.is_file()
        assert list(outside.iterdir()) == []
    finally:
        state.close()


def test_manifest_tamper_and_object_identity_swap_are_rejected(tmp_path: Path) -> None:
    state = _state(tmp_path)
    store = BlobStore(Path(state.db_path).parent / "blobs")
    try:
        _digest, source = _blob(store, b"original")
        manifest = _manifest(state, store)
        tampered = json.loads(json.dumps(manifest))
        tampered["candidate_bytes"] += 1
        with pytest.raises(lifecycle.StorageLifecycleError, match="digest mismatch"):
            lifecycle.validate_cas_gc_manifest(tampered)

        source.write_bytes(b"changed after planning")
        with pytest.raises(lifecycle.StorageLifecycleError, match="identity changed"):
            lifecycle.quarantine_cas_orphans(
                state,
                manifest,
                tmp_path / "quarantine",
                expected_manifest_blake3=manifest["manifest_blake3"],
            )
        assert source.read_bytes() == b"changed after planning"
    finally:
        state.close()
