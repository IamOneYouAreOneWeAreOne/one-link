"""Focused safety tests for the manifest-driven quarantine executor."""

from __future__ import annotations

import ast
import json
import sqlite3
from pathlib import Path

import blake3
import pytest

from scripts import quarantine_manifest as qm


def _digest(data: bytes) -> str:
    return blake3.blake3(data).hexdigest()


def _write_manifest(path: Path, document: dict) -> str:
    raw = json.dumps(
        document, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    path.write_bytes(raw)
    return _digest(raw)


def _fixture_manifest(tmp_path: Path, *, target_count: int = 2) -> dict:
    app_root = tmp_path / "app"
    inbox = app_root / "inbox"
    resume = app_root / "transfer_resume"
    cache = app_root / "file_chunks"
    for directory in (inbox, resume, cache):
        directory.mkdir(parents=True, exist_ok=True)

    output = inbox / "synthetic-output.bin"
    output.write_bytes(b"preallocated-output")
    output_blob = _digest(output.read_bytes())
    sidecar = resume / f"{output_blob}.json"
    sidecar_bytes = json.dumps(
        {
            "blob_hex": output_blob,
            "name": "synthetic-output.bin",
            "cdc_chunks": [{"hash": output_blob}],
        },
        separators=(",", ":"),
    ).encode("utf-8")
    sidecar.write_bytes(sidecar_bytes)
    preserve = inbox / "preserve.txt"
    preserve.write_bytes(b"genuine completed inbound")
    state_db = app_root / "state.db"
    connection = sqlite3.connect(state_db)
    try:
        connection.executescript(
            """
            CREATE TABLE transfers(blob_hash TEXT, name TEXT);
            CREATE TABLE chunk_availability(chunk_hash TEXT, blob_hash TEXT);
            CREATE TABLE chunk_sources(chunk_hash TEXT);
            CREATE TABLE blobs(hash TEXT);
            CREATE TABLE file_index_cache(blob_hash TEXT);
            CREATE TABLE folder_manifest(blob_hash TEXT);
            CREATE TABLE folder_audit(blob_hash TEXT);
            CREATE TABLE manifest_conflicts(
                local_blob_hash TEXT, remote_blob_hash TEXT
            );
            """
        )
        connection.commit()
    finally:
        connection.close()

    targets = [
        {
            "kind": "inbox_output",
            "source_path": str(output.resolve()),
            "relative_destination": "inbox/synthetic-output.bin",
            "size": output.stat().st_size,
            "blake3": _digest(output.read_bytes()),
        },
        {
            "kind": "resume_sidecar",
            "source_path": str(sidecar.resolve()),
            "relative_destination": f"transfer_resume/{sidecar.name}",
            "size": sidecar.stat().st_size,
            "blake3": _digest(sidecar.read_bytes()),
        },
    ][:target_count]
    canonical = json.dumps(
        targets,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    quarantine_root = tmp_path / "quarantine-parent" / "quarantine-run"
    document = {
        "schema": qm.SUPPORTED_SCHEMA,
        "proposed_quarantine_root_not_created": str(quarantine_root.resolve()),
        "roots": {
            "app_root": str(app_root.resolve()),
            "inbox": str(inbox.resolve()),
            "resume_metadata": str(resume.resolve()),
            "file_chunks": str(cache.resolve()),
            "state_db": str(state_db.resolve()),
        },
        "quarantine_target_schema": {
            "required_keys": sorted(qm.TARGET_KEYS),
            "allowed_kinds_and_source_roots": {
                "inbox_output": str(inbox.resolve()),
                "resume_sidecar": str(resume.resolve()),
                "chunk_cache": str(cache.resolve()),
            },
            "destination_must_be_relative_to": str(quarantine_root.resolve()),
        },
        "quarantine_target_count": len(targets),
        "quarantine_target_bytes": sum(item["size"] for item in targets),
        "quarantine_target_set_blake3": _digest(canonical),
        "quarantine_targets": targets,
        "preserve_genuine_files": [
            {
                "relative_path": preserve.relative_to(inbox).as_posix(),
                "size": preserve.stat().st_size,
                "blake3": _digest(preserve.read_bytes()),
                "inbound_complete_ledger_match_count": 1,
                "ledger_size_match": True,
            }
        ],
        "state_reference_audit": {
            "state_opened_uri_mode_ro_and_query_only": True,
            "target_reference_counts": {
                label: 0 for label in qm.STATE_REFERENCE_KEYS
            },
        },
    }
    manifest = tmp_path / "manifest-v2.json"
    manifest_digest = _write_manifest(manifest, document)
    companion = tmp_path / "manifest-v1.json"
    companion.write_bytes(b'{"schema":"synthetic-v1"}')
    return {
        "app_root": app_root,
        "inbox": inbox,
        "resume": resume,
        "output": output,
        "sidecar": sidecar,
        "sidecar_bytes": sidecar_bytes,
        "output_blob": output_blob,
        "state_db": state_db,
        "preserve": preserve,
        "quarantine_root": quarantine_root,
        "document": document,
        "manifest": manifest,
        "manifest_digest": manifest_digest,
        "companion": companion,
        "companion_digest": _digest(companion.read_bytes()),
    }


def _load(fixture: dict) -> qm.QuarantinePlan:
    return qm.load_plan(
        fixture["manifest"],
        expected_manifest_blake3=fixture["manifest_digest"],
        quarantine_root=fixture["quarantine_root"],
    )


def _zero_reference_counts() -> dict[str, int]:
    return {label: 0 for label in qm.STATE_REFERENCE_KEYS}


def test_default_mode_is_read_only_and_validates_every_source(tmp_path: Path):
    fixture = _fixture_manifest(tmp_path)
    result = qm.run(
        [
            "--manifest",
            str(fixture["manifest"]),
            "--expected-manifest-blake3",
            fixture["manifest_digest"],
            "--quarantine-root",
            str(fixture["quarantine_root"]),
        ]
    )
    assert result["mode"] == "validate-only"
    assert result["production_mutation"] is False
    assert result["targets"] == 2
    assert fixture["output"].read_bytes() == b"preallocated-output"
    assert fixture["sidecar"].is_file()
    assert fixture["preserve"].is_file()
    assert not fixture["quarantine_root"].exists()


def test_manifest_hash_mismatch_is_rejected_before_parse(tmp_path: Path):
    fixture = _fixture_manifest(tmp_path)
    with pytest.raises(qm.QuarantineError, match="manifest digest mismatch"):
        qm.load_plan(
            fixture["manifest"],
            expected_manifest_blake3="0" * 64,
            quarantine_root=fixture["quarantine_root"],
        )


def test_source_escape_is_rejected_by_full_preflight(tmp_path: Path):
    fixture = _fixture_manifest(tmp_path, target_count=1)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside")
    target = fixture["document"]["quarantine_targets"][0]
    target.update(
        source_path=str(outside.resolve()),
        size=outside.stat().st_size,
        blake3=_digest(outside.read_bytes()),
    )
    canonical = json.dumps(
        fixture["document"]["quarantine_targets"],
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    fixture["document"]["quarantine_target_set_blake3"] = _digest(canonical)
    fixture["document"]["quarantine_target_bytes"] = outside.stat().st_size
    fixture["manifest_digest"] = _write_manifest(
        fixture["manifest"], fixture["document"]
    )
    plan = _load(fixture)
    with pytest.raises(qm.QuarantineError, match="escapes allowed root"):
        qm.validate_sources(plan)
    assert outside.is_file()
    assert not fixture["quarantine_root"].exists()


def test_destination_traversal_is_rejected_structurally(tmp_path: Path):
    fixture = _fixture_manifest(tmp_path, target_count=1)
    fixture["document"]["quarantine_targets"][0][
        "relative_destination"
    ] = "../escape.bin"
    canonical = json.dumps(
        fixture["document"]["quarantine_targets"],
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    fixture["document"]["quarantine_target_set_blake3"] = _digest(canonical)
    fixture["manifest_digest"] = _write_manifest(
        fixture["manifest"], fixture["document"]
    )
    with pytest.raises(qm.QuarantineError, match="unsafe destination components"):
        _load(fixture)


def test_execute_requires_hash_pinned_companion_before_shutdown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    fixture = _fixture_manifest(tmp_path, target_count=1)
    called = False

    def _must_not_stop(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("shutdown must not run without companion proof")

    monkeypatch.setattr(qm, "stop_runtime_gracefully", _must_not_stop)
    with pytest.raises(qm.QuarantineError, match="requires a hash-pinned companion"):
        qm.run(
            [
                "--manifest",
                str(fixture["manifest"]),
                "--expected-manifest-blake3",
                fixture["manifest_digest"],
                "--quarantine-root",
                str(fixture["quarantine_root"]),
                "--execute",
            ]
        )
    assert called is False


def test_graceful_stop_uses_control_only_and_proves_runtime_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    app_root = tmp_path / "app"
    app_root.mkdir()
    calls: list[str] = []

    def _read_port(path: Path, *, required: bool):
        del required
        return {
            "control.port": 41001,
            "server.port": 41002,
            "peer.port": 41003,
            "ui_port.txt": 41002,
        }.get(path.name)

    def _control(port: int, command: str, *, timeout: float):
        assert port == 41001
        assert timeout > 0
        calls.append(command)
        return {"ok": True, "pid": 4242} if command == "status" else {"ok": True}

    monkeypatch.setattr(qm, "_read_port", _read_port)
    monkeypatch.setattr(qm, "_read_small_decimal", lambda *_a, **_kw: 4343)
    monkeypatch.setattr(qm, "_control_request", _control)
    monkeypatch.setattr(qm, "_runtime_is_stopped", lambda *_a, **_kw: True)
    snapshot = qm.stop_runtime_gracefully(app_root, timeout=1.0)
    assert calls == ["status", "shutdown"]
    assert snapshot.daemon_pid == 4242
    assert snapshot.supervisor_pid == 4343
    assert snapshot.ports == (41001, 41002, 41003)


def test_success_moves_only_explicit_paths_and_verifies_destinations(tmp_path: Path):
    fixture = _fixture_manifest(tmp_path)
    plan = _load(fixture)
    qm.validate_sources(plan)
    companion = qm._load_companion(
        fixture["companion"], fixture["companion_digest"]
    )
    completion = qm.execute_moves(
        plan,
        companion=companion,
        runtime=qm.RuntimeSnapshot(daemon_pid=1, supervisor_pid=2, ports=()),
        post_stop_reference_counts=_zero_reference_counts(),
    )
    assert completion["target_count"] == 2
    assert completion["deletion_performed"] is False
    assert not fixture["output"].exists()
    assert not fixture["sidecar"].exists()
    output_destination = fixture["quarantine_root"] / "inbox" / fixture["output"].name
    sidecar_destination = (
        fixture["quarantine_root"] / "transfer_resume" / fixture["sidecar"].name
    )
    assert output_destination.read_bytes() == b"preallocated-output"
    assert sidecar_destination.read_bytes() == fixture["sidecar_bytes"]
    assert fixture["preserve"].read_bytes() == b"genuine completed inbound"
    audit = fixture["quarantine_root"] / "audit"
    assert (audit / "manifest-v2.json").read_bytes() == fixture["manifest"].read_bytes()
    assert (audit / "manifest-v1.json").read_bytes() == fixture[
        "companion"
    ].read_bytes()
    report = json.loads((audit / "completion.json").read_text(encoding="utf-8"))
    assert report["all_sources_absent"] is True
    assert report["all_destinations_hash_verified"] is True


def test_failure_rolls_back_completed_exact_moves(tmp_path: Path, monkeypatch):
    fixture = _fixture_manifest(tmp_path)
    plan = _load(fixture)
    qm.validate_sources(plan)
    companion = qm._load_companion(
        fixture["companion"], fixture["companion_digest"]
    )
    real_rename = qm._atomic_rename_no_replace
    calls = 0

    def _fail_second_move(source: Path, destination: Path):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected second-move failure")
        real_rename(source, destination)

    monkeypatch.setattr(qm, "_atomic_rename_no_replace", _fail_second_move)
    with pytest.raises(qm.QuarantineError, match="every completed move was rolled back"):
        qm.execute_moves(
            plan,
            companion=companion,
            runtime=qm.RuntimeSnapshot(daemon_pid=1, supervisor_pid=2, ports=()),
            post_stop_reference_counts=_zero_reference_counts(),
        )
    assert fixture["output"].read_bytes() == b"preallocated-output"
    assert fixture["sidecar"].read_bytes() == fixture["sidecar_bytes"]
    assert fixture["preserve"].is_file()
    journal = (
        fixture["quarantine_root"] / "audit" / "move-journal.jsonl"
    ).read_text(encoding="utf-8")
    assert '"event":"rollback_verified"' in journal
    assert not (fixture["quarantine_root"] / "audit" / "completion.json").exists()


def test_directory_publication_failure_after_rename_rolls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    fixture = _fixture_manifest(tmp_path)
    plan = _load(fixture)
    qm.validate_sources(plan)
    companion = qm._load_companion(
        fixture["companion"], fixture["companion_digest"]
    )
    real_publish = qm._publish_rename_durably
    calls = 0

    def _fail_first_publication(source_parent: Path, destination_parent: Path):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("injected parent-directory fsync failure")
        return real_publish(source_parent, destination_parent)

    monkeypatch.setattr(qm, "_publish_rename_durably", _fail_first_publication)
    with pytest.raises(qm.QuarantineError, match="every completed move was rolled back"):
        qm.execute_moves(
            plan,
            companion=companion,
            runtime=qm.RuntimeSnapshot(daemon_pid=1, supervisor_pid=2, ports=()),
            post_stop_reference_counts=_zero_reference_counts(),
        )
    assert calls >= 2
    assert fixture["output"].read_bytes() == b"preallocated-output"
    assert fixture["sidecar"].read_bytes() == fixture["sidecar_bytes"]
    journal = (
        fixture["quarantine_root"] / "audit" / "move-journal.jsonl"
    ).read_text(encoding="utf-8")
    assert '"event":"move_complete"' not in journal
    assert '"event":"rollback_verified"' in journal


def test_post_stop_state_requery_is_query_only_and_rejects_reference(tmp_path: Path):
    fixture = _fixture_manifest(tmp_path)
    plan = _load(fixture)
    qm.validate_sources(plan)
    database_before = _digest(fixture["state_db"].read_bytes())
    assert qm.verify_post_stop_state_references(plan) == _zero_reference_counts()
    assert _digest(fixture["state_db"].read_bytes()) == database_before
    assert not fixture["state_db"].with_name("state.db-wal").exists()
    assert not fixture["state_db"].with_name("state.db-shm").exists()

    connection = sqlite3.connect(fixture["state_db"])
    try:
        connection.execute(
            "INSERT INTO transfers(blob_hash, name) VALUES (?, ?)",
            (fixture["output_blob"], "unrelated-name.bin"),
        )
        connection.commit()
    finally:
        connection.close()
    database_with_reference = _digest(fixture["state_db"].read_bytes())
    with pytest.raises(qm.QuarantineError, match="durable state still references"):
        qm.verify_post_stop_state_references(plan)
    assert _digest(fixture["state_db"].read_bytes()) == database_with_reference
    assert not fixture["state_db"].with_name("state.db-wal").exists()
    assert not fixture["state_db"].with_name("state.db-shm").exists()


def test_post_stop_state_requery_opens_sqlcipher_without_migration_or_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    sqlcipher3 = pytest.importorskip("sqlcipher3")
    fixture = _fixture_manifest(tmp_path)
    fixture["state_db"].unlink()
    passphrase = "quarantine-read-only-test-passphrase"
    monkeypatch.setenv("ONE_LINK_PASSPHRASE", passphrase)
    connection = sqlcipher3.connect(str(fixture["state_db"]), isolation_level=None)
    try:
        key_hex = passphrase.encode("utf-8").hex()
        connection.execute(f"PRAGMA key = \"x'{key_hex}'\"")
        connection.execute("PRAGMA cipher_page_size = 4096")
        connection.execute("PRAGMA kdf_iter = 256000")
        connection.executescript(
            """
            CREATE TABLE transfers(blob_hash TEXT, name TEXT);
            CREATE TABLE chunk_availability(chunk_hash TEXT, blob_hash TEXT);
            CREATE TABLE chunk_sources(chunk_hash TEXT);
            CREATE TABLE blobs(hash TEXT);
            CREATE TABLE file_index_cache(blob_hash TEXT);
            CREATE TABLE folder_manifest(blob_hash TEXT);
            CREATE TABLE folder_audit(blob_hash TEXT);
            CREATE TABLE manifest_conflicts(
                local_blob_hash TEXT, remote_blob_hash TEXT
            );
            """
        )
    finally:
        connection.close()
    plan = _load(fixture)
    qm.validate_sources(plan)
    database_before = _digest(fixture["state_db"].read_bytes())
    assert qm.verify_post_stop_state_references(plan) == _zero_reference_counts()
    assert _digest(fixture["state_db"].read_bytes()) == database_before
    assert not fixture["state_db"].with_name("state.db-wal").exists()
    assert not fixture["state_db"].with_name("state.db-shm").exists()


def test_execute_requeries_state_after_stop_before_any_move(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    fixture = _fixture_manifest(tmp_path)
    plan = _load(fixture)
    companion = qm._load_companion(
        fixture["companion"], fixture["companion_digest"]
    )
    events: list[str] = []

    def _stopped(*_args, **_kwargs):
        events.append("stopped")
        return qm.RuntimeSnapshot(daemon_pid=1, supervisor_pid=None, ports=())

    def _refuse(_plan: qm.QuarantinePlan):
        events.append("state_requery")
        raise qm.QuarantineError("injected post-stop durable reference")

    def _must_not_move(*_args, **_kwargs):
        events.append("moved")
        raise AssertionError("move engine must not run after state-audit refusal")

    monkeypatch.setattr(qm, "stop_runtime_gracefully", _stopped)
    monkeypatch.setattr(qm, "verify_post_stop_state_references", _refuse)
    monkeypatch.setattr(qm, "execute_moves", _must_not_move)
    with pytest.raises(qm.QuarantineError, match="injected post-stop"):
        qm.execute_plan(
            plan,
            companion=companion,
            expected_manifest_blake3=fixture["manifest_digest"],
            stop_timeout=1.0,
        )
    assert events == ["stopped", "state_requery"]
    assert fixture["output"].is_file()
    assert not fixture["quarantine_root"].exists()


def test_script_has_no_delete_or_glob_selection_calls():
    tree = ast.parse(Path(qm.__file__).read_text(encoding="utf-8"))
    forbidden_attributes = {"glob", "rglob", "unlink", "remove", "rmdir", "rmtree"}
    used = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert used.isdisjoint(forbidden_attributes)
