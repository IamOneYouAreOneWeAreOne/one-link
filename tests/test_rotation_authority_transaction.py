"""Crash-consistency and exactness gates for journaled identity rotation."""
from __future__ import annotations

from pathlib import Path

import pytest


def _prepared_rotation(tmp_path: Path, monkeypatch, peers: list[str]):
    from one_link import identity_rotation, master_seed, paths
    from one_link.state import State

    data = tmp_path / "data"
    config = tmp_path / "config"
    data.mkdir()
    config.mkdir()
    identity_path = config / "identity.key"
    monkeypatch.setattr(paths, "data_dir", lambda: data)
    monkeypatch.setattr(paths, "key_path", lambda: identity_path)
    old_seed = master_seed.load_or_create_seed(data)[0]
    master_seed.install_seed_derived_authority(
        data,
        identity_path=identity_path,
        seed=old_seed,
        previous_seed=old_seed,
    )
    old_priv = master_seed.derive_identity_priv(old_seed)
    state = State(data / "state.db")
    before = {
        "seed": master_seed.load_seed(data),
        "identity": identity_path.read_bytes(),
        "drk": (data / "data-root-key.bin").read_bytes(),
    }
    result = identity_rotation.perform_local_rotation(
        data_dir=data,
        old_priv=old_priv,
        pinned_peer_fingerprints=peers,
        state=state,
    )
    return data, identity_path, old_priv, state, before, result


def test_rotation_stage_is_observational_until_boot(tmp_path, monkeypatch):
    from one_link import master_seed, recovery_api

    peers = ["bb" * 32, "aa" * 32, "bb" * 32]
    data, identity_path, _old_priv, state, before, result = _prepared_rotation(
        tmp_path, monkeypatch, peers,
    )
    assert master_seed.load_seed(data) == before["seed"]
    assert identity_path.read_bytes() == before["identity"]
    assert (data / "data-root-key.bin").read_bytes() == before["drk"]
    assert state.list_pending_rotation_announcements() == []
    assert result.staged_peer_count == 2
    assert result.queued_peer_count == 0
    assert recovery_api.pending_recovery_summary(data) == {
        "pending": True,
        "kind": "rotation",
        "phase": "prepared",
        "restart_required": True,
        "staged_peer_count": 2,
        "old_fp": result.old_fp,
        "new_fp": result.new_fp,
    }


@pytest.mark.asyncio
async def test_pending_phrase_is_auth_no_store_and_single_rotation_bound(
    tmp_path, monkeypatch,
):
    """A lost success response is recoverable, but no old/later rotation is."""
    from types import SimpleNamespace

    from aiohttp.test_utils import TestClient, TestServer

    from one_link import recovery_api
    from one_link import server as server_module

    peers = ["aa" * 32, "bb" * 32]
    data, identity_path, _old_priv, state, _before, result = _prepared_rotation(
        tmp_path, monkeypatch, peers,
    )
    monkeypatch.setattr(server_module, "data_dir", lambda: data)
    server = server_module.UIServer(
        SimpleNamespace(state=state, peer_rtc=None, me=None)
    )
    client = TestClient(TestServer(server.app))
    await client.start_server()
    path = "/api/v1/recovery/rotate/pending-phrase"
    payload = {
        "confirmed_view": True,
        "expected_new_fp": result.new_fp,
    }
    auth = {"Authorization": f"Bearer {server.token}"}
    try:
        unauthenticated = await client.post(path, json=payload)
        assert unauthenticated.status == 401
        assert "new_phrase" not in await unauthenticated.json()

        revealed = await client.post(path, json=payload, headers=auth)
        assert revealed.status == 200
        body = await revealed.json()
        assert body["new_phrase"] == result.new_phrase
        assert body["new_fp"] == result.new_fp
        assert body["staged_peer_count"] == 2
        assert revealed.headers["Cache-Control"].startswith("no-store")
        assert revealed.headers["Pragma"] == "no-cache"
        assert revealed.headers["Expires"] == "0"

        # Retry is intentional: an HTTP response can be lost after the daemon
        # reads the seed. It remains bound to this exact prepared fingerprint.
        retry = await client.post(path, json=payload, headers=auth)
        assert retry.status == 200
        assert (await retry.json())["new_phrase"] == result.new_phrase

        wrong = await client.post(
            path,
            json={**payload, "expected_new_fp": "ff" * 32},
            headers=auth,
        )
        assert wrong.status == 409
        assert "new_phrase" not in await wrong.json()

        recovery_api.complete_pending_recovery(
            data_dir=data,
            identity_path=identity_path,
        )
        recovery_api.finalize_pending_rotation(
            data_dir=data,
            state=state,
            identity_path=identity_path,
        )
        expired = await client.post(path, json=payload, headers=auth)
        assert expired.status == 409
        assert "new_phrase" not in await expired.json()
    finally:
        await client.close()


def test_rotation_authority_and_queue_replay_across_boot_boundary(
    tmp_path, monkeypatch,
):
    from one_link import master_seed, mnemonic, recovery_api

    peers = ["aa" * 32, "bb" * 32, "cc" * 32]
    data, identity_path, _old_priv, state, _before, result = _prepared_rotation(
        tmp_path, monkeypatch, peers,
    )
    new_seed = mnemonic.decode(result.new_phrase)
    first = recovery_api.complete_pending_recovery(
        data_dir=data,
        identity_path=identity_path,
    )
    assert first["pending_finalization"] is True
    assert master_seed.load_seed(data) == new_seed
    assert state.list_pending_rotation_announcements() == []

    # A crash before State opens re-enters authority replay idempotently.
    second = recovery_api.complete_pending_recovery(
        data_dir=data,
        identity_path=identity_path,
    )
    assert second["pending_finalization"] is True
    finalized = recovery_api.finalize_pending_rotation(
        data_dir=data,
        state=state,
        identity_path=identity_path,
    )
    assert finalized == {"completed": True, "queued_peer_count": 3}
    rows = state.list_pending_rotation_announcements(unacked_only=False)
    assert {row["peer_fp"] for row in rows} == set(peers)
    assert all(row["old_fp"] == result.old_fp for row in rows)
    assert all(row["new_fp"] == result.new_fp for row in rows)
    assert recovery_api.has_pending_recovery(data) is False


def test_v2_pending_rotation_intent_replays_after_overwrite_policy_upgrade(
    tmp_path, monkeypatch,
):
    import json

    from one_link import recovery_api

    data, identity_path, _old_priv, state, _before, _result = _prepared_rotation(
        tmp_path, monkeypatch, ["aa" * 32],
    )
    intent_path = data / recovery_api.RECOVERY_INTENT_FILENAME
    intent = json.loads(intent_path.read_text(encoding="utf-8"))
    intent["version"] = 2
    intent.pop("overwrite_files")
    # Journal bytes are deliberately canonical and platform-independent;
    # Path.write_text() would translate LF to CRLF on Windows.
    intent_path.write_bytes(
        (json.dumps(intent, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )
    )

    applied = recovery_api.complete_pending_recovery(
        data_dir=data,
        identity_path=identity_path,
    )
    assert applied["pending_finalization"] is True
    finalized = recovery_api.finalize_pending_rotation(
        data_dir=data,
        state=state,
        identity_path=identity_path,
    )
    assert finalized == {"completed": True, "queued_peer_count": 1}


def test_rotation_metadata_tamper_blocks_authority_install(tmp_path, monkeypatch):
    from one_link import master_seed, recovery_api

    data, identity_path, _old_priv, _state, before, _result = _prepared_rotation(
        tmp_path, monkeypatch, ["aa" * 32],
    )
    stage_path = data / recovery_api.RECOVERY_ROTATION_STAGE_FILENAME
    blob = bytearray(stage_path.read_bytes())
    blob[len(blob) // 2] ^= 1
    stage_path.write_bytes(bytes(blob))

    with pytest.raises(
        recovery_api.RecoveryTransactionError,
        match="does not match the durable intent commitment",
    ):
        recovery_api.complete_pending_recovery(
            data_dir=data,
            identity_path=identity_path,
        )
    assert master_seed.load_seed(data) == before["seed"]
    assert identity_path.read_bytes() == before["identity"]
    assert (data / "data-root-key.bin").read_bytes() == before["drk"]
    assert recovery_api.has_pending_recovery(data) is True


def test_rotation_refuses_unmigrated_legacy_passphrase_factor(
    tmp_path, monkeypatch,
):
    from one_link import identity_rotation, lockbox, master_seed, paths, recovery_api

    data = tmp_path / "data"
    config = tmp_path / "config"
    data.mkdir()
    config.mkdir()
    identity_path = config / "identity.key"
    monkeypatch.setattr(paths, "key_path", lambda: identity_path)
    seed = master_seed.load_or_create_seed(data)[0]
    master_seed.install_seed_derived_authority(
        data,
        identity_path=identity_path,
        seed=seed,
        previous_seed=seed,
    )
    # A salt with no dual-slot envelope represents legacy direct-scrypt rows.
    lockbox.load_or_create_salt(data)
    with pytest.raises(
        recovery_api.RecoveryTransactionError,
        match="export a new backup before identity rotation",
    ):
        identity_rotation.perform_local_rotation(
            data_dir=data,
            old_priv=master_seed.derive_identity_priv(seed),
            pinned_peer_fingerprints=[],
        )
    assert master_seed.load_seed(data) == seed
    assert recovery_api.has_pending_recovery(data) is False


def test_queue_commit_replays_if_finalized_marker_write_crashes(
    tmp_path, monkeypatch,
):
    from one_link import recovery_api
    from one_link.key_material import KeyMaterialPersistenceError

    peers = ["aa" * 32, "bb" * 32]
    data, identity_path, _old_priv, state, _before, _result = _prepared_rotation(
        tmp_path, monkeypatch, peers,
    )
    recovery_api.complete_pending_recovery(
        data_dir=data,
        identity_path=identity_path,
    )
    original = recovery_api._atomic_small_private_file

    def _crash_marker(path, payload, *, label):
        if label == "finalized recovery rotation intent":
            raise KeyMaterialPersistenceError("simulated finalized-marker crash")
        return original(path, payload, label=label)

    monkeypatch.setattr(recovery_api, "_atomic_small_private_file", _crash_marker)
    with pytest.raises(KeyMaterialPersistenceError, match="simulated"):
        recovery_api.finalize_pending_rotation(
            data_dir=data,
            state=state,
            identity_path=identity_path,
        )
    assert len(state.list_pending_rotation_announcements(unacked_only=False)) == 2
    assert recovery_api.pending_recovery_summary(data)["phase"] == "applied"

    monkeypatch.setattr(recovery_api, "_atomic_small_private_file", original)
    replay = recovery_api.finalize_pending_rotation(
        data_dir=data,
        state=state,
        identity_path=identity_path,
    )
    assert replay == {"completed": True, "queued_peer_count": 2}
    assert len(state.list_pending_rotation_announcements(unacked_only=False)) == 2
    assert recovery_api.has_pending_recovery(data) is False


def test_finalized_cleanup_crash_replays_without_metadata_or_duplicates(
    tmp_path, monkeypatch,
):
    from one_link import recovery_api
    from one_link.key_material import KeyMaterialPersistenceError

    data, identity_path, _old_priv, state, _before, _result = _prepared_rotation(
        tmp_path, monkeypatch, ["aa" * 32],
    )
    recovery_api.complete_pending_recovery(
        data_dir=data,
        identity_path=identity_path,
    )
    original = recovery_api._durable_unlink

    def _crash_last(path, *, label):
        if label == "recovery intent":
            raise KeyMaterialPersistenceError("simulated cleanup crash")
        return original(path, label=label)

    monkeypatch.setattr(recovery_api, "_durable_unlink", _crash_last)
    with pytest.raises(KeyMaterialPersistenceError, match="simulated"):
        recovery_api.finalize_pending_rotation(
            data_dir=data,
            state=state,
            identity_path=identity_path,
        )
    assert recovery_api.pending_recovery_summary(data)["phase"] == "finalized"
    assert not (data / recovery_api.RECOVERY_ROTATION_STAGE_FILENAME).exists()
    assert len(state.list_pending_rotation_announcements(unacked_only=False)) == 1

    monkeypatch.setattr(recovery_api, "_durable_unlink", original)
    # This models the next daemon boot: authority replay recognizes finalized,
    # then State finalization retires the last marker without needing metadata.
    again = recovery_api.complete_pending_recovery(
        data_dir=data,
        identity_path=identity_path,
    )
    assert again["pending_finalization"] is True
    replay = recovery_api.finalize_pending_rotation(
        data_dir=data,
        state=state,
        identity_path=identity_path,
    )
    assert replay["completed"] is True
    assert len(state.list_pending_rotation_announcements(unacked_only=False)) == 1
    assert recovery_api.has_pending_recovery(data) is False


def test_conflicting_queue_row_fails_closed_and_rolls_back_batch(
    tmp_path, monkeypatch,
):
    from one_link import recovery_api

    peers = ["aa" * 32, "bb" * 32]
    data, identity_path, _old_priv, state, _before, result = _prepared_rotation(
        tmp_path, monkeypatch, peers,
    )
    recovery_api.complete_pending_recovery(
        data_dir=data,
        identity_path=identity_path,
    )
    conflict_id = state.queue_rotation_announcement(
        peer_fp=peers[0],
        old_fp=result.old_fp,
        new_fp=result.new_fp,
        cert_json="{}",
        sig_hex="00" * 64,
        now_ms=1,
    )
    with pytest.raises(RuntimeError, match="does not match journal"):
        recovery_api.finalize_pending_rotation(
            data_dir=data,
            state=state,
            identity_path=identity_path,
        )
    rows = state.list_pending_rotation_announcements(unacked_only=False)
    assert [row["id"] for row in rows] == [conflict_id]
    assert recovery_api.has_pending_recovery(data) is True

    with state.durable_write_transaction():
        state._conn.execute(
            "DELETE FROM pending_rotation_announcements WHERE id = ?",
            (conflict_id,),
        )
    replay = recovery_api.finalize_pending_rotation(
        data_dir=data,
        state=state,
        identity_path=identity_path,
    )
    assert replay == {"completed": True, "queued_peer_count": 2}
