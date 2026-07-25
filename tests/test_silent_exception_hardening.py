"""Regression coverage for audited silent-exception failure boundaries."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from one_link import app, keychain, peer_https
from one_link.daemon import Daemon
from one_link.server import UIServer
from one_link.state import State


class _BrokenCallRegistry:
    def active_call_ids(self):
        raise RuntimeError("call registry unavailable")


class _EmptyCallRegistry:
    def active_call_ids(self):
        return ()


@pytest.mark.asyncio
async def test_auto_install_defers_when_user_preference_cannot_be_read(
    monkeypatch,
):
    class _State:
        def get_setting(self, _key):
            raise RuntimeError("state unavailable")

    daemon = Daemon.__new__(Daemon)
    daemon.state = _State()
    daemon._call_registry = _EmptyCallRegistry()
    daemon._auto_install_in_flight = False
    daemon.ui_server = None
    monkeypatch.delenv("ONE_LINK_EXPERIMENTAL_AUTOINSTALL", raising=False)

    await daemon._maybe_auto_install("9.9.9", "1.0.0")

    assert daemon._auto_install_in_flight is False


@pytest.mark.asyncio
async def test_auto_install_defers_when_active_call_state_is_unknown(monkeypatch):
    daemon = Daemon.__new__(Daemon)
    daemon.state = None
    daemon._call_registry = _BrokenCallRegistry()
    daemon._auto_install_in_flight = False
    daemon.ui_server = None
    monkeypatch.delenv("ONE_LINK_EXPERIMENTAL_AUTOINSTALL", raising=False)

    await daemon._maybe_auto_install("9.9.9", "1.0.0")

    assert daemon._auto_install_in_flight is False


@pytest.mark.asyncio
async def test_auto_install_defers_when_active_transfer_state_is_unknown(
    monkeypatch,
):
    class _State:
        def get_setting(self, _key):
            return None

        def list_transfers(self, *, limit):
            assert limit == 20
            raise RuntimeError("transfer state unavailable")

    daemon = Daemon.__new__(Daemon)
    daemon.state = _State()
    daemon._call_registry = _EmptyCallRegistry()
    daemon._auto_install_in_flight = False
    daemon.ui_server = None
    monkeypatch.delenv("ONE_LINK_EXPERIMENTAL_AUTOINSTALL", raising=False)

    await daemon._maybe_auto_install("9.9.9", "1.0.0")

    assert daemon._auto_install_in_flight is False


def test_folder_permission_reconcile_does_not_mark_partial_scan_complete():
    class _State:
        def __init__(self):
            self.settings: dict[str, str] = {}

        def get_setting(self, key):
            return self.settings.get(key)

        def list_folder_offers(self, *, state_filter, limit):
            assert state_filter == "accepted"
            assert limit == 1000
            return [{"folder_name": "received", "peer_fp": "ab" * 32}]

        def get_folder(self, _name):
            return {"shared_with": ["ab" * 32]}

        def get_folder_peer_permission(self, _name, _peer):
            raise RuntimeError("temporary sqlite failure")

        def set_setting(self, key, value):
            self.settings[key] = value

    state = _State()
    daemon = Daemon.__new__(Daemon)
    daemon.state = state

    assert daemon._reconcile_received_folder_permissions_on_boot() == 0
    assert "folder_perm_reconcile_v1_done" not in state.settings


def test_rendezvous_inheritance_refuses_policy_read_failure():
    class _State:
        wrote_urls = False

        def get_setting(self, _key):
            raise RuntimeError("settings unavailable")

        def set_rendezvous_urls(self, _urls):
            self.wrote_urls = True

    state = _State()
    daemon = Daemon.__new__(Daemon)
    daemon.state = state
    daemon._inherited_rdz_from = set()
    daemon._is_pinned = lambda _fp: True

    daemon._inherit_rendezvous_urls_from(
        "ab" * 32, ["https://untrusted-rendezvous.invalid"],
    )

    assert state.wrote_urls is False
    assert daemon._inherited_rdz_from == set()


def test_sync_policy_failure_pauses_instead_of_sending():
    class _State:
        def get_setting(self, _key):
            raise RuntimeError("settings unavailable")

    daemon = Daemon.__new__(Daemon)
    daemon.state = _State()

    paused, reason = daemon._sync_paused_or_quiet()

    assert paused is True
    assert "unavailable" in reason


def test_presence_read_failure_does_not_advertise_online():
    class _State:
        def get_setting(self, _key):
            raise RuntimeError("settings unavailable")

    daemon = Daemon.__new__(Daemon)
    daemon.state = _State()

    assert daemon.get_my_presence() == "invisible"


def test_stun_resolution_fails_private_when_state_is_unavailable(monkeypatch):
    class _State:
        def get_setting(self, _key):
            raise RuntimeError("state unavailable")

    server = UIServer.__new__(UIServer)
    server.daemon = SimpleNamespace(state=_State())
    monkeypatch.setenv("ONE_LINK_STUN_SERVERS", "stun:external.invalid:3478")

    assert server._resolved_stun_servers() == []


@pytest.mark.asyncio
async def test_clear_verified_rejects_malformed_json_without_mutating_state():
    class _State:
        clear_called = False

        def clear_peer_verified(self, *_args, **_kwargs):
            self.clear_called = True
            raise AssertionError("must not mutate on malformed JSON")

    class _Request:
        match_info = {"fp": "ab" * 32}
        can_read_body = True

        async def json(self):
            raise ValueError("malformed")

    state = _State()
    server = UIServer.__new__(UIServer)
    server.daemon = SimpleNamespace(state=state)

    response = await server.api_clear_peer_verified(_Request())

    assert response.status == 400
    assert json.loads(response.text)["error"] == "request body must be valid JSON"
    assert state.clear_called is False


@pytest.mark.asyncio
async def test_identity_rotation_refuses_incomplete_peer_snapshot():
    class _State:
        def list_peers(self):
            raise RuntimeError("peer table unavailable")

    class _Request:
        async def json(self):
            return {"reason": "scheduled", "confirmed_rotate": True}

    server = UIServer.__new__(UIServer)
    server.daemon = SimpleNamespace(
        state=_State(),
        me=SimpleNamespace(private=object()),
    )
    server._rate_limited = lambda *_args, **_kwargs: False
    server._client_rate_key = lambda _request: "test"

    response = await server.api_recovery_rotate(_Request())

    assert response.status == 503
    assert "was not rotated" in json.loads(response.text)["error"]


@pytest.mark.asyncio
async def test_peer_list_refuses_incomplete_persistent_state_snapshot():
    class _State:
        def get_setting(self, _key):
            return None

        def list_peers(self):
            raise RuntimeError("peer table unavailable")

    server = UIServer.__new__(UIServer)
    server.daemon = SimpleNamespace(
        state=_State(),
        discovery=None,
        me=SimpleNamespace(
            fingerprint="aa" * 32,
            short_id="aaaaaaaa",
            hostname="local",
            public_bytes=b"\xaa" * 32,
        ),
    )
    request = SimpleNamespace(query={})

    response = await server.api_peers(request)

    assert response.status == 503
    assert json.loads(response.text) == {
        "error": "peer state temporarily unavailable",
    }


@pytest.mark.asyncio
async def test_pair_confirmation_propagates_peer_persistence_failure():
    class _State:
        def upsert_peer(self, **_kwargs):
            raise RuntimeError("peer write failed")

    daemon = Daemon.__new__(Daemon)
    daemon.state = _State()
    daemon._peer_fp_from_peer = lambda _peer: "ab" * 32
    peer = SimpleNamespace(
        short_id="abcd1234",
        ed_pub_hex="11" * 32,
        hostname="peer",
        address="127.0.0.1",
        port=7117,
    )

    with pytest.raises(RuntimeError, match="peer write failed"):
        await daemon.confirm_pair(peer)


def test_corrupt_group_event_is_not_silently_dropped(tmp_path: Path):
    state = State(db_path=tmp_path / "state.db")
    try:
        group_id = b"\xaa" * 16
        state.upsert_group_event(
            group_id=group_id,
            event_id="corrupt-event",
            timestamp_ms=1,
            wire_dict={"kind": "create"},
        )
        state._conn.execute(
            "UPDATE group_events SET wire_json = ? WHERE event_id = ?",
            ("{not-json", "corrupt-event"),
        )

        with pytest.raises(ValueError, match="corrupt-event"):
            state.list_group_events(group_id)
    finally:
        state.close()


def test_forget_chunk_available_propagates_database_failure(tmp_path: Path):
    state = State(db_path=tmp_path / "state.db")
    original_conn = state._conn

    class _BrokenConnection:
        def execute(self, *_args, **_kwargs):
            raise RuntimeError("database write failed")

    try:
        state._conn = _BrokenConnection()
        with pytest.raises(RuntimeError, match="database write failed"):
            state.forget_chunk_available("ab" * 32)
    finally:
        state._conn = original_conn
        state.close()


def test_tls_key_permission_failure_is_fatal_on_posix(monkeypatch, tmp_path: Path):
    path = tmp_path / "key.pem"
    path.write_bytes(b"private")
    monkeypatch.setattr(peer_https, "_must_enforce_private_permissions", lambda: True)

    def _deny_chmod(*_args, **_kwargs):
        raise OSError("permission denied")

    monkeypatch.setattr(peer_https.os, "chmod", _deny_chmod)

    with pytest.raises(PermissionError, match="restrict TLS key material"):
        peer_https._restrict_private_files(path)


def test_tls_key_write_fails_before_secret_when_fchmod_is_unavailable(
    monkeypatch,
    tmp_path: Path,
):
    path = tmp_path / "key.pem"
    path.write_bytes(b"pre-existing-public-bytes")
    monkeypatch.setattr(peer_https, "_must_enforce_private_permissions", lambda: True)
    monkeypatch.delattr(peer_https.os, "fchmod", raising=False)

    with pytest.raises(PermissionError, match="restrict TLS key material"):
        peer_https._write_private_bytes(path, b"new-secret-key-material")

    assert path.read_bytes() == b"pre-existing-public-bytes"


def test_key_forget_logs_failed_secure_overwrite_but_still_unlinks(
    monkeypatch, tmp_path: Path, caplog,
):
    key_path = tmp_path / "state.key"
    key_path.write_bytes(b"secret-key-material")
    monkeypatch.setattr(keychain, "_local_key_path", lambda: key_path)
    monkeypatch.setattr(keychain, "_load_keyring", lambda: None)

    def _fail_fsync(_fd):
        raise OSError("disk refused flush")

    monkeypatch.setattr(keychain.os, "fsync", _fail_fsync)

    with caplog.at_level("WARNING", logger="one_link.keychain"):
        assert keychain.forget_passphrase() is True

    assert not key_path.exists()
    assert any("secure overwrite failed" in record.message for record in caplog.records)


def test_incompatible_daemon_stop_reports_taskkill_failure(monkeypatch):
    monkeypatch.setattr(app.os, "name", "nt", raising=False)
    monkeypatch.setattr(app.os, "getpid", lambda: 9999)
    monkeypatch.setattr(app.os, "kill", lambda _pid, _sig: None)
    monkeypatch.setattr(app.time, "time", iter([0.0, 10.0]).__next__)
    monkeypatch.setattr(
        app,
        "resolve_system_executable",
        lambda *_args, **_kwargs: r"C:\Windows\System32\taskkill.exe",
    )

    def _taskkill_failed(*_args, **_kwargs):
        raise OSError("taskkill unavailable")

    monkeypatch.setattr(app.subprocess, "run", _taskkill_failed)

    assert app._terminate_pid(1234, timeout=0.0) is False
