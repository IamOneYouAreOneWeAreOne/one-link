from __future__ import annotations

from one_link.capabilities import FILE_CDC, FOLDER_SYNC, LOCAL_CAPABILITIES, normalize_caps
from one_link.sessions import protocol_catalog
from one_link.state import State


def test_capability_normalization_and_state_roundtrip(tmp_path):
    assert normalize_caps(["files", "chat", "files", "", None]) == ("chat", "files")

    state = State(db_path=tmp_path / "state.db")
    try:
        fp = "aa" * 32
        state.set_peer_capabilities(fp, [FILE_CDC, FOLDER_SYNC, FILE_CDC])
        assert state.get_peer_capabilities(fp) == [FILE_CDC, FOLDER_SYNC]
        assert state.get_peer_capability_policy(fp) is None
        state.set_peer_capability_policy(fp, ["chat", FILE_CDC, "chat"])
        assert state.get_peer_capability_policy(fp) == ["chat", FILE_CDC]
        state.clear_peer_capability_policy(fp)
        assert state.get_peer_capability_policy(fp) is None
    finally:
        state.close()


def test_local_capabilities_include_new_sync_features():
    assert FILE_CDC in LOCAL_CAPABILITIES
    assert FOLDER_SYNC in LOCAL_CAPABILITIES


def test_session_catalog_names_core_peer_flows():
    names = {p["name"] for p in protocol_catalog()}
    assert {"chat_text", "file_cdc_transfer", "folder_merkle_sync", "pairing"} <= names
