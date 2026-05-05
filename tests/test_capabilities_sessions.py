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


def test_transfer_ledger_tracks_progress_and_metadata(tmp_path):
    state = State(db_path=tmp_path / "state.db")
    try:
        rec = state.upsert_transfer(
            id="xfer-1",
            direction="out",
            peer_fp="aa" * 32,
            kind="file",
            name="dataset.bin",
            size=4096,
            blob_hash="bb" * 32,
            status="offered",
            progress_bytes=1024,
            total_bytes=4096,
            chunks_done=1,
            chunks_total=4,
            metadata={"mode": "cdc"},
        )
        assert rec.status == "offered"
        assert rec.metadata == {"mode": "cdc"}

        rec = state.update_transfer(
            "xfer-1",
            status="complete",
            progress_bytes=4096,
            chunks_done=4,
            raw_bytes=2048,
            wire_bytes=1024,
            metadata={"mode": "cdc", "skipped_chunks": 2},
        )
        assert rec is not None
        assert rec.status == "complete"
        assert rec.progress_bytes == 4096
        assert rec.metadata["skipped_chunks"] == 2

        listed = state.list_transfers(peer_fp="aa" * 32)
        assert [t.id for t in listed] == ["xfer-1"]
    finally:
        state.close()


def test_local_capabilities_include_new_sync_features():
    assert FILE_CDC in LOCAL_CAPABILITIES
    assert FOLDER_SYNC in LOCAL_CAPABILITIES


def test_session_catalog_names_core_peer_flows():
    names = {p["name"] for p in protocol_catalog()}
    assert {"chat_text", "file_cdc_transfer", "folder_merkle_sync", "pairing"} <= names
