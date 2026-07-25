"""Path-boundary tests for peer-supplied folder offers."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from one_link.server import (
    UIServer,
    _contained_leaf_path,
    _safe_untrusted_folder_leaf,
)


@pytest.mark.parametrize(
    "name",
    [
        "",
        ".",
        "..",
        "../escape",
        "..\\escape",
        "/absolute",
        "\\\\server\\share",
        "C:\\escape",
        "name:stream",
        "nested/name",
        "nested\\name",
        "CON",
        "nul.txt",
        "COM1.log",
        "trailing.",
        "trailing ",
        "line\nbreak",
    ],
)
def test_untrusted_folder_name_must_be_one_portable_leaf(name: str) -> None:
    with pytest.raises(ValueError):
        _safe_untrusted_folder_leaf(name)


def test_untrusted_folder_name_allows_normal_unicode_leaf() -> None:
    assert _safe_untrusted_folder_leaf("Résumé 2026") == "Résumé 2026"


def test_contained_leaf_path_rejects_preexisting_symlink_escape(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    link = root / "shared"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(ValueError, match="escapes"):
        _contained_leaf_path(root, "shared")


class _Request:
    def __init__(self, offer_id: int, local_path: str):
        self.match_info = {"offer_id": str(offer_id)}
        self._body = {"local_path": local_path}

    async def json(self) -> dict:
        return self._body


class _OfferState:
    def __init__(self, folder_name: str):
        self.offer = {
            "id": 1,
            "peer_fp": "bb" * 32,
            "folder_name": folder_name,
            "state": "pending",
        }

    def get_folder_offer(self, offer_id: int) -> dict | None:
        return self.offer if offer_id == 1 else None

    def get_folder(self, _name: str):
        return None


def _server(tmp_path: Path, monkeypatch, folder_name: str, engine) -> UIServer:
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = _OfferState(folder_name)
    daemon = SimpleNamespace(
        state=state,
        folder_engine=engine,
        blob_store=None,
        discovery=None,
        me=SimpleNamespace(
            fingerprint="aa" * 32,
            short_id="aaaaaaaa",
            hostname="path-test",
        ),
        _is_pinned=lambda _fp: True,
    )
    return UIServer(daemon)


@pytest.mark.asyncio
async def test_accept_offer_rejects_peer_path_before_folder_creation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    engine = MagicMock()
    server = _server(tmp_path, monkeypatch, "../../escape", engine)

    response = await server.api_accept_folder_offer(
        _Request(1, str(tmp_path / "chosen")),
    )
    body = json.loads(response.text)

    assert response.status == 400
    assert body["code"] == "unsafe_folder_name"
    engine.add_folder.assert_not_called()


@pytest.mark.asyncio
async def test_accept_fallback_rejects_symlinked_child_outside_root(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from one_link import server as server_module

    root = tmp_path / "fallback"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    link = root / "shared"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    engine = MagicMock()
    engine.add_folder.side_effect = OSError("chosen path is unwritable")
    monkeypatch.setattr(server_module, "_pick_writable_share_root", lambda: root)
    server = _server(tmp_path, monkeypatch, "shared", engine)

    response = await server.api_accept_folder_offer(
        _Request(1, str(tmp_path / "unwritable")),
    )

    assert response.status == 500
    # Only the user-selected path reached the engine. The escaped fallback was
    # rejected before it could be created or registered.
    assert engine.add_folder.call_count == 1
    assert list(outside.iterdir()) == []
