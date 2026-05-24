"""v0.21.x social-share recovery (guardian side).

Pin the guardian-side store of recovery shares: state schema,
import endpoint, list/delete endpoints, UI wiring. The third
restore path - users distribute Shamir shares, each guardian
holds one, and when the owner needs to recover they collect K
shares back from K guardians.

This file covers ship 1 (state + import/list/delete + UI card).
Ships 2 + 3 cover unwrap + recoverer-side combine.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]


def _server_src() -> str:
    return (ROOT / "src" / "one_link" / "server.py").read_text(encoding="utf-8")


def _index_html() -> str:
    return (ROOT / "src" / "one_link" / "web" / "index.html").read_text(encoding="utf-8")


def _open_state(tmp_path):
    from one_link.state import State
    return State(tmp_path / "state.db")


def _make_wrapped_share(*, threshold_k=3, total_n=5) -> bytes:
    """Mint a real .olss-shaped share for a fresh seed + dummy
    guardian keys. Returns the wire bytes of share #1."""
    from one_link import social_recovery
    seed = os.urandom(32)
    guardian_pubs = [
        Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        for _ in range(total_n)
    ]
    shares = social_recovery.split_and_wrap(
        seed=seed,
        contact_ed_pubs=guardian_pubs,
        threshold_k=threshold_k,
        total_n=total_n,
    )
    return shares[0].encoded


# ── state schema + helpers ──────────────────────────────────────────


def test_insert_held_share_persists_metadata_and_blob(tmp_path):
    state = _open_state(tmp_path)
    blob = _make_wrapped_share()
    row_id = state.insert_held_share(
        share_index=1, threshold_k=3, total_n=5,
        setup_ms=1_700_000_000_000,
        wrapped_blob=blob,
        label="Alice's share",
        owner_hint="ab12cd",
    )
    assert row_id > 0
    rows = state.list_held_shares()
    assert len(rows) == 1
    r = rows[0]
    assert r["share_index"] == 1
    assert r["threshold_k"] == 3
    assert r["total_n"] == 5
    assert r["setup_ms"] == 1_700_000_000_000
    assert r["wrapped_blob"] == blob
    assert r["label"] == "Alice's share"
    assert r["owner_hint"] == "ab12cd"


def test_insert_held_share_is_idempotent_on_blob(tmp_path):
    """Re-importing the same .olss file returns the same row id."""
    state = _open_state(tmp_path)
    blob = _make_wrapped_share()
    id_a = state.insert_held_share(
        share_index=1, threshold_k=3, total_n=5,
        setup_ms=1, wrapped_blob=blob,
    )
    id_b = state.insert_held_share(
        share_index=1, threshold_k=3, total_n=5,
        setup_ms=1, wrapped_blob=blob, label="(retry)",
    )
    assert id_a == id_b
    assert len(state.list_held_shares()) == 1


def test_delete_held_share_drops_row(tmp_path):
    state = _open_state(tmp_path)
    row_id = state.insert_held_share(
        share_index=1, threshold_k=3, total_n=5,
        setup_ms=1, wrapped_blob=_make_wrapped_share(),
    )
    assert state.delete_held_share(row_id) is True
    assert state.list_held_shares() == []
    # Second delete is a no-op.
    assert state.delete_held_share(row_id) is False


def test_get_held_share_returns_full_row(tmp_path):
    state = _open_state(tmp_path)
    blob = _make_wrapped_share()
    row_id = state.insert_held_share(
        share_index=2, threshold_k=2, total_n=3,
        setup_ms=42, wrapped_blob=blob,
        label="bob", owner_hint="ff00aa",
    )
    rec = state.get_held_share(row_id)
    assert rec is not None
    assert rec["id"] == row_id
    assert rec["share_index"] == 2
    assert rec["wrapped_blob"] == blob
    assert state.get_held_share(99999) is None


# ── recovery_api.parse_held_share_blob ──────────────────────────────


def test_parse_held_share_blob_extracts_metadata(tmp_path):
    from one_link import recovery_api
    blob = _make_wrapped_share(threshold_k=2, total_n=4)
    parsed = recovery_api.parse_held_share_blob(blob)
    assert parsed["share_index"] == 1
    assert parsed["threshold_k"] == 2
    assert parsed["total_n"] == 4
    assert parsed["wrapped_blob"] == blob


def test_parse_held_share_blob_rejects_bad_magic(tmp_path):
    from one_link import recovery_api
    with pytest.raises(ValueError):
        recovery_api.parse_held_share_blob(b"NOTOLSS" + os.urandom(80))


# ── HTTP endpoints ──────────────────────────────────────────────────


def test_held_shares_routes_registered_guarded():
    from one_link.server import UIServer
    daemon = SimpleNamespace(state=None, peer_rtc=None)
    server = UIServer(daemon)
    routes: dict[str, set[str]] = {}
    for resource in server.app.router.resources():
        info = resource.get_info()
        path = info.get("path") or info.get("formatter") or ""
        if "/recovery/shares" in path:
            for route in resource:
                routes.setdefault(path, set()).add(route.method)
    assert "POST" in routes.get("/api/v1/recovery/shares/import", set())
    assert "GET" in routes.get("/api/v1/recovery/shares", set())
    # The DELETE route uses a path-template parameter.
    delete_paths = [p for p in routes if p.startswith("/api/v1/recovery/shares/")
                    and "{share_id}" in p]
    assert delete_paths, f"DELETE route missing; routes={sorted(routes)}"
    assert "DELETE" in routes[delete_paths[0]]

    src = _server_src()
    for path_marker in (
        '"/api/v1/recovery/shares/import"',
        '"/api/v1/recovery/shares"',
        '"/api/v1/recovery/shares/{share_id}"',
    ):
        idx = src.find(path_marker)
        assert idx > 0, f"{path_marker} not registered"
        line_start = src.rfind("\n", 0, idx) + 1
        line_end = src.find("\n", idx)
        assert "self._guarded(" in src[line_start:line_end]


def test_held_shares_import_handler_caps_payload_and_validates_b64():
    """The handler caps blob_b64 at 3 KiB (.olss files are ~150B; the
    cap stops a hostile UI from triggering memory pressure) AND
    validates base64 before parsing."""
    src = _server_src()
    idx = src.find("async def api_recovery_shares_import(")
    assert idx > 0
    body = src[idx:idx + 3500]
    assert "len(blob_b64) > 4096" in body
    assert "validate=True" in body
    assert "parse_held_share_blob" in body
    assert "insert_held_share" in body
    assert "_recovery_no_store_headers" in body


# ── UI wiring ───────────────────────────────────────────────────────


def test_index_html_held_shares_api_methods_exist():
    html = _index_html()
    assert "recoveryHeldSharesList()" in html
    assert "recoveryHeldSharesImport(blobB64, label, ownerHint)" in html
    assert "recoveryHeldSharesDelete(shareId)" in html
    assert '"/api/v1/recovery/shares"' in html


def test_index_html_held_shares_card_in_wizard():
    html = _index_html()
    assert 'id="recwiz-track-held-shares"' in html
    assert 'data-track="held-shares"' in html
    assert "_recwizRenderHeldSharesCard" in html
    # Card has the import button + plain-English help disclosure.
    idx = html.find("async function _recwizRenderHeldSharesCard()")
    assert idx > 0
    body = html[idx:idx + 5000]
    assert 'data-recwiz-held="import"' in body
    assert "<summary>How does this work?</summary>" in body
    # Drop button uses native confirm before the destructive call.
    drop_idx = html.find("async function _recwizHeldShareDrop(")
    assert drop_idx > 0
    drop_body = html[drop_idx:drop_idx + 1000]
    assert "window.confirm" in drop_body
    assert "recoveryHeldSharesDelete" in drop_body
