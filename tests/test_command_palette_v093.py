"""v0.9.3 — global search / command palette (Ctrl+K).

Adds a unified search across messages (FTS5), peers, groups, and
inbox files. Ctrl+K opens a modal; arrow keys + Enter navigate +
activate; Esc closes.

These tests cover the state-layer global_search merge, the server
endpoint shape, and the UI surfaces.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from one_link.state import State


@pytest.fixture
def state(tmp_path: Path) -> State:
    s = State(db_path=tmp_path / "state.db")
    yield s
    s.close()


# ───────── state.global_search semantics ─────────────────────────────

def test_empty_query_returns_empty(state: State):
    out = state.global_search("")
    assert out == {"messages": [], "peers": [], "groups": []}


def test_whitespace_only_query_returns_empty(state: State):
    assert state.global_search("   ") == {"messages": [], "peers": [], "groups": []}


def test_finds_peer_by_hostname(state: State):
    state.upsert_peer(
        fingerprint="aa" * 32, short_id="alice123", pubkey=b"\x00" * 32,
        hostname="alice-laptop",
    )
    out = state.global_search("alice")
    assert len(out["peers"]) == 1
    assert out["peers"][0]["hostname"] == "alice-laptop"


def test_finds_peer_by_short_id(state: State):
    state.upsert_peer(
        fingerprint="aa" * 32, short_id="alice123", pubkey=b"\x00" * 32,
        hostname="x",
    )
    out = state.global_search("alice123")
    assert len(out["peers"]) >= 1
    assert out["peers"][0]["short_id"] == "alice123"


def test_finds_peer_by_local_alias(state: State):
    fp = "aa" * 32
    state.upsert_peer(
        fingerprint=fp, short_id="x", pubkey=b"\x00" * 32, hostname="x",
    )
    state.set_peer_profile(fp, local_alias="Mom's iPad")
    out = state.global_search("mom")
    assert any(p["display_name"] == "Mom's iPad" for p in out["peers"])


def test_peer_search_case_insensitive(state: State):
    state.upsert_peer(
        fingerprint="aa" * 32, short_id="bob", pubkey=b"\x00" * 32,
        hostname="BobsMacbook",
    )
    out = state.global_search("BOB")
    assert len(out["peers"]) >= 1


def test_finds_message_by_fts(state: State):
    state.upsert_peer(
        fingerprint="aa" * 32, short_id="alice", pubkey=b"\x00" * 32,
        hostname="alice",
    )
    state.record_message(
        id="m1", ts_ms=1000, direction="in", peer_fp="aa" * 32,
        msg_type="TEXT", body="hello world from alice",
    )
    state.record_message(
        id="m2", ts_ms=1100, direction="out", peer_fp="aa" * 32,
        msg_type="TEXT", body="goodbye",
    )
    out = state.global_search("hello")
    assert any("hello" in m["body"] for m in out["messages"])


def test_per_kind_limit_honored(state: State):
    for i in range(15):
        fp = f"{i:02x}" * 32
        state.upsert_peer(
            fingerprint=fp, short_id=f"hostX{i}", pubkey=b"\x00" * 32,
            hostname=f"hostX{i}",
        )
    out = state.global_search("hostX", per_kind_limit=5)
    assert len(out["peers"]) == 5


def test_pinned_peers_rank_first(state: State):
    """Pinned peers should sort ahead of pending ones — they're the
    user's actually-paired devices."""
    state.upsert_peer(
        fingerprint="aa" * 32, short_id="alpha", pubkey=b"\x00" * 32,
        hostname="alpha-host",
    )  # pending
    state.upsert_peer(
        fingerprint="bb" * 32, short_id="alpha2", pubkey=b"\x00" * 32,
        hostname="alpha2-host",
    )
    state.set_peer_trust("bb" * 32, "pinned")
    out = state.global_search("alpha")
    assert out["peers"][0]["trust"] == "pinned"


def test_fts_special_chars_safe(state: State):
    """A user typing 'auth: user' would otherwise hit FTS5's
    field-restricted query parser. Phrase-quoting in global_search
    must keep it safe."""
    state.upsert_peer(
        fingerprint="aa" * 32, short_id="x", pubkey=b"\x00" * 32, hostname="x",
    )
    state.record_message(
        id="m1", ts_ms=1000, direction="in", peer_fp="aa" * 32,
        msg_type="TEXT", body="auth: user logged in",
    )
    # No exception means we didn't blow up on the colon.
    out = state.global_search("auth: user")
    assert "messages" in out


def test_message_body_truncated_for_payload(state: State):
    """Long messages must be truncated server-side so the palette
    payload stays small."""
    fp = "aa" * 32
    state.upsert_peer(fingerprint=fp, short_id="a", pubkey=b"\x00" * 32, hostname="a")
    long_body = "lorem ipsum " * 100  # ~1.2 KB
    state.record_message(
        id="m1", ts_ms=1000, direction="in", peer_fp=fp,
        msg_type="TEXT", body=long_body,
    )
    out = state.global_search("lorem")
    assert all(len(m["body"]) <= 200 for m in out["messages"])


# ───────── server route + UI smoke ───────────────────────────────────

def test_route_registered():
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    assert (
        'r.add_get("/api/palette", '
        'self._guarded(self.api_global_search))'
    ) in src


def test_handler_present():
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    assert "async def api_global_search(" in src


def test_handler_includes_inbox_files():
    """Files from the inbox listing are added by the server on top
    of state-layer results — they don't live in sqlite. Pin so a
    refactor doesn't drop them."""
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    idx = src.find("async def api_global_search(")
    snippet = src[idx:idx + 3000]
    assert "inbox_dir()" in snippet
    assert '"name": name' in snippet


def test_handler_enriches_peer_display_names():
    """Message rows must surface peer_display_name for the UI's
    'from <peer>' rendering, otherwise the palette shows raw
    fingerprints."""
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    idx = src.find("async def api_global_search(")
    # 2026-05-22 audit Batch O: rate-limit block pushed
    # peer_display_name past the original 3000-char window. Read
    # to the next def or 6000 chars (whichever is shorter) so the
    # structural check survives reasonable in-function additions.
    end_idx = src.find("\n    async def ", idx + 30)
    if end_idx == -1 or end_idx - idx > 6000:
        end_idx = idx + 6000
    snippet = src[idx:end_idx]
    assert "peer_display_name" in snippet


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


def test_palette_modal_exists(index_html: str):
    assert 'id="palette-backdrop"' in index_html
    assert 'id="palette-input"' in index_html
    assert 'id="palette-results"' in index_html


def test_palette_helpers_present(index_html: str):
    for fn in ("openPalette", "closePalette", "renderPaletteResults",
               "runPaletteSearch", "paletteFocus", "paletteActivateFocused",
               "paletteHighlight"):
        assert f"function {fn}(" in index_html or f"function {fn} (" in index_html, fn


def test_ctrl_k_opens_palette(index_html: str):
    """Pin the keyboard binding."""
    assert '(e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k"' in index_html
    assert "openPalette()" in index_html


def test_ctrl_f_replaces_old_per_convo_binding(index_html: str):
    """Old Ctrl+K-for-per-convo-search must move to Ctrl+F so it
    doesn't fight the new global palette."""
    assert 'e.key === "f" || e.key === "F"' in index_html


def test_arrow_keys_navigate(index_html: str):
    """Arrow up/down + Enter must drive selection."""
    idx = index_html.find("if (!state.paletteOpen) return;")
    snippet = index_html[idx:idx + 1000]
    assert 'e.key === "ArrowDown"' in snippet
    assert 'e.key === "ArrowUp"' in snippet
    assert 'e.key === "Enter"' in snippet
    assert 'e.key === "Escape"' in snippet


def test_search_debounced(index_html: str):
    """Hitting the API on every keystroke would hammer the FTS
    table on long words — debounce must wrap input."""
    idx = index_html.find('"#palette-input"')
    snippet = index_html[idx:idx + 600]
    assert "setTimeout(" in snippet


def test_stale_response_dropped(index_html: str):
    """If the user keeps typing while a search is in flight, the
    stale response must NOT overwrite a newer one."""
    idx = index_html.find("async function runPaletteSearch(")
    snippet = index_html[idx:idx + 1000]
    assert "state.paletteQuery !== q" in snippet


def test_shortcuts_help_documents_palette(index_html: str):
    assert "Open command palette" in index_html


def test_page_version_bumped(index_html: str):
    from one_link import __version__

    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
