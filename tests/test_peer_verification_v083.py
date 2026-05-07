"""v0.7.7 — verified-in-person trust mark.

The Double Ratchet (v0.8.2) gives us forward-secret channels, but the
cryptographic primitives can't tell the user whether the *peer's
pubkey* belongs to the human they think it does — only a side channel
can do that. v0.7.7 adds a per-peer flag the user flips after they've
compared the SAS face-to-face / on a call / by reading it aloud.

These tests cover the persistence layer (state.py) and the HTTP
endpoint shape exposed by server.py. UI surfaces are smoke-checked in
the index.html string assertions at the bottom.
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


def _seed_peer(state: State, fp: str = "aa" * 32) -> str:
    state.upsert_peer(
        fingerprint=fp, short_id="alice123", pubkey=b"\x00" * 32,
        hostname="alice-laptop",
    )
    return fp


# ───────── schema migration ──────────────────────────────────────────

def test_migration_v8_adds_verification_columns(state: State):
    """ALTER TABLE peers must add verified_at_ms / verified_method /
    verified_note, and the schema_version row must advance to 8."""
    cols = {row["name"] for row in state._conn.execute(
        "PRAGMA table_info(peers)"
    ).fetchall()}
    assert "verified_at_ms" in cols
    assert "verified_method" in cols
    assert "verified_note" in cols
    assert state.schema_version() >= 8


# ───────── set_peer_verified ─────────────────────────────────────────

def test_set_peer_verified_persists_state(state: State):
    fp = _seed_peer(state)
    rec = state.set_peer_verified(fp, method="sas-digits", note="met at office")
    assert rec is not None
    assert rec.is_verified is True
    assert rec.verified_at_ms is not None
    assert rec.verified_method == "sas-digits"
    assert rec.verified_note == "met at office"


def test_set_peer_verified_round_trip_via_get_peer(state: State):
    fp = _seed_peer(state)
    state.set_peer_verified(fp, method="sas-qr")
    fresh = state.get_peer(fp)
    assert fresh.is_verified is True
    assert fresh.verified_method == "sas-qr"


def test_set_peer_verified_rejects_unknown_method(state: State):
    fp = _seed_peer(state)
    with pytest.raises(ValueError):
        state.set_peer_verified(fp, method="vibes-only")


def test_set_peer_verified_returns_none_for_missing_peer(state: State):
    rec = state.set_peer_verified("ff" * 32, method="manual")
    assert rec is None


def test_set_peer_verified_normalizes_blank_note_to_null(state: State):
    fp = _seed_peer(state)
    rec = state.set_peer_verified(fp, method="manual", note="   ")
    assert rec.verified_note is None


def test_set_peer_verified_rejects_oversized_note(state: State):
    fp = _seed_peer(state)
    with pytest.raises(ValueError):
        state.set_peer_verified(fp, method="manual", note="x" * 281)


def test_set_peer_verified_writes_audit_row(state: State):
    fp = _seed_peer(state)
    state.set_peer_verified(fp, method="sas-digits", note="hallway", actor="ui")
    rows = state.recent_capability_audit(fingerprint=fp, limit=10)
    kinds = [r["kind"] for r in rows]
    assert "verify_set" in kinds


# ───────── clear_peer_verified ───────────────────────────────────────

def test_clear_peer_verified_removes_state(state: State):
    fp = _seed_peer(state)
    state.set_peer_verified(fp, method="sas-digits")
    cleared = state.clear_peer_verified(fp, actor="ui", note="rotated keys")
    assert cleared is not None
    assert cleared.is_verified is False
    assert cleared.verified_at_ms is None
    assert cleared.verified_method is None
    assert cleared.verified_note is None


def test_clear_peer_verified_writes_audit_row(state: State):
    fp = _seed_peer(state)
    state.set_peer_verified(fp, method="sas-digits")
    state.clear_peer_verified(fp, actor="ui")
    rows = state.recent_capability_audit(fingerprint=fp, limit=10)
    kinds = [r["kind"] for r in rows]
    assert kinds.count("verify_clear") == 1


def test_clear_peer_verified_idempotent_on_unverified(state: State):
    """Clearing an already-unverified peer should be a no-op (no
    audit row, no exception, returns the unchanged record)."""
    fp = _seed_peer(state)
    rec = state.clear_peer_verified(fp)
    assert rec is not None
    assert rec.is_verified is False
    rows = state.recent_capability_audit(fingerprint=fp, limit=10)
    assert all(r["kind"] != "verify_clear" for r in rows)


def test_clear_peer_verified_returns_none_for_missing_peer(state: State):
    assert state.clear_peer_verified("ff" * 32) is None


# ───────── property semantics ────────────────────────────────────────

def test_is_verified_independent_of_trust(state: State):
    """Trust gates wire access; verification gates UI affordance.
    A peer can be 'pinned' but not yet verified-in-person — that's
    the common state for the first day after pairing."""
    fp = _seed_peer(state)
    state.set_peer_trust(fp, "pinned")
    rec = state.get_peer(fp)
    assert rec.trust == "pinned"
    assert rec.is_verified is False  # pinned ≠ verified


def test_is_verified_survives_unrelated_profile_update(state: State):
    """Setting an alias must not clear verification state."""
    fp = _seed_peer(state)
    state.set_peer_verified(fp, method="sas-digits")
    state.set_peer_profile(fp, local_alias="Alice")
    rec = state.get_peer(fp)
    assert rec.is_verified is True
    assert rec.local_alias == "Alice"


# ───────── api_peers serialization ───────────────────────────────────

def test_api_peers_response_includes_verification_fields():
    """Read-only static check: server.py's api_peers must surface
    the new columns so the UI can render the avatar overlay."""
    src = Path(
        "src/one_link/server.py"
    ).read_text(encoding="utf-8")
    assert '"verified_at_ms": rec.verified_at_ms' in src
    assert '"verified_method": rec.verified_method' in src
    assert '"verified_note": rec.verified_note' in src
    assert '"is_verified": rec.is_verified' in src


def test_routes_register_verify_endpoints():
    """POST + DELETE /api/peers/{fp}/verify must be wired."""
    src = Path(
        "src/one_link/server.py"
    ).read_text(encoding="utf-8")
    assert (
        'r.add_post(r"/api/peers/{fp}/verify", '
        'self._guarded(self.api_set_peer_verified))'
    ) in src
    assert (
        'r.add_delete(r"/api/peers/{fp}/verify", '
        'self._guarded(self.api_clear_peer_verified))'
    ) in src


def test_index_html_renders_verification_surfaces():
    """Smoke-check the UI: avatar overlay + drawer section +
    conversation header pill must all be present."""
    src = Path(
        "src/one_link/web/index.html"
    ).read_text(encoding="utf-8")
    # Drawer section
    assert 'id="dev-verify-section"' in src
    assert 'id="dev-verify-confirm"' in src
    assert 'id="dev-verify-revoke"' in src
    # Sidebar overlay class hook
    assert "verified-overlay" in src
    # Conversation header pill / CTA
    assert 'id="convo-trust"' in src
    assert "verified-pill" in src
    assert "verify-cta" in src
    # Live WS event handler
    assert 'm.type === "peer_verified"' in src
    # Page version constant present (post-v0.8.3); each subsequent
    # ship can bump the digit, so we just check the surface exists.
    assert "PAGE_BUILT_FOR" in src
