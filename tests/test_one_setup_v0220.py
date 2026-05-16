"""One Setup first-run foundation.

These tests pin the new setup contract at the API/UI boundary. One Setup is
state-driven, skippable, and has a technical diagnostics layer for people who
want proof without forcing normal users through jargon.
"""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _server_src() -> str:
    return (ROOT / "src" / "one_link" / "server.py").read_text(encoding="utf-8")


def _index_html() -> str:
    return (ROOT / "src" / "one_link" / "web" / "index.html").read_text(encoding="utf-8")


def test_setup_api_routes_exist() -> None:
    src = _server_src()
    assert 'r.add_get("/api/setup", self._guarded(self.api_setup_status))' in src
    assert 'r.add_post("/api/setup", self._guarded(self.api_update_setup))' in src


def test_setup_snapshot_is_state_derived_and_human_first() -> None:
    src = _server_src()
    idx = src.find("def _one_setup_snapshot(")
    assert idx > 0
    snippet = src[idx:idx + 14000]
    assert "state.list_self_mesh_roots()" in snippet
    assert "state.list_self_mesh_devices()" in snippet
    assert "state.list_self_mesh_presence()" in snippet
    assert '"mode": "human"' in snippet
    assert '"technical": {' in snippet
    assert '"diagnostics": diagnostics' in snippet
    assert '"receipt_redacted": True' in snippet
    assert '"next_action"' in snippet
    for item in (
        "One identity",
        "This device",
        "Add phone or laptop",
        "First message",
        "First file",
        "Privacy proof",
        "Device safety",
        "Recovery",
    ):
        assert item in snippet


def test_setup_post_actions_cover_skip_complete_and_real_milestones() -> None:
    src = _server_src()
    idx = src.find("async def api_update_setup(")
    assert idx > 0
    snippet = src[idx:idx + 5000]
    for action in (
        '"skip"',
        '"complete"',
        '"privacy_proof_viewed"',
        '"safety_reviewed"',
        '"first_message_sent"',
        '"first_file_sent"',
        '"recovery_configured"',
        '"reset"',
    ):
        assert action in snippet
    assert 'state.set_setting("onboarding_completed", "true")' in snippet
    assert "unsupported setup action" in snippet


def test_me_surfaces_one_setup_compatibility_flags() -> None:
    src = _server_src()
    idx = src.find("async def api_me(")
    snippet = src[idx:idx + 3200]
    assert '"one_setup_completed": one_setup_completed' in snippet
    assert '"one_setup_skipped_at_ms": one_setup_skipped_at_ms' in snippet
    assert 'state.get_setting("one_setup_completed")' in snippet
    assert 'state.get_setting("one_setup_skipped_at_ms")' in snippet


def test_one_setup_ui_contract_markers_present_after_build() -> None:
    html = _index_html()
    for marker in (
        "You are One",
        "Set up One Link",
        "Skip for now",
        "Name this device",
        "Create your One identity",
        "Add your phone or laptop",
        "Send something to yourself",
        "Technical setup details",
        'id="one-setup-panel"',
        'id="one-setup-resume"',
        'id="one-setup-panel-technical"',
        'id="one-setup-safety-panel"',
        'id="one-setup-review-safety"',
        "Technical verification",
        "function refreshOneSetup()",
        "function renderOneSetup()",
        "async function skipOneSetup()",
        "async function createOneSetupIdentity()",
        "async function oneSetupSendTest()",
        "async function oneSetupSendFile()",
        "async function oneSetupReviewSafety()",
        "hello-from-one-link.txt",
        "This moved through your private One Link fabric.",
        'api.setupAction("first_file_sent")',
        'api.setupAction("safety_reviewed")',
        'api.setupAction("complete")',
        'api.setupAction("skip")',
    ):
        assert marker in html
