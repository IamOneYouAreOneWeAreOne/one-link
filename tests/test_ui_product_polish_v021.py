from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _html() -> str:
    return (ROOT / "src" / "one_link" / "web" / "index.html").read_text(
        encoding="utf-8",
    )


def test_jump_date_accepts_human_dates_and_reports_errors() -> None:
    html = _html()
    assert "function _normalizeJumpDateInput(raw)" in html
    assert "YYYY-MM-DD or MM/DD/YYYY" in html
    assert 'input.classList.toggle("invalid", kind === "bad")' in html
    assert 'toast(text, "bad", 4500)' in html
    assert "That calendar date does not exist." in html


def test_first_conversation_render_forces_latest_messages_into_view() -> None:
    html = _html()
    assert 'const firstRender = !m._renderSig || m._renderSig === "no-peer";' in html
    assert "firstRender && state.searchResults == null" in html
    assert "prevBottomState.forceBottom = true;" in html
    assert "_forceNextMessagesToBottom(1800);" in html
    assert "_renderGroupSig" in html


def test_nearby_devices_have_explicit_details_and_chat_actions() -> None:
    html = _html()
    assert "activity-nearby-actions" in html
    assert 'label: "Details"' in html
    assert 'label: "Chat"' in html
    assert "openDeviceDrawer(p.short_id)" in html
    assert "ev.stopPropagation();" in html


def test_file_details_explain_open_route_and_actions() -> None:
    html = _html()
    assert "function fileAccessInfoForMessage(msg, t)" in html
    assert '"Open route"' in html
    assert '"Source"' in html
    assert '"Needs"' in html
    assert '"Save a copy"' in html
    assert "Preview not available on this side" in html


def test_launcher_and_tray_open_authenticated_owner_url() -> None:
    cli = (ROOT / "src" / "one_link" / "cli.py").read_text(encoding="utf-8")
    tray = (ROOT / "src" / "one_link" / "tray.py").read_text(encoding="utf-8")
    assert '"ui.token"' in cli
    assert 'f"?t={token}"' in cli
    assert '"server.port"' in cli
    assert "ui_port.txt" not in cli
    assert "def _display_url(url: str)" in tray
    assert "urlsplit(url)" in tray
    assert "_display_url(self._url)" in tray
