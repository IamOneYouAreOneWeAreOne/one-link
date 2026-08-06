import re
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
    assert "Years must be four digits" in html
    assert 'id="jump-date-hint" role="status" aria-live="polite"' in html
    assert 'input.setAttribute("aria-describedby", "jump-date-hint")' in html
    assert 'input.classList.toggle("invalid", kind === "bad")' in html
    assert 'toast(text, "bad", 4500)' in html
    assert "That calendar date does not exist." in html
    assert "That date is outside this conversation" in html


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
    assert "function _fileDiagnosticPayload(msg, t, access, kind)" in html
    assert '"Open route"' in html
    assert '"Source"' in html
    assert '"Needs"' in html
    assert '"Preview route"' in html
    assert '"Save a copy"' in html
    assert '"Copy file details"' in html
    assert 'copyToClipboard(JSON.stringify(diagnostic, null, 2), "file details")' in html
    assert "Preview not available on this side" in html
    assert "Preview unavailable on this device" in html


def test_chat_file_preview_avoids_fragile_unicode_separators() -> None:
    html = _html()
    assert "? ` - ${_lightboxState.index + 1} of ${count}`" in html
    assert '+ (ent.sizeBytes ? ` - ${fmtBytes(ent.sizeBytes)}` : "")' in html
    assert 'prev.textContent = "<";' in html
    assert 'next.textContent = ">";' in html
    assert "? ` · ${_lightboxState.index + 1} of ${count}`" not in html
    assert '+ (ent.sizeBytes ? ` · ${fmtBytes(ent.sizeBytes)}` : "")' not in html


def test_launcher_and_tray_open_authenticated_owner_url() -> None:
    cli = (ROOT / "src" / "one_link" / "cli.py").read_text(encoding="utf-8")
    app = (ROOT / "src" / "one_link" / "app.py").read_text(encoding="utf-8")
    tray = (ROOT / "src" / "one_link" / "tray.py").read_text(encoding="utf-8")
    assert "control_ipc.request_control" in cli
    assert "_resolve_running_daemon(timeout=timeout)" in cli
    assert '"ui_launch_info"' in app
    assert "_open_verified_ui_instance" in app
    assert '"ui.token"' not in cli
    assert '"server.port"' not in cli
    # 2026-08-06: this used to pin the literal `f"http://127.0.0.1:{port}/?t={token}"`,
    # which was the leaking construction -- that URL is handed to a browser, and a browser
    # command line is readable by any same-user process (threat T7b in docs/SECURITY.md).
    # The INTENT of this assertion was "the launcher and tray open an AUTHENTICATED owner
    # URL, not a bare one", and that intent survives: the credential is now a single-use
    # launch nonce minted per open. Narrowed to the intent rather than deleted, and
    # strengthened -- it now also refuses the construction it previously required.
    assert "_ui_launch_url" in cli, "the CLI no longer builds an authenticated UI URL"
    assert 'f"http://127.0.0.1:{info.server_port}{path}?t={credential}"' in cli
    assert 'f"http://127.0.0.1:{port}/?t={token}"' not in cli, (
        "the long-lived bearer is back in a browser-bound URL")
    assert "ui_port.txt" not in cli
    assert "def _display_url(url: str)" in tray
    assert "urlsplit(url)" in tray
    assert "_display_url(self._url)" in tray
    assert "url_provider" in tray, "the tray no longer mints a fresh credential per click"


def test_composer_toolbar_uses_icons_not_text_labels() -> None:
    html = _html()
    composer_start = html.index('<div class="composer">')
    composer_end = html.index("<!-- v0.9.2 voice recording overlay", composer_start)
    composer = html[composer_start:composer_end]

    for control_id in ("btn-attach2", "btn-voice", "btn-emoji"):
        assert f'id="{control_id}"' in composer
        assert "composer-icon" in composer
        assert re.search(rf'id="{control_id}"[^>]+aria-label="', composer), control_id

    assert ">Attach</button>" not in composer
    assert ">Mic</button>" not in composer
    assert ">:)</button>" not in composer
    assert "COMPOSER_MIC_ICON" in html
    assert "COMPOSER_STOP_ICON" in html
    assert "setVoiceButtonIcon(false)" in html
    assert "setVoiceButtonIcon(true)" in html
    assert '$("#btn-voice").textContent = "Mic"' not in html
    assert '$("#btn-voice").textContent = "Attach"' not in html


def test_image_metadata_removal_fails_closed_before_staging() -> None:
    html = _html()
    stage_start = html.index("async function stageFile(file, relPath = null)")
    stage_end = html.index("function _isImageFileForStrip", stage_start)
    stage_body = html[stage_start:stage_end]
    strip_start = html.index("async function _stripImageMetadata(file)")
    strip_end = html.index("function removeStaged", strip_start)
    strip_body = html[strip_start:strip_end]

    assert "EXIF strip failed, sending original" not in html
    assert "Image metadata removal failed; attachment blocked" in stage_body
    assert "could not safely remove its location and camera metadata" in stage_body
    assert "return false;" in stage_body
    assert stage_body.index("return false;") < stage_body.index("state.staged.push(")
    assert "if (!blob) return file" not in strip_body
    assert "if (!ctx) throw new Error" in strip_body
    assert "if (!value || value.size === 0)" in strip_body
    assert "browser did not honor sanitized image type" in strip_body
