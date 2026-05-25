"""v0.9.2 — voice messages.

Hold-to-record (or Ctrl+Shift+M) → MediaRecorder captures opus blob
→ uploads via the existing /api/send-file pipeline. Receiver's
chat bubble auto-renders an inline <audio controls> player.

Pure UI ship — no schema, no new server endpoint. The /api/files
route already serves audio inbox content; renderFileBubble just
needs to recognize audio extensions.

These tests pin the surface contract.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


# ───────── composer surface ──────────────────────────────────────────

def test_composer_has_voice_button(index_html: str):
    assert 'id="btn-voice"' in index_html


def test_voice_overlay_exists(index_html: str):
    assert 'id="voice-overlay"' in index_html
    assert 'id="voice-timer"' in index_html
    assert 'id="voice-cancel"' in index_html
    assert 'id="voice-stop"' in index_html


def test_audio_extension_recognizer_present(index_html: str):
    """isAudioName powers the audio bubble; AUDIO_EXT must include
    at least the formats MediaRecorder emits across browsers."""
    assert "const AUDIO_EXT = new Set([" in index_html
    assert "const isAudioName" in index_html
    # The MediaRecorder-emitted formats:
    for ext in ('"webm"', '"ogg"', '"opus"', '"m4a"', '"mp3"', '"wav"'):
        assert ext in index_html


# ───────── state machine ─────────────────────────────────────────────

def test_voice_state_fields_initialized(index_html: str):
    for field in ("voiceRec", "voiceStream", "voiceChunks",
                  "voiceStartedAt", "voiceTimerId", "voiceCancelled"):
        assert f"state.{field} =" in index_html, f"missing state field {field}"


def test_voice_recording_helpers_present(index_html: str):
    assert "function _pickVoiceMime(" in index_html
    assert "function _voiceFilenameFor(" in index_html
    assert "async function startVoiceRecording(" in index_html
    assert "function stopVoiceRecording(" in index_html


def test_pick_voice_mime_prefers_opus(index_html: str):
    """Codec preference order matters: webm/opus first (best
    quality + smallest), ogg/opus next (Firefox), then plain
    fallbacks. This pins the priority list."""
    idx = index_html.find("function _pickVoiceMime(")
    snippet = index_html[idx:idx + 1000]
    webm_idx = snippet.find('"audio/webm;codecs=opus"')
    ogg_idx = snippet.find('"audio/ogg;codecs=opus"')
    plain_webm_idx = snippet.find('"audio/webm"')
    assert webm_idx > 0
    assert ogg_idx > webm_idx
    assert plain_webm_idx > ogg_idx


def test_no_op_if_no_peer_selected(index_html: str):
    """startVoiceRecording must early-return when no peer is
    selected — otherwise we'd pop a mic-permission prompt for a
    send that has no destination."""
    idx = index_html.find("async function startVoiceRecording(")
    snippet = index_html[idx:idx + 1500]
    assert "state.selectedPeer" in snippet
    assert "Pick a device on the left to start." in snippet


def test_handles_permission_denial_gracefully(index_html: str):
    idx = index_html.find("async function startVoiceRecording(")
    snippet = index_html[idx:idx + 3000]
    assert "NotAllowedError" in snippet
    assert "NotFoundError" in snippet


def test_recording_capped_at_5_minutes(index_html: str):
    """Hard cap so a stuck-recording loop can't fill the channel
    with a 4 GB clip."""
    idx = index_html.find("function updateVoiceTimer(")
    snippet = index_html[idx:idx + 800]
    assert "300" in snippet  # seconds = 5 min
    assert "stopVoiceRecording" in snippet


def test_minimum_blob_threshold(index_html: str):
    """Tiny blobs (sub-1KB) are mis-clicks; discard them rather
    than spawn a peer-side bubble."""
    idx = index_html.find("rec.onstop")
    snippet = index_html[idx:idx + 2500]
    assert "blob.size < 1024" in snippet


def test_keyboard_shortcut_ctrl_shift_m(index_html: str):
    """Ctrl+Shift+M toggles record. Pinned so a future shortcut
    refactor doesn't silently drop voice."""
    assert "ctrlKey && e.shiftKey" in index_html
    assert '"M" || e.key === "m"' in index_html


def test_microphone_stream_cleanup(index_html: str):
    """getUserMedia stream tracks must be stopped on rec.onstop —
    otherwise the OS-level mic indicator stays on (Windows shows
    the orange dot even when recording is finished)."""
    idx = index_html.find("rec.onstop")
    snippet = index_html[idx:idx + 2500]
    assert "stream.getTracks().forEach" in snippet
    assert ".stop()" in snippet


def test_recording_uploads_via_existing_pipeline(index_html: str):
    """No new endpoint — voice clips just go through api.upload like
    any other file. Pin so a future split doesn't bypass the
    transient-error retry / paused-resume logic that lives in
    the multipart handler."""
    idx = index_html.find("rec.onstop")
    snippet = index_html[idx:idx + 2500]
    assert "api.upload(" in snippet


# ───────── chat bubble surface ───────────────────────────────────────

def test_inbound_audio_bubble_renders_player(index_html: str):
    """renderFileBubble grew in v0.21.x with status-pill rendering,
    autopilot facts, image-preview inline lightboxes etc. The
    inbound-audio branch now sits further down the function. Widen
    the search slice to cover it."""
    idx = index_html.find("function renderFileBubble(msg)")
    snippet = index_html[idx:idx + 12000]
    assert "isAudioName(" in snippet
    assert 'document.createElement("audio")' in snippet
    assert "audio.controls = true" in snippet


def test_audio_bubble_uses_files_endpoint(index_html: str):
    """Audio src must point at /api/files/{name} so the path
    matches the inbox dir on the daemon."""
    idx = index_html.find("function renderFileBubble(msg)")
    snippet = index_html[idx:idx + 12000]
    assert "/api/files/" in snippet
    assert "encodeURIComponent(fname)" in snippet


def test_outbound_audio_shows_status_note(index_html: str):
    """We don't have an outbox-mirror endpoint yet; outbound
    voice bubbles show a 'Voice message sent' note instead of a
    broken player."""
    idx = index_html.find("function renderFileBubble(msg)")
    snippet = index_html[idx:idx + 12000]
    assert "Voice message sent" in snippet


def test_shortcuts_help_documents_voice(index_html: str):
    """The keyboard shortcuts modal must list Ctrl+Shift+M so the
    feature is discoverable beyond the mic icon."""
    assert "Ctrl + Shift + M" in index_html
    assert "Record / stop voice" in index_html


def test_page_version_bumped(index_html: str):
    from one_link import __version__

    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
