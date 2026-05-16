"""Tier α browser media tests + Call-Mom button on contact rows.

Substring assertions over index.html pin:
  - <video id="call-local-video"> + <video id="call-remote-video">
  - getUserMedia is requested with audio + video
  - addTrack is wired into the RTCPeerConnection
  - ontrack handler attaches the remote stream to the video element
  - Mute + Camera toggles modify MediaStreamTrack.enabled (the
    track stays connected so DTLS-SRTP doesn't churn)
  - stopAllMedia is called on hangup and on phase=ended/async_capture
  - Call button on contact rows is wired to startLivingPresenceCall
"""

from __future__ import annotations

from pathlib import Path

import pytest


INDEX_HTML_PATH = (
    Path(__file__).resolve().parent.parent
    / "src" / "one_link" / "web" / "index.html"
)


@pytest.fixture(scope="module")
def index_html() -> str:
    return INDEX_HTML_PATH.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Video elements
# ---------------------------------------------------------------------------

def test_remote_video_element_present(index_html: str) -> None:
    assert 'id="call-remote-video"' in index_html
    # autoplay + playsinline are needed for cross-browser stream rendering
    idx = index_html.find('id="call-remote-video"')
    snippet = index_html[idx:idx + 300]
    assert "autoplay" in snippet
    assert "playsinline" in snippet


def test_local_video_element_present(index_html: str) -> None:
    assert 'id="call-local-video"' in index_html
    idx = index_html.find('id="call-local-video"')
    snippet = index_html[idx:idx + 300]
    # Local preview must be muted to avoid feedback.
    assert "muted" in snippet


def test_remote_video_styled(index_html: str) -> None:
    assert ".call-remote-video" in index_html


def test_local_video_styled_picture_in_picture(index_html: str) -> None:
    """Picture-in-picture: local view sits absolute-positioned over
    the remote video. CSS pin."""
    assert ".call-local-video" in index_html
    # The CSS rule should target positioning, not just look.
    idx = index_html.find(".call-local-video {")
    snippet = index_html[idx:idx + 400]
    assert "position: absolute" in snippet


# ---------------------------------------------------------------------------
# getUserMedia + RTC wiring
# ---------------------------------------------------------------------------

def test_get_user_media_audio_and_video(index_html: str) -> None:
    """When a call starts, the browser requests audio + video.
    Falls back to audio-only on permission denial — that's also
    asserted."""
    assert "navigator.mediaDevices.getUserMedia" in index_html
    assert "{ audio: true, video: true }" in index_html
    # Audio-only fallback exists.
    assert "{ audio: true }" in index_html


def test_setup_rtc_peer_connection_function(index_html: str) -> None:
    assert "function setupRtcPeerConnection" in index_html
    assert "new RTCPeerConnection" in index_html


def test_ontrack_attaches_remote_stream(index_html: str) -> None:
    idx = index_html.find("pc.ontrack")
    assert idx > 0
    snippet = index_html[idx:idx + 800]
    assert "attachRemoteStream" in snippet


def test_addtrack_on_call_start(index_html: str) -> None:
    """When startLivingPresenceCall fires + media comes up,
    each track is added to the RTCPeerConnection. Pin the wiring."""
    idx = index_html.find("window.startLivingPresenceCall = async function")
    snippet = index_html[idx:idx + 3000]
    assert "media.pc.addTrack" in snippet


def test_addtrack_on_accept(index_html: str) -> None:
    """Same wiring on the receiving side when the user accepts."""
    # The accept handler is registered in the JS driver section.
    idx = index_html.find('const acceptBtn = $$("#btn-call-accept");')
    assert idx > 0
    snippet = index_html[idx:idx + 1500]
    assert "media.pc.addTrack" in snippet


# ---------------------------------------------------------------------------
# Mute / Camera toggles
# ---------------------------------------------------------------------------

def test_mute_button_in_active_surface(index_html: str) -> None:
    assert 'id="btn-call-mute"' in index_html


def test_camera_button_in_active_surface(index_html: str) -> None:
    assert 'id="btn-call-camera"' in index_html


def test_mute_toggles_audio_track_enabled(index_html: str) -> None:
    """The mute toggle flips MediaStreamTrack.enabled — keeps the
    track wired so DTLS-SRTP doesn't churn."""
    # Anchor on the click handler registration specifically.
    idx = index_html.find(
        'if (muteBtn) muteBtn.addEventListener("click"',
    )
    assert idx > 0
    snippet = index_html[idx:idx + 500]
    assert "getAudioTracks" in snippet
    assert "t.enabled" in snippet


def test_camera_toggles_video_track_enabled(index_html: str) -> None:
    idx = index_html.find(
        'if (cameraBtn) cameraBtn.addEventListener("click"',
    )
    assert idx > 0
    snippet = index_html[idx:idx + 500]
    assert "getVideoTracks" in snippet
    assert "t.enabled" in snippet


def test_mute_button_aria_pressed_synced(index_html: str) -> None:
    """Doctrine §5.b — screen-reader navigability. The aria-pressed
    attribute reflects the toggle state."""
    assert "syncMuteCameraButtons" in index_html
    assert 'setAttribute("aria-pressed"' in index_html


# ---------------------------------------------------------------------------
# Media teardown on hangup / phase transitions
# ---------------------------------------------------------------------------

def test_stop_all_media_function_defined(index_html: str) -> None:
    assert "function stopAllMedia" in index_html


def test_stop_all_media_stops_tracks(index_html: str) -> None:
    idx = index_html.find("function stopAllMedia")
    snippet = index_html[idx:idx + 1200]
    assert "t.stop()" in snippet
    # Closes the RTCPeerConnection
    assert "media.pc.close()" in snippet


def test_hangup_button_calls_stop_all_media(index_html: str) -> None:
    idx = index_html.find('const hangupBtn = $$("#btn-call-hangup");')
    assert idx > 0
    snippet = index_html[idx:idx + 600]
    assert "stopAllMedia()" in snippet


def test_phase_ended_stops_media(index_html: str) -> None:
    """When the daemon broadcasts phase_changed=ended (or
    async_capture), the browser tears down media too — otherwise
    the camera stays on after the peer ends."""
    idx = index_html.find('phase === "ended"')
    snippet = index_html[idx:idx + 800]
    assert "stopAllMedia()" in snippet


# ---------------------------------------------------------------------------
# Call Mom button on contact rows
# ---------------------------------------------------------------------------

def test_call_button_on_pinned_peers(index_html: str) -> None:
    """May 15 2026 — the single 📞 call button was split into two
    distinct buttons (📞 voice / 📹 video) so the user can pick the
    call kind explicitly. Both render only on pinned-trust peers."""
    assert 'el("button", "call-btn-voice", "📞")' in index_html
    assert 'el("button", "call-btn-video", "📹")' in index_html


def test_call_button_only_for_pinned_trust(index_html: str) -> None:
    """Calls require pinned identity. Pending / rejected peers
    don't get either call button."""
    idx = index_html.find('el("button", "call-btn-voice"')
    # Search backwards for the conditional.
    pre = index_html[max(0, idx - 800):idx]
    assert 'p.trust === "pinned"' in pre


def test_call_button_calls_startlivingpresencecall(index_html: str) -> None:
    """Both buttons route to startLivingPresenceCall with the peer's
    fingerprint, display name, AND an explicit {video:bool} opts so
    the camera state matches the icon clicked."""
    idx_v = index_html.find('el("button", "call-btn-voice"')
    voice_snippet = index_html[idx_v:idx_v + 1200]
    assert "startLivingPresenceCall(" in voice_snippet
    assert "p.fingerprint" in voice_snippet
    assert "{ video: false }" in voice_snippet
    idx_V = index_html.find('el("button", "call-btn-video"')
    video_snippet = index_html[idx_V:idx_V + 1200]
    assert "startLivingPresenceCall(" in video_snippet
    assert "p.fingerprint" in video_snippet
    assert "{ video: true }" in video_snippet


def test_call_button_has_aria_label(index_html: str) -> None:
    """Doctrine §5.b — every button is screen-reader accessible.
    Both voice + video buttons set aria-label distinctly."""
    idx_v = index_html.find('el("button", "call-btn-voice"')
    voice_snippet = index_html[idx_v:idx_v + 800]
    assert 'setAttribute("aria-label"' in voice_snippet
    assert 'Voice call' in voice_snippet
    idx_V = index_html.find('el("button", "call-btn-video"')
    video_snippet = index_html[idx_V:idx_V + 800]
    assert 'setAttribute("aria-label"' in video_snippet
    assert 'Video call' in video_snippet


def test_call_button_styled(index_html: str) -> None:
    """Both call buttons inherit the base .peer .call-btn style + each
    has its own hover-tint (green for voice, blue for video) so they're
    visually distinct."""
    assert ".peer .call-btn" in index_html
    assert ".peer .call-btn-voice" in index_html
    assert ".peer .call-btn-video" in index_html
    assert ".peer .call-btn-voice:hover" in index_html
    assert ".peer .call-btn-video:hover" in index_html
