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

import json
import shutil
import subprocess
import tempfile
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


def test_remote_audio_sink_present(index_html: str) -> None:
    assert 'id="call-remote-audio"' in index_html
    idx = index_html.find('id="call-remote-audio"')
    snippet = index_html[idx:idx + 260]
    assert "autoplay" in snippet
    assert "Remote audio stream" in snippet


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
    assert "media.iceConfigReady" in index_html
    assert 'fetch("/api/peer-rtc/ice-config"' in index_html


def test_sdp_waits_for_ice_config(index_html: str) -> None:
    """Regression: SDP offers/answers must not be minted before the
    daemon-provided STUN configuration has had a chance to apply.
    Otherwise the call can connect at the UI layer while media remains
    host-candidate-only."""
    offer_idx = index_html.find("async function sendLocalSdpOffer")
    offer_snippet = index_html[offer_idx:offer_idx + 600]
    assert "await media.iceConfigReady" in offer_snippet
    assert offer_snippet.find("await media.iceConfigReady") < offer_snippet.find("createOffer")

    answer_idx = index_html.find("async function sendLocalSdpAnswer")
    answer_snippet = index_html[answer_idx:answer_idx + 600]
    assert "await media.iceConfigReady" in answer_snippet
    assert answer_snippet.find("await media.iceConfigReady") < answer_snippet.find("createAnswer")


def test_ontrack_attaches_remote_stream(index_html: str) -> None:
    idx = index_html.find("pc.ontrack")
    assert idx > 0
    snippet = index_html[idx:idx + 800]
    assert "attachRemoteStream" in snippet
    assert "stream.addTrack(ev.track)" in snippet
    assert snippet.find("stream.addTrack(ev.track)") < snippet.find("attachRemoteStream(stream)")
    assert "Remote ${ev.track.kind} connected." in snippet


def test_report_metrics_includes_media_state(index_html: str) -> None:
    idx = index_html.find("async function reportCallMetricsOnce")
    snippet = index_html[idx:idx + 2600]
    assert "ice_connection_state" in snippet
    assert "remote_audio_tracks" in snippet
    assert "remote_video_tracks" in snippet
    assert "local_live_audio_tracks" in snippet
    assert "remote_live_video_tracks" in snippet
    assert "has_local_description" in snippet
    assert "has_remote_description" in snippet


def test_media_watchdog_restarts_stuck_negotiation(index_html: str) -> None:
    """The live failure mode was active call + live local tracks but
    signaling stayed stable/new forever. The watchdog must re-drive SDP
    offer creation from that state."""
    assert "function startMediaWatchdog" in index_html
    assert 'ensureMediaNegotiation("watchdog")' in index_html
    assert "function ensureLocalTracksOnPeerConnection" in index_html
    idx = index_html.find("async function ensureMediaNegotiation")
    snippet = index_html[idx:idx + 1400]
    assert "ensureLocalTracksOnPeerConnection()" in snippet
    assert "callUI.localMediaReady = true" in snippet
    assert "media.pc.localDescription" in snippet
    assert "media.pc.signalingState" in snippet
    assert "sendLocalSdpOffer" in snippet
    metrics_idx = index_html.find("async function reportCallMetricsOnce")
    metrics_snippet = index_html[metrics_idx:metrics_idx + 3300]
    assert 'ensureMediaNegotiation("metrics").catch' in metrics_snippet
    active_idx = index_html.find('window.handleLivingPresenceCallEvent = function')
    active_idx = index_html.find('if (phase === "active")', active_idx)
    active_snippet = index_html[active_idx:active_idx + 700]
    assert 'ensureMediaNegotiation("active")' in active_snippet


def test_accept_answers_pending_offer_before_self_offer(index_html: str) -> None:
    """Receiver side must not create an offer while a remote offer is
    waiting. That causes WebRTC glare and can strand media setup."""
    idx = index_html.find("async function acceptInboundCall")
    assert idx > 0
    snippet = index_html[idx:idx + 1800]
    pending_idx = snippet.find("if (callUI.pendingRemoteOffer)")
    apply_idx = snippet.find("await applyRemoteSdpOffer")
    ensure_idx = snippet.find('await ensureMediaNegotiation("accept")')
    assert pending_idx > 0
    assert apply_idx > pending_idx
    assert ensure_idx > apply_idx
    assert "} else {" in snippet[pending_idx:ensure_idx]


def test_remote_sdp_backfill_is_deduped(index_html: str) -> None:
    assert "appliedRemoteOfferKeys: new Set()" in index_html
    assert "appliedRemoteAnswerKeys: new Set()" in index_html
    assert "function sdpKey" in index_html
    offer_idx = index_html.find("async function applyRemoteSdpOffer")
    offer_snippet = index_html[offer_idx:offer_idx + 1200]
    assert "appliedRemoteOfferKeys.has(key)" in offer_snippet
    assert 'media.pc.signalingState !== "stable"' in offer_snippet
    answer_idx = index_html.find("async function applyRemoteSdpAnswer")
    answer_snippet = index_html[answer_idx:answer_idx + 1200]
    assert "appliedRemoteAnswerKeys.has(key)" in answer_snippet
    assert 'media.pc.signalingState !== "have-local-offer"' in answer_snippet


def test_sdp_offer_answer_retries_when_signaling_is_lost(index_html: str) -> None:
    """Live call recovery: the daemon can best-effort a frame over a
    reverse control channel, so browsers must retransmit unanswered
    WebRTC setup instead of waiting forever in have-local-offer."""
    assert "lastLocalOfferSdp" in index_html
    assert "lastLocalAnswerSdp" in index_html
    assert "async function resendLocalSdpOffer" in index_html
    assert "async function resendLocalSdpAnswer" in index_html
    ensure_idx = index_html.find("async function ensureMediaNegotiation")
    ensure_snippet = index_html[ensure_idx:ensure_idx + 1800]
    assert 'media.pc.signalingState === "have-local-offer"' in ensure_snippet
    assert "await resendLocalSdpOffer" in ensure_snippet
    offer_idx = index_html.find("async function applyRemoteSdpOffer")
    offer_snippet = index_html[offer_idx:offer_idx + 1800]
    assert "remote_offer_echo_ignored" in offer_snippet
    assert 'await resendLocalSdpOffer("offer_echo")' in offer_snippet
    assert 'await resendLocalSdpOffer("offer_collision")' in offer_snippet
    assert 'await resendLocalSdpAnswer("duplicate_offer")' in offer_snippet


def test_call_media_events_are_reported(index_html: str) -> None:
    assert 'action: "report_call_event"' in index_html
    for event in [
        "local_media_ready",
        "negotiation_starting",
        "offer_preparing",
        "offer_sent",
        "answer_preparing",
        "answer_sent",
        "remote_offer_received",
        "remote_answer_received",
        "remote_track_connected",
        "ice_state_changed",
        "offer_resend",
        "answer_resend",
    ]:
        assert event in index_html


def test_source_fingerprint_drift_triggers_soft_reload(index_html: str) -> None:
    assert 'const PAGE_SOURCE_FINGERPRINT = "__ONE_LINK_SOURCE_FINGERPRINT__";' in index_html
    assert "me.source_fingerprint" in index_html
    assert 'scheduleSoftReload(`${v || PAGE_BUILT_FOR}:${fp}`, "source")' in index_html


def test_outgoing_overlay_does_not_stop_active_call_stream(index_html: str) -> None:
    """Regression: the outgoing self-preview reuses media.localStream.
    Hiding the ringing overlay must detach that preview without stopping
    the tracks already attached to RTCPeerConnection."""
    idx = index_html.find("function hideOutgoingOverlay")
    snippet = index_html[idx:idx + 1200]
    assert "selfPrev.srcObject !== media.localStream" in snippet
    assert "selfPrev.srcObject = null" in snippet


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_call_lifecycle_keeps_sender_tracks_live_in_runtime(index_html: str) -> None:
    """Execute the real call driver in a browser-like VM.

    This catches bugs substring tests miss: the outgoing self-preview,
    RTCPeerConnection sender tracks, and phase_changed active transition
    all share the same MediaStream object in the real UI lifecycle.
    """
    marker = "call UI driver."
    marker_at = index_html.index(marker)
    start = index_html.rfind("// Living Presence Tier", 0, marker_at)
    assert start >= 0
    end = index_html.index("</script>", start)
    call_driver = index_html[start:end]
    harness = f"""
const vm = require("vm");
const driver = {json.dumps(call_driver)};

class FakeTrack {{
  constructor(kind) {{
    this.kind = kind;
    this.enabled = true;
    this.readyState = "live";
  }}
  stop() {{ this.readyState = "ended"; }}
}}

class FakeStream {{
  constructor() {{
    this._tracks = [new FakeTrack("audio"), new FakeTrack("video")];
  }}
  getTracks() {{ return this._tracks.slice(); }}
  getAudioTracks() {{ return this._tracks.filter((t) => t.kind === "audio"); }}
  getVideoTracks() {{ return this._tracks.filter((t) => t.kind === "video"); }}
  addTrack(track) {{ if (!this._tracks.includes(track)) this._tracks.push(track); }}
}}

const elements = new Map();
function el(selector) {{
  if (!elements.has(selector)) {{
    const node = {{
      selector,
      srcObject: null,
      textContent: "",
      innerHTML: "",
      style: {{}},
      classList: {{
        add() {{}},
        remove() {{}},
        toggle() {{}},
        contains() {{ return false; }},
      }},
      setAttribute() {{}},
      addEventListener() {{}},
      appendChild() {{}},
      querySelector() {{ return null; }},
      play() {{ return Promise.resolve(); }},
      closest() {{ return null; }},
    }};
    elements.set(selector, node);
  }}
  return elements.get(selector);
}}

const pcInstances = [];
class FakeRTCPeerConnection {{
  constructor() {{
    this.signalingState = "stable";
    this.iceConnectionState = "new";
    this.iceGatheringState = "new";
    this.connectionState = "new";
    this.localDescription = null;
    this.remoteDescription = null;
    this._senders = [];
    pcInstances.push(this);
  }}
  setConfiguration() {{}}
  addTrack(track, stream) {{
    this._senders.push({{ track, stream }});
    return this._senders[this._senders.length - 1];
  }}
  getSenders() {{ return this._senders.slice(); }}
  async createOffer() {{ return {{ type: "offer", sdp: "v=0\\r\\nm=audio 9 UDP/TLS/RTP/SAVPF 111\\r\\n" }}; }}
  async createAnswer() {{ return {{ type: "answer", sdp: "v=0\\r\\nm=audio 9 UDP/TLS/RTP/SAVPF 111\\r\\n" }}; }}
  async setLocalDescription(desc) {{ this.localDescription = desc; }}
  async setRemoteDescription(desc) {{ this.remoteDescription = desc; }}
  async addIceCandidate() {{}}
  async getStats() {{ return new Map(); }}
  close() {{ this.signalingState = "closed"; }}
}}

const context = {{
  console,
  Map,
  Set,
  Promise,
  Date,
  Array,
  Error,
  Element: function Element() {{}},
  MediaStream: FakeStream,
  MediaRecorder: function MediaRecorder() {{
    this.start = function () {{}};
    this.stop = function () {{}};
  }},
  RTCPeerConnection: FakeRTCPeerConnection,
  setInterval() {{ return 1; }},
  clearInterval() {{}},
  setTimeout() {{ return 1; }},
  clearTimeout() {{}},
  crypto: {{ subtle: {{ async digest() {{ return new ArrayBuffer(32); }} }} }},
  Blob: function Blob() {{ this.arrayBuffer = async () => new ArrayBuffer(0); }},
  _callPermissionPreflight: async () => true,
  startCallRingback() {{}},
  startCallRingtone() {{}},
  stopCallRing() {{}},
  fetch: async (_url, opts) => {{
    const body = opts && opts.body ? JSON.parse(opts.body) : {{}};
    return {{
      ok: true,
      json: async () => {{
        if (body.action === "initiate") return {{ ok: true, call_id: "call-runtime-1" }};
        return {{ ok: true, call_id: body.call_id || "call-runtime-1", iceServers: [] }};
      }},
    }};
  }},
  document: {{
    querySelector: el,
    getElementById: (id) => el("#" + id),
    createElement: () => el("created-" + Math.random()),
    body: el("body"),
    addEventListener() {{}},
  }},
  navigator: {{
    permissions: {{
      query: async () => ({{ state: "granted" }}),
    }},
    mediaDevices: {{
      getUserMedia: async () => new FakeStream(),
    }},
  }},
  localStorage: {{
    getItem() {{ return null; }},
    setItem() {{}},
  }},
  window: {{}},
}};
context.window = context;
context.globalThis = context;

vm.createContext(context);
vm.runInContext(driver, context, {{ timeout: 1000 }});

(async () => {{
  await context.window.startLivingPresenceCall("peer-master-vk-hex", "Computer 2", {{ video: true }});
  const pc = pcInstances[0];
  if (!pc) throw new Error("RTCPeerConnection was not created");
  if (pc.getSenders().length !== 2) throw new Error("expected audio+video senders");
  const before = pc.getSenders().map((s) => s.track.readyState).join(",");
  context.window.handleLivingPresenceCallEvent({{
    type: "call_event",
    tail_kind: "phase_changed",
    call_id: "call-runtime-1",
    new_phase: "active",
    peer_master_vk_hex: "peer-master-vk-hex",
  }});
  const after = pc.getSenders().map((s) => s.track.readyState).join(",");
  if (before !== "live,live") throw new Error("tracks were not live before active transition: " + before);
  if (after !== "live,live") throw new Error("active transition stopped sender tracks: " + after);
}})().catch((err) => {{
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
}});
"""
    with tempfile.NamedTemporaryFile("w", suffix=".cjs", delete=False, encoding="utf-8") as tmp:
        tmp.write(harness)
        tmp_path = Path(tmp.name)
    try:
        proc = subprocess.run(
            ["node", str(tmp_path)],
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
    finally:
        tmp_path.unlink(missing_ok=True)
    assert proc.returncode == 0, proc.stderr or proc.stdout


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
