from __future__ import annotations

from scripts.e2e_call_ui_browser_gate import MEDIA_PATCH_JS, _debug_summary, evaluate_report


def test_e2e_call_ui_gate_installs_synthetic_media_without_real_devices() -> None:
    assert "navigator.mediaDevices.getUserMedia" in MEDIA_PATCH_JS
    assert "canvas.captureStream(30)" in MEDIA_PATCH_JS
    assert "createOscillator" in MEDIA_PATCH_JS
    assert "_callPermissionPreflight = async () => true" in MEDIA_PATCH_JS


def test_e2e_call_ui_gate_summarizes_debug_without_sdp_or_candidates() -> None:
    summary = _debug_summary({
        "call_id": "call-1",
        "pc": {
            "signalingState": "stable",
            "iceConnectionState": "connected",
            "connectionState": "connected",
            "localDescriptionType": "offer",
            "remoteDescriptionType": "answer",
        },
        "remote_tracks": [{"kind": "video", "readyState": "live"}],
        "remote_video_element": {"videoWidth": 640, "videoHeight": 360, "readyState": 4},
        "remote_audio_element": {"readyState": 4},
        "stats": [
            {"type": "inbound-rtp", "kind": "audio", "packetsReceived": 22},
            {"type": "inbound-rtp", "kind": "video", "packetsReceived": 44, "framesDecoded": 30},
        ],
    })

    assert summary["inboundAudioPackets"] == 22
    assert summary["inboundVideoPackets"] == 44
    assert summary["framesDecoded"] == 30
    assert "candidate" not in repr(summary).lower()
    assert "sdp" not in repr(summary).lower()


def test_e2e_call_ui_gate_passes_when_both_sides_have_media() -> None:
    side = {
        "iceConnectionState": "connected",
        "remoteDescriptionType": "answer",
        "inboundAudioPackets": 22,
        "inboundVideoPackets": 44,
        "framesDecoded": 30,
        "remoteVideoWidth": 640,
        "remoteVideoHeight": 360,
    }
    failures = evaluate_report({
        "ok": True,
        "caller": side,
        "receiver": {**side, "remoteDescriptionType": "offer"},
        "min_audio_packets": 8,
        "min_video_packets": 8,
        "min_video_frames": 8,
        "privacy": {
            "contains_media": False,
            "contains_sdp": False,
            "contains_ice_candidates": False,
            "contains_ip_addresses": False,
            "contains_device_names": False,
            "contains_user_content": False,
        },
    })

    assert failures == []


def test_e2e_call_ui_gate_fails_when_media_is_missing() -> None:
    failures = evaluate_report({
        "ok": False,
        "caller": {},
        "receiver": {},
        "min_audio_packets": 8,
        "min_video_packets": 8,
        "min_video_frames": 8,
        "privacy": {
            "contains_media": False,
            "contains_sdp": False,
            "contains_ice_candidates": False,
            "contains_ip_addresses": False,
            "contains_device_names": False,
            "contains_user_content": False,
        },
    })

    assert any("not ok" in failure for failure in failures)
    assert any("caller ICE" in failure for failure in failures)
    assert any("receiver ICE" in failure for failure in failures)
    assert any("audio packets" in failure for failure in failures)
    assert any("video packets" in failure for failure in failures)
