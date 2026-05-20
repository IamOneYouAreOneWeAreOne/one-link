from __future__ import annotations

from scripts.browser_call_media_soak_gate import build_harness_html, evaluate_report


def test_browser_media_soak_harness_exercises_real_webrtc_paths() -> None:
    html = build_harness_html()

    assert "new RTCPeerConnection" in html
    assert "createOffer" in html
    assert "createAnswer" in html
    assert "addIceCandidate" in html
    assert "pcA.restartIce()" in html
    assert "sender.setParameters" in html
    assert "getStats" in html
    assert "framesDecoded" in html
    assert "audioPackets" in html
    assert "canvas.captureStream(30)" in html


def test_browser_media_soak_report_passes_when_media_moves() -> None:
    failures = evaluate_report({
        "ok": True,
        "setupMs": 1200,
        "maxFrozenObservedMs": 200,
        "thresholds": {
            "maxSetupMs": 5000,
            "maxFrozenMs": 1400,
            "minVideoFrames": 24,
            "minAudioPackets": 20,
        },
        "final": {
            "framesDecoded": 120,
            "audioPackets": 200,
        },
        "remoteVideo": {
            "width": 640,
            "height": 360,
        },
        "events": [
            {"type": "ice-restart"},
            {"type": "renegotiate"},
        ],
        "privacy": {
            "containsMedia": False,
            "containsSdp": False,
            "containsIceCandidates": False,
            "containsIpAddresses": False,
            "containsDeviceNames": False,
            "containsUserContent": False,
        },
    })

    assert failures == []


def test_browser_media_soak_report_fails_on_freeze_or_missing_media() -> None:
    failures = evaluate_report({
        "ok": False,
        "setupMs": 7000,
        "maxFrozenObservedMs": 3000,
        "thresholds": {
            "maxSetupMs": 5000,
            "maxFrozenMs": 1400,
            "minVideoFrames": 24,
            "minAudioPackets": 20,
        },
        "final": {
            "framesDecoded": 1,
            "audioPackets": 0,
        },
        "remoteVideo": {
            "width": 0,
            "height": 0,
        },
        "events": [],
        "privacy": {
            "containsMedia": False,
            "containsSdp": False,
            "containsIceCandidates": False,
            "containsIpAddresses": False,
            "containsDeviceNames": False,
            "containsUserContent": False,
        },
    })

    assert any("not ok" in failure for failure in failures)
    assert any("setup" in failure for failure in failures)
    assert any("frames" in failure for failure in failures)
    assert any("audio" in failure for failure in failures)
    assert any("froze" in failure for failure in failures)
    assert any("dimensions" in failure for failure in failures)
    assert any("ICE restart" in failure for failure in failures)
    assert any("renegotiation" in failure for failure in failures)
