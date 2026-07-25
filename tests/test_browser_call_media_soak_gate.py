from __future__ import annotations

import asyncio
import socket

import pytest

import scripts.browser_call_media_soak_gate as browser_gate
from scripts.browser_call_media_soak_gate import (
    BrowserCandidate,
    BrowserStartupError,
    _free_loopback_port,
    _sanitize_browser_diagnostics,
    build_harness_html,
    evaluate_report,
)


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


def test_browser_media_soak_startup_failure_does_not_fabricate_media_failures() -> None:
    failures = evaluate_report({
        "ok": False,
        "phase": "browser_startup",
        "error": "browser startup failed",
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
    assert any("browser_startup" in failure for failure in failures)
    assert not any("frames" in failure for failure in failures)
    assert not any("audio packets" in failure for failure in failures)
    assert not any("dimensions" in failure for failure in failures)
    assert not any("ICE restart" in failure for failure in failures)


def test_browser_diagnostics_are_bounded_and_redacted() -> None:
    private_path = r"C:\Users\Alice\AppData\Local\Temp\profile"
    raw = "x" * 5000 + f"\nfailed at {private_path} http://127.0.0.1:9222/json/version\x00"

    diagnostic = _sanitize_browser_diagnostics(raw, redactions=(private_path,))

    assert len(diagnostic) <= 2048
    assert "Alice" not in diagnostic
    assert "127.0.0.1" not in diagnostic
    assert "9222" not in diagnostic
    assert "\x00" not in diagnostic


def test_free_browser_debugging_port_is_loopback_bindable() -> None:
    port = _free_loopback_port()

    assert 0 < port <= 65535
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", port))


def test_browser_profile_cleanup_errors_cannot_overwrite_media_result(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class FakeTemporaryDirectory:
        def __init__(self, **kwargs) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(browser_gate.tempfile, "TemporaryDirectory", FakeTemporaryDirectory)

    directory = browser_gate._browser_temp_directory()

    assert isinstance(directory, FakeTemporaryDirectory)
    assert captured == {
        "prefix": "ol_browser_soak_",
        "ignore_cleanup_errors": True,
    }


def test_browser_launch_retries_only_startup_with_fresh_port_and_profile(monkeypatch, tmp_path) -> None:
    ports = iter((43101, 43102))
    commands: list[list[str]] = []
    terminated: list[object] = []

    class FakeProcess:
        pid = 999_991

        def poll(self):
            return None

    def fake_popen(args, **_kwargs):
        commands.append(list(args))
        return FakeProcess()

    readiness_attempts = 0

    async def fake_wait(_proc, _port, *, timeout_s):
        nonlocal readiness_attempts
        assert timeout_s == 15.0
        readiness_attempts += 1
        if readiness_attempts == 1:
            raise BrowserStartupError("transient startup failure")

    monkeypatch.setattr(browser_gate, "_free_loopback_port", lambda: next(ports))
    monkeypatch.setattr(browser_gate.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(browser_gate, "_wait_for_browser_ready", fake_wait)
    monkeypatch.setattr(browser_gate, "_terminate_process_tree", terminated.append)

    process = asyncio.run(browser_gate._launch_browser_process(
        BrowserCandidate("test", "browser.exe"),
        tmp_path,
        browser_args=["--test-switch"],
    ))
    process.close()

    assert readiness_attempts == 2
    assert len(commands) == 2
    assert "--remote-debugging-port=43101" in commands[0]
    assert "--remote-debugging-port=43102" in commands[1]
    assert commands[0] != commands[1]
    assert process.profile.name == "browser-profile-2-43102"
    assert len(terminated) == 2


def test_browser_readiness_fails_immediately_when_process_exits() -> None:
    class ExitedProcess:
        def poll(self):
            return 23

    with pytest.raises(BrowserStartupError, match="exit code 23"):
        asyncio.run(browser_gate._wait_for_browser_ready(
            ExitedProcess(),
            43103,
            timeout_s=5.0,
        ))
