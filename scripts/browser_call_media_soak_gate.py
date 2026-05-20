"""Real Chromium/Edge WebRTC media soak gate for One Link.

This gate launches a local Chromium-family browser, creates two real
RTCPeerConnection endpoints inside that browser, pushes synthetic camera and
microphone tracks through SRTP, restarts ICE, renegotiates, and verifies that
remote video frames and audio packets keep moving.

It is intentionally content-free and privacy-safe: the media is generated in
the browser from a canvas and oscillator (or browser fake devices when
available). No camera image, microphone audio, SDP, ICE candidates, IP
addresses, or device names are written to the report.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

import aiohttp


RESULTS_DIR = Path("benchmarks") / "results"


@dataclass(frozen=True)
class BrowserCandidate:
    name: str
    path: str


def browser_candidates() -> list[BrowserCandidate]:
    """Return likely Chromium-family browsers without exposing local state."""
    candidates: list[BrowserCandidate] = []
    env = os.environ.get("ONE_LINK_BROWSER_BIN")
    if env:
        candidates.append(BrowserCandidate("env", env))
    if os.name == "nt":
        for name, value in [
            ("edge", r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
            ("edge-x86", r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
            ("edge-local", r"%LocalAppData%\Microsoft\Edge\Application\msedge.exe"),
            ("chrome", r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
            ("chrome-x86", r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
            ("chrome-local", r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
        ]:
            candidates.append(BrowserCandidate(name, os.path.expandvars(value)))
    for name in ("msedge", "microsoft-edge", "google-chrome", "chromium", "chromium-browser", "chrome"):
        found = shutil.which(name)
        if found:
            candidates.append(BrowserCandidate(name, found))
    deduped: list[BrowserCandidate] = []
    seen: set[str] = set()
    for candidate in candidates:
        path = str(candidate.path)
        key = os.path.normcase(os.path.abspath(os.path.expandvars(path)))
        if key in seen:
            continue
        seen.add(key)
        if Path(path).exists() or shutil.which(path):
            deduped.append(candidate)
    return deduped


def find_browser() -> BrowserCandidate | None:
    candidates = browser_candidates()
    return candidates[0] if candidates else None


def build_harness_html() -> str:
    """Browser-side WebRTC media soak harness."""
    return r"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>One Link Browser Media Soak</title>
  <style>
    html, body { margin: 0; background: #05070d; color: #eef2ff; font-family: system-ui, sans-serif; }
    video { width: 320px; height: 180px; background: #111827; margin: 8px; object-fit: cover; }
    #status { padding: 12px; font-size: 14px; }
  </style>
</head>
<body>
  <div id="status">ready</div>
  <video id="local" autoplay muted playsinline></video>
  <video id="remote" autoplay playsinline></video>
  <audio id="remoteAudio" autoplay></audio>
  <script>
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const now = () => performance.now();
  const statusEl = document.getElementById("status");

  function setStatus(text) {
    statusEl.textContent = text;
  }

  async function waitFor(predicate, timeoutMs, label) {
    const deadline = now() + timeoutMs;
    let lastError = null;
    while (now() < deadline) {
      try {
        const value = await predicate();
        if (value) return value;
      } catch (err) {
        lastError = String(err && err.message || err);
      }
      await sleep(50);
    }
    throw new Error(`timeout waiting for ${label}${lastError ? ": " + lastError : ""}`);
  }

  async function bounded(promise, timeoutMs, label) {
    return Promise.race([
      promise,
      new Promise((resolve) => setTimeout(() => resolve({ oneLinkTimeout: label }), timeoutMs)),
    ]);
  }

  async function makeSyntheticStream() {
    const canvas = document.createElement("canvas");
    canvas.width = 640;
    canvas.height = 360;
    const ctx = canvas.getContext("2d", { alpha: false });
    let frame = 0;
    function draw() {
      frame += 1;
      const t = frame / 30;
      ctx.fillStyle = "#0b1020";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = `hsl(${(frame * 7) % 360}, 80%, 62%)`;
      ctx.fillRect((Math.sin(t) * 0.35 + 0.45) * canvas.width, 80, 72, 72);
      ctx.fillStyle = "#f8fafc";
      ctx.font = "28px system-ui";
      ctx.fillText(`one-link-frame-${frame}`, 24, 52);
      ctx.fillText(new Date().toISOString().slice(11, 19), 24, 332);
      requestAnimationFrame(draw);
    }
    draw();
    const videoStream = canvas.captureStream(30);
    const audioContext = new (window.AudioContext || window.webkitAudioContext)();
    const oscillator = audioContext.createOscillator();
    const gain = audioContext.createGain();
    const destination = audioContext.createMediaStreamDestination();
    oscillator.frequency.value = 440;
    gain.gain.value = 0.018;
    oscillator.connect(gain);
    gain.connect(destination);
    oscillator.start();
    const stream = new MediaStream([
      ...videoStream.getVideoTracks(),
      ...destination.stream.getAudioTracks(),
    ]);
    stream._oneLinkSyntheticAudioContext = audioContext;
    stream._oneLinkSyntheticOscillator = oscillator;
    return stream;
  }

  async function makeLocalStream(options = {}) {
    if (options.preferGetUserMedia && navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
      try {
        return await navigator.mediaDevices.getUserMedia({
          audio: {
            echoCancellation: true,
            noiseSuppression: true,
            autoGainControl: true,
          },
          video: {
            width: { ideal: 640, max: 1280 },
            height: { ideal: 360, max: 720 },
            frameRate: { ideal: 30, max: 30 },
          },
        });
      } catch (err) {
        console.warn("getUserMedia failed, using synthetic stream", err);
      }
    }
    return makeSyntheticStream();
  }

  async function collectInboundStats(pc) {
    const stats = await pc.getStats();
    const result = {
      audioPackets: 0,
      videoPackets: 0,
      framesDecoded: 0,
      framesDropped: 0,
      jitter: 0,
      packetsLost: 0,
      bytesReceived: 0,
      rttMs: 0,
      candidateType: "unknown",
    };
    stats.forEach((row) => {
      if (row.type === "inbound-rtp" && !row.isRemote) {
        if (row.kind === "audio" || row.mediaType === "audio") {
          result.audioPackets += Number(row.packetsReceived || 0);
          result.jitter = Math.max(result.jitter, Number(row.jitter || 0));
        }
        if (row.kind === "video" || row.mediaType === "video") {
          result.videoPackets += Number(row.packetsReceived || 0);
          result.framesDecoded += Number(row.framesDecoded || 0);
          result.framesDropped += Number(row.framesDropped || 0);
        }
        result.packetsLost += Number(row.packetsLost || 0);
        result.bytesReceived += Number(row.bytesReceived || 0);
      }
      if (row.type === "candidate-pair" && row.selected) {
        result.rttMs = Math.round(Number(row.currentRoundTripTime || 0) * 1000);
        const remote = stats.get(row.remoteCandidateId);
        if (remote && remote.candidateType) result.candidateType = remote.candidateType;
      }
    });
    return result;
  }

  async function negotiate(pcA, pcB) {
    const offer = await pcA.createOffer({ offerToReceiveAudio: true, offerToReceiveVideo: true });
    await pcA.setLocalDescription(offer);
    await pcB.setRemoteDescription(pcA.localDescription);
    const answer = await pcB.createAnswer();
    await pcB.setLocalDescription(answer);
    await pcA.setRemoteDescription(pcB.localDescription);
  }

  async function runOneLinkBrowserMediaSoak(options = {}) {
    const durationMs = Number(options.durationMs || 8000);
    const maxSetupMs = Number(options.maxSetupMs || 5000);
    const maxFrozenMs = Number(options.maxFrozenMs || 1400);
    const minVideoFrames = Number(options.minVideoFrames || 24);
    const minAudioPackets = Number(options.minAudioPackets || 20);
    const iceServers = Array.isArray(options.iceServers) ? options.iceServers : [];
    const started = now();
    const events = [];
    function event(type, extra = {}) {
      events.push({ t: Math.round(now() - started), type, ...extra });
      setStatus(type);
    }

    const localVideo = document.getElementById("local");
    const remoteVideo = document.getElementById("remote");
    const remoteAudio = document.getElementById("remoteAudio");
    const localStream = await makeLocalStream({ preferGetUserMedia: !!options.preferGetUserMedia });
    if (localStream._oneLinkSyntheticAudioContext && localStream._oneLinkSyntheticAudioContext.state !== "running") {
      await bounded(localStream._oneLinkSyntheticAudioContext.resume().catch(() => {}), 500, "audio-context-resume");
    }
    localVideo.srcObject = localStream;
    await bounded(localVideo.play().catch(() => {}), 500, "local-video-play");
    const remoteStream = new MediaStream();
    remoteVideo.srcObject = remoteStream;
    remoteAudio.srcObject = remoteStream;
    remoteAudio.muted = false;
    await bounded(remoteVideo.play().catch(() => {}), 500, "remote-video-play");
    await bounded(remoteAudio.play().catch(() => {}), 500, "remote-audio-play");

    const config = {
      iceServers,
      bundlePolicy: "max-bundle",
      rtcpMuxPolicy: "require",
      iceCandidatePoolSize: 4,
    };
    const pcA = new RTCPeerConnection(config);
    const pcB = new RTCPeerConnection(config);
    const iceStates = [];
    pcA.onicecandidate = (ev) => { if (ev.candidate) pcB.addIceCandidate(ev.candidate).catch((err) => event("ice-a-to-b-failed", { error: String(err) })); };
    pcB.onicecandidate = (ev) => { if (ev.candidate) pcA.addIceCandidate(ev.candidate).catch((err) => event("ice-b-to-a-failed", { error: String(err) })); };
    pcA.oniceconnectionstatechange = () => { iceStates.push(`a:${pcA.iceConnectionState}`); event("ice-a", { state: pcA.iceConnectionState }); };
    pcB.oniceconnectionstatechange = () => { iceStates.push(`b:${pcB.iceConnectionState}`); event("ice-b", { state: pcB.iceConnectionState }); };
    pcB.ontrack = (ev) => {
      remoteStream.addTrack(ev.track);
      event("remote-track", { kind: ev.track.kind });
    };
    localStream.getTracks().forEach((track) => pcA.addTrack(track, localStream));
    event("negotiate-initial");
    await negotiate(pcA, pcB);
    await waitFor(
      () => ["connected", "completed"].includes(pcA.iceConnectionState)
        && ["connected", "completed"].includes(pcB.iceConnectionState),
      maxSetupMs,
      "ICE connected",
    );
    await waitFor(() => remoteStream.getVideoTracks().some((t) => t.readyState === "live"), maxSetupMs, "remote video track");
    await waitFor(() => remoteStream.getAudioTracks().some((t) => t.readyState === "live"), maxSetupMs, "remote audio track");

    let stats = await collectInboundStats(pcB);
    await waitFor(async () => {
      stats = await collectInboundStats(pcB);
      const playbackFrames = remoteVideo.getVideoPlaybackQuality ? remoteVideo.getVideoPlaybackQuality().totalVideoFrames : 0;
      return (stats.framesDecoded >= 2 || playbackFrames >= 2) && stats.audioPackets >= 2;
    }, maxSetupMs, "first media packets");
    const firstMediaMs = Math.round(now() - started);

    let lastFrames = Math.max(stats.framesDecoded, remoteVideo.getVideoPlaybackQuality ? remoteVideo.getVideoPlaybackQuality().totalVideoFrames : 0);
    let lastFrameAt = now();
    let maxFrozenObservedMs = 0;
    const samples = [];
    const end = now() + durationMs;
    let restarted = false;
    let renegotiated = false;
    while (now() < end) {
      await sleep(250);
      stats = await collectInboundStats(pcB);
      const playbackFrames = remoteVideo.getVideoPlaybackQuality ? remoteVideo.getVideoPlaybackQuality().totalVideoFrames : 0;
      const decodedFrames = Math.max(stats.framesDecoded, playbackFrames);
      const sample = {
        t: Math.round(now() - started),
        framesDecoded: decodedFrames,
        audioPackets: stats.audioPackets,
        videoPackets: stats.videoPackets,
        framesDropped: stats.framesDropped,
        packetsLost: stats.packetsLost,
        rttMs: stats.rttMs,
        candidateType: stats.candidateType,
        videoWidth: remoteVideo.videoWidth || 0,
        videoHeight: remoteVideo.videoHeight || 0,
        readyState: remoteVideo.readyState,
      };
      samples.push(sample);
      if (decodedFrames > lastFrames) {
        lastFrames = decodedFrames;
        lastFrameAt = now();
      }
      maxFrozenObservedMs = Math.max(maxFrozenObservedMs, Math.round(now() - lastFrameAt));
      const elapsed = now() - started;
      if (!restarted && elapsed > durationMs * 0.35) {
        restarted = true;
        event("ice-restart");
        pcA.restartIce();
        await negotiate(pcA, pcB);
      }
      if (!renegotiated && elapsed > durationMs * 0.65) {
        renegotiated = true;
        event("renegotiate");
        const sender = pcA.getSenders().find((s) => s.track && s.track.kind === "video");
        if (sender && sender.setParameters) {
          const params = sender.getParameters();
          if (!params.encodings || !params.encodings.length) params.encodings = [{}];
          params.encodings[0].maxBitrate = 750000;
          params.encodings[0].maxFramerate = 24;
          await sender.setParameters(params).catch((err) => event("set-params-failed", { error: String(err) }));
        }
        await negotiate(pcA, pcB);
      }
      if (maxFrozenObservedMs > maxFrozenMs) {
        event("media-freeze-risk", { maxFrozenObservedMs });
      }
    }
    stats = await collectInboundStats(pcB);
    const finalPlaybackFrames = remoteVideo.getVideoPlaybackQuality ? remoteVideo.getVideoPlaybackQuality().totalVideoFrames : 0;
    const finalStats = {
      ...stats,
      framesDecoded: Math.max(stats.framesDecoded, finalPlaybackFrames),
    };
    const report = {
      ok: (
        finalStats.framesDecoded >= minVideoFrames
        && stats.audioPackets >= minAudioPackets
        && maxFrozenObservedMs <= maxFrozenMs
        && remoteVideo.videoWidth > 0
        && remoteVideo.videoHeight > 0
        && ["connected", "completed"].includes(pcA.iceConnectionState)
        && ["connected", "completed"].includes(pcB.iceConnectionState)
      ),
      setupMs: firstMediaMs,
      totalMs: Math.round(now() - started),
      final: finalStats,
      remoteVideo: {
        width: remoteVideo.videoWidth || 0,
        height: remoteVideo.videoHeight || 0,
        readyState: remoteVideo.readyState,
        paused: remoteVideo.paused,
      },
      maxFrozenObservedMs,
      iceStates,
      events,
      samples,
      thresholds: { maxSetupMs, maxFrozenMs, minVideoFrames, minAudioPackets },
      privacy: {
        containsMedia: false,
        containsSdp: false,
        containsIceCandidates: false,
        containsIpAddresses: false,
        containsDeviceNames: false,
        containsUserContent: false,
      },
    };
    [...localStream.getTracks(), ...remoteStream.getTracks()].forEach((track) => track.stop());
    try { localStream._oneLinkSyntheticOscillator && localStream._oneLinkSyntheticOscillator.stop(); } catch (_) {}
    try { localStream._oneLinkSyntheticAudioContext && localStream._oneLinkSyntheticAudioContext.close(); } catch (_) {}
    pcA.close();
    pcB.close();
    return report;
  }
  window.runOneLinkBrowserMediaSoak = runOneLinkBrowserMediaSoak;
  </script>
</body>
</html>
"""


def evaluate_report(report: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    final = report.get("final") or {}
    remote = report.get("remoteVideo") or {}
    thresholds = report.get("thresholds") or {}
    if not report.get("ok"):
        failures.append("browser media soak reported not ok")
    if int(report.get("setupMs") or 0) > int(thresholds.get("maxSetupMs") or 5000):
        failures.append("first media setup exceeded budget")
    if int(final.get("framesDecoded") or 0) < int(thresholds.get("minVideoFrames") or 0):
        failures.append("decoded video frames below gate")
    if int(final.get("audioPackets") or 0) < int(thresholds.get("minAudioPackets") or 0):
        failures.append("audio packets below gate")
    if int(report.get("maxFrozenObservedMs") or 0) > int(thresholds.get("maxFrozenMs") or 1400):
        failures.append("remote video froze longer than gate")
    if int(remote.get("width") or 0) <= 0 or int(remote.get("height") or 0) <= 0:
        failures.append("remote video never rendered dimensions")
    events = {str(row.get("type")) for row in report.get("events") or [] if isinstance(row, dict)}
    if "ice-restart" not in events:
        failures.append("ICE restart path was not exercised")
    if "renegotiate" not in events:
        failures.append("renegotiation path was not exercised")
    privacy = report.get("privacy") or {}
    for key in ("containsMedia", "containsSdp", "containsIceCandidates", "containsIpAddresses", "containsDeviceNames", "containsUserContent"):
        if privacy.get(key):
            failures.append(f"privacy flag failed: {key}")
    return _dedupe(failures)


async def _wait_for_devtools_port(profile: Path, timeout_s: float) -> tuple[int, str]:
    marker = profile / "DevToolsActivePort"
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            lines = marker.read_text(encoding="utf-8").splitlines()
            if len(lines) >= 2:
                return int(lines[0]), lines[1]
        except OSError:
            pass
        await asyncio.sleep(0.05)
    raise RuntimeError("browser did not expose DevToolsActivePort")


async def _new_page_ws(port: int, url: str) -> str:
    async with aiohttp.ClientSession() as session:
      async with session.put(f"http://127.0.0.1:{port}/json/new?{quote(url, safe=':/?&=%')}") as resp:
        if resp.status not in (200, 201):
            async with session.get(f"http://127.0.0.1:{port}/json/new?{quote(url, safe=':/?&=%')}") as fallback:
                data = await fallback.json()
        else:
            data = await resp.json()
    ws = data.get("webSocketDebuggerUrl")
    if not ws:
        raise RuntimeError("DevTools target did not expose a page websocket")
    return str(ws)


async def _cdp_send(
    ws: aiohttp.ClientWebSocketResponse,
    counter: list[int],
    method: str,
    params: dict[str, Any] | None = None,
    *,
    timeout: float = 30.0,
) -> Any:
    counter[0] += 1
    msg_id = counter[0]
    await ws.send_json({"id": msg_id, "method": method, "params": params or {}})
    while True:
        msg = await ws.receive(timeout=timeout)
        if msg.type == aiohttp.WSMsgType.TEXT:
            payload = json.loads(msg.data)
            if payload.get("id") == msg_id:
                if "error" in payload:
                    raise RuntimeError(f"CDP {method} failed: {payload['error']}")
                return payload.get("result")
        if msg.type in (aiohttp.WSMsgType.ERROR, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSE):
            raise RuntimeError(f"DevTools websocket closed during {method}")


async def run_browser_soak(
    *,
    browser: BrowserCandidate,
    duration_ms: int,
    max_setup_ms: int,
    max_frozen_ms: int,
    min_video_frames: int,
    min_audio_packets: int,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="ol_browser_soak_") as td:
        root = Path(td)
        profile = root / "profile"
        profile.mkdir()
        harness = root / "browser_media_soak.html"
        harness.write_text(build_harness_html(), encoding="utf-8")
        args = [
            browser.path,
            "--headless=new",
            "--remote-debugging-port=0",
            f"--user-data-dir={profile}",
            "--no-first-run",
            "--no-default-browser-check",
            "--autoplay-policy=no-user-gesture-required",
            "--use-fake-device-for-media-stream",
            "--use-fake-ui-for-media-stream",
            "--allow-file-access-from-files",
            "--disable-background-timer-throttling",
            "--disable-renderer-backgrounding",
            "about:blank",
        ]
        if os.name != "nt":
            args.insert(1, "--no-sandbox")
        proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            port, _ = await _wait_for_devtools_port(profile, 15)
            page_ws = await _new_page_ws(port, harness.as_uri())
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(page_ws, timeout=30) as ws:
                    counter = [0]
                    await _cdp_send(ws, counter, "Runtime.enable")
                    await _cdp_send(ws, counter, "Page.enable")
                    await _cdp_send(ws, counter, "Page.navigate", {"url": harness.as_uri()})
                    await asyncio.sleep(0.5)
                    await _cdp_send(
                        ws,
                        counter,
                        "Runtime.evaluate",
                        {
                            "expression": "typeof window.runOneLinkBrowserMediaSoak === 'function'",
                            "returnByValue": True,
                        },
                    )
                    expression = (
                        "window.runOneLinkBrowserMediaSoak("
                        + json.dumps({
                            "durationMs": duration_ms,
                            "maxSetupMs": max_setup_ms,
                            "maxFrozenMs": max_frozen_ms,
                            "minVideoFrames": min_video_frames,
                            "minAudioPackets": min_audio_packets,
                        })
                        + ")"
                    )
                    result = await _cdp_send(
                        ws,
                        counter,
                        "Runtime.evaluate",
                        {
                            "expression": expression,
                            "awaitPromise": True,
                            "returnByValue": True,
                        },
                        timeout=(duration_ms + max_setup_ms + 30000) / 1000.0,
                    )
                    remote = result.get("result") or {}
                    if "value" not in remote:
                        raise RuntimeError(f"browser did not return soak report: {remote}")
                    report = dict(remote["value"])
                    report["browser"] = {"name": browser.name, "path": Path(browser.path).name}
                    return report
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", help="Path to msedge/chrome/chromium")
    parser.add_argument("--duration-ms", type=_positive_int, default=8000)
    parser.add_argument("--max-setup-ms", type=_positive_int, default=5000)
    parser.add_argument("--max-frozen-ms", type=_positive_int, default=1400)
    parser.add_argument("--min-video-frames", type=_positive_int, default=24)
    parser.add_argument("--min-audio-packets", type=_positive_int, default=20)
    parser.add_argument("--out", type=Path, default=RESULTS_DIR / "browser-call-media-soak.json")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--list-browsers", action="store_true")
    args = parser.parse_args(argv)

    if args.list_browsers:
        print(json.dumps([candidate.__dict__ for candidate in browser_candidates()], indent=2))
        return 0

    browser = BrowserCandidate("explicit", args.browser) if args.browser else find_browser()
    if browser is None:
        print("FAIL: no Chromium-family browser found. Set ONE_LINK_BROWSER_BIN or pass --browser.")
        return 2
    if not Path(browser.path).exists() and shutil.which(browser.path) is None:
        print(f"FAIL: browser path does not exist: {browser.path}")
        return 2

    args.out.parent.mkdir(parents=True, exist_ok=True)
    started = time.time()
    try:
        report = asyncio.run(run_browser_soak(
            browser=browser,
            duration_ms=int(args.duration_ms),
            max_setup_ms=int(args.max_setup_ms),
            max_frozen_ms=int(args.max_frozen_ms),
            min_video_frames=int(args.min_video_frames),
            min_audio_packets=int(args.min_audio_packets),
        ))
    except Exception as exc:
        report = {
            "ok": False,
            "error": repr(exc),
            "browser": {"name": browser.name, "path": Path(browser.path).name},
            "privacy": {
                "containsMedia": False,
                "containsSdp": False,
                "containsIceCandidates": False,
                "containsIpAddresses": False,
                "containsDeviceNames": False,
                "containsUserContent": False,
            },
        }
    report["created_at"] = int(time.time())
    report["elapsed_s"] = round(time.time() - started, 3)
    failures = evaluate_report(report)
    report["ok"] = not failures
    report["gate_failures"] = failures
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        verdict = "PASS" if report["ok"] else "FAIL"
        final = report.get("final") or {}
        print(
            f"{verdict}: browser media soak "
            f"frames={final.get('framesDecoded', 0)} "
            f"audio_packets={final.get('audioPackets', 0)} "
            f"setup={report.get('setupMs', '--')}ms "
            f"max_frozen={report.get('maxFrozenObservedMs', '--')}ms"
        )
        print(f"report: {args.out}")
        for failure in failures:
            print(f"  - {failure}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
