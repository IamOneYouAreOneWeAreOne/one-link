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
import re
import shutil
import signal
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


class BrowserStartupError(RuntimeError):
    """A browser failed before its loopback DevTools endpoint became ready."""


def _browser_temp_directory() -> tempfile.TemporaryDirectory[str]:
    """Create an isolated profile whose late cache unlock cannot erase a pass.

    Chromium-family browsers can keep cache-journal handles alive for a short
    period after their controlling process exits, especially on Windows.  The
    profile is disposable test state; a transient cleanup ``PermissionError``
    must not replace a completed media report with a fabricated gate failure.
    ``TemporaryDirectory`` still removes every entry it can and retries its
    normal permission recovery, while ``ignore_cleanup_errors`` makes any
    remaining locked cache file advisory rather than test-semantic.
    """

    return tempfile.TemporaryDirectory(
        prefix="ol_browser_soak_",
        ignore_cleanup_errors=True,
    )


@dataclass
class BrowserProcess:
    """A started browser and the resources that must live with it."""

    proc: subprocess.Popen
    port: int
    profile: Path
    stderr_path: Path
    stderr_fh: Any

    def close(self) -> None:
        _terminate_process_tree(self.proc)
        try:
            self.stderr_fh.close()
        except OSError:
            pass


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


def _free_loopback_port() -> int:
    """Return a currently free IPv4 loopback port.

    There is necessarily a small bind-after-close race on platforms where a
    listening socket cannot be handed to Chromium. Browser startup retries use
    a new port and a new profile, so a collision cannot poison later attempts.
    """

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _diagnostic_tail(path: Path, *, max_bytes: int = 8192) -> str:
    """Read at most ``max_bytes`` from the end of a browser diagnostic file."""

    try:
        with path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - max_bytes), os.SEEK_SET)
            return fh.read(max_bytes).decode("utf-8", errors="replace")
    except OSError:
        return ""


def _sanitize_browser_diagnostics(
    raw: str,
    *,
    redactions: tuple[str, ...] = (),
    max_chars: int = 2048,
) -> str:
    """Return a bounded diagnostic that cannot disclose local paths/endpoints."""

    text = str(raw or "")
    sensitive_paths = (*redactions, str(Path.home()), tempfile.gettempdir())
    spellings: set[str] = set()
    for value in sensitive_paths:
        if not value:
            continue
        spellings.update({value, value.replace("\\", "/"), value.replace("/", "\\")})
    for spelling in sorted(spellings, key=len, reverse=True):
        text = text.replace(spelling, "<redacted-path>")
    text = re.sub(r"https?://[^\s\]\[(){}<>\"']+", "<redacted-url>", text, flags=re.IGNORECASE)
    text = re.sub(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?![\w.])", "<redacted-endpoint>", text)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "?", text)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    bounded = " | ".join(lines[-20:])
    if len(bounded) > max_chars:
        bounded = "..." + bounded[-(max_chars - 3):]
    return bounded or "<no browser diagnostics>"


def _safe_exception(exc: BaseException, *, redactions: tuple[str, ...] = ()) -> str:
    return _sanitize_browser_diagnostics(
        f"{type(exc).__name__}: {exc}",
        redactions=redactions,
        max_chars=1024,
    )


def _signal_process_group(proc: subprocess.Popen, sig: int) -> bool:
    """Signal a POSIX process group without assuming POSIX APIs exist."""

    getpgid = getattr(os, "getpgid", None)
    killpg = getattr(os, "killpg", None)
    if not callable(getpgid) or not callable(killpg):
        return False
    try:
        killpg(getpgid(proc.pid), sig)
        return True
    except (OSError, ProcessLookupError):
        return False


def _terminate_process_tree(proc: subprocess.Popen, *, timeout_s: float = 5.0) -> None:
    """Best-effort cleanup for Chromium's multi-process tree."""

    if proc.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout_s,
            )
        except (OSError, subprocess.TimeoutExpired):
            try:
                proc.terminate()
            except OSError:
                pass
    else:
        if not _signal_process_group(proc, signal.SIGTERM):
            try:
                proc.terminate()
            except OSError:
                pass
    try:
        proc.wait(timeout=timeout_s)
        return
    except (OSError, subprocess.TimeoutExpired):
        pass
    if os.name != "nt":
        sigkill = getattr(signal, "SIGKILL", signal.SIGTERM)
        _signal_process_group(proc, sigkill)
    try:
        proc.kill()
    except OSError:
        pass
    try:
        proc.wait(timeout=timeout_s)
    except (OSError, subprocess.TimeoutExpired):
        pass


async def _wait_for_browser_ready(
    proc: subprocess.Popen,
    port: int,
    *,
    timeout_s: float,
) -> None:
    """Poll the explicit loopback CDP endpoint and fail early if Chromium exits."""

    deadline = time.monotonic() + timeout_s
    last_status: int | None = None
    timeout = aiohttp.ClientTimeout(total=0.75, connect=0.25)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        while time.monotonic() < deadline:
            return_code = proc.poll()
            if return_code is not None:
                raise BrowserStartupError(
                    f"browser exited before DevTools readiness (exit code {return_code})"
                )
            try:
                async with session.get(f"http://127.0.0.1:{port}/json/version") as response:
                    last_status = response.status
                    if response.status == 200:
                        payload = await response.json(content_type=None)
                        if isinstance(payload, dict) and payload.get("webSocketDebuggerUrl"):
                            return
            except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError):
                pass
            await asyncio.sleep(0.05)
    suffix = f" (last HTTP status {last_status})" if last_status is not None else ""
    raise BrowserStartupError(f"browser DevTools endpoint was not ready within {timeout_s:g}s{suffix}")


async def _launch_browser_process(
    browser: BrowserCandidate,
    root: Path,
    *,
    browser_args: list[str],
    startup_timeout_s: float = 15.0,
    startup_attempts: int = 3,
) -> BrowserProcess:
    """Start Chromium with bounded startup-only retries and fresh state."""

    if startup_attempts <= 0:
        raise ValueError("startup_attempts must be positive")
    last_failure = "browser startup did not run"
    for attempt in range(1, startup_attempts + 1):
        port = _free_loopback_port()
        profile = root / f"browser-profile-{attempt}-{port}"
        profile.mkdir(parents=True, exist_ok=False)
        stderr_path = root / f"browser-stderr-{attempt}.log"
        stderr_fh = stderr_path.open("wb")
        args = [
            browser.path,
            "--headless=new",
            "--remote-debugging-address=127.0.0.1",
            f"--remote-debugging-port={port}",
            f"--user-data-dir={profile}",
            "--no-first-run",
            "--no-default-browser-check",
            *browser_args,
            "about:blank",
        ]
        if os.name == "nt" and Path(browser.path).name.lower() in {"msedge.exe", "msedge"}:
            # Edge otherwise performs a compatibility-layer relaunch. The
            # launcher exits with code 0 while the unowned browser tree keeps
            # the profile locked and obscures genuine startup failures.
            args.insert(1, "--edge-skip-compat-layer-relaunch")
        if os.name != "nt":
            args.insert(1, "--no-sandbox")
        popen_kwargs: dict[str, Any] = {
            "stdout": subprocess.DEVNULL,
            "stderr": stderr_fh,
            "stdin": subprocess.DEVNULL,
        }
        if os.name == "nt":
            popen_kwargs["creationflags"] = int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
        else:
            popen_kwargs["start_new_session"] = True
        try:
            proc = subprocess.Popen(args, **popen_kwargs)
        except OSError as exc:
            stderr_fh.close()
            raise BrowserStartupError(
                _safe_exception(exc, redactions=(str(root), str(profile), browser.path))
            ) from exc
        try:
            await _wait_for_browser_ready(proc, port, timeout_s=startup_timeout_s)
        except BrowserStartupError as exc:
            _terminate_process_tree(proc)
            stderr_fh.close()
            diagnostic = _sanitize_browser_diagnostics(
                _diagnostic_tail(stderr_path),
                redactions=(str(root), str(profile), browser.path),
            )
            last_failure = f"{exc}; stderr: {diagnostic}"
            continue
        return BrowserProcess(
            proc=proc,
            port=port,
            profile=profile,
            stderr_path=stderr_path,
            stderr_fh=stderr_fh,
        )
    raise BrowserStartupError(
        f"browser startup failed after {startup_attempts} attempts: {last_failure}"
    )


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
    phase = str(report.get("phase") or "")
    has_media_report = bool(final or remote or thresholds or "events" in report)
    if phase and phase != "complete" and not report.get("ok"):
        failures.append(f"browser media soak stopped during {phase}")
    if phase and phase != "complete" and not has_media_report:
        privacy = report.get("privacy") or {}
        for key in ("containsMedia", "containsSdp", "containsIceCandidates", "containsIpAddresses", "containsDeviceNames", "containsUserContent"):
            if privacy.get(key):
                failures.append(f"privacy flag failed: {key}")
        return _dedupe(failures)
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
    with _browser_temp_directory() as td:
        root = Path(td)
        harness = root / "browser_media_soak.html"
        harness.write_text(build_harness_html(), encoding="utf-8")
        process = await _launch_browser_process(
            browser,
            root,
            browser_args=[
                "--autoplay-policy=no-user-gesture-required",
                "--use-fake-device-for-media-stream",
                "--use-fake-ui-for-media-stream",
                "--allow-file-access-from-files",
                "--disable-background-timer-throttling",
                "--disable-renderer-backgrounding",
            ],
        )
        try:
            page_ws = await _new_page_ws(process.port, harness.as_uri())
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(
                    page_ws,
                    timeout=aiohttp.ClientWSTimeout(ws_close=10.0),
                ) as ws:
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
                    report["phase"] = "complete"
                    report["browser"] = {"name": browser.name, "path": Path(browser.path).name}
                    return report
        finally:
            process.close()


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
            "phase": "browser_startup" if isinstance(exc, BrowserStartupError) else "browser_execution",
            "error": _safe_exception(exc),
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
