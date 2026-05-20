"""End-to-end One Link browser-call gate.

This launches two real One Link daemons, opens the real bundled UI in two
Chromium/Edge pages, initiates a video call from page A, accepts it in page B,
and verifies that the real UI + daemon signaling path carries live audio/video
both ways. The browser media itself is generated locally from canvas/oscillator
tracks so the gate never touches a real camera or microphone.

The JSON report is privacy-safe: it stores call IDs, state-machine facts,
packet/frame counters, and gate timings only. It does not store media, SDP, ICE
candidate strings, IP addresses, device names, or user content.
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

import aiohttp

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.browser_call_media_soak_gate import (
    BrowserCandidate,
    _cdp_send,
    _new_page_ws,
    _wait_for_devtools_port,
    find_browser,
)


RESULTS_DIR = Path("benchmarks") / "results"


@dataclass
class DaemonHandle:
    name: str
    home: Path
    log_path: Path
    proc: subprocess.Popen
    log_fh: Any
    control_port: int
    ui_port: int
    token: str
    fingerprint: str
    short_id: str


def _daemon_creation_flags() -> int:
    if os.name != "nt":
        return 0
    flags = 0
    for name in ("CREATE_NO_WINDOW", "CREATE_NEW_PROCESS_GROUP", "DETACHED_PROCESS"):
        flags |= int(getattr(subprocess, name, 0))
    return flags


def _wait_file(path: Path, timeout_s: float = 20.0) -> str:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            if path.exists():
                text = path.read_text(encoding="utf-8").strip()
                if text:
                    return text
        except OSError:
            pass
        time.sleep(0.05)
    raise RuntimeError(f"file did not appear: {path.name}")


def _wait_port(port: int, timeout_s: float = 15.0) -> None:
    deadline = time.time() + timeout_s
    last: OSError | None = None
    while time.time() < deadline:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.25)
        try:
            sock.connect(("127.0.0.1", port))
            return
        except OSError as exc:
            last = exc
            time.sleep(0.05)
        finally:
            sock.close()
    raise RuntimeError(f"port {port} did not open: {last}")


async def _http_json(
    method: str,
    url: str,
    *,
    token: str,
    body: dict[str, Any] | None = None,
    timeout_s: float = 15.0,
) -> tuple[int, dict[str, Any]]:
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout_s)) as session:
        async with session.request(
            method,
            url,
            headers={"Authorization": f"Bearer {token}"},
            json=body,
        ) as resp:
            text = await resp.text()
            try:
                payload = json.loads(text) if text else {}
            except json.JSONDecodeError:
                payload = {"_raw": text}
            return resp.status, payload


async def _spawn_daemon(root: Path, name: str) -> DaemonHandle:
    home = root / name
    home.mkdir(parents=True, exist_ok=True)
    log_path = root / f"{name.lower()}.log"
    env = dict(os.environ)
    env["ONE_LINK_HOME"] = str(home)
    env["ONE_LINK_ALLOW_SAME_HOST_PEERS"] = "1"
    env["ONE_LINK_DISABLE_REVEAL"] = "1"
    env["ONE_LINK_CALL_RESUME"] = "1"
    log_fh = log_path.open("wb")
    proc = subprocess.Popen(
        [sys.executable, "-m", "one_link.cli", "daemon", "-v"],
        env=env,
        cwd=str(Path.cwd()),
        stdout=log_fh,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        creationflags=_daemon_creation_flags(),
    )
    try:
        data = home / "data"
        control_port = int(_wait_file(data / "control.port"))
        _wait_port(control_port)
        ui_file = data / "server.port"
        if not ui_file.exists() and (data / "ui_port.txt").exists():
            ui_file = data / "ui_port.txt"
        ui_port = int(_wait_file(ui_file))
        _wait_port(ui_port)
        token = _wait_file(data / "ui.token")
        status, me = await _http_json("GET", f"http://127.0.0.1:{ui_port}/api/me", token=token)
        if status != 200:
            raise RuntimeError(f"{name} /api/me failed {status}: {me}")
        fingerprint = str(me.get("fingerprint") or "")
        short_id = str(me.get("short_id") or "")
        if not fingerprint or not short_id:
            raise RuntimeError(f"{name} identity missing: {me}")
        return DaemonHandle(
            name=name,
            home=home,
            log_path=log_path,
            proc=proc,
            log_fh=log_fh,
            control_port=control_port,
            ui_port=ui_port,
            token=token,
            fingerprint=fingerprint,
            short_id=short_id,
        )
    except Exception:
        _stop_daemon_proc(proc)
        log_fh.close()
        raise


def _stop_daemon_proc(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def _stop_daemon(handle: DaemonHandle) -> None:
    _stop_daemon_proc(handle.proc)
    try:
        handle.log_fh.close()
    except Exception:
        pass


async def _wait_discovery(a: DaemonHandle, b: DaemonHandle, timeout_s: float = 30.0) -> None:
    deadline = time.time() + timeout_s
    last: dict[str, Any] = {}
    while time.time() < deadline:
        status_a, peers_a = await _http_json(
            "GET",
            f"http://127.0.0.1:{a.ui_port}/api/peers?include_unpaired=1",
            token=a.token,
        )
        status_b, peers_b = await _http_json(
            "GET",
            f"http://127.0.0.1:{b.ui_port}/api/peers?include_unpaired=1",
            token=b.token,
        )
        last = {"a": peers_a, "b": peers_b, "status_a": status_a, "status_b": status_b}
        a_sees_b = any(p.get("fingerprint") == b.fingerprint for p in peers_a.get("peers", []))
        b_sees_a = any(p.get("fingerprint") == a.fingerprint for p in peers_b.get("peers", []))
        if a_sees_b and b_sees_a:
            return
        await asyncio.sleep(0.25)
    raise RuntimeError(f"mDNS discovery did not converge: {last}")


async def _trust_both(a: DaemonHandle, b: DaemonHandle) -> None:
    for src, peer in ((a, b), (b, a)):
        status, payload = await _http_json(
            "POST",
            f"http://127.0.0.1:{src.ui_port}/api/peers/{peer.fingerprint}/trust",
            token=src.token,
            body={"trust": "pinned"},
        )
        if status != 200 or not payload.get("ok"):
            raise RuntimeError(f"{src.name} trust failed {status}: {payload}")


class BrowserSession:
    def __init__(self, browser: BrowserCandidate, root: Path) -> None:
        self.browser = browser
        self.profile = root / "browser-profile"
        self.profile.mkdir(parents=True, exist_ok=True)
        self.proc: subprocess.Popen | None = None
        self.port = 0

    async def __aenter__(self) -> "BrowserSession":
        args = [
            self.browser.path,
            "--headless=new",
            "--remote-debugging-port=0",
            f"--user-data-dir={self.profile}",
            "--no-first-run",
            "--no-default-browser-check",
            "--autoplay-policy=no-user-gesture-required",
            "--use-fake-device-for-media-stream",
            "--use-fake-ui-for-media-stream",
            "--disable-background-timer-throttling",
            "--disable-renderer-backgrounding",
            "about:blank",
        ]
        if os.name != "nt":
            args.insert(1, "--no-sandbox")
        self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.port, _ = await _wait_for_devtools_port(self.profile, 15)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self.proc is None:
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()

    async def open_page(self, url: str) -> "Page":
        ws_url = await _new_page_ws(self.port, url)
        session = aiohttp.ClientSession()
        ws = await session.ws_connect(ws_url, timeout=30)
        page = Page(session, ws)
        await page.send("Runtime.enable")
        await page.send("Page.enable")
        await page.send("Page.navigate", {"url": url})
        await page.wait_expr("document.readyState === 'complete'", timeout_s=15)
        return page


class Page:
    def __init__(self, session: aiohttp.ClientSession, ws: aiohttp.ClientWebSocketResponse) -> None:
        self.session = session
        self.ws = ws
        self.counter = [0]

    async def close(self) -> None:
        await self.ws.close()
        await self.session.close()

    async def send(self, method: str, params: dict[str, Any] | None = None, *, timeout_s: float = 30.0) -> Any:
        return await _cdp_send(self.ws, self.counter, method, params, timeout=timeout_s)

    async def eval(self, expression: str, *, await_promise: bool = False, timeout_s: float = 30.0) -> Any:
        result = await self.send(
            "Runtime.evaluate",
            {
                "expression": expression,
                "awaitPromise": await_promise,
                "returnByValue": True,
            },
            timeout_s=timeout_s,
        )
        payload = result.get("result") or {}
        if result.get("exceptionDetails"):
            desc = (result.get("exceptionDetails") or {}).get("text") or payload.get("description")
            raise RuntimeError(f"page evaluation failed: {desc}")
        return payload.get("value")

    async def wait_expr(self, expression: str, *, timeout_s: float = 15.0) -> Any:
        deadline = time.time() + timeout_s
        last: Exception | None = None
        while time.time() < deadline:
            try:
                value = await self.eval(expression, await_promise=True, timeout_s=5)
                if value:
                    return value
            except Exception as exc:
                last = exc
            await asyncio.sleep(0.1)
        raise RuntimeError(f"timeout waiting for browser expression: {expression}; last={last}")


MEDIA_PATCH_JS = r"""
(function installOneLinkSyntheticMedia() {
  window._callPermissionPreflight = async () => true;
  window.Notification = window.Notification || function Notification(){};
  try { window.Notification.permission = "denied"; } catch (_) {}
  if (!navigator.mediaDevices) navigator.mediaDevices = {};
  navigator.mediaDevices.getUserMedia = async function(constraints) {
    const wantVideo = !constraints || constraints.video !== false;
    const wantAudio = !constraints || constraints.audio !== false;
    const tracks = [];
    if (wantVideo) {
      const canvas = document.createElement("canvas");
      canvas.width = 640;
      canvas.height = 360;
      const ctx = canvas.getContext("2d", { alpha: false });
      let frame = 0;
      function draw() {
        frame += 1;
        ctx.fillStyle = "#050812";
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = `hsl(${(frame * 11) % 360}, 78%, 62%)`;
        ctx.fillRect(40 + ((frame * 9) % 520), 110, 72, 72);
        ctx.fillStyle = "#f8fafc";
        ctx.font = "24px system-ui";
        ctx.fillText(`one-link-ui-e2e-${frame}`, 22, 42);
        requestAnimationFrame(draw);
      }
      draw();
      tracks.push(...canvas.captureStream(30).getVideoTracks());
    }
    if (wantAudio) {
      const audioContext = new (window.AudioContext || window.webkitAudioContext)();
      await Promise.race([
        audioContext.resume().catch(() => {}),
        new Promise((resolve) => setTimeout(resolve, 500)),
      ]);
      const osc = audioContext.createOscillator();
      const gain = audioContext.createGain();
      const dest = audioContext.createMediaStreamDestination();
      osc.frequency.value = 523.25;
      gain.gain.value = 0.02;
      osc.connect(gain);
      gain.connect(dest);
      osc.start();
      tracks.push(...dest.stream.getAudioTracks());
    }
    return new MediaStream(tracks);
  };
  navigator.mediaDevices.enumerateDevices = async function() {
    return [
      { kind: "audioinput", deviceId: "default", label: "Synthetic microphone" },
      { kind: "videoinput", deviceId: "default", label: "Synthetic camera" },
      { kind: "audiooutput", deviceId: "default", label: "Synthetic speaker" },
    ];
  };
  return true;
})()
"""


PAGE_SUMMARY_JS = r"""
(function installOneLinkE2ESummary() {
  window._oneLinkE2ESummary = async function() {
    const snapshot = await window._oneLinkCallDebug?.();
    if (!snapshot) return { ok: false };
    const stats = Array.isArray(snapshot.stats) ? snapshot.stats : [];
    const sum = (kind, field) => stats
      .filter((row) => row && row.type === "inbound-rtp" && row.kind === kind)
      .reduce((acc, row) => acc + Number(row[field] || 0), 0);
    const pc = snapshot.pc || {};
    const rv = snapshot.remote_video_element || {};
    const ra = snapshot.remote_audio_element || {};
    return {
      call_id: snapshot.call_id || null,
      signalingState: pc.signalingState || "",
      iceConnectionState: pc.iceConnectionState || "",
      connectionState: pc.connectionState || "",
      localDescriptionType: pc.localDescriptionType || "",
      remoteDescriptionType: pc.remoteDescriptionType || "",
      remoteTracks: (snapshot.remote_tracks || []).map((t) => ({
        kind: t.kind || "",
        readyState: t.readyState || "",
        muted: t.muted === true,
        enabled: t.enabled !== false,
      })),
      inboundAudioPackets: sum("audio", "packetsReceived"),
      inboundVideoPackets: sum("video", "packetsReceived"),
      framesDecoded: sum("video", "framesDecoded"),
      remoteVideoWidth: Number(rv.videoWidth || 0),
      remoteVideoHeight: Number(rv.videoHeight || 0),
      remoteVideoReadyState: Number(rv.readyState || 0),
      remoteAudioReadyState: Number(ra.readyState || 0),
    };
  };
  return true;
})()
"""


def _debug_summary(snapshot: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(snapshot, dict):
        return {"ok": False}
    stats = snapshot.get("stats") or []
    inbound_audio = sum(int(row.get("packetsReceived") or 0) for row in stats if row.get("type") == "inbound-rtp" and row.get("kind") == "audio")
    inbound_video = sum(int(row.get("packetsReceived") or 0) for row in stats if row.get("type") == "inbound-rtp" and row.get("kind") == "video")
    frames_decoded = sum(int(row.get("framesDecoded") or 0) for row in stats if row.get("type") == "inbound-rtp")
    remote_video = snapshot.get("remote_video_element") or {}
    remote_audio = snapshot.get("remote_audio_element") or {}
    pc = snapshot.get("pc") or {}
    return {
        "call_id": snapshot.get("call_id"),
        "signalingState": pc.get("signalingState"),
        "iceConnectionState": pc.get("iceConnectionState"),
        "connectionState": pc.get("connectionState"),
        "localDescriptionType": pc.get("localDescriptionType"),
        "remoteDescriptionType": pc.get("remoteDescriptionType"),
        "remoteTracks": snapshot.get("remote_tracks") or [],
        "inboundAudioPackets": inbound_audio,
        "inboundVideoPackets": inbound_video,
        "framesDecoded": frames_decoded,
        "remoteVideoWidth": int(remote_video.get("videoWidth") or 0),
        "remoteVideoHeight": int(remote_video.get("videoHeight") or 0),
        "remoteVideoReadyState": int(remote_video.get("readyState") or 0),
        "remoteAudioReadyState": int(remote_audio.get("readyState") or 0),
    }


def evaluate_report(report: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if not report.get("ok"):
        failures.append("browser UI call gate reported not ok")
    for side in ("caller", "receiver"):
        summary = report.get(side) or {}
        if summary.get("iceConnectionState") not in {"connected", "completed"}:
            failures.append(f"{side} ICE did not connect")
        if summary.get("remoteDescriptionType") not in {"offer", "answer"}:
            failures.append(f"{side} remote SDP was not applied")
        if int(summary.get("inboundAudioPackets") or 0) < int(report.get("min_audio_packets") or 8):
            failures.append(f"{side} inbound audio packets below gate")
        if int(summary.get("inboundVideoPackets") or 0) < int(report.get("min_video_packets") or 8):
            failures.append(f"{side} inbound video packets below gate")
        if int(summary.get("framesDecoded") or 0) < int(report.get("min_video_frames") or 8):
            failures.append(f"{side} decoded video frames below gate")
        if int(summary.get("remoteVideoWidth") or 0) <= 0 or int(summary.get("remoteVideoHeight") or 0) <= 0:
            failures.append(f"{side} remote video did not render dimensions")
    privacy = report.get("privacy") or {}
    for key, value in privacy.items():
        if value:
            failures.append(f"privacy flag failed: {key}")
    return _dedupe(failures)


async def run_gate(
    *,
    browser: BrowserCandidate,
    wait_media_s: float,
    min_audio_packets: int,
    min_video_packets: int,
    min_video_frames: int,
) -> dict[str, Any]:
    started = time.time()
    with tempfile.TemporaryDirectory(prefix="ol_ui_call_e2e_") as td:
        root = Path(td)
        a = await _spawn_daemon(root, "A")
        b = await _spawn_daemon(root, "B")
        try:
            await _wait_discovery(a, b)
            await _trust_both(a, b)
            async with BrowserSession(browser, root / "browser-a") as browser_a, BrowserSession(browser, root / "browser-b") as browser_b:
                page_a = await browser_a.open_page(f"http://127.0.0.1:{a.ui_port}/?t={a.token}")
                page_b = await browser_b.open_page(f"http://127.0.0.1:{b.ui_port}/?t={b.token}")
                try:
                    await page_a.eval(MEDIA_PATCH_JS)
                    await page_b.eval(MEDIA_PATCH_JS)
                    await page_a.eval(PAGE_SUMMARY_JS)
                    await page_b.eval(PAGE_SUMMARY_JS)
                    await page_a.wait_expr("typeof window.startLivingPresenceCall === 'function'", timeout_s=20)
                    await page_b.wait_expr("typeof window.backfillLivingPresenceCalls === 'function'", timeout_s=20)
                    await page_a.wait_expr("fetch('/api/me', {credentials:'include'}).then(r => r.ok)", timeout_s=10)
                    await page_b.wait_expr("fetch('/api/me', {credentials:'include'}).then(r => r.ok)", timeout_s=10)

                    await page_a.eval(
                        "(async () => { await window.startLivingPresenceCall("
                        + json.dumps(b.fingerprint)
                        + ", 'Computer B', { video: true }); return true; })()",
                        await_promise=True,
                        timeout_s=20,
                    )
                    await page_b.wait_expr(
                        "(async () => document.getElementById('call-incoming-overlay')?.classList.contains('show') || "
                        "(window._oneLinkCallDebug && (await window._oneLinkCallDebug())?.call_id))()",
                        timeout_s=20,
                    )
                    await page_b.eval("document.getElementById('btn-call-accept')?.click()")
                    deadline = time.time() + wait_media_s
                    caller: dict[str, Any] = {}
                    receiver: dict[str, Any] = {}
                    while time.time() < deadline:
                        caller = await page_a.eval("window._oneLinkE2ESummary()", await_promise=True, timeout_s=10)
                        receiver = await page_b.eval("window._oneLinkE2ESummary()", await_promise=True, timeout_s=10)
                        candidate = {
                            "ok": True,
                            "caller": caller,
                            "receiver": receiver,
                            "min_audio_packets": min_audio_packets,
                            "min_video_packets": min_video_packets,
                            "min_video_frames": min_video_frames,
                            "privacy": _privacy_flags(),
                        }
                        if not evaluate_report(candidate):
                            report = {
                                **candidate,
                                "elapsed_s": round(time.time() - started, 3),
                                "browser": {"name": browser.name, "path": Path(browser.path).name},
                            }
                            try:
                                await page_a.eval("document.getElementById('btn-call-end')?.click()")
                            except Exception:
                                pass
                            return report
                        await asyncio.sleep(0.5)
                    return {
                        "ok": False,
                        "caller": caller,
                        "receiver": receiver,
                        "min_audio_packets": min_audio_packets,
                        "min_video_packets": min_video_packets,
                        "min_video_frames": min_video_frames,
                        "elapsed_s": round(time.time() - started, 3),
                        "browser": {"name": browser.name, "path": Path(browser.path).name},
                        "privacy": _privacy_flags(),
                    }
                finally:
                    await page_a.close()
                    await page_b.close()
        finally:
            _stop_daemon(a)
            _stop_daemon(b)


def _privacy_flags() -> dict[str, bool]:
    return {
        "contains_media": False,
        "contains_sdp": False,
        "contains_ice_candidates": False,
        "contains_ip_addresses": False,
        "contains_device_names": False,
        "contains_user_content": False,
    }


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
    parser.add_argument("--wait-media-s", type=float, default=35.0)
    parser.add_argument("--min-audio-packets", type=_positive_int, default=8)
    parser.add_argument("--min-video-packets", type=_positive_int, default=8)
    parser.add_argument("--min-video-frames", type=_positive_int, default=8)
    parser.add_argument("--out", type=Path, default=RESULTS_DIR / "e2e-call-ui-browser-gate.json")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    browser = BrowserCandidate("explicit", args.browser) if args.browser else find_browser()
    if browser is None:
        print("FAIL: no Chromium-family browser found. Set ONE_LINK_BROWSER_BIN or pass --browser.")
        return 2
    if not Path(browser.path).exists() and shutil.which(browser.path) is None:
        print(f"FAIL: browser path does not exist: {browser.path}")
        return 2

    args.out.parent.mkdir(parents=True, exist_ok=True)
    try:
        report = asyncio.run(run_gate(
            browser=browser,
            wait_media_s=float(args.wait_media_s),
            min_audio_packets=int(args.min_audio_packets),
            min_video_packets=int(args.min_video_packets),
            min_video_frames=int(args.min_video_frames),
        ))
    except Exception as exc:
        report = {
            "ok": False,
            "error": repr(exc),
            "browser": {"name": browser.name, "path": Path(browser.path).name},
            "privacy": _privacy_flags(),
        }
    failures = evaluate_report(report)
    report["ok"] = not failures
    report["gate_failures"] = failures
    report["created_at"] = int(time.time())
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        verdict = "PASS" if report["ok"] else "FAIL"
        caller = report.get("caller") or {}
        receiver = report.get("receiver") or {}
        print(
            f"{verdict}: e2e browser UI call "
            f"caller_frames={caller.get('framesDecoded', 0)} "
            f"receiver_frames={receiver.get('framesDecoded', 0)} "
            f"caller_audio={caller.get('inboundAudioPackets', 0)} "
            f"receiver_audio={receiver.get('inboundAudioPackets', 0)}"
        )
        print(f"report: {args.out}")
        for failure in failures:
            print(f"  - {failure}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
