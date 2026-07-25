"""Live WebSocket monitor — connect to the running daemon's /api/events
and print every message that arrives, with a timestamp. Run this in
one terminal while you call from the other computer. Anything that
shows up here is what your browser would see.

If you call from Computer 2 and NOTHING shows up here, the daemon
isn't receiving the CALL_INVITE wire message at all (network /
peer-session issue, not UI). If `call_event` events DO appear here,
your browser is failing to render them (cache, JS bug)."""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path


async def main() -> None:
    import websockets

    data_dir = Path(os.environ.get("LOCALAPPDATA", "")) / "Coherence" / "One_link"
    port = int((data_dir / "ui_port.txt").read_text(encoding="utf-8").strip())
    token = (data_dir / "ui.token").read_text(encoding="utf-8").strip()

    url = f"ws://127.0.0.1:{port}/api/events?token={token}"
    print(f"[monitor] connecting to {url} …")
    print("[monitor] press the call button on Computer 2 now; will run 90s")
    started = time.time()
    duration = float(os.environ.get("MONITOR_SECONDS", "90"))

    n_events = 0
    n_call_events = 0
    async with websockets.connect(
        url,
        additional_headers={"Authorization": f"Bearer {token}"},
        open_timeout=5,
    ) as ws:
        print(f"[monitor] connected — listening for {duration:.0f}s")
        while time.time() - started < duration:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            n_events += 1
            try:
                ev = json.loads(raw)
            except Exception:
                print(f"[{time.time() - started:6.1f}s] RAW {raw!r}")
                continue
            t = ev.get("type", "?")
            if t == "call_event":
                n_call_events += 1
                kind = ev.get("tail_kind", "?")
                cid = ev.get("call_id", "?")[:16]
                peer = ev.get("peer_master_vk_hex", "?")[:12]
                rest = {
                    k: v for k, v in ev.items()
                    if k not in ("type", "tail_kind", "call_id", "peer_master_vk_hex")
                }
                print(f"[{time.time() - started:6.1f}s] CALL_EVENT  kind={kind}  call={cid}  peer={peer}")
                if rest:
                    print(f"           {rest!r}")
            elif t in ("peers_changed", "peer_presence", "self_presence"):
                # Quiet noise.
                continue
            else:
                print(f"[{time.time() - started:6.1f}s] {t}  {ev!r}")

    print(f"\n[monitor] done. Events seen: {n_events}, call_events: {n_call_events}")
    if n_call_events == 0:
        print("[monitor] NO call_event ARRIVED — daemon isn't receiving CALL_INVITE")
        print("[monitor]   ⇒ Computer 2's daemon isn't sending it, OR the wire path is broken")
    else:
        print("[monitor] daemon DID emit call_events — bug is browser-side (cache, JS)")


if __name__ == "__main__":
    asyncio.run(main())
