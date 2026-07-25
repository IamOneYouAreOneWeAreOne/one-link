# Phase A2 QUIC Cutover — Deferred with Plan

> **Status: partial.** The `ol_quic` crate and identity-bound native endpoint
> are wired into runtime-gated daemon file lanes. The daemon advertises the
> capability only after its native ABI is usable and retains authenticated
> peer-channel fallback. A universal whole-session cutover, physical
> cellular/Wi-Fi migration, cross-network soak, and browser replacement remain
> deliberately deferred. The plan below records that larger target.

## Why deferred

The existing authenticated peer and browser WebRTC transports work. Replacing
every daemon session with QUIC is
a multi-day project where breakage is silent + catastrophic:

1. **Pairing handshake** runs on the same socket as in-flight
   transfers. A broken QUIC handshake doesn't just lose a packet;
   it loses the peer.
2. **Browser-as-peer** must stay on WebRTC (browsers don't speak
   QUIC datagrams to arbitrary peers without WebTransport, which
   has its own deployment story).
3. **Connection migration** (cellular ↔ WiFi) is a Phase A2 gate.
   QUIC supports it natively; WebRTC doesn't. But verifying it
   requires real cellular handoff — hardware not on the dev box.

Doing a half-cutover that "mostly works" would break shipped flows
(iOS pair, browser-as-peer fallback, etc.) in ways the test suite
doesn't catch.

## What's done

- `native/ol_quic/` crate exists with `quinn`-based transport.
- pyo3 binding (`one_link_native.quic`) exposes encode/decode +
  bulk-frame helpers.
- Capable daemons create identity-bound native endpoints, advertise the runtime
  capability only after self-test, exchange endpoint metadata, and negotiate
  QUIC file lanes with bounded fallback to the authenticated peer channel.
- 6 native crate tests + perf benches passing.
- Loopback throughput scaffold (`scripts/quic_measurement_scaffold.py`)
  reports 29.8 GiB/s encode.

## What the cutover requires

In dependency order:

### Step 1: Dual-stack transport selector

Daemon already has `peer_rtc.py` (WebRTC). Add `peer_quic.py` (QUIC)
that exposes the same `OutboundSession` / `InboundSession` interface.
The daemon's `send_text` / `send_file` paths call through the
interface; they don't care which transport is underneath.

```python
class PeerTransport(Protocol):
    async def open_outbound(self, peer: Peer) -> OutboundSession: ...
    async def accept_inbound(self, ...) -> InboundSession: ...
```

Both `WebRTCTransport` and `QUICTransport` implement this.

### Step 2: Capability-gated negotiation

Add a `QUIC_TRANSPORT_V1` capability. During pairing handshake,
each peer advertises which transports they support. If both
advertise QUIC, use QUIC; otherwise fall back to WebRTC.

This means a v0.21+ daemon talking to a v0.20.x daemon stays on
WebRTC — no flag day, no breakage.

### Step 3: Per-peer transport state

The daemon keeps per-peer connection state. When peer P is QUIC,
that state lives in a `QUICSession`; when P is WebRTC, in an
`RtcSession`. The lookup table is keyed by peer fingerprint.

### Step 4: Migration path for in-flight transfers

If a transfer is in flight via WebRTC and the daemon restarts with
QUIC available, the transfer should resume on QUIC. Resume requires:
- Same chunk-id / manifest-id (already content-addressed; works).
- Same channel keys (DH-derived; transport-agnostic; works).
- Connection migration on the wire (QUIC's built-in `CONN_ID`
  migration — needs daemon to track + re-negotiate).

### Step 5: 0-RTT resume cache

Cache QUIC session tickets per peer. On reconnect, use the ticket
for a 0-RTT handshake (plan gate: <50ms warm cache).

### Step 6: Cellular ↔ WiFi migration verification

Real device, dual NIC, force handoff mid-transfer. Verify the
daemon's QUIC connection migrates without app-visible drop.

### Step 7: TCP fallback measurement

Real LAN, measure QUIC stream throughput vs `iperf3` TCP baseline.
Plan gate: within 10% of TCP.

## Acceptance gates per plan

| Gate | Plan target | What it takes |
|---|---|---|
| Stream throughput | within 10% of TCP on tuned LAN | Step 7 |
| 0-RTT resume | <50ms warm | Step 5 + real LAN |
| Migration | zero app-visible drop on cellular↔WiFi | Step 6 + real device |
| Daemon cutover | daemon↔daemon over QUIC | Steps 1–4 |

## Estimated effort

Steps 1–3 (dual-stack + negotiation + per-peer state):
**3-5 days** of careful work + thorough integration tests.

Steps 4–5 (resume + 0-RTT): **2 days**.

Steps 6–7 (real-hardware verification): hardware-blocked. Cannot
estimate without access.

## What we did instead

Built the rest of Phase A1+B+C+D+E so the entire stack is ready
to ride QUIC the moment the cutover happens. The daemon's
performance, durability, and Phase E machinery are all locked in
on the WebRTC transport. Switching transports doesn't require
re-architecting anything above the transport layer.

## When to do this

When at least three conditions hold:
1. v0.21.x has soaked in production for ≥ 1 release cycle without
   regressions.
2. Hardware for the migration gates (real LAN + real cellular)
   is available.
3. The full transport interface refactor (Step 1) can be done
   in a focused multi-day window without other architectural
   work in flight.

Until then, WebRTC remains a fallback transport in the alpha development tree.
Neither that path nor the whole engine is represented as production-ready
without the exact-commit physical-device and release gates described above.
