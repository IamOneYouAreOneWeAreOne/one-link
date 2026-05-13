# Universal Comms Fabric

Status: in_progress
Last updated: 2026-05-12

This document captures the next major One Link frontier: every device should
use every communication surface it has, automatically, safely, and
intelligently.

The goal is not "file transfer over Wi-Fi." The goal is:

> A trusted delivery fabric that finds, creates, combines, and heals every
> possible path between a user's devices and trusted people.

To the user, One Link remains simple: pick a device or person, send anything,
and it gets there. Underneath, One Link becomes a transport organism: LAN,
Wi-Fi Direct, hotspot, Bluetooth, USB, Ethernet, WebRTC, relay, QR, audio,
offline courier, LoRa, SDR, and future hardware all become candidate routes
for the same encrypted, resumable, content-addressed delivery intent.

---

## 1. North Star

One Link should not ask "what socket can I open?"

It should ask:

1. What trusted identity needs this data?
2. What physical paths exist right now?
3. What paths can I create with this hardware?
4. What paths might appear later?
5. Which trusted devices already have pieces?
6. Which route is safest, fastest, cheapest, and least annoying?
7. How do I make the delivery intent true without user babysitting?

The product promise:

> Send anything, any size, to any trusted device or person. If any path exists,
> One Link uses it. If no path exists, One Link waits, carries, resumes, and
> heals until the data arrives.

The implementation promise:

> All transports are untrusted byte pipes. Identity, authorization,
> encryption, chunk verification, replay protection, resumability, and delivery
> truth live above every transport.

---

## 2. Design Doctrine

### 2.1 Slow Links Carry Control, Fast Links Carry Data

Not every communication surface needs to carry whole files.

Low-rate paths are still powerful if they carry:

- presence beacons
- pairing handshakes
- route hints
- hotspot credentials
- chunk manifests
- missing-chunk requests
- wake/resume signals
- sealed relay rendezvous hints
- emergency text

Bulk data should move over the fastest safe available path:

- LAN TCP/QUIC
- Wi-Fi Direct
- private hotspot
- Ethernet
- USB
- WebRTC/DataChannel
- WebTransport
- sealed relay fallback
- multi-source swarm

### 2.2 The User Sends an Intent, Not a Socket Event

A send must become durable before any transfer starts.

Required behavior:

- Browser/upload source is staged before transfer starts.
- A delivery intent is written to durable storage.
- Every chunk state is recoverable after crash/restart.
- Failed chunks retry individually.
- Offline peers move the transfer to waiting state, not failure.
- Version mismatch negotiates the best shared protocol.
- Route/session desync triggers auto-repair.

The UI states should stay human:

- Sending
- Waiting for device
- Resuming
- Finding faster path
- Sending missing pieces
- Done

### 2.3 Every Transport Is Replaceable

The secure One Link packet/chunk layer must not depend on any transport.

Correct:

```text
Delivery Intent
  -> Secure Session / Capability / Chunk Manifest
  -> Transport Brain
  -> Adapter: LAN / Wi-Fi Direct / BLE / USB / WebRTC / RF / etc.
```

Incorrect:

```text
Feature code directly opens TCP socket and invents its own retry/security.
```

### 2.4 Hardware Is Opportunity, Not Requirement

Normal computers should get the strongest possible experience from hardware
they already have:

- Wi-Fi card
- Bluetooth adapter
- Ethernet port
- USB port
- speaker/microphone
- camera/screen
- storage devices

Optional hardware expands the fabric:

- LoRa / Meshtastic
- Zigbee / Thread
- SDR / HackRF / LimeSDR / USRP
- NFC
- serial radios
- satellite modems

The architecture must make these optional adapters, not required dependencies.

### 2.5 No Raw Trust In The Path

Every path is hostile until proven otherwise.

Rules:

- Transport adapters never receive plaintext user data unless explicitly
  operating after the secure decrypt boundary.
- All chunks are content-addressed and hash-verified.
- All control messages are authenticated.
- Capabilities gate who may request what.
- Relays and couriers are blind.
- RF/hardware adapters obey safety, regulatory, and power policy gates.

---

## 3. Hardware And Path Inventory

One Link needs a local hardware/path inventory daemon that continuously
maintains a live map of communication surfaces.

### 3.1 Inventory Output

Each path candidate reports:

```json
{
  "adapter_id": "wifi_direct.windows.0",
  "kind": "wifi_direct",
  "available": true,
  "requires_user_action": false,
  "requires_admin": false,
  "bulk_capable": true,
  "control_capable": true,
  "estimated_bps": 480000000,
  "measured_bps": 0,
  "latency_ms": 8,
  "loss": 0.0,
  "power_cost": "medium",
  "privacy": "direct_local",
  "range": "room_or_building",
  "safety_state": "ok",
  "platform_notes": "Windows Wi-Fi Direct available through OS APIs"
}
```

### 3.2 Required Inventory Sources

Desktop:

- active LAN interfaces
- Wi-Fi SSID/BSSID when available
- link-local IPv4/IPv6
- mDNS reachability
- Bluetooth adapter availability
- BLE permissions
- USB device attach events
- Ethernet link state
- local firewall constraints when detectable
- OS hotspot capability
- Wi-Fi Direct capability
- camera/microphone permission for QR/audio bootstrap
- installed OneField/SDR dependencies
- connected LoRa/serial/SDR devices

Browser/PWA:

- WebRTC availability
- WebTransport availability
- Web Bluetooth availability
- WebUSB availability
- camera permission
- microphone permission
- storage quota
- service worker state
- network information hints when exposed

Mobile:

- Wi-Fi/hotspot capability exposed by native wrapper
- BLE scan/advertise
- NFC
- camera
- microphone/speaker
- local network permission
- background execution limits
- battery saver state

---

## 4. Transport Adapter Contract

Every communication method must implement the same conceptual contract.

### 4.1 Adapter Lifecycle

```python
class TransportAdapter:
    def probe(self) -> AdapterProbe:
        ...

    def score(self, intent: DeliveryIntent, peer: PeerState) -> RouteScore:
        ...

    async def prepare(self, peer: PeerState, intent: DeliveryIntent) -> PreparedRoute:
        ...

    async def open(self, route: PreparedRoute) -> TransportSession:
        ...

    async def close(self) -> None:
        ...
```

### 4.2 Transport Session Contract

```python
class TransportSession:
    mtu: int
    ordered: bool
    reliable: bool
    bulk_capable: bool
    control_capable: bool

    async def send_frame(self, frame: bytes) -> None:
        ...

    async def recv_frame(self) -> bytes:
        ...

    async def stats(self) -> SessionStats:
        ...

    async def repair(self, reason: RepairReason) -> RepairResult:
        ...
```

### 4.3 Required Adapter Guarantees

Adapters must:

- never invent identity
- never bypass capability checks
- never assume plaintext
- expose MTU and reliability truth
- surface failures as machine-readable repair reasons
- support cancellation
- avoid blocking the daemon event loop
- avoid unbounded memory growth
- provide deterministic test fakes

---

## 5. First-Class Adapters

### 5.1 LAN Adapter

Purpose:

Use existing local network paths.

Capabilities:

- mDNS/UDP discovery
- direct TCP/QUIC transfer
- route refresh when peer IP/port changes
- multi-connection striping where useful
- local-only operation without internet

Ship gate:

- two laptops on same router can discover, pair, chat, and transfer large files
- router restart causes waiting/resuming, not lost transfer

### 5.2 Private Hotspot Adapter

Purpose:

If no LAN exists, create one.

Behavior:

1. Device A creates a One Link private hotspot.
2. Device B receives join info through QR, BLE, audio, invite file, or manual fallback.
3. Both devices establish a local encrypted One Link session.
4. Bulk transfer uses the newly created private Wi-Fi path.

Platform notes:

- Windows: use WLAN hosted network / Mobile Hotspot APIs where available.
- macOS: hotspot creation is restricted; may require native helper or user-assisted flow.
- Linux: NetworkManager/AP mode where adapter supports it.
- Mobile: native wrappers required for useful automation.

Ship gate:

- no router, no internet, two normal laptops can still send a file with minimal user action.

### 5.3 Wi-Fi Direct Adapter

Purpose:

Peer-to-peer Wi-Fi without router/hotspot UX where OS support allows.

Behavior:

- discover Wi-Fi Direct peers
- negotiate group owner/client roles
- exchange One Link route endpoint
- use secure chunk transfer over the created IP link

Risks:

- inconsistent driver/platform exposure
- Windows support exists but app access can be awkward
- macOS support is limited for third-party apps

Ship gate:

- adapter must gracefully report unsupported rather than confuse users.

### 5.4 BLE Control Adapter

Purpose:

Low-rate control, not bulk file transfer.

Uses:

- proximity discovery
- pair bootstrap
- exchange route hints
- carry hotspot credentials
- wake/resume nudges
- tiny emergency messages
- missing-manifest negotiation when no high-rate path exists

Never use BLE as the default bulk path except for tiny payloads.

Ship gate:

- BLE can bootstrap a private hotspot transfer without typing IP addresses.

### 5.5 USB Link Adapter

Purpose:

Use direct cable paths when possible.

Variants:

- USB networking / RNDIS / CDC ECM
- Android/iOS tethering path
- WebUSB/native helper for specialized devices
- removable drive courier mode

Courier mode:

1. Sender writes encrypted chunk bundle + manifest to removable storage.
2. Receiver imports bundle.
3. Mesh index updates.
4. Missing chunks continue over any live path.

Ship gate:

- a USB drive can move encrypted pieces without revealing plaintext or breaking resume.

### 5.6 Ethernet Link-Local Adapter

Purpose:

Direct cable or switch-only operation.

Behavior:

- detect link state
- use IPv4 link-local / IPv6 link-local
- advertise over mDNS
- prefer for bulk when available

Ship gate:

- two laptops connected by Ethernet can transfer without router/DHCP/internet.

### 5.7 WebRTC / WebTransport Adapter

Purpose:

Cross-network reachability when internet exists.

Behavior:

- direct NAT traversal first
- sealed relay only when direct fails
- use DataChannel for reliable messages and chunk frames
- use WebTransport where available for bulk
- expose route regime: direct, hole-punched, relayed

Ship gate:

- two devices on different networks can transfer with relay blind to plaintext.

### 5.8 QR / Optical Adapter

Purpose:

Human-visible bootstrap and small payload handoff.

Uses:

- pair proof
- offline invite
- route hint
- recovery shard
- hotspot credentials
- tiny manifest

Future:

- animated QR/frame burst for larger control bundles
- camera-to-screen optical courier mode

Ship gate:

- first pair can complete with no network path beyond camera/screen.

### 5.9 Audio Adapter

Purpose:

Tiny out-of-band data path using speaker/microphone.

Uses:

- pair proof
- nearby presence chirp
- emergency text
- route hint
- anti-MITM proximity signal

Constraints:

- must be optional
- must ask permission
- must be quiet or explicitly user-triggered by default
- low bandwidth

Ship gate:

- audio can exchange a short authenticated pairing nonce in a room.

### 5.10 OneField Hardware Adapter

Purpose:

Optional extreme hardware path using OneField Mesh concepts and devices.

Candidate sources:

- `$HOME\Projects\OneField Mesh\tools\onefield_transport`
- `tools\onefield_node.py`
- `tools\comms\tier2_link.py`
- `onefield\bridge\*.cl`
- `onefield\radio\hal\*.cl`

Usable now:

- parallel TCP transport concepts
- CDC dedup protocol concepts
- UDP-FEC concepts
- MPTCP fallback concepts
- QUIC pacing concepts
- RF mesh software loopback tests
- route scoring / adapter registry / safety policy ideas

Hardware-gated:

- HackRF / SDR over-the-air transport
- LoRa / Zigbee adapters
- multi-radio coherent combining

Rules:

- OneField is a transport provider, not a replacement for One Link security.
- Hardware paths carry encrypted One Link frames/chunks only.
- RF transmit requires explicit safety/regulatory gates.
- Experimental hardware mode must never degrade normal user flows.

Ship gate:

- software-loopback adapter proves One Link frames can travel through a
  OneField transport fake before any hardware path is exposed.

---

## 6. Transport Brain

The Transport Brain scores and chooses paths.

### 6.1 Route Score Inputs

- measured throughput
- estimated throughput
- RTT
- jitter
- loss/retry rate
- MTU
- setup time
- peer trust state
- privacy level
- relay exposure
- power cost
- battery state
- data cap/cost hints
- user friction
- required permissions
- admin/root requirement
- protocol compatibility
- storage availability
- safety/regulatory state
- recent failure history

### 6.2 Route Classes

User-facing:

- Wi-Fi direct
- Local network
- Private hotspot
- Ethernet
- USB
- Internet direct
- Relay fallback
- Bluetooth control
- Offline courier
- OneField radio
- Waiting for device

Internal:

- `DIRECT_LAN`
- `WIFI_DIRECT`
- `PRIVATE_AP`
- `ETH_LINK_LOCAL`
- `USB_NET`
- `WEBRTC_DIRECT`
- `WEBRTC_RELAYED`
- `BLE_CONTROL`
- `QR_CONTROL`
- `AUDIO_CONTROL`
- `STORAGE_COURIER`
- `ONEFIELD_RF`
- `OFFLINE`

### 6.3 Route Selection

The brain should prefer:

1. already-open high-quality direct routes
2. fast local bulk paths
3. low-friction generated paths
4. internet direct paths
5. sealed relays
6. offline/courier paths
7. experimental hardware paths only when enabled and safe

But the route choice must be adaptive:

- If Wi-Fi slows, add another source/path.
- If a route fails, repair or switch.
- If a peer changes IP/port, refresh route.
- If a faster route appears mid-transfer, migrate.
- If the peer already has most chunks, minimize sent bytes rather than maximize link speed.

---

## 7. Swarm Memory And Multi-Source Pull

This is the "everything acts as One" layer.

### 7.1 Chunk Availability Index

Every trusted device can advertise, privately and selectively:

- file manifest IDs it is allowed to discuss
- chunk hashes it has
- freshness/version
- storage pressure
- willingness to serve
- route quality

The advertisement must avoid leaking a user's whole library to every peer.

Privacy-preserving options:

- pair-specific Bloom filters
- capability-scoped manifests
- salted chunk-set sketches
- request-by-manifest only after authorization

### 7.2 Receiver-Led Pull

The receiver should own the final assembly.

Flow:

1. Receiver obtains signed manifest.
2. Receiver checks local chunk store.
3. Receiver asks authorized trusted devices for missing chunks.
4. Transport Brain assigns chunks to fastest/safest sources.
5. Chunks are verified by hash and AEAD before commit.
6. Failed chunks are retried from another source.
7. Final manifest root verifies the whole object.

### 7.3 Prior-Knowledge Transfer

If receiver already has most content:

- detect common chunks through CDC and manifest sketches
- send only missing chunks
- show user the truth: "98% already known"
- avoid recompression/transcoding unless explicitly needed

This creates the "impossible" moment: huge files complete fast because the
mesh recognized what was already there.

---

## 8. Delay-Tolerant Operation

Devices do not need to be online together.

### 8.1 Store-Carry-Forward

Trusted devices may carry encrypted chunks for later delivery.

Examples:

- laptop carries chunks from home to office
- phone bridges two networks over time
- USB drive carries sealed bundle
- friend device temporarily stores authorized pieces
- office NAS acts as local blind cache

### 8.2 Courier Bundle Format

Each bundle should contain:

- bundle header
- sender identity
- intended recipient identity or group
- capability proof
- manifest reference
- encrypted chunks
- chunk hashes
- expiration policy
- replay protection
- optional route hints

Couriers must not learn plaintext or unauthorized metadata.

### 8.3 Expiration And Abuse Limits

To avoid storage abuse:

- per-peer storage caps
- per-group storage caps
- expiration policies
- backpressure
- recipient opt-in for large deliveries
- proof-of-authorization before accepting bulk
- quarantine suspicious bundles

---

## 9. Safety And Security

### 9.1 Threats

The fabric must defend against:

- malicious peer flooding huge fake sends
- malicious courier storing malware-labeled files
- replayed manifests
- chunk poisoning
- relay metadata observation
- path downgrade attacks
- fake route advertisements
- hotspot impersonation
- BLE/QR/audio MITM
- malicious USB devices
- RF regulatory violations
- battery drain attacks
- storage exhaustion attacks

### 9.2 Required Defenses

- Every transfer starts with a signed intent and capability.
- Receiver budget checks happen before accepting bulk.
- Large sends require receiver policy approval or trusted auto-accept policy.
- Chunk hashes are verified before commit.
- Manifests are signed and versioned.
- Transport claims are authenticated when they affect trust.
- Path downgrade detection records when a secure/fast route was available but not used.
- Local API remains loopback-bound unless explicitly authorized.
- USB adapter treats attached devices as hostile.
- RF adapter defaults receive-only until operator enables transmit.
- Safety policy gates RF band/power/duty cycle.
- UI shows human action only when automatic recovery is not safe.

### 9.3 Resource Budgets

Each peer has budgets:

- max active sends
- max active receives
- max bytes accepted without prompt
- max disk reserved
- max memory
- max CPU
- max radio duty cycle
- max relay bytes
- max courier storage

Budgets are dynamic:

- battery low reduces background work
- metered network reduces bulk
- storage pressure refuses large inbound chunks
- trusted local devices get higher limits
- blocked/quarantined peers get zero

---

## 10. User Experience

The UI must show the magic without exposing machinery.

### 10.1 Transfer Truth

Examples:

- Sending at 640 Mbps
- 98% already known
- Only sending missing pieces
- Using Wi-Fi Direct
- Route: local network
- Resuming automatically
- Waiting for Computer 2
- Pulled from Laptop + Phone + Desktop
- Bluetooth is keeping the connection alive
- Private hotspot created
- USB courier bundle ready

### 10.2 No Scary Raw Errors

Bad:

```text
ECONNRESET 10054
```

Good:

```text
Computer 2 changed networks. One Link is reconnecting.
```

Bad:

```text
Protocol mismatch 0.8.0.1 vs 0.7.3
```

Good:

```text
Computer 2 is older. One Link is using the compatible transfer path.
```

### 10.3 Simple Controls

Default:

- Send file
- Send folder
- Pair device
- Devices
- Activity

Advanced:

- route details
- transport preferences
- hardware adapters
- RF mode
- courier bundles
- diagnostics

Advanced controls must never be required for normal success.

---

## 11. Implementation Roadmap

### Phase 1: Fabric Core

Deliverables:

- `hardware_inventory.py` - side-effect-light path inventory
- `transport_adapters/base.py` - adapter/session/probe contract
- `transport_adapters/static.py` - deterministic inventory adapter
- `transport_activation.py` - activation governor and safety policy
- `transport_fabric.py` - route score + transfer-brain bridge
- daemon `/api/fabric` snapshot
- `/api/status.performance.fabric` and `/api/metrics.fabric`
- Activity-panel fabric truth card
- file-send metadata field `fabric_plan`
- deterministic route, activation, and UI tests

Gate:

- unit tests prove route selection is deterministic and explainable
- activation tests prove low-risk trusted paths can auto-open while
  admin/user-ceremony/control-only paths cannot be silently abused
- `/api/fabric` is token-guarded like every other API surface
- no existing LAN transfer regression

Current implementation status:

- `complete` for read-only inventory, route scoring, activation policy,
  daemon/API exposure, file-send metadata, and UI truth surfacing.
- `partial` for active transport opening. No adapter currently starts
  hotspot/Wi-Fi Direct/BLE/RF on its own; that is deliberate until Phase 2
  platform helpers pass safety gates.

Activation rules now in force:

- unavailable paths are visible but cannot be selected
- control-only paths cannot carry bulk file payloads
- admin-required paths never auto-start
- user-ceremony paths require explicit local action
- untrusted peers cannot receive automatic route activation
- cross-internet routes remain end-to-end encrypted and relay-blind
- every active path is still below identity, capability, session crypto,
  chunk verification, durable intent, and retry/reopen logic

### Phase 2: Generated Local Paths

Deliverables:

- hotspot capability detector
- Wi-Fi Direct capability detector
- Ethernet link-local detector
- BLE control proof-of-concept
- QR route bootstrap payload

Gate:

- no-router two-device path documented and tested where platform allows

### Phase 3: Multi-Source Swarm Pull

Deliverables:

- chunk availability index
- capability-scoped chunk offers
- receiver-led source assignment
- per-source speed scoring
- source failover
- UI: "pulled from N devices"

Gate:

- test with three local daemons: receiver reconstructs object from two partial sources

### Phase 4: Store-Carry-Forward

Deliverables:

- courier bundle format
- import/export bundle UI
- USB/removable storage watcher
- expiration and budget policy
- replay-safe bundle import

Gate:

- offline sender -> USB bundle -> offline receiver completes transfer without plaintext exposure

### Phase 5: OneField Adapter

Deliverables:

- OneField software-loopback adapter
- OneField transport score bridge
- optional `tools/onefield_transport` import/wrapper
- RF mode hidden behind advanced safety gate

Gate:

- encrypted One Link frames pass through OneField fake transport
- hardware mode cannot transmit unless safety gate passes

### Phase 6: Phone And Native Reach

Deliverables:

- Capacitor/native wrappers for BLE, hotspot hints, share sheet, background resume
- phone as courier
- phone as route bridge
- mobile storage budgets

Gate:

- phone can help two computers exchange route hints or chunks without cloud

---

## 12. Integration With Existing One Link Work

Existing One Link systems this must reuse:

- durable transfer intent queue
- staged upload/source material
- native chunk store
- CDC/prior-knowledge transfer
- transfer brain/adaptive selector
- peer capabilities
- identity and trust graph
- secure sessions
- per-peer permissions
- relay/rendezvous paths
- activity feed
- production readiness gates

Do not duplicate these. The Universal Comms Fabric expands the route layer
under them.

---

## 13. Engineering Rules

1. Add one adapter at a time behind the common contract.
2. Every adapter gets deterministic fake tests.
3. Every adapter reports truth to the route brain.
4. Every route is optional and replaceable.
5. No transport gets plaintext by default.
6. No experimental hardware path can break normal sends.
7. No user-facing feature ships without a recovery story.
8. No "works on my machine" path ships without platform disposition.
9. Prefer automatic recovery over user instructions.
10. Prefer creating a path over failing, when safe.

---

## 14. What Makes This Different

Individual pieces exist in other systems:

- AirDrop uses local discovery and Wi-Fi handoff.
- Syncthing syncs files P2P.
- BitTorrent pulls from multiple sources.
- Tailscale builds virtual networks.
- Meshtastic sends off-grid LoRa messages.
- Delay-tolerant networking exists in specialized domains.

One Link's uncommon goal is to combine them into one open, cross-platform,
user-owned system:

> identity + encrypted chunks + content-addressed storage + prior knowledge +
> multi-source pull + local/offline discovery + generated paths + store-carry-
> forward + optional RF hardware + a simple UX.

That is the "for the people" version: not a walled garden, not a cloud
subscription, not a single protocol, but a sovereign communications fabric.
