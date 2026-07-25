# Coherence Mesh Plan — sovereign-network track

> Status: planning-of-record. Living document.
> Last truth review: 2026-07-24.
>
> “Shipped” dates in the historical table below primarily record a Rust/Python
> primitive landing. They do **not** establish daemon integration, default
> activation, anonymity, post-quantum protection, hardware binding, production
> readiness, or release evidence. Current product truth is reported by
> `/api/audit`, the in-app feature truth matrix, and
> `TRANSFER_RELIABILITY_AUDIT_2026-07-21.md`. Current daemon-to-daemon channels
> now require the signed, key-confirmed v3 X25519 + ML-KEM-768 handshake when
> the verified native ABI is present; classical interoperability is an explicit
> migration override and is reported as non-PQ. This does **not** establish
> post-quantum signatures/identity, browser-WebRTC PQ protection, onion
> anonymity, DHT discovery, coherence-field multi-hop routing, or
> hardware-attested transport. The optional native v2 relay now uses rotating
> pairwise route tags and seals both identity-bearing channel first flights,
> but that narrow wire property is not sender anonymity or traffic-analysis
> resistance; a single relay still observes endpoints, timing, sizes, counts,
> and tag linkage. No live message/file route uses onion routing or an
> independent mix-net.

## What this is

The architectural track that turns One Link from "best-in-class file
+ chat engine" into "a global communications layer that no company,
government, ISP, or attacker can lock out, surveil, censor, or
destroy — and that any person can use without understanding any of
that."

This plan lives alongside [FILE_ENGINE_V2_PLAN.md](./FILE_ENGINE_V2_PLAN.md)
(the engine substrate, all phases now structurally complete) and
[ARCHITECTURE.md](./ARCHITECTURE.md) (the PWA pivot). The Coherence
Mesh is the **network + identity + trust layer above the engine**:
how devices find each other, how identities federate, how messages
route privately, and how the user's own devices act as both ONE
contact (to friends) and SEPARATE addressable peers (to themselves).

## The single load-bearing insight

> **Target architecture — three trust tiers, three default privacy modes.**
> Self-traffic is direct-first for performance, an explicit tradeoff that still
> exposes device endpoints, timing, and location changes to route observers.
> Friend traffic targets multi-hop identifier blinding and cover scheduling
> because the social graph is sensitive. A hardened mode targets independent
> multi-hop routing and shape-matched cover for hostile environments. None of
> those targets is an anonymity guarantee until the complete path survives its
> global-passive-observer and multi-operator qualification gates.

This is the only architectural decision that makes "insanely
secure" and "insanely fast" compatible.

## The 10-layer stack

| # | Layer | Status | What it delivers |
|---|---|---|---|
| 1 | **Post-quantum sessions / identity** | 🟡 SESSION KEM LIVE; PQ IDENTITY PARTIAL | Native ML-KEM-768 + X25519 protects current daemon channel establishment through a signed v3 transcript and mutual key confirmation. Identity authentication is still Ed25519 on this wire path; `ol_pqsig`/ML-DSA primitives are not yet the authoritative live identity signature. No product-wide “survives quantum” identity claim until every transport and rotation/recovery path uses and interoperates with the hybrid signature. |
| 2 | **Pair-by-QR + channel-reciprocity 2FA** | 🟡 PRIMITIVES / NOT DAEMON-WIRED | `ol_pair_qr` implements signed Invite/Response/Confirm, SAS, X25519 derivation, and explicit bidirectional confirmation for externally supplied Factor-2 candidates. The Python adapters have no daemon caller. `ol_proximity_pair` is research-only: no probe acquisition, real interactive reconciliation, entropy proof, or hardware evidence; its old high-level secret API now fails closed. Physical-proximity / remote-relay resistance is not shipped. |
| 3 | **Sovereign discovery** | 🟡 PRIMITIVE / DAEMON DHT ROUTE ABSENT | `ol_discovery` contains tested Kademlia records, lookup, UDP, and maintenance primitives. The current product route still uses mDNS plus configured rendezvous; it does not advertise decentralized DHT reachability. |
| 4 | **Coherence-field routing** | 🟡 PRIMITIVE / SINGLE-HOP COUPLINGS ONLY | Helmholtz, Green-function, BE-RAR, and route-scoring primitives are Python-callable and selected metrics feed daemon decisions. There is no deployed multi-hop coherence-field relay graph, so “PDE-routed mesh transport” is still a target. |
| 5 | **Onion circuits** | 🟡 PRIMITIVE / PRODUCT ROUTE ABSENT | `ol_onion` and Python adapters test nested AEAD, Sphinx, padding, and peel/build operations. Cover-frame experiments call parts of that substrate, but no live message/file route uses onion routing; no anonymity or default 1-hop/3-hop claim is active. |
| 6 | **Cover traffic** | 🟡 EXPERIMENTAL WIRE SUBSTRATE | Sphinx cover packets, schedulers, adaptive-rate logic, and browser-peer cover-frame dispatch have tests. They are not a constant-rate production anonymity layer, do not make real and dummy traffic globally indistinguishable, and are not active across normal native relay traffic. |
| 7 | **Obfuscated/attested transport** | 🟡 QUIC + OBFS PRIMITIVES; HARDWARE ATTESTATION PARTIAL | Identity-bound QUIC and obfs-style handshake/session primitives exist and have targeted gates. They do not establish universal hardware-backed identity, remote attestation on every channel, DPI indistinguishability, or JA3-perfect camouflage. |
| 8 | **Personal Device Mesh** | 🟡 IN PROGRESS 2026-05-14 (F5 mobile handoff + telemetry budget slice) | Core planner, State schema v18/v19/v20, `/api/self-mesh`, root create/import, cert mint/enroll/revoke, invite deep-link/QR, daemon self-mesh presence, live secure-channel remote-instruct, per-action capabilities, replay protection, scoped path policy, audit/activity events, Activity-panel controls, trusted-folder management, self-route resolution (`self:<root>`), persisted performance telemetry, launcher/backend build-fingerprint binding, phone-first `/peer` self-mesh invite preview/claim shell, in-process two-daemon E2E, and real subprocess daemon E2E are wired. Next: native-device OS handoff polish and long-run soak evidence. |
| 9 | **Threshold recovery** | ✓ SHIPPED 2026-05-13 | `ol_threshold_recovery` Shamir(K,N) over GF(2^8) + field-bound layer + WIRED into daemon's `social_recovery.py` via `split_compat`/`combine_compat` helpers. Pure-Python `threshold.py` stays as fallback. |
| 10 | **Confidential-compute daemon** | ❌ NEW BUILD | Where hardware supports (Intel SGX, AMD SEV-SNP, Apple Secure Memory, ARM TrustZone), daemon runs in an enclave so even local malware can't extract keys. Beyond Signal. Beyond what any consumer messenger ships. |

## Personal Device Mesh — the multi-device-per-identity capability

> Your phone, laptop, tablet, desktop are ONE identity to your friends
> and SEPARATE addressable peers to you. Both at the same time.

### Target identity hierarchy

The diagram below is the intended hybrid/hardware-bound end state. Current
self-mesh authority uses the implemented Ed25519 root/device-certificate path;
it does not yet make ML-DSA/Dilithium or hardware-backed key storage
authoritative across platforms.

```
Master identity (Ed25519 + Dilithium hybrid, hardware-bound when possible)
├─ Phone subkey   (derived; per-device; revocable)
├─ Laptop subkey  (derived; per-device; revocable)
├─ Tablet subkey  (derived; per-device; revocable)
└─ Desktop subkey (derived; per-device; revocable)
```

The **master pubkey is what friends pin.** Per-device subkeys are
derived from the master via deterministic key derivation (HKDF + a
device-class context tag). When a friend sends to "you," the mesh
delivers to whichever device's subkey is currently reachable. From
the friend's point of view, you're ONE contact.

### Internal addressing (what YOU see)

In your own UI, your devices appear as a small addressable group:

```
You (Alex)
├─ My phone        (online, last-seen 0s ago)
├─ My laptop       (offline, last-seen 4h ago)
├─ My tablet       (online, last-seen 2m ago)
└─ My desktop      (online, last-seen 12s ago)
```

You can target a specific device explicitly when you want
("Send this 20GB screen recording to MY LAPTOP specifically because
it has the disk space") or leave it as "any" and the mesh routes
to whichever wakes first.

### Self-mesh routing

The table below is the **target routing policy**, not the current daemon route
matrix. Today self-mesh instructions and file sends use the available direct or
configured single-relay path; friend traffic does not automatically enter an
onion circuit or constant-rate cover schedule.

| | Self-traffic | Friend-traffic |
|---|---|---|
| Encryption | E2E AEAD (always) | E2E AEAD (always) |
| Onion routing | **Skipped by direct-first default; endpoint/timing linkability is accepted, not absent** | Target: independent multi-hop route; hardened mode uses a larger anonymity set |
| Cover traffic | **Skipped by direct-first default; traffic shape remains observable** | Target: real and dummy traffic share one measured schedule and size distribution |
| NAT traversal | UDP hole punching via STUN-by-paired-peer | Same |
| Path selection | Direct or circuit-relay via paired peer if NATs hostile | Coherence-field routing via paired peers |
| Latency budget | Network speed only (~10-50ms) | +30-80ms onion (1-hop) or +100-200ms (3-hop) |

The target experience is: **"can we also somehow be separate, like if
you want to grab a file from your computer to send but on your phone
in another state?"** That's self-traffic. No onion, no cover, no
latency penalty. The current source proves scoped remote instructions and
daemon file dispatch, but not an across-state paired-peer STUN path, full
network-speed SLA, or physical mobile handoff.

### Two flavors of cross-device file access

**Pull-and-forward (phone pays bandwidth twice):**
```
Phone in TX                  Laptop in CA               Friend
   │                              │                       │
   ├── "list files" ─────────────>│                       │
   │<──── file manifest ──────────│                       │
   ├── "pull file X" ────────────>│                       │
   │<──── file bytes ─────────────│                       │
   ├──────── "send file X to friend" ──────────────────── │
   │                              │                       │
```

User can preview / scrub on phone first; phone bears the bandwidth.
Right answer for small files or "I want to look at it before
sending."

**Remote-instruct (phone pays kilobytes; laptop pays bandwidth):**
```
Phone in TX                  Laptop in CA               Friend
   │                              │                       │
   ├── "send blob X to friend ────│                       │
   │    Y, signed by me, scope =  │                       │
   │    single-file" ─────────────│                       │
   │   (~200 bytes)               │──── file bytes ──────>│
   │                              │                       │
   │<───── "sent, ack" ───────────│                       │
```

Capability-token command goes phone → laptop (signed by phone's
subkey, which laptop verifies against master pubkey). Laptop
forwards the file directly to friend. Phone pays ~kilobytes;
laptop bears the bandwidth. **Right answer for huge files** (4K
video, full project folders, dataset uploads). Total time =
laptop-to-friend transfer time, period.

### Sleep/wake handoff

When the phone backgrounds and the screen goes off, its mesh
presence drops to "asleep." Friends sending to "Alex" land on
whichever-device-is-awake. When the phone wakes, it pulls the
delta from the device that received during sleep.

This is implemented via a **device-presence CRDT** that all your
devices share. Each device announces presence + last-seen + battery
state. The receiving-device for any inbound message is chosen by
the sender's mesh routing using:
- presence score (awake / asleep / dormant)
- battery score (>20% preferred over <20%)
- network quality (Wi-Fi > cellular > LE)
- recency (most-recently-active device gets priority)

### Revocation

Lose a device → revoke its subkey from any other paired device.
The revocation propagates through the mesh; within the mesh's
sync interval (~minutes) every paired contact and every other
device of yours knows the lost subkey is dead. Inbound messages
to it are rejected; the device, if it ever comes back online, can
no longer participate.

## Target performance design (not current qualification)

Five proposed mechanisms are intended to hide security overhead. The latency
figures below are acceptance targets; the repository has no deployed onion
circuit set from which to measure them.

1. **Tiered routing.** Direct-first self-mesh skips onion + cover and accepts
   observable endpoint/timing metadata. A one-relay friend path can blind a
   stable recipient identifier but is not anonymity. The hardened target uses
   at least two independently operated hops plus shape-matched cover; its
   latency and anonymity-set gates must pass before it is enabled or claimed.

2. **Pre-established circuits (target).** The repository has transfer-oriented
   predictor and route-bandit primitives, but no daemon circuit manager. A
   future privacy-reviewed predictor may prewarm circuits without exposing or
   retaining an avoidable contact-frequency graph.

3. **Coherence-field path selection (target).** τ_c/coherence route-scoring
   primitives exist, but no deployed multi-hop graph proves the proposed
   latency. Any claim that an onion route is close to direct speed requires a
   physical, independently operated circuit benchmark.

4. **Multi-path racing.** Critical messages send over 2-3 paths
   simultaneously; whichever arrives first wins. Trades bandwidth
   for tail-latency. Opt-in per message ("send fast" mode).

5. **0-RTT resume.** QUIC 0-RTT (Phase A2 gate, scaffold shipped)
   means returning circuits resume instantly with no handshake.
   Sub-50ms warm-cache latency.

### Target end-state perceived latency

- **Self-mesh (phone↔laptop):** network speed only (~30-60ms
  cross-country). Indistinguishable from a raw QUIC connection.
- **Friend chat (pinned-contact default):** +30-80ms via 1-hop
  onion. Imperceptible vs Signal/iMessage.
- **Paranoid mode (3-hop + cover):** +100-200ms. Noticeable but
  acceptable; only when the user explicitly chose it.

## Phase F sequence

Each ship below has a falsifiable acceptance gate. No phase ships
without passing its gate.

### Phase F1 — Harvest the easy wins (parallel)

Three OneField Mesh primitives port straight over:

| Item | Source | Action |
|---|---|---|
| `ol_threshold_recovery` | `OneField/onefield/privacy/sharding.cl` (Tier 15 production) | Port Shamir(k,n) over GF(2^8) to Rust crate; wire to identity master-key seed; UI for "Add this friend as a recovery contact" |
| `ol_discovery` scaffold | `OneField/onefield/bridge/discovery.cl` | Port TTL + announce cadence logic; add Kademlia DHT layer with signed-peer-announcement entries on top |
| `ol_proximity_pair` | `OneField/onefield/mesh/bootstrap.cl` | Research primitives only. Remaining: aligned physical probes, authenticated interactive reconciliation, entropy/leakage analysis, explicit daemon wiring, and adversarial hardware validation before enabling as Factor-2. |

**Phase F1 acceptance gate:**
- Lose 2 of 5 trusted devices, recover identity from remaining 3 (Shamir round-trip test ≥ 1000 random seeds)
- Two daemons find each other via DHT without any rendezvous server (LAN + cross-NAT both)
- **UNMET:** captured-QR + remote-actor rejection needs a real probe protocol and adversarial hardware evidence; deterministic unit fixtures do not prove it

### Phase F2 — Pair-by-QR (foundation under everything else)

Target: replace the `--lan` token URL with a daemon-wired authenticated
pairing handshake initiated by QR scan. The Rust/Python pair-by-QR primitive
exists, but repository search finds no daemon caller; Dilithium is also not in
this pair protocol. The replacement and remote-pair security claim therefore
remain unshipped.

**Phase F2 acceptance gate:**
- **UNMET E2E:** scan QR with phone → phone becomes paired peer of laptop
- **UNPROVEN E2E:** laptop UI port is never bound to LAN during the flow
- Primitive tests cover transcript/signature replay and substitution cases;
  daemon/network red-team evidence is still required
- **UNMET:** captured-QR/no-proximity rejection requires the unfinished
  channel-reciprocity protocol and physical-device tests

### Phase F3 — Onion circuits (`partial`: primitive only)

The target is 1-hop default for pinned-contact friend-traffic and 3-hop for
paranoid mode, selected through coherence-field routing. Current code has
tested onion/Sphinx build-and-peel primitives and limited cover-frame calls,
but no live message/file route, relay circuit manager, default activation, or
physical latency evidence.

**Phase F3 acceptance gate:**
- 1-hop circuit added latency < 80ms over LAN; < 200ms over cross-country WAN
- 3-hop circuit added latency < 250ms cross-country
- Each hop only knows previous + next (cryptographic verification:
  no hop can decrypt destination metadata)
- Path selection prefers high-τ_c relays (measurable via Phase E metrics)

### Phase F4 — Sealed sender + cover traffic (`partial`)

The implemented native v2 single-relay boundary uses rotating pairwise route
tags and recipient-seals the identity-bearing HELLO/REPLY flights. It does not
put either identity public key on that relay wire. It does not hide endpoint
IPs, timing, size, count, tag linkage, or presence correlation and therefore
does not satisfy the target of sender anonymity. Loopix-style constant-rate
cover traffic and independent multi-hop mixing remain unimplemented product
routes.

**Phase F4 acceptance gate:**
- Observer sniffing WiFi cannot determine who-talks-to-whom from
  timing analysis over 24h capture
- Cover-traffic byte budget < 50KB/hour per pinned contact

### Phase F5 — Personal Device Mesh

The multi-device-per-identity capability. Master identity + per-device
subkeys + device-presence CRDT + remote-instruct command channel.

**2026-05-14 foundation + live-channel slice landed:**
- `src/one_link/personal_device_mesh.py`
- `src/one_link/self_mesh_enrollment.py`
- `tests/test_personal_device_mesh.py`
- `tests/test_personal_device_mesh_daemon.py`
- `tests/test_self_mesh_ui.py`
- `tests/test_self_mesh_performance.py`
- `tests/test_self_mesh_e2e.py`
- `State` schema v18: `self_mesh_devices`, `self_mesh_presence`,
  `remote_instruction_seen`
- `State` schema v19: `self_mesh_roots` and `self_mesh_audit`
- `State` schema v20: bounded `self_mesh_perf_samples` telemetry history
- `/api/self-mesh` read model for root/device/presence/audit/routing state
- API root/device controls: create/import root, mint device cert, enroll cert,
  revoke device, and send a signed remote instruction.
- Enrollment invite controls: tokenized deep link and no-store QR SVG carrying
  a root-signed device cert for mobile/self-device handoff.
- Enrollment handoff now has preview + claim endpoints, so a self-device can
  parse the QR/deep-link token, confirm it is for its local key, enroll the
  root/cert locally, and publish presence immediately.
- Daemon publishes local self-mesh presence at startup and presence changes.
- Daemon accepts `SELF_MESH_PRESENCE` over pinned live channels.
- Daemon accepts signed `SELF_MESH_REMOTE_INSTRUCTION` over pinned live
  channels and executes scoped `pull_file_manifest` / `send_file_from_device`
  actions.
- Daemon resolves `self:<root_pub_b64>` through the self-mesh target selector
  before normal send resolution.
- Remote file actions are constrained to allowed self-mesh roots: inbox,
  configured `self_mesh_allowed_roots`, and synced folder roots.
- `/api/self-mesh/allowed-roots` plus the Activity-panel "Trust folder"
  control make remote file scopes user-visible and auditable.
- Per-action prompt-required capabilities are defined for
  `self_mesh_manifest` and `self_mesh_send`; remote-instruct receive rejects
  actions that the peer policy has not granted.
- Self-mesh audit/activity events cover enrollment, revocation, presence,
  command accepted/rejected/replayed, and remote send queued/complete/failed.
- `/api/self-mesh/performance` records and reports route-choice probe cost,
  live row counts, and recent telemetry history; the Activity panel surfaces
  latency/ready/device chips inline.
- Production telemetry observations now record presence fanout, command
  verify/replay/execute/total timing, remote-send dispatch, and UI/API polling
  budgets into the bounded perf history.
- In-process two-daemon E2E proves an enrolled phone can sign a scoped
  command, an enrolled laptop can receive it through the live handler, enforce
  `self_mesh_send`, and queue/complete the delegated file send.
- Real subprocess E2E (`tests/test_self_mesh_subprocess.py`) proves two daemon
  processes can enroll under one root, send a signed remote instruction over
  the encrypted live transport, route a fingerprint-addressed recipient through
  the live endpoint instead of stale persisted LAN state, transfer the requested
  file, and write command/remote-send audit receipts.
- Activity panel renders the token-guarded "My devices" self-mesh surface and
  refreshes on `self_mesh_changed` WebSocket events; compact controls can
  create roots, enroll certs, revoke devices, pull manifests, and request
  remote sends.
- Activity panel also renders recent action receipts/timeline state and the
  latest measured perf observations so remote actions are visible as
  sent/accepted/queued/completed/failed.
- `/peer` now recognizes self-mesh invite query tokens, verifies them through
  a public parse-only endpoint, checks the certificate against the browser
  device public key, and stores a claimed local certificate record for the
  phone-first flow.
- Recent telemetry is evaluated against production budgets for route probes,
  presence fanout, command verify/replay/execute/total, remote-send dispatch,
  and UI/API polling; the Activity panel exposes the current budget state.
- `scripts/self_mesh_soak_gate.py` reads the live daemon's self-mesh
  performance endpoint, evaluates those budgets, and writes a JSON artifact
  suitable for release gates and 24h soak jobs.
- `scripts/self_mesh_soak_rollup.py` runs repeated budget probes over a
  configured duration and writes an aggregate pass/fail rollup.
- Native URL handoff has per-user installers for Windows, macOS, and Linux:
  `install_url_protocol.ps1`, `install_url_protocol_macos.sh`, and
  `install_url_protocol_linux.sh`.
- Browser-peer app traffic can require a fresh, channel-bound proof of the
  enrolled Ed25519 device key
  (`ONE_LINK_REQUIRE_BROWSER_IDENTITY_POSSESSION=required`). The legacy
  `ONE_LINK_REQUIRE_ATTESTED_PEERS` spelling remains a compatibility alias,
  but this browser proof is identity possession, not hardware or platform
  attestation. Daemon status names that distinction and reports gate drops.
- Row 6/7 browser-peer cover traffic is now wire-capable: control-channel
  open announces each side's Sphinx onion pubkey, inbound cover packets are
  peeled and sentinel-checked before being dropped, and daemon cover emission
  prefers a real ready peer before falling back to local loopback crypto.
- Presence facts converge by `(sequence, updated_ms)`.
- Delivery planning rejects revoked/untrusted/offline/storage-starved devices.
- Self-mesh target choice scores awake/asleep state, network class, battery,
  storage headroom, freshness, bandwidth, and latency.
- Remote-instruct commands are signed by a certified controller device,
  root-bound, target-bound, expiry-bound, nonce-bearing, and replay-checkable.
- Runtime remote-instruct requires a trusted local device-cert row for the
  command root, so arbitrary roots cannot address this daemon by raw pubkey.
- `one-link app` now compares launcher/UI/daemon source fingerprints in
  addition to semantic version and schema, so desktop launch cannot silently
  reuse a stale backend during alpha iteration.

**Remaining for F5 completion:**
- Native-device OS handoff polish: `one-link open-url` maps
  `one-link://self-mesh/enroll?token=...` into the local authenticated
  `/peer?self_mesh_invite=...` flow, and desktop OS installers exist.
  Remaining work is mobile-packaging-specific registration.
- Long-running soak evidence: run 24h+ sessions and persist budget rollups as
  release-gate artifacts, not just recent in-app samples. Gate + rollup
  writers exist; the remaining work is sustained wall-clock collection across
  real devices and operating systems.

**Phase F5 acceptance gate:**
- One Ed25519 master derives N device subkeys deterministically
- Friend sees one contact "Alex"; messages route to whichever device
  is awake; phone wakes → catches up
- "Grab file from my laptop in another state" works at full network
  speed (no onion overhead, NAT-traversed via paired-peer STUN)
- "Send file from my laptop to my friend, initiated from my phone"
  costs the phone < 1KB of command-bandwidth
- Lose a device → revoke from any other → revocation propagates to
  all paired contacts within 5 minutes

### Phase F6 — DPI-evading pluggable transport

Make One Link traffic indistinguishable from generic HTTPS on the
wire. Defeats censorship + ISP throttling.

**Phase F6 acceptance gate:**
- DPI fingerprinter (e.g., GFW, Iran's protocols) cannot distinguish
  One Link bytes from random HTTPS sample across ≥ 10,000 connections
- Throughput within 15% of raw QUIC

### Phase F7 — PQ signatures

Add Dilithium / SLH-DSA signature hybrid alongside Ed25519. Survives
post-quantum.

**Phase F7 acceptance gate:**
- Hybrid signature verifies under both Ed25519 + Dilithium
- Either primitive alone is sufficient (defense in depth: if one
  scheme breaks, the other still authenticates)
- Backwards-compatible: older peers verifying only Ed25519 still work

### Phase F8 — Confidential-compute daemon (per-platform)

Where hardware supports, run the daemon (or at minimum the
key-handling subsystem) in a hardware-attested enclave.

**Phase F8 acceptance gate (per platform):**
- macOS: keys held in Secure Enclave; sealed cipher operations
- Windows: TPM-bound; remote attestation chain validates
- Linux: SGX/SEV-SNP detection + opt-in enclave mode
- Local malware with root cannot extract identity key

## Sovereignty audit per layer

Every layer is checked against the defang ladder in
[SOVEREIGNTY.md](./SOVEREIGNTY.md). No dependency on any single
corporate substrate.

| Layer | Default substrate | Sovereign substitute if compromised |
|---|---|---|
| PQ libraries | `pq-crystals` reference (BSD) | Vendor-multiple impls (NIST + libsodium-pqc) |
| Channel reciprocity | Direct radio hardware | Already vendor-neutral (any SDR / WiFi/LE/LoRa NIC) |
| DHT | Custom Kademlia | Easy substitute (libp2p Kademlia, IPFS) |
| STUN | Self-hosted / swarm-peer | Multiple competing public STUN (Google + Mozilla + Cloudflare — pick one randomly per session) |
| TURN | Paired-peer circuit relay | No external TURN dependency at all |
| Hardware enclave | Platform-specific | TOFU-degrading; vendor attestation chain optional, not required |
| Pluggable transport | Cloak-style (open spec) | Multiple impls (Obfs4, MeekHTTPS) |
| Shamir recovery | OneField (in-house) | Any RFC-compliant Shamir impl |

**Net: zero new corporate dependencies introduced.** Every layer
either has no external dependency or degrades gracefully to a
sovereign substitute.

## Target user outcomes after the open phases pass

Cross-references the audit in this plan's conversation transcript:

- **Individual users (target):** Talk to anyone, anywhere, with no account,
  no phone number, no email. Lose your phone, recover from 3
  friends. All devices = one contact to friends; separate to you.
  Send any file size. Survives quantum. Works on hostile networks.

- **Journalists / sources / activists (target):** The metadata is the threat.
  Independently operated multi-hop routing and shape-matched cover are intended
  to reduce who-talks-to-whom and when leakage. The product must not claim that
  those facts are hidden, that no party can be subpoenaed, or that DPI cannot
  fingerprint it until the complete deployment and adversarial evidence exist.

- **Refugees / displaced people (target):** validated channel-reciprocity
  pair-trust could reduce remote-relay impersonation after the unmet protocol
  and hardware gates above. DTN/disaster bootstrap also remains subject to
  its own daemon and field-test evidence.

- **Small ops (the strategic wedge):** Capability-based shares.
  CRDT folders. Enterprise infra for $0. No SaaS subscription, no
  per-seat pricing, no IT department needed.

## Feature comparison

This is explicitly the **post-F target**, not a comparison of the current alpha
or any released artifact.

| Capability | One Link (post-F) | Signal | WhatsApp | iMessage | Telegram |
|---|:-:|:-:|:-:|:-:|:-:|
| End-to-end encryption | ✓ | ✓ | ✓ | ✓ | opt-in |
| Forward + post-compromise secrecy | ✓ | ✓ | ✓ | partial | partial |
| PQ signatures (not just KEM) | ✓ | ✗ | ✗ | ✗ | ✗ |
| No central server (true P2P) | ✓ | ✗ | ✗ | ✗ | ✗ |
| No phone number / email required | ✓ | ✗ | ✗ | ✗ | ✗ |
| Threshold recovery via friends | ✓ | ✗ | ✗ | ✗ | ✗ |
| Onion routing by default | ✓ | ✗ | ✗ | ✗ | ✗ |
| Cover traffic | ✓ | ✗ | ✗ | ✗ | ✗ |
| Physics-based pair authentication | ✓ | ✗ | ✗ | ✗ | ✗ |
| PDE-routed mesh transport | ✓ | ✗ | ✗ | ✗ | ✗ |
| Multi-device-per-identity (P2P) | ✓ | partial | ✗ | partial | partial |
| Personal Device Mesh (self-traffic) | ✓ | ✗ | ✗ | partial | ✗ |
| Confidential-compute daemon | ✓ | ✗ | ✗ | partial | ✗ |
| Sovereign discovery (no DNS) | ✓ | ✗ | ✗ | ✗ | ✗ |
| Capability-based shares (audit + revoke) | ✓ | ✗ | ✗ | ✗ | ✗ |

## Effort summary

| Phase | Net-new code | Harvest | Calendar effort (focused) |
|---|---|---|---|
| F1 — Harvest | minimal glue | Shamir + discovery + bootstrap | 1-2 weeks |
| F2 — Pair-by-QR | Ed25519 + Dilithium handshake + UI | QR libs | 2-3 weeks |
| F3 — Onion circuits | nested AEAD + circuit construction | Phase E routing | 2-3 weeks |
| F4 — Sealed sender + cover traffic | Loopix-style scheduler | (none) | 1-2 weeks |
| F5 — Personal Device Mesh | device CRDT + remote-instruct | Capability layer | 3-4 weeks |
| F6 — DPI-evading transport | Cloak adapter | quinn transport | 2-3 weeks |
| F7 — PQ signatures | Dilithium hybrid | pq-crystals | 1-2 weeks |
| F8 — Confidential compute | per-platform | platform SDKs | 2-3 weeks per platform |

**Total focused effort: ~12-18 weeks** to ship the entire Coherence
Mesh on top of the already-shipped engine. No phase blocks another;
F1/F2/F3 in parallel; F5 unblocks the "everyone on any device" UX
once it lands.

## Verification

How each phase is validated end-to-end:

1. **Per-phase acceptance gates** above. No ship without pass.
2. **Required adversarial fuzz / physical testing**: inject packet loss, NAT
   changes, captured-QR replay, and (once a probe protocol exists)
   channel-reciprocity spoofing. This is a gate, not current evidence.
3. **Cross-platform soak**: 48h continuous mesh on Linux + macOS +
   Windows + iOS Safari + Android Chrome.
4. **Sovereignty audit per release**: every dep verified against the
   table above; new dep requires explicit review.

## How this composes with FILE_ENGINE_V2_PLAN.md

The file engine plan covers Phases A-E (substrate, transport, info
layer, baseline, visionary, coherence-field). All structurally
shipped as of 2026-05-12.

The Coherence Mesh plan covers Phase F (network + identity + trust)
and builds on top:

```
┌──────────────────────────────────────────────┐
│  Phase F — Coherence Mesh (THIS PLAN)        │
│  Identity, pair-trust, onion routing,        │
│  personal device mesh, PQ sigs, enclaves     │
└──────────────────────────────────────────────┘
                    ↑
                    │ uses
                    │
┌──────────────────────────────────────────────┐
│  Phase E — Coherence-field substrate          │
│  τ_c PDE routing primitive (shipped)         │
└──────────────────────────────────────────────┘
                    ↑
┌──────────────────────────────────────────────┐
│  Phases A-D — File engine                    │
│  Chunk store, crypto, transport, info layer  │
└──────────────────────────────────────────────┘
```

Each layer is independent. Phase F can ship piece-by-piece on top
of the existing engine without re-architecting anything below.

## Open questions (intentionally not resolved here)

1. **Should the per-device subkey be derived deterministically from
   master (HKDF-with-device-tag) OR generated independently and
   bound by master signature?** Tradeoff: deterministic = simpler
   recovery, harder revocation (revoked key derivable). Independent
   = easier revocation, recovery needs master-key access. Lean:
   independent + master signature.
2. **What's the device-presence CRDT exact shape?** OR-Set
   (presence is add-wins) vs LWW-Register (last-write-wins). Lean:
   OR-Set for presence, LWW for last-seen timestamp.
3. **Confidential compute: how much of the daemon goes in the
   enclave?** Just the key handling (smallest TCB, easiest port)?
   Or the full crypto pipeline (more secure, larger TCB)? Lean:
   start with keys-only; expand.
4. **Channel-reciprocity 2FA: is it mandatory or optional?** This cannot be
   enabled in either mode until the probe, reconciliation, entropy, daemon,
   and hardware-validation gates above are complete. Current Factor-2 APIs
   confirm candidate equality only; they do not prove physical provenance.

These get resolved at ADR time as each phase starts.
