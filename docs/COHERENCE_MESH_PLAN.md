# Coherence Mesh Plan — sovereign-network track

> Status: planning-of-record. Living document.
> Last updated: 2026-05-12.

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

> **Three trust tiers, three default privacy modes.** Self-traffic
> is direct + fast because there's no metadata to hide. Friend-traffic
> is 1-hop-onion + sealed-sender because the network observer must
> not learn the social graph. Paranoid mode is 3-hop-onion + cover
> traffic for users in hostile environments. The user never picks
> which tier — pair-by-QR puts your devices in self-mesh, the
> friend's contact lands in pinned, and paranoid is an explicit opt-in.

This is the only architectural decision that makes "insanely
secure" and "insanely fast" compatible.

## The 10-layer stack

| # | Layer | Status | What it delivers |
|---|---|---|---|
| 1 | **Post-quantum identity** | ✓ SHIPPED 2026-05-13 (`ol_pqsig` Ed25519 + ML-DSA-65 hybrid; PQ KEM already in `ol_pqkem` + Sphinx) | Ed25519 + Dilithium hybrid master key; ML-KEM-768 + X25519 hybrid per-device KEM; hardware-bound (Secure Enclave / StrongBox / TPM) where available; TOFU-degrading where not. Survives quantum. |
| 2 | **Pair-by-QR + channel-reciprocity 2FA** | ✓ SHIPPED 2026-05-12 (Phase F2) | `ol_pair_qr` crate: Ed25519-signed Invite + transcript-bound PairResponse + PairConfirm + 5-word SAS over 30 bits + X25519 chain-key derivation. Optional Factor-2 mix-in via `ol_proximity_pair`. Refuses cross-invite replay + key-substitution + transcript-swap. Daemon-side via `pair_qr_native.{Inviter,Scanner}`. |
| 3 | **Sovereign discovery** | ✓ SHIPPED 2026-05-13 | `ol_discovery` Kademlia DHT + `DhtNode` production orchestrator + Row 3 maintenance loops (`refresh_stale_buckets`, `republish_records`, `tick_maintenance`) + Python `run_maintenance_loop` asyncio helper. |
| 4 | **Coherence-field routing** | ✓ SHIPPED 2026-05-11 (Phase E) | τ_c PDE-routed mesh transport. Routes through high-coherence peers; auto-avoids fragility before partition. Phase E ships full Helmholtz solver + Green-function nonlocal kernel + BE-RAR loss penalty. Production wiring complete this session. |
| 5 | **Onion circuits** | ✓ SHIPPED 2026-05-12 (Phase F3) | `ol_onion` crate: nested ChaCha20-Poly1305 AEAD with per-layer ephemeral X25519 keys. Each hop only knows predecessor + successor. 1-hop, 3-hop, and up to 5-hop circuits supported. `build_onion` + `peel_one_layer` primitives wired into daemon via `onion_native.{build_onion,peel_one_layer,derive_pubkey}`. Sphinx-style single-pubkey blinding deferred to F3-polish v2; transport-layer padding addresses hop-count leak. |
| 6 | **Cover traffic** | 🟡 PRIMITIVE SHIPPED 2026-05-12 (`afd3478`) | `ol_onion::sphinx::cover`: build_cover_packet (sentinel + random pad, indistinguishable size from real Sphinx) + CoverScheduler (Poisson-rate emission, BLAKE3-seeded for determinism). Daemon-side timer wiring + active-inference adaptive rate (Tier 2) deferred. |
| 7 | **Hardware-attested transport** | ✓ SHIPPED 2026-05-13 | QUIC over TLS 1.3 (Phase A2) + `ol_onion::transport_obfs` complete: primitive byte XOR + obfs4-style handshake (BridgeKeypair + ClientHandshake + ServerHandshake with epoch-bound HMAC binding + 1-epoch skew tolerance) + bidirectional Session with per-direction keys. JA3-perfect TLS-fingerprint mimicry on top is a separate ship (the keys + nonces are here). |
| 8 | **Personal Device Mesh** | 🟡 IN PROGRESS 2026-05-14 (F5 real-daemon proof slice) | Core planner, State schema v18/v19/v20, `/api/self-mesh`, root create/import, cert mint/enroll/revoke, invite deep-link/QR, daemon self-mesh presence, live secure-channel remote-instruct, per-action capabilities, replay protection, scoped path policy, audit/activity events, Activity-panel controls, trusted-folder management, self-route resolution (`self:<root>`), persisted performance telemetry, launcher/backend build-fingerprint binding, in-process two-daemon E2E, and real subprocess daemon E2E are wired. Next: richer native/mobile handoff and long-run production telemetry. |
| 9 | **Threshold recovery** | ✓ SHIPPED 2026-05-13 | `ol_threshold_recovery` Shamir(K,N) over GF(2^8) + field-bound layer + WIRED into daemon's `social_recovery.py` via `split_compat`/`combine_compat` helpers. Pure-Python `threshold.py` stays as fallback. |
| 10 | **Confidential-compute daemon** | ❌ NEW BUILD | Where hardware supports (Intel SGX, AMD SEV-SNP, Apple Secure Memory, ARM TrustZone), daemon runs in an enclave so even local malware can't extract keys. Beyond Signal. Beyond what any consumer messenger ships. |

## Personal Device Mesh — the multi-device-per-identity capability

> Your phone, laptop, tablet, desktop are ONE identity to your friends
> and SEPARATE addressable peers to you. Both at the same time.

### Identity hierarchy

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

Traffic between YOUR OWN devices is **self-traffic** — different
routing semantics from friend-traffic:

| | Self-traffic | Friend-traffic |
|---|---|---|
| Encryption | E2E AEAD (always) | E2E AEAD (always) |
| Onion routing | **Skipped** (no metadata to hide — it's you talking to you) | 1-hop default, 3-hop paranoid |
| Cover traffic | **Skipped** | On between pinned contacts |
| NAT traversal | UDP hole punching via STUN-by-paired-peer | Same |
| Path selection | Direct or circuit-relay via paired peer if NATs hostile | Coherence-field routing via paired peers |
| Latency budget | Network speed only (~10-50ms) | +30-80ms onion (1-hop) or +100-200ms (3-hop) |

The user said it best: **"can we also somehow be separate, like if
you want to grab a file from your computer to send but on your phone
in another state?"** That's self-traffic. No onion, no cover, no
latency penalty. Just a direct encrypted transfer between two of
your devices, NAT-traversed, at full network speed.

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

## How it stays insanely fast under all the security

Five mechanisms hide the security overhead from perceived latency:

1. **Tiered routing.** Self-mesh skips onion + cover entirely.
   Pinned-contact friend-chat uses 1-hop, not 3-hop. 3-hop is
   explicit paranoid-mode opt-in for activists/journalists. Most
   users never pay the heavy overhead.

2. **Pre-established circuits.** Active inference + bandit (Phase D,
   shipped) learns who you message often. Pre-warms onion circuits
   to those friends in idle time so first-hop is hot when you send.

3. **Coherence-field path selection.** The τ_c routing (Phase E,
   shipped) picks high-coherence (= low loss + low latency) paths.
   Onion through high-τ_c peers is barely slower than direct
   because the chosen paths are the fastest available.

4. **Multi-path racing.** Critical messages send over 2-3 paths
   simultaneously; whichever arrives first wins. Trades bandwidth
   for tail-latency. Opt-in per message ("send fast" mode).

5. **0-RTT resume.** QUIC 0-RTT (Phase A2 gate, scaffold shipped)
   means returning circuits resume instantly with no handshake.
   Sub-50ms warm-cache latency.

### End-state perceived latency

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
| `ol_proximity_pair` | `OneField/onefield/mesh/bootstrap.cl` | Port channel-reciprocity 128-probe protocol; wire as optional Factor-2 alongside QR-scan Factor-1 |

**Phase F1 acceptance gate:**
- Lose 2 of 5 trusted devices, recover identity from remaining 3 (Shamir round-trip test ≥ 1000 random seeds)
- Two daemons find each other via DHT without any rendezvous server (LAN + cross-NAT both)
- Captured-QR + remote-actor attack fails the channel-reciprocity gate

### Phase F2 — Pair-by-QR (foundation under everything else)

Replace the `--lan` token URL with a proper Ed25519 + Dilithium pair
handshake initiated by QR scan. Eliminates the entire class of
remote-pair vulnerabilities.

**Phase F2 acceptance gate:**
- Scan QR with phone → phone becomes paired peer of laptop
- Laptop UI port is NEVER bound to LAN during the entire flow
- Adversary on same WiFi cannot replay or MITM the pair handshake
- Adversary with the captured QR but no proximity fails channel-reciprocity Factor 2

### Phase F3 — Onion circuits

1-hop default for pinned-contact friend-traffic; 3-hop for paranoid
mode. Path selection via Phase E coherence-field routing.

**Phase F3 acceptance gate:**
- 1-hop circuit added latency < 80ms over LAN; < 200ms over cross-country WAN
- 3-hop circuit added latency < 250ms cross-country
- Each hop only knows previous + next (cryptographic verification:
  no hop can decrypt destination metadata)
- Path selection prefers high-τ_c relays (measurable via Phase E metrics)

### Phase F4 — Sealed sender + cover traffic

Hide sender identity from observers (sealed sender like Signal's,
extended to the mesh). Add Loopix-style constant-rate cover traffic
between pinned contacts.

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
- Richer mobile handoff ceremony: use the QR/deep-link exchange as the first
  step of a full browser/native mobile enrollment flow, not just cert import.
- Production telemetry expansion beyond route-choice history: presence fanout,
  command verify/replay, remote-send dispatch, and UI/API polling budgets over
  long-running sessions.

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

## What this enables for real users

Cross-references the audit in this plan's conversation transcript:

- **Individual users:** Talk to anyone, anywhere, with no account,
  no phone number, no email. Lose your phone, recover from 3
  friends. All devices = one contact to friends; separate to you.
  Send any file size. Survives quantum. Works on hostile networks.

- **Journalists / sources / activists:** The metadata is the threat.
  Onion routing hides who-talks-to-whom. Cover traffic hides when.
  No central party exists to subpoena. DPI can't fingerprint the
  protocol.

- **Refugees / displaced people:** Channel-reciprocity pair-trust
  defeats remote-relay impersonation. DTN + disaster-bootstrap
  primitives (from OneField) let the mesh self-organize without
  pre-existing infrastructure.

- **Small ops (the strategic wedge):** Capability-based shares.
  CRDT folders. Enterprise infra for $0. No SaaS subscription, no
  per-seat pricing, no IT department needed.

## Feature comparison

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
2. **Per-PR adversarial fuzz**: inject packet loss, NAT changes,
   captured-QR replay, channel-reciprocity spoofing — engine must
   degrade gracefully.
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
4. **Channel-reciprocity 2FA: is it mandatory or optional?**
   Mandatory = harder for some users (need RF-capable devices);
   optional = weaker. Lean: optional Factor 2 on hardware that
   supports it; mandatory only in Hardened tier.

These get resolved at ADR time as each phase starts.
