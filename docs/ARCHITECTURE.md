# Architecture — v0.15.0 → v1.0.0 implementation specification

Status: living document. Implementation-grade depth for the PWA
pivot. Every ship between v0.15.0 and v1.0.0 has a frontier, a
primitive, a wire-format addition, a state migration, a test
contract, and a defang cross-reference.

Companion docs:
- [`PRINCIPLES.md`](./PRINCIPLES.md) — the four-principle gate.
- [`SOVEREIGNTY.md`](./SOVEREIGNTY.md) — corporate-substrate defangs.
- [`ROADMAP.md`](./ROADMAP.md) — ship ordering.
- [`PHONE_TIER.md`](./PHONE_TIER.md) — phone surface specification.

Last updated: 2026-05-08.

---

## North-star architecture

By v1.0.0, One Link runs as a **pure-browser P2P chat + file sync
PWA** on any modern phone or desktop browser, with the existing
Python daemon as an optional same-protocol peer. Both speak the
same wire format; neither knows or cares which side is "native."

The architecture has eight layers. Each layer has its own ship in
the v0.15.0+ sequence. Each layer specifies the corporate-floor
defang it ships. Each layer reuses Coherence Language stdlib
primitives where they exist, with explicit cross-references.

```
┌─ User-visible UX ──────────────────────────────────┐
│  Tier-selector, pair-flow, settings, conversation │
├─ Intelligence ─────────────────────────────────────┤
│  WebGPU LLM, federated learning, predictive cache  │
├─ Sync ─────────────────────────────────────────────┤
│  CRDT (Yjs/Automerge), HLC, lazy sync, Web Push    │
├─ Cryptography ─────────────────────────────────────┤
│  Double Ratchet, MLS, sealed sender, cover traffic │
│  Post-quantum hybrid (ML-KEM + X25519)              │
├─ Identity ─────────────────────────────────────────┤
│  Threshold-of-N, Passkey opt-in, attestation,      │
│  verifiable revocation log, plausibly deniable     │
├─ Storage ──────────────────────────────────────────┤
│  OPFS for blobs, IDB for indexed records, AES-GCM  │
│  at rest, multi-source entropy                     │
├─ Transport ────────────────────────────────────────┤
│  WebRTC DataChannel + WebTransport, BLE proximity, │
│  ultrasonic, mDNS-equiv, adaptive bandit, mix-net  │
├─ Bootstrap ────────────────────────────────────────┤
│  PWA shell, Service Worker, signed updates,        │
│  IPFS / .onion / signed-archive distribution       │
└────────────────────────────────────────────────────┘
```

---

## Cross-cutting: Coherence stdlib reuse

The Coherence Language stdlib at
`coherence_lang/coherence_lang/bootstrap/stdlib/std/` already
contains production implementations of several primitives we need.
Where reuse is possible, the v0.15.0+ ships **port** rather than
**reinvent**.

| Primitive | Coherence module | Reuse mode | One Link target |
|---|---|---|---|
| HKDF | `std/crypto/kdf.cl` | Direct port (call Web Crypto under the hood) | All key derivation; ratchets; entropy mixing |
| Argon2id | `std/crypto/kdf.cl` | Direct port | At-rest passphrase derivation (OPFS encryption key) |
| AES-GCM (with GHASH) | `std/crypto/symmetric.cl` | Reference impl; production uses Web Crypto AES-GCM | At-rest OPFS / IDB; Double Ratchet symmetric phase |
| ChaCha20-Poly1305 | `std/crypto/symmetric.cl` (RFC 8439) | Direct port for browsers without AES-GCM hardware acceleration; otherwise prefer AES-GCM | Transport layer; mix-net hop encryption |
| Hybrid Logical Clock | `std/crdt/causality.cl::HybridLogicalClock` | Direct port | Message ordering across devices, conflict-free without OS clock trust |
| Vector clock / DotContext | `std/crdt/vector_clock.cl` | Direct port | Multi-device causal ordering |
| Interval Tree Clock | `std/crdt/vector_clock.cl::IntervalTreeClock` | Direct port | Threshold-of-N device membership churn |
| Causal delivery / graph | `std/crdt/causality.cl` | Direct port | Message sequencing in groups |
| Merge strategies (LWW, FWW, etc.) | `std/crdt/merge.cl` | Direct port (compose with Yjs) | Conflict resolution policy framework |
| GCounter / PNCounter | `std/crdt/counters/` | Direct port | Read counters, message counters |
| ORSet / AWSet | `std/crdt/sets/` | Direct port | Group membership presence |
| LWWMap / MVMap | `std/crdt/maps/` | Direct port | Settings sync, profile fields |
| RGA / YATA / Logoot | `std/crdt/sequences/` | Direct port (alt to Yjs sequences) | Long-form message ordering, edit-friendly |
| Post-quantum (ML-KEM + X25519) | `std/crypto/quantum_safe.cl` | Direct port if implementations are mature; else use `@noble/post-quantum` | Hybrid key agreement |
| Signature schemes (Ed25519, ECDSA) | `std/crypto/asymmetric.cl` | Direct port (Web Crypto wrapper) | Sealed sender, revocation log signatures |
| Identity provenance | `std/identity/provenance.cl` | Pattern reuse | Device attestation chain |
| Anti-deception / spoofing | `std/identity/anti_deception.cl` | Pattern reuse | Risk model for pair-flow simplification |
| Session types (binary) | `std/session/binary/channel.cl` | Pattern reuse | Wire-format protocol design |
| Multiparty session types | `std/session/multiparty/` | Pattern reuse | MLS group ratchet protocol structure |

This table is the canonical reuse manifest. When a v0.15.0+ ship
implements one of these primitives, the spec MUST cite the
Coherence module it ports from + document any deviations.

---

## v0.15.0 — PWA shell + Web Crypto identity foundation

**Frontier:** PWA install criteria fully met on iOS Safari + Android
Chrome; Web Crypto identity keypair generation reproducibly executes
in <50ms p95 on a 5-year-old phone.

**Primitives:**
- `manifest.json` with PNG icons (192×192, 512×512, maskable variants)
- Service Worker registered (already shipped v0.14.0; refresh)
- Ed25519 keypair generation via `subtle.crypto.generateKey({name: "Ed25519"})`
- Hybrid keypair: also generate X25519 for ECDH
- Future-proofing: ML-KEM-768 keypair (via `@noble/post-quantum`) generated
  alongside, used in hybrid mode from v0.21.0+

**Wire-format additions:** none yet (this ship is local).

**State migration:** new IDB store `identity.v1` with fields:
`{fingerprint, ed25519_pub, ed25519_priv_wrapped, x25519_pub,
x25519_priv_wrapped, mlkem_pub, mlkem_priv_wrapped, created_ms,
attestation}`. Wrapping uses AES-GCM with a key derived from a
passphrase (Argon2id from `std/crypto/kdf.cl`). On first launch
the user sets the passphrase; subsequent unlocks use it.

**Test contract:** `tests/test_pwa_shell_v0150.py`
- manifest.json validates against W3C PWA criteria
- Service Worker registration succeeds on a TestServer
- Ed25519 + X25519 + ML-KEM keypair generation completes
- Identity reproducibly persists/loads across SW restart

**Defang shipped:** signed-update verification in SW (defangs CDN
compromise). See `SOVEREIGNTY.md` § "TLS / Certificate Authorities."

**Stdlib reuse:** `std/crypto/kdf.cl::Argon2id` (port to JS for the
passphrase-to-wrap-key derivation).

**Ship-gate:**
- Reach: anyone with a phone + a URL can install One Link to home
  screen without a desktop.
- Hide: no new jargon; install prompt copy is "Install One Link?".
- Async: identity is local-first; Service Worker survives tab close.
- Depth: <50ms keypair generation as a measured SLA; signed-update
  refusal-on-mismatch as a regression-tested invariant.
- Defang: signed updates pinned in source.

---

## v0.16.0 — OPFS storage layer + at-rest encryption

**Frontier:** every byte One Link writes to disk in the browser is
AES-GCM encrypted with a per-device key never visible to the OS or
to JS unless the user has unlocked the app in this session.

**Primitives:**
- OPFS API (`navigator.storage.getDirectory()`) for blobs, chunks,
  attachments, anything > 64KB
- IDB for indexed records (messages, peers, settings) — also encrypted
- AES-GCM 256-bit at rest, key derived from the v0.15.0 passphrase
  via Argon2id
- Plausibly deniable storage: outer file/blob carries no header that
  identifies it as One Link data; bytes look random

**Wire-format additions:** none.

**State migration:** schema v16 (or whatever the next sequential
version is). New OPFS layout:
```
/blobs/<hash-prefix>/<full-hash>          encrypted chunk content
/messages.idb                              encrypted message index
/peers.idb                                 encrypted peer record
/groups.idb                                encrypted group state
/_meta/version                             unencrypted version pin
```
The `_meta/version` is the only unencrypted file; everything else
is opaque to a forensic exfiltrator without the unlocked session.

**Test contract:** `tests/test_opfs_storage_v0160.py`
- Round-trip a 10MB blob through OPFS encrypted; decrypt; byte-equal
- IDB-stored message round-trip with AES-GCM
- Wrong passphrase → decryption fails; storage looks like noise
- Outer file headers do not identify content type (plausibly deniable)

**Defang shipped:** OPFS-stored identity, never OS keychain (defangs
iCloud / Google Password Manager). See `SOVEREIGNTY.md` § "OS keychain."
Plus: multi-source entropy mixing (defangs hardware RNG).

**Stdlib reuse:** `std/crypto/symmetric.cl::AES-GCM` reference impl
for verification; production calls Web Crypto `subtle.encrypt`. Plus
`std/crypto/kdf.cl::HKDF` for nonce derivation patterns.

---

## v0.17.0 — Threshold-of-N device bootstrap

**Frontier:** adding a new device to your identity requires consent
from at least 2 of your existing N devices via a P2P-only ceremony,
zero corporate substrate involvement. Lose a single device → identity
intact.

**Primitives:**
- Shamir Secret Sharing (or BLS threshold signatures) over the
  identity master secret. N=3 minimum (split into 3 shares; any 2
  reconstruct).
- Pairing ceremony: new device generates a Web Crypto keypair locally,
  broadcasts an enrollment request over P2P (LAN, BLE, or rendezvous)
  signed by zero existing shares; existing devices accept-or-reject;
  on 2+ accepts, devices each transmit their share to the new device,
  which combines them locally to derive the master.
- Master secret never leaves any device in clear. Each share is
  encrypted to the new device's public key during transmission.
- Optional Passkey integration (opt-in) for users who want
  iCloud / Google sync as a fallback recovery path; tier-gated.

**Wire-format additions:**
- New CAPS field `threshold_v1: true`
- New wire kind `THRESHOLD_ENROLL_REQUEST`,
  `THRESHOLD_ENROLL_GRANT`, `THRESHOLD_ENROLL_SHARE`
- Backward compatible: peers without `threshold_v1` use single-device
  identity (legacy).

**State migration:** v17 schema:
- `device_cluster.v1` IDB store
- `{device_id, ed_pub, x25519_pub, mlkem_pub, joined_ms,
   share_index, share_encrypted}`
- `cluster_threshold` setting: N (default 3), M (default 2)

**Test contract:** `tests/test_threshold_bootstrap_v0170.py`
- 3 devices generate cluster; 1 device added with 2 grants → identity
  reconstructs
- 1 grant → enrollment refused
- Lost device (revoked) → cluster reseals; lost device's share useless
- Cluster works over LAN-only (air-gap tier)

**Defang shipped:** threshold-of-N (defangs OS-keychain dependency
for cross-device identity). Lost-phone resilience is structural,
not corporate-recovery-dependent.

**Stdlib reuse:**
- `std/crypto/asymmetric.cl` for signature primitives
- `std/crdt/vector_clock.cl::IntervalTreeClock` for cluster
  membership churn (joining and leaving threshold devices)
- `std/identity/provenance.cl` patterns for device attestation chain

---

## v0.18.0 — WebRTC DataChannel transport (the biggest single ship)

**Frontier:** browser-to-browser direct P2P encrypted transport with
NAT traversal, sub-second handshake on LAN, sub-3-second handshake
across networks via STUN.

**Primitives:**
- `RTCPeerConnection` with our own ICE candidate handling
- Multi-vendor STUN list (6 orgs, rotated)
- DataChannel(s): 1 control channel (reliable, ordered) + 1 bulk
  channel (unreliable, unordered) for chunk traffic
- Signaling: project-hosted rendezvous OR manual QR-mode (zero servers)
- WebRTC's encryption (DTLS-SRTP) is the outer layer; our Double
  Ratchet (v0.7.2 primitive) is the inner layer. Defense in depth.

**Wire-format additions:**
- All existing wire kinds run identically over WebRTC DataChannel as
  they did over WebSocket; no protocol change. The DataChannel is
  framed-message; same JSON encoding (with binary FILE_BIN_CHUNK).
- New ICE-related kinds: `ICE_OFFER`, `ICE_ANSWER`, `ICE_CANDIDATE`
  (relay over signaling).

**State migration:** none persisted; live state only.

**Test contract:** `tests/test_webrtc_transport_v0180.py`
- LAN-only handshake completes in <1s p95
- Cross-network with STUN handshake completes in <3s p95
- Manual-QR signaling completes (no rendezvous touched)
- Same-LAN mode skips STUN entirely (verify no STUN packets sent)

**Defang shipped:** multi-vendor STUN (defangs single-STUN
observation); manual-QR mode (total elision). See `SOVEREIGNTY.md`.

**Stdlib reuse:** session-type patterns from
`std/session/binary/channel.cl` inform the DataChannel framing
abstraction (typed messages, in-order delivery contracts).

---

## v0.19.0 — WebTransport bulk path + adaptive transport selector

**Frontier:** large file transfers use HTTP/3 + QUIC's built-in
connection migration so a Wi-Fi → cellular → Wi-Fi handoff doesn't
drop the transfer. Adaptive selector picks the fastest live path
per peer per chunk.

**Primitives:**
- `WebTransport` API for HTTP/3 streams (iOS Safari 17.4+, Android
  Chrome 97+)
- Adaptive bandit (multi-armed bandit; ε-greedy with decay) over
  available paths per peer: BLE, LAN, WebRTC, WebTransport, relay
- Path quality: EWMA over recent throughput + recent failure rate
- Optional Web Push for "wake on incoming" (off by default)

**Wire-format additions:** `transport_caps` field in CAPS frame
advertising which paths the peer supports. Backward compatible.

**State migration:** new IDB store `path_stats.v1`:
`{peer_fp, path_kind, ewma_throughput_bps, ewma_failure_rate,
 last_used_ms, samples}`.

**Test contract:** `tests/test_webtransport_v0190.py`
- WebTransport handshake completes for browsers that support it
- Adaptive selector chooses fastest path on a synthetic 3-path
  test (LAN fast, WiFi slow, relay slowest)
- Path stats persist across restart
- Handoff: simulate Wi-Fi → cellular interface change; transfer
  resumes without restart

**Defang shipped:** Web Push optional (off by default). Encrypted
payloads + per-device rotating pseudonym.

**Stdlib reuse:**
- Adaptive bandit reuses patterns from `std/concurrent/async/scheduler.cl`
  task-priority semantics (architectural inspiration)

---

## v0.20.0 — BLE proximity + ultrasonic pairing

**Frontier:** "hold two phones close, both see each other and
offer to pair" — AirDrop-style on Android via Web Bluetooth; on iOS
fallback to QR + ultrasonic chirp pairing in <2s.

**Primitives:**
- Web Bluetooth API on Android Chrome (iOS blocks it; we detect)
- Ultrasonic data-over-audio: 18-22kHz inaudible carrier; transmits a
  16-byte pairing token. Implementation via `OfflineAudioContext`
  + DSP. ~50bps reliable.
- QR code: generated client-side via canvas, scanned via
  `BarcodeDetector` API where available, else manual photo + decode
- Pairing token is a one-time random 256-bit blob; expires in 60s
- Token bootstraps a WebRTC offer/answer exchange

**Wire-format additions:** none new; reuses ICE_OFFER/ANSWER from
v0.18.0.

**State migration:** none.

**Test contract:** `tests/test_proximity_pairing_v0200.py`
- Mock Web Bluetooth → pairing succeeds
- Ultrasonic encode/decode round-trip on synthetic audio
- QR encode/decode round-trip
- Token expires after 60s

**Defang shipped:** total elision of network for pairing — proximity
modes use no internet at all. Air-gap tier ready.

**Stdlib reuse:** `std/identity/anti_deception.cl` informs the
risk-model that decides whether SAS is required (BLE proximity =
low-risk, skip SAS by default; cold internet contact = high-risk,
demand SAS).

---

## v0.21.0 — MLS group ratchet (RFC 9420)

**Frontier:** properly forward-secret group chat at scale.
Replaces the v0.6.x sender-key scheme with deniable, post-compromise
secure, scalable group encryption.

**Primitives:**
- MLS protocol (RFC 9420) — TreeKEM, key rotation on every member
  add/remove, application messages encrypted with epoch keys
- Post-quantum hybrid: ML-KEM-768 + X25519 in the HPKE layer
- Reuse identity keys from v0.15.0+ (Ed25519 + X25519 + ML-KEM)

**Wire-format additions:**
- New CAPS field `mls_v1: true`
- New wire kinds: `MLS_WELCOME`, `MLS_COMMIT`, `MLS_PROPOSAL`,
  `MLS_APPLICATION`
- Backward compatible: peers without `mls_v1` fall back to v0.6.x
  sender-key for groups they share with such peers; new groups
  formed entirely among `mls_v1` peers use MLS.

**State migration:** v21 schema:
- `mls_groups.v1`: TreeKEM state, current epoch, member roster
- `mls_keys.v1`: pending key packages

**Test contract:** `tests/test_mls_group_v0210.py`
- 3-member group; commit; epoch advances; old keys can't decrypt
  new messages
- Member removal: removed member can't decrypt subsequent epoch
- Member rejoin: new key packages, new tree position
- Cross-version compat: an MLS group with all-MLS members works
  alongside legacy groups in the same UI

**Defang shipped:** post-quantum hybrid in the HPKE layer (defangs
harvest-now-decrypt-later future quantum threats).

**Stdlib reuse:**
- `std/crypto/kdf.cl::HKDF` for tree-key derivation
- `std/crypto/asymmetric.cl` for signatures
- `std/crypto/quantum_safe.cl` for ML-KEM if mature; else `@noble/post-quantum`
- `std/session/multiparty/` patterns for multiparty protocol structure

---

## v0.22.0 — Sealed sender + cover traffic

**Frontier:** even an adversary with full traffic visibility cannot
build a contact graph. Recipients can decrypt who a message is from;
nobody else can. Plus per-link cover traffic + mix-net hop routing
makes traffic timing/shape uninformative.

**Primitives:**
- Sealed sender (Signal-style): outer envelope identifies only the
  recipient; sender identity is in the encrypted-to-recipient inner
  envelope. The rendezvous and any observer see "someone sent peer
  X a message."
- Per-message random sender pseudonym for outer envelope so even
  the rendezvous can't link two messages as same-sender.
- Cover traffic: each peer emits dummy padded frames at a fixed
  Poisson rate (e.g., λ = 1/30s) when active. Real messages slot
  into the same shape.
- Mix-net cover routing (optional, hardened-tier default-on):
  messages route through 2-3 hops of volunteer peers; each hop
  sees only previous + next; payload onion-encrypted at each hop.

**Wire-format additions:**
- All messages now wrapped in sealed-sender envelope
- New wire kinds: `MIX_HOP` (relay frame for mix-net), `COVER_DUMMY`
  (indistinguishable from real)
- Backward compatible: peers without `sealed_sender_v1` cap fall
  back to plaintext-sender envelopes for messages between them.

**State migration:** v22 schema:
- `mix_volunteers.v1`: peers willing to relay (consent-gated)

**Test contract:** `tests/test_sealed_sender_v0220.py`
- A passive observer between rendezvous and recipient cannot
  determine the sender from the wire
- Cover traffic emits at Poisson rate when idle; real msgs slot in
- Mix-net 2-hop routing: hop A knows source + B, hop B knows A + dest;
  source identity not visible to hop B
- All messages padded to fixed sizes (256B, 1KB, 4KB, 16KB buckets)

**Defang shipped:** sealed sender + cover traffic + mix-net (defangs
rendezvous metadata; defangs traffic-shape analysis).

**Stdlib reuse:**
- `std/identity/anti_deception.cl` informs sender-pseudonym rotation
- `std/crdt/causality.cl::CausalDelivery` for in-order delivery
  through mix-net hops with reordering tolerance

---

## v0.23.0 — CRDT layer (Yjs/Automerge integration)

**Frontier:** every mergeable piece of state (messages, drafts,
group membership, settings, profile) is a CRDT. No "last write wins"
surprises across devices. Lazy sync via the Markov chain: pre-decode
the right history before the user taps.

**Primitives:**
- Yjs (chosen over Automerge for smaller wire size + more battle-tested
  in browsers) as the CRDT engine
- Layer our wire-protocol message format atop Yjs document updates
- HybridLogicalClock (port from `coherence_lang/std/crdt/causality.cl`)
  for cross-device causal ordering. Wall time is a hint; HLC is
  authoritative.
- Markov-chain prefetch (already shipped v0.14.0) extends to
  pre-fetch *the right CRDT subdoc* for the predicted next conversation

**Wire-format additions:**
- New CAPS field `crdt_v1: true`
- Yjs document updates carried in `CRDT_UPDATE` wire frames
- Backward compatible: legacy peers receive flattened
  individual messages.

**State migration:** v23 schema:
- `crdt_docs.v1`: per-conversation Yjs document state
- HLC fields added to existing `messages.v1` rows

**Test contract:** `tests/test_crdt_v0230.py`
- 3-device merge: each device offline-edits a different message; all
  merge converges to the same state without "winner" picking
- Group settings (color, archive, mute) merge across devices
- HLC ordering survives a 6-month-skewed device clock
- Prefetch hits the right Yjs subdoc on conversation switch

**Defang shipped:** HLC for ordering (defangs OS-clock dependency).

**Stdlib reuse:**
- `std/crdt/causality.cl::HybridLogicalClock` — direct port
- `std/crdt/merge.cl::MergeStrategy` traits — compose with Yjs
- `std/crdt/maps/LWWMap`, `std/crdt/maps/MVMap` — port for Yjs maps
- `std/crdt/sequences/RGA` — fallback alternative to Yjs sequences
  if we ever want to swap engines
- `std/crdt/sets/ORSet`, `std/crdt/sets/AWSet` — group membership

---

## v0.24.0 — On-device LLM (WebGPU + tiny model)

**Frontier:** smart features that other chat apps ship to the cloud
run entirely on-device. Semantic search, smart-reply suggestions,
thread summarization, harassment heuristics. Nothing leaves the device.

**Primitives:**
- WebGPU (Chrome 113+, Safari 18+, Firefox 121+ behind flag)
- Quantized small model: 1-3B parameters (e.g., Phi-3-mini-int4 or
  similar; ~1-2GB on disk; ~700MB RAM)
- Inference engine: `transformers.js` or `webllm` (open-source, no
  vendor)
- Runs in a Web Worker so it doesn't block the UI thread
- Battery + thermal monitoring: yields when device temp > 40°C or
  battery < 20%; falls back to keyword-only path

**Wire-format additions:** none (this is local).

**State migration:** OPFS layout extension:
- `/_models/<model-id>/` — model files, encrypted at rest

**Test contract:** `tests/test_on_device_llm_v0240.py`
- Model loads in <30s on a mid-tier 2022 device (initial download)
- Semantic search returns relevant results for a 100-msg test corpus
- Smart-reply suggestions are generated in <5s for an open conversation
- Battery threshold: simulate <20% battery → LLM yields, falls back
- WebGPU absence → smart features absent, no degraded experience

**Defang shipped:** total elision of cloud LLM dependency.

**Stdlib reuse:** none directly (Coherence stdlib doesn't have ML).

---

## v0.25.0 — Federated learning across user's devices

**Frontier:** the on-device LLM is fine-tuned on the user's actual
usage, but the training stays local. Updates propagate from your
phone to your laptop over the existing P2P link. Nobody's data
center sees a token.

**Primitives:**
- Federated Averaging (FedAvg) over the user's device cluster
- LoRA-style adapter weights (small; ~10MB per device per epoch)
- Updates wrapped in CRDT updates (using v0.23.0 layer)
- Threshold-quorum signed: model update is accepted across cluster
  only if signed by 2-of-N devices

**Wire-format additions:**
- New wire kind: `MODEL_UPDATE` (encrypted to cluster, signed by 2-of-N)

**State migration:**
- `model_state.v1` IDB store: per-device LoRA weights + version

**Test contract:** `tests/test_federated_learning_v0250.py`
- 3-device cluster: each device trains 1 epoch; weights average;
  resulting model performs >= individual device performance on
  held-out test set
- Single-device cluster: federated path silently disabled
- Compromised device: rejected updates (without 2-of-N signing)

**Defang shipped:** federated learning entirely on-device (defangs
cloud-training corporate dependency).

**Stdlib reuse:**
- `std/crypto/asymmetric.cl` for threshold signing
- `std/crdt/merge.cl::WeightedMerge` patterns for averaging logic
  (port the merge-strategy framework, not the specific weighted impl)

---

## v1.0.0 — One Link Web (the phone-only milestone)

**Frontier:** all 11 prior ships compose into a single coherent PWA
that a phone-only user can install, use, and rely on with zero
computer involvement and minimum corporate substrate exposure.

**Primitives:** none new; this ship is integration + paranoia-tier
selector + final polish + signed release.

**Wire-format additions:** none.

**State migration:** none.

**Test contract:** `tests/test_one_link_web_v1.py` — end-to-end
journey:
- Fresh phone, never installed: visit URL, install, set up identity,
  pair with a friend's phone via QR, send messages, receive messages,
  send a file, receive a file. All without a single tap on
  "Settings → Advanced."
- All three paranoia tiers selectable; all three behave per the
  matrix in `SOVEREIGNTY.md`.
- Reproducible build: clone source, build, hash matches signed release.

**Defang shipped:** v1.0.0 is the **complete defang ladder fully
deployed**:
- IPFS distribution + `.onion` mirror + signed `.html` archive
- OPFS-stored identity, no OS keychain by default
- Multi-vendor STUN + same-LAN mode + manual-QR mode
- Sealed sender + cover traffic + mix-net (hardened tier on)
- HLC for ordering
- Multi-source entropy
- Reproducible builds + SLSA-3 attestation
- Three paranoia tiers selectable in setup

This is the "no computer required, free of corporations by default,
just works" ship. The promise is met.

---

## v1.1+ — Native iOS / Android via Capacitor

**Frontier:** same code as the PWA, wrapped as a native app for
users who want App Store / Play Store discovery + push notifications
+ home-screen install via store. The web build remains the canonical;
the native wrappers add nothing but distribution.

**Primitives:**
- Capacitor 6+ for the native shell
- Same JS/CSS bundle that runs in the PWA
- Native plugins only for: BLE proximity (iOS), background sync
  refinement, FCM/APNS native push (still encrypted), local
  notifications

**Defang notes:** Capacitor wrappers DO go through App Store / Play
Store. Users on the air-gap or hardened tier should still install
via PWA. The native-app distribution exists as a Reach win, not a
Sovereignty win.

---

## Beyond v1.0.0 — long-term frontier items

These don't have a fixed slot but are tracked here so they're not
lost:

- **Decentralized rendezvous via DHT + gossip.** Replaces project-hosted
  rendezvous entirely. Connection requests route via consistent-hashing
  over the active peer set.
- **Verifiable revocation log per identity.** Append-only signed log
  of device revocations; gossiped across the user's contacts; checked
  on every key change.
- **Hardware attestation chain.** WebAuthn attestation extension
  proves the keypair was generated in a Secure Enclave / StrongBox.
- **Anonymous group membership via blind signatures.** Members prove
  membership without revealing which member.
- **Private set intersection for contact discovery.** "Which of my
  address book is on One Link?" answered cryptographically with no
  central server, no diff exposure.
- **Encrypted searchable indexes (SSE).** Full-text search over
  encrypted history without leaking queries.
- **Duress codes + decoy identity.** Optional second passphrase
  unlocks a parallel decoy identity. Plausible deniability under
  compulsion.
- **Constant-time everything.** Cryptographic ops in constant time
  + memory. No timing/cache side-channels.
- **Self-healing peer recovery.** Resync local state from another
  of your devices OR from a friend's copy of the public-side
  conversation, with cryptographic injection-detection.

Each of these can land as a v1.x or v2.x ship; they're noted for
continuity.

---

## Test ladder summary

Every ship has a regression test file. By v1.0.0 the suite includes:

```
tests/test_pwa_shell_v0150.py
tests/test_opfs_storage_v0160.py
tests/test_threshold_bootstrap_v0170.py
tests/test_webrtc_transport_v0180.py
tests/test_webtransport_v0190.py
tests/test_proximity_pairing_v0200.py
tests/test_mls_group_v0210.py
tests/test_sealed_sender_v0220.py
tests/test_crdt_v0230.py
tests/test_on_device_llm_v0240.py
tests/test_federated_learning_v0250.py
tests/test_one_link_web_v1.py        ← end-to-end + tier matrix
```

Plus continued ship-specific tests for the v0.14.x phone-tier
sequence (see `PHONE_TIER.md`).

---

## Ship-gate verification

Every ship in this document is gated by `PRINCIPLES.md` checklist.
Spot check that the v0.15.0 → v1.0.0 sequence answers all five for
each ship:

- **Reach** — every ship explicitly expands who can use One Link
  (more browsers, more network conditions, more paranoia levels).
- **Hide** — every ship adds zero user-facing technical knobs;
  the engine grows, the surface stays small.
- **Async** — every ship works when one side is offline, asleep,
  or moving.
- **Depth** — every ship has a measurable frontier + a regression
  test that pins the SLA.
- **Defang** — every ship cross-references at least one mitigation
  in `SOVEREIGNTY.md`.

A ship that fails any of the five gets pulled back to spec.

---

## Audit cadence

Per `PRINCIPLES.md`, every quarter:

1. Re-read this document. Has any ship slipped its frontier (e.g.,
   the SLA regressed)? File a ticket.
2. Re-check the stdlib reuse manifest. Has the Coherence stdlib
   evolved in ways that change reuse opportunities? Update.
3. Re-check the wire-format additions. Are old peers still
   gracefully degrading? Spot-check a v0.13.x peer interoperating
   with a v0.20.x peer.
4. Re-check the test ladder. Every ship's regression test still
   green? Tier matrix still passing all three tiers?

This document is the project's load-bearing technical plan from
v0.15.0 onward. Treat it as code: review it, edit it, keep it
current.
