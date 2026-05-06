# One Link Sovereign Network Blueprint

Status: in_progress — v0.3.0 shipped (audit hardening); v0.4 → v1.0
roadmap below.

One Link should feel simple enough for a non-technical person to use,
while becoming a real people-owned network layer. The product promise
is direct: no accounts, no mandatory company server, no telemetry, no
rent to keep talking to people you care about — anywhere on Earth.

---

## North Star

A free, sovereign, encrypted communication and file-sharing layer for
**people**, not platforms:

- One identity per device. Pair once, talk forever, anywhere.
- Pairing should feel like Bluetooth proximity but with cryptography
  so strong it survives the transition to quantum computing.
- Reachability is independent of trust. Take your laptop to Tokyo —
  it still talks to your home devices because the keys travel with it.
- Groups (family, friends, teams) work across continents with the same
  primitive that powers two-device LAN chat.
- Every byte on the wire is end-to-end encrypted. No relay anywhere in
  the path can read it. Operators of relays cannot be compelled to
  surrender what they don't have.
- The architecture survives losing every centralized service — DNS,
  certificate authorities, ISPs — by having never required them.

---

## Layer Separation (corrects the v0.3 conflation)

Three independent layers. Mixing them is the root cause of most bad
design in this space.

| Layer | Question it answers | Lives where |
|---|---|---|
| **Identity** | Who is this device, cryptographically? | Permanent Ed25519 keypair per device |
| **Trust** | Who am I willing to talk to? | A signed graph of pubkey ↔ pubkey edges |
| **Reachability** | How do I find this peer right now? | mDNS (LAN) → rendezvous (internet) → onion (high-sensitivity) |

**Identity is portable.** A device's key never changes. Take it
anywhere — its identity goes with it.

**Trust is portable.** Once paired, two devices stay paired across
continents until explicitly revoked. There is no concept of "you must
be on the same WiFi to keep chatting."

**Reachability is the layer we build out.** Everything One Link does
beyond mDNS-on-the-LAN lives here.

---

## Imported Concepts (OneField Mesh + coherence_lang)

Each item below is mapped to its OneField origin and the One Link
feature it enables.

### From OneField transport doctrine

| OneField primitive | One Link use |
|---|---|
| Content-defined chunking (CDC) | File / folder dedup (already shipped) |
| Merkle drift sync | Folder fast-path when roots match (already shipped) |
| Pluggable transports | LAN TCP today → QUIC, RF, audio, BLE, satellite tomorrow without changing identity / trust |
| Auto-regime classification (LOS / 1WALL / SUBNOISE / DEAD) | Per-peer link regime: `DIRECT_LAN / NAT_HOLEPUNCH / RELAYED / ONION / OFFLINE`. UI says *"friend is on a flaky hotel WiFi — using relay fallback"* instead of generic "connecting…" |
| τ_c coherence-time prior | Per-link coherence-time map drives retry / queue / transport-switch decisions; UI exposes link health as a live metric |
| τ_c-gradient MAC scheduler | Multiple One Link daemons in one household self-organize their TX timing; no thundering herds |

### From OneField crypto + ZK

| OneField primitive | One Link use |
|---|---|
| ZK provenance (Plonky3) | Sealed sender — relays see who's online, never who's talking to whom. Per-message origin proof without revealing the sending member's key |
| Constant-time crypto rails | Compile-time-checked invariant: every AEAD primitive runs in constant time, no timing side-channels |
| Information-theoretic model-as-key (capability #2) | Household-shared trained model becomes a quantum-resistant primitive: without the model, captured packets are unrecoverable noise. No PKI to migrate when quantum computers arrive |

### From OneField perception layer

| OneField primitive | One Link use |
|---|---|
| Multimodal Bayesian fusion (BioMesh pattern) | Environment-fingerprint pairing combining WiFi BSSIDs + BLE beacons + acoustic ambient + 60/120 Hz light flicker + mDNS service set + NAT/router fingerprint. Whatever the platform exposes, fuse what's available |
| ISAC — joint sensing on every exchange | Every chat / file transfer passively measures the link: round-trip jitter, retransmit ratio, MITM tells. Free anomaly detection |
| Holographic multi-receiver fusion | When a household has multiple paired devices, retransmission of a corrupted chat / file uses the *other devices* as additional receivers — `3·log₂(K)` dB SNR gain in TCP-equivalent terms (fewer dropped sends, faster recovery) |

### From OneField "alien-tier" voice/video

These are v1.0 frontiers — they require a trained shared model per
household. Listed here so the architecture below leaves room for
them rather than walling them out.

| OneField primitive | One Link use |
|---|---|
| Semantic-delta encoding (capability #5) | Don't transmit "Hey, dinner?" verbatim — transmit the delta from the conversation's current model state. With a shared household LLM, message bandwidth drops 100× – 10,000× |
| Predictive negative latency (capability #6) | Receiver UI ghosts likely-next messages before they arrive. When the delta lands, only the unpredicted bits update. Receiver runs *ahead of* the sender |
| Federated DP world-model refinement (capability #8) | Every message refines the household's shared model under (ε, δ)-differential privacy. The system gets smarter; no individual message is reconstructable |

### From coherence_lang

- Vector clocks for causal ordering (CRDT spine, already shipped).
- Capability thinking: explicit powers, no ambient authority (already
  shipped — per-peer capability policy + audit log).
- Compiler rails: extend the OneField doctrine — Z3-verified
  invariants enforced at build time. *"This code path can never
  reach the network without going through AEAD"*; *"this code can
  never log a private key"*; *"all incoming bytes pass through the
  rate-limiter."* This is the long-term path to making every bug
  class structurally impossible rather than tested-against.

---

## Roadmap

Each version is independently shippable. Each one earns its keep.

### v0.4 — Paired-only main view + discovery modal *(this week)*

Solves the "12 ghost devices in the sidebar" problem.

- Sidebar = paired devices only (online + offline, with status dot)
- "+ Pair a new device" button opens a modal; mDNS-discovered
  unpaired peers live *only* there
- Aggressive same-machine ghost collapsing (own-pubkey detection)
- Empty state for first-launch users says "Pair a device" with a
  large CTA
- `/api/peers` filters to paired-only by default; modal uses
  `?include_unpaired=1`

### v0.5 — Reachability beyond the LAN *(≈2 weeks)*

The unlock. Without this, One Link is a LAN toy regardless of how
good the crypto is. With it, your laptop at work talks to your home
devices.

- **Rendezvous nodes** (federated, stateless, no plaintext exposure):
  each device registers `(pubkey, current public IP:port, NAT type)`
  signed by its key
- **Endpoint discovery**: ask rendezvous "where is `home-pubkey`?" →
  get current address
- **NAT traversal ladder**:
  1. Direct UDP hole-punch (STUN-style) — works ~70% of residential NATs
  2. Encrypted TCP relay fallback — relay forwards bytes blindly,
     can't decrypt (E2E AEAD)
  3. Path quality reported to UI as *regime* (DIRECT / HOLEPUNCH /
     RELAYED) using the OneField auto-regime pattern
- **Sealed-sender envelope** — relays see *who is online*, never *who
  is talking to whom*. Destination pubkey encrypted to the relay's
  session key only as routing info; source pubkey encrypted to the
  destination only
- **Anti-abuse on relays**: per-pubkey rate limits + bytes-per-day
  cap + signed eviction events. No identity beyond the pubkey
- **Self-host story**: a $5/month box handles thousands of devices.
  Federation in v0.5.1: anyone can run a rendezvous; devices pick
  which to register with

### v0.6 — Groups *(≈1 week)*

Friends across the world. Family chat. Team rooms.

- A **group** is a CRDT of `(pubkey, role, added_at, added_by)`
  member entries
- Membership changes are signed events; CRDT tolerates concurrent
  admin changes (no central server arbitrating)
- Each member holds a **per-group sender key**, rotated automatically
  when membership changes (Signal "Sender Keys" pattern)
- Each message: signed by the sender's device key, encrypted under
  the current group sender key
- **Invite by one-time link** — signed, expiring, single-use. No
  phone numbers, no email, no central directory
- Same rendezvous + relay flow from v0.5; groups are just a
  membership semantic over the existing transport

### v0.7 — Signal-class crypto *(≈1 week)*

Forward secrecy + post-compromise security + safety numbers.

- **Double Ratchet** (Signal's design — public spec, MIT reference
  implementations exist). If a device is compromised today,
  yesterday's messages stay safe; tomorrow's recover safety once the
  next ratchet step happens
- **Hardware-backed keys** where the OS allows: Secure Enclave
  (Mac/iOS), TPM (Windows/Linux), WebAuthn (browsers). Private key
  never leaves the secure element even if the OS is rooted
- **Out-of-band safety-number alerts** — Signal-style. Contact's key
  changed (lost device, new install) → "Bob's safety number changed"
  before sending. Defends against silent key replacement by a
  compromised rendezvous
- **Per-folder / per-feature capability tokens** with expiry —
  extends the existing per-peer capability system into time-scoped
  delegations

### v0.8 — Hybrid post-quantum *(≈3 days)*

Today's traffic stays safe even if a quantum computer is built in
15 years.

- Hybrid X25519 + Kyber768 (NIST PQC, standardized 2024)
- libsodium and rustls both ship reference implementations
- Hybrid form means: classical attacks must break X25519 *and* PQ
  attacks must break Kyber768 — strictly stronger than either alone

### v0.9 — Multimodal environment-fingerprint pairing *(≈1 week)*

The zero-friction first-pair shortcut. **Not** a continuous
re-attestation; **not** an access-control mechanism. Just kills the
6-digit-SAS friction for co-located devices.

Multimodal Bayesian fusion of whichever signals the platform
exposes:

| Signal | Locked macOS | iOS Safari | Android Chrome | Linux |
|---|---|---|---|---|
| WiFi BSSID/RSSI | ✗ | ✗ | ✓ | ✓ |
| BLE beacon set | ✓ | partial | ✓ | ✓ |
| Acoustic ambient | ✓ (perm) | ✓ (perm) | ✓ (perm) | ✓ |
| 60/120 Hz light flicker | ✓ (perm) | ✓ (perm) | ✓ (perm) | ✓ |
| Magnetometer | n/a | ✓ | ✓ | n/a |
| mDNS service set | ✓ | ✓ | ✓ | ✓ |
| External IP + NAT TTL | ✓ | ✓ | ✓ | ✓ |

- ≥ 99.5% confidence → "Same room" badge, one-tap pair, no SAS
- 80–99% → derive 4-digit *environmental SAS* from the shared
  fingerprint; both devices show the same number; one-tap confirm
- < 80% → fall back to the v0.3 SAS / QR flow
- **ZK proof of shared environment** — fingerprint never leaves the
  device. Both sides prove "we share environment X with confidence
  Y" without revealing X (uses OneField's `zk_provenance` pattern)
- **Adversary-location signal**: if a device on the LAN has a
  fingerprint that *strongly diverges* from yours, UI says *"unknown
  device on your network — appears to be in a different room or
  outside the building."* Unprecedented in consumer software

### v1.0 — Alien-tier *(research; reserved)*

These are real and proven in OneField's lab; whether they ship in
One Link depends on whether household-scale trained-model training
becomes practical:

- **Semantic-delta chat** with a shared household language model.
  Compression scales as `1 / (1 - p)` where `p` is the model's
  prediction accuracy. At p=0.9999 the wire carries ~0 bits/message.
- **Predictive negative latency** — receiver UI runs ahead of the
  sender; OneField's `confirm_ratio()` lock at 98%
- **Federated (ε, δ)-DP refinement** — every message improves the
  shared model; no individual message is reconstructable
- **Information-theoretic security** — no PKI, no cert authorities,
  the trained model itself is the credential. Quantum-immune by
  construction (no algebraic structure for Shor / Grover to attack)

---

## Compiler Rails (long-term doctrine)

OneField has Z3-verified physical correctness rails: programs that
violate `tau.stability.cfl.v1`, `signal.nyquist.v1`, `em.maxwell_courant.v1`,
or `em.pml_thickness.v1` are rejected at build time with a
counterexample.

We extend this to **security correctness** for One Link:

- `net.aead.coverage.v1` — every byte that crosses the network
  boundary passes through AEAD. Bypass = compile error.
- `net.rate_limit.coverage.v1` — every inbound code path passes
  through the per-peer rate limiter.
- `secret.no_log.v1` — private keys, ratchet state, and PSKs are
  marked `Secret[T]`; logging or stringifying a `Secret[T]` is a
  type error.
- `auth.gate.v1` — every state-mutating handler runs
  `_inbound_is_rejected` first.
- `cap.honor.v1` — every feature path checks the per-peer
  capability policy before acting.

The audit findings from May 5 (C1, H1–H4, M1–M2, M5–M7) become
*compile-time invariants* rather than tests-only assertions — the
post-v0.3 hardening becomes structurally impossible to regress.

---

## Anti-Vendor Pledges

These are commitments the architecture makes possible and that the
project will hold to:

- **No accounts.** Identity is a key on a device, not a row in our
  database. We don't have a database.
- **No mandatory relay operator.** A user can self-host or pick a
  federation; the protocol is symmetric, no operator has special
  capability.
- **No telemetry.** The audit endpoint enumerates every outbound
  destination; users can verify zero phone-home traffic against
  the registered destination set.
- **No data lock-in.** All state (sqlite + blob store) is on the
  user's disk in documented schemas. Migration to another client is
  a copy.
- **All-source-everything.** No proprietary modules; every audit
  rail, every primitive, every capability is in the repo and
  reviewable.
- **Zero-cost path.** A LAN-only / household-only deployment never
  needs a paid relay or third-party service; v0.4 already meets this.

---

## Current Active Foundation (v0.3.0 — commit 089a335)

- Ed25519 device identity + fingerprint
- X25519 + ChaCha20-Poly1305 encrypted sessions
- mDNS LAN discovery
- Local-only token-gated UI
- BLAKE3 content-addressed file store
- Vector-clock manifest merge primitives
- Single-instance daemon lock (with PID liveness check, M5)
- Per-IP handshake throttle + handshake deadline (H3)
- Outbound session liveness probe (H4)
- Capability audit log + endpoint (H1)
- Per-peer capability policy
- Content-defined chunking + Merkle drift sync
- Adaptive compression on CDC chunks
- Persistent transfer ledger with live WebSocket updates
- Mesh operations console + status API
- Benchmark gate (`scripts/bench_transfer_primitives.py`)
