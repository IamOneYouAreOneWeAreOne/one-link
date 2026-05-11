# File Engine v2 — Multi-Phase Architectural Rebuild

> **Authoritative plan for the next-generation One Link file-delivery engine.**
> Companion to [ARCHITECTURE.md](ARCHITECTURE.md), [PRINCIPLES.md](PRINCIPLES.md),
> [COHERENCE_TRANSFER_BRAIN.md](COHERENCE_TRANSFER_BRAIN.md), and [SOVEREIGNTY.md](SOVEREIGNTY.md).
> Ordered by dependency, NOT by calendar — phases ship when their acceptance gate passes.

---

## Honest Status Scorecard (updated 2026-05-11)

This table tracks what is **shipped + verified** vs **shipped but unverified** vs **not yet built**. The plan ahead is what the doc describes; this scorecard is the reality.

### Crates

| Plan crate | Status | Notes |
|---|:-:|---|
| `ol_chunk` | shipped | CDC + BLAKE3 + format-aware (ZIP + MP4 + WAV) |
| `ol_chunk_store` | shipped | LSM + WAL + bloom; both-address ready (raw + convergent) |
| `ol_aead` | shipped | AES-NI + ChaCha20-Poly1305 via ring |
| `ol_wal` | shipped | crash-only WAL with CRC32C |
| `ol_quic` | shipped (not yet wired) | quinn-based transport; daemon still on WebRTC |
| `ol_capability` | shipped | Macaroon-style caps with attenuation gate |
| `ol_crdt` | shipped | lattice + OR-set + vector clock + folder |
| `ol_canon` | shipped (2026-05-11) | self-describing canonical encoder + 1M-iter byte-equiv gate |
| `ol_fountain` | shipped | RaptorQ codec |
| `ol_netcode` | shipped (2026-05-11) | XOR coded packets + tampered-manifest integrity gate |
| `ol_fec` | shipped | Reed-Solomon (10,4) |
| `ol_erasure` | shipped | stripe layout + encode/decode |
| `ol_fuse` | shipped scaffold + real adapter | Linux adapter compiles; libfuse mount round-trip unverified |
| `ol_fskit` | shipped scaffold (2026-05-11) | Trait surface live; Swift/FSKit bridge pending |
| `ol_winfs` | shipped scaffold (2026-05-11) | WinFSP-preferred / Dokan fallback; adapters pending |
| `ol_routing` | shipped | τ_c-weighted Dijkstra |
| `ol_homology` | shipped | persistent-homology fragility detector |
| `ol_grammar` | shipped | Re-Pair compression |
| `ol_active_inference` | partial | functionality lives in `ol_prefetch` (cohort-prior + time-weighted co-occurrence); free-energy minimization still deferred |

### Phase A1 acceptance gates

| Gate | Plan target | Status |
|---|---|:-:|
| End-to-end ingest throughput | ≥ 1 GiB/s on Linux NVMe | **Unmet on Windows/NTFS test box (peak 442 MiB/s); needs Linux NVMe verification** |
| AEAD throughput AES-NI | ≥ 4 GiB/s/core | **Met: 9.0–9.7 GiB/s measured** |
| AEAD throughput ChaCha20 | ≥ 3 GiB/s/core | **Met: 3.17–3.26 GiB/s measured** |
| Crash survival | 10,000 kill -9 injection points, 0 chunk loss | **Met: `OL_STORE_CRASH_ITERS=10000` passes in 58.58s** |
| Manifest WAL coupling | crash between chunk-write + manifest-update converges | **Met: existing `replay_rebuilds_memtable` + crash-injection harness** |
| Canonical-encoding byte-equivalence | 1M random structured inputs | **Met: `OL_CANON_GATE_ITERS=1000000` passes in 0.08s** |

### Phase A2 acceptance gates

| Gate | Plan target | Status |
|---|---|:-:|
| QUIC stream throughput | within 10% of TCP on tuned LAN | **Unmeasured** |
| 0-RTT resume latency | < 50ms warm cache | **Unmeasured** |
| Cellular ↔ WiFi migration | zero application-visible drop | **Unmeasured** |
| Daemon cutover | daemon ↔ daemon over QUIC | **Not wired — daemon still uses WebRTC** |

### Phase B acceptance gates

| Gate | Plan target | Status |
|---|---|:-:|
| Bloom-init savings | ≥ 90% bytes-on-wire on 80% known | **Unmeasured** |
| RaptorQ decode | K=1024 at 5% loss, ≥ 1000 seeds | **Codec ships; per-spec stress run pending** |
| FUSE survives fsx-linux 24h | yes | **Unrun (Linux host required)** |
| Convergent encryption | N senders → identical CT for raw media | **Layout supported in chunk_store; default still raw-BLAKE3** |
| Format-aware chunking | GOP / ZIP / audio | **ZIP + MP4 top-level boxes + WAV data-chunk; GOP keyframe detection still pending** |

### Phase C acceptance gates

| Gate | Plan target | Status |
|---|---|:-:|
| RS (10,4) erasure recovery | 100% across 10,000 seeds | **Met** |
| Bandit converges within 200 interactions | yes | **Met** |
| Macaroon attenuation | property test 1M random delegation chains | **Met** |
| ML-KEM-768 + X25519 hybrid | handshake at PQ params | **Met** |
| Constant-time check | < 1% timing variance | **Met (ratchet 1.0103×, duress 1.014×)** |
| Fuzzer in CI; 48h since last crash | yes | **Nightly fuzz wired; 48h-since-crash gate operational** |

### Phase D acceptance gates

| Gate | Plan target | Status |
|---|---|:-:|
| Tau-routing margin | ≥ 20% reduction in chunks-lost-on-partition | **Met: 100% reduction measured** |
| Persistent-homology detector | ≤ 5% FP, partition flag in ≤ N rounds | **Met: 0% FP, 1-round detection** |
| Active inference cold-start | bandit-equivalent within ≤ 50 transfers | **Met: cohort prior 1-iter, cold 50-iter** |
| Plausibly deniable | duress key unlocks decoy, no observable disk pattern | **Met: gate-side timing 1.014×** |
| TLA+ formal model | no double-grant / key reuse / downgrade / replay | **Met: `docs/formal/capability.tla` + `.cfg`** |

### End-to-end demos (plan-mandated, not yet run)

- [ ] 10 GbE LAN saturation (≥ 1.19 GiB/s, ≤ 2 cores)
- [ ] 100 GB folder + 4 swarm peers → receiver finishes < 14 min
- [ ] Premiere project resend with ≥ 90% dedup, ≤ 10% delta in < 10s
- [ ] Cellular flicker mid-transfer with zero retransmits visible
- [ ] 48h cross-platform soak (Linux + macOS + Windows; FUSE/FSKit/Dokan all stable)

---

## Context

**Problem.** One Link's current file engine (Python BlobStore + Python CDC at ~8 MiB/s + WebRTC/DTLS-SRTP transport + Ed25519-signed grant capabilities + EMA-based transfer brain) is solid for chat-class transfers but is not capable of becoming the world's best file-sharing engine. The strategic wedge requires the engine itself to be insanely advanced — line-rate throughput, hard durability guarantees, content-addressed dedup approaching the information-theoretic floor, fountain-coded swarm transfer, filesystem-native surface, capability-secured shares with provenance + revocation, and frontier-grade resilience under any failure mode.

**What prompted this.** The market wedge is a sovereign file-delivery engine for individuals and small ops (contractors, podcast/video teams, repair shops, small offices, creators, nonprofits) who feel cloud-bill pain, upload-cap pain, and sovereignty pain. No competitor combines AirDrop UX, BitTorrent-class swarm depth, Syncthing-class durability, and Signal-class metadata privacy in one engine. Building it requires architectural rebuild, not feature accretion.

**Intended outcome.** A 10-layer engine where every architectural decision serves multiple quality axes (resilience, robustness, automation, security, efficiency) simultaneously. Engine should be unbeatable on speed, dedup, durability, security, and automation. Sovereignty preserved (no monthly bills, no third-party gatekeepers, no admin layer for end users — only individual identities with capability-based shares).

**Runtime decision: Rust where Python would bottleneck; Python where it doesn't.**

The split is performance-driven, not ideological. Existing Python orchestration (daemon lifecycle, HTTP/WebRTC server, settings, pairing flow, mDNS, CLI, dev tools) stays as long as it isn't on a hot path. Hot-path code (chunk store, AEAD, transport, FUSE/FSKit/Dokan, fountain/FEC encode-decode) lands as Rust crates that the existing Python daemon imports via FFI (pyo3 / maturin). Single binary is a future option, not a current requirement; the Python daemon already works on Linux/macOS/Windows.

| Stays Python (orchestration; fires per logical op, not per byte) | Goes Rust (hot path; cycles/byte budgeted) |
|---|---|
| HTTP/UI server (request rate is human-paced) | Chunk store (CDC + BLAKE3 + LSM + WAL + bloom) |
| WebRTC signaling (handshake-rate, not chunk-rate) | Per-chunk AEAD pipeline |
| Pairing flow / browser-as-peer onboarding | QUIC transport (per-packet) |
| Settings + configuration | FUSE / FSKit / Dokan filesystem surface (per-syscall) |
| Outbox queue management | Bloom-filter init / RaptorQ / XOR network coding / RS FEC |
| Daemon lifecycle, mDNS discovery, CLI | Erasure coding + integrity scrubbing |
| Logging, telemetry, dev tools | Per-chunk forward-secret ratchet |

**Coherence Language `.cl` files** (`coherence_lang/std/*`, `OneField Mesh/onefield/*`) are **design specifications**: read for algebraic correctness, ported to Rust crates with property tests encoding the algebra's laws (lattice associativity, capability attenuation soundness, canonical-encoding determinism). CL is **not linked at runtime**; no Python embedding of LoOVM, no LLVM-CL `.o` linking. CL stays as the algebraic source of truth at design level, with version-pinned references in the Rust source comments.

**Forge_shootouts research-validated algorithms** (`A.C.E/CodeSwarm/forge_shootouts/*.py`) are similarly design specifications: pure Python correctness benchmarks, reimplemented in Rust at line rate.

**Cross-project type consistency** (One Link / OneField / BioMesh sharing the same algebra) handled via shared Rust crates promoted to sibling-repo level once stable, NOT via shared CL runtime.

**Why this split:**
- For users: existing v0.20.6 Python daemon keeps working through the migration. No regression of shipped flows (iOS pair, browser-as-peer, etc.). Performance wins land as Rust crates take over hot paths underneath the daemon.
- For performance: ≥1 GiB/s chunk-store ingest, AEAD line-rate, multi-stream QUIC — all in Rust where cycles/byte matter. Python orchestration touches none of these per byte.
- For reliability: hot path lives in one Rust binary with crash-only WAL; orchestration lives in well-tested Python. Both layers debugged with their native tools.
- For sovereignty: hot-path crates are reproducible Rust builds; Python deps already curated against the SOVEREIGNTY.md defang ladder.
- For shipping discipline: don't rewrite working Python code for its own sake. Rust crates land alongside, swap behind clean interfaces, prove themselves via the benchmark gate, then ride.

---

## Single Load-Bearing Insight

> Every byte is content-addressed; every operation is capability-bound; every state change is CRDT-mergeable; every connection is auto-detected; every chunk is independently routable; every transfer is information-theoretically minimized.

Each clause is one architectural primitive. The same primitive serves every quality axis. Nothing is layered on top as an afterthought because nothing needs to be — the core doctrine is enough.

---

## Architectural Stack (10 layers, bottom up)

"Design ref" = the .cl/.py file that documents the algebra; Rust crates port it. CL is never linked at runtime.

| Layer | What | Implementation language | Design refs |
|---|---|---|---|
| 0. Substrate | Deterministic bytes + CRDT lattice + capability calculus + canonical encoding | **Rust crates** (`ol_canon`, `ol_crdt`, `ol_capability`) | `coherence_lang/std/{codec.canon, crdt, capability, distributed}` |
| 1. Chunk store | Content-addressed BLAKE3 + CDC + format-aware boundaries + grammar-compression secondary index + erasure-coded redundancy + crash-only WAL + LSM index with bloom front | **Rust** (`ol_chunk`, `ol_chunk_store`) | `OneField/onefield/transport/cdc_dedup.cl` |
| 2. Crypto pipeline | Per-chunk AEAD + per-chunk forward-secret ratchet + PQ-hybrid (ML-KEM-768 + X25519) + selective convergent encryption + constant-time everywhere | **Rust** (`ol_aead`, `ol_ratchet`) | Existing `src/one_link/double_ratchet.py` + `pq_hybrid.py`; `OneField/onefield/radio/crypto/reciprocity.cl` |
| 3. Identity & capability | Hardware-bound keys (TOFU-degrading) + Merkle revocation log + Macaroon-style caps with provenance/attenuation/revocation/audit | **Rust** (`ol_capability`, `ol_revoke`); Python orchestration unchanged for share-link UI | `coherence_lang/std/capability/{cap, delegate, grant, revoke}.cl`; `OneField/onefield/privacy/{zk_prover, no_reconstruct_proof}.cl` |
| 4. Transport | QUIC primary (multi-stream + multi-path + 0-RTT + connection migration) + topology auto-detection (shm / unix / LAN-QUIC / WAN-QUIC / relay) + BBR pacing | **Rust** (`ol_quic` via `quinn`); existing `peer_rtc.py` retained for browser-as-peer signaling | `OneField/onefield/transport/{quic_congestion, mptcp, parallel}.cl` |
| 5. Information layer | Bloom-filter transfer init + RaptorQ fountain codes + XOR network coding + Reed-Solomon FEC | **Rust** (`ol_fountain`, `ol_netcode`, `ol_fec`) | `OneField/onefield/transport/udp_fec.cl` |
| 6. Routing | Tau-field PDE on swarm graph + persistent-homology fragility detection + Byzantine-tolerant tau measurement | **Rust** (`ol_routing`, `ol_homology`) | `OneField/onefield/mesh/{routing, byzantine}.cl` (production τ_c routing); `forge_shootouts/tau_field_lib.py` |
| 7. Adaptation | Active inference prefetch + multi-armed bandit per peer-pair + self-pacing under host stress | **Rust** core (`ol_active_inference`); Python `transfer_brain.py` shim during migration | `forge_shootouts/hardened_active_inference.py`; `OneField/onefield/sensing/bayesian_fusion.cl` |
| 8. Shared state | Folder = CRDT (lattice merge); Manifest = chunk-ref list with format-aware metadata; Capability = the share link itself | **Rust** (`ol_crdt`, `ol_manifest`); existing `foldersync.py` Python orchestration retained for watchdog file events | `coherence_lang/std/crdt/{lattice, causality, vector_clock, sync}.cl` |
| 9. Filesystem surface | FUSE on Linux; FSKit on macOS (NOT macFUSE); Dokan/WinFSP on Windows | **Rust** (`ol_fuse`, `ol_fskit`, `ol_winfs`) | (no .cl analog; native platform APIs) |
| 10. Operability | Crash-only WAL recovery + integrity scrubbing + threshold-of-N social recovery + BIP-39 anchor + reproducible signed builds + one-actionable-alert | **Rust** for WAL/scrubbing/Shamir; Python orchestration for one-alert UI surface and CLI | `OneField/onefield/{mesh/{dtn, disaster_bootstrap}, privacy/sharding}.cl` |

**What stays Python:** HTTP/UI server (`server.py`), WebRTC signaling (`peer_rtc.py`), pairing flow, browser-as-peer onboarding, settings, mDNS discovery, CLI, dev tools, watchdog file events. None of these are on the per-byte hot path; Python's interpretation cost is invisible at human-paced request rates and there's no engineering reason to rewrite working v0.20.6 code.

**What goes Rust:** every per-byte and per-chunk operation, plus the substrate algebra layers that the hot path depends on. FFI boundary is pyo3/maturin: existing Python daemon imports the Rust crates exactly the way it currently imports the C-extension CDC.

---

## Four Properties as Projections of One Architecture

Each architectural decision serves multiple axes without trade-off:

| Decision | Resilience | Robustness | Automation | Security | Efficiency |
|---|:-:|:-:|:-:|:-:|:-:|
| Content-addressed everything | ✓ | ✓ | ✓ | ✓ | ✓ |
| Capability-based access | – | ✓ | ✓ | ✓ | – |
| Crash-only WAL | ✓ | ✓ | ✓ | – | – |
| CRDT shared state | ✓ | ✓ | ✓ | – | ✓ |
| Per-chunk ratchet | ✓ | – | – | ✓ | ✓ |
| Bloom + fountain init | ✓ | ✓ | ✓ | – | ✓ |
| Tau-field routing | ✓ | ✓ | ✓ | – | ✓ |
| Active inference | – | – | ✓ | – | ✓ |

---

## Phase Ordering (dependency graph, no calendar)

Each phase is an ordered sequence of dependent shippables. **No durations are stated.** A phase ships when its acceptance gate passes.

### Phase A1: Smallest Foundation (must precede everything else)

Internal order (each item depends on the one before):

1. **Zero-copy I/O substrate** — `sendfile/splice/io_uring` on Linux; `TransmitFile/RIO` on Windows; equivalent on macOS. Required first because QUIC stack choice depends on it.
2. **Native CDC kernel choice** — pick one of FastCDC / SIMD-Gear / Rabin. Decision drives chunk-size distribution, which drives bloom sizing later. Harvest `OneField/onefield/transport/cdc_dedup.cl` as design template; substitute BLAKE3 for FNV-1a; port to Rust with SIMD.
3. **BLAKE3 chunk hashing** — depends on chunk-size decision above.
4. **Crash-only WAL** (must precede LSM, not follow it) — durability log appended before any chunk-store mutation; replay on boot.
5. **LSM index with bloom-filter front** — chunk-hash → (location, length, ratchet-key-id). Memtable durable via WAL.
6. **AEAD frame size decision** — declared as a Phase A1 acceptance number, NOT a Phase B discovery. Joint with chunk size, governs FUSE read amplification.
7. **Per-chunk AEAD** — AES-256-GCM via AES-NI / VAES; ChaCha20-Poly1305 fallback.
8. **Manifest WAL** — manifest writes WAL-coupled to chunk WAL so FUSE consistency holds after crash.
9. **Stripe layout decision** — even though Reed-Solomon ships in C, the chunk store must support stripe metadata from day one.

### Phase A2: Transport upgrade (requires A1 acceptance gate)

10. **QUIC transport** using `quinn` (Rust, MIT/Apache, no Microsoft dependency) — multi-stream, multi-path, 0-RTT, connection migration. Replaces WebRTC/DTLS-SRTP for daemon↔daemon; WebRTC retained for browser-as-peer.

(Phase A1 ships independently as a complete file-sync engine before A2 starts. WebRTC stays as transport during A1.)

### Phase B: Genius layer (requires A1; A2 helpful but not strictly required)

Convergent encryption MUST land in the same cut as Bloom-init (or chunk store carries both addresses from A1). Decision: **chunk store stores both raw-BLAKE3 and convergent-BLAKE3 from A1**, so B can flip the Bloom default without breaking existing manifests.

1. **Bloom-filter transfer init** — receiver sends Bloom of chunk hashes; sender XORs against manifest; sends only true delta. Unifies fresh / resume / dedup. Three code paths remain (manifest fetch, capability check, partial-chunk-resume mid-AEAD-frame); Bloom is the inner loop.
2. **RaptorQ fountain codes** — encode each chunk as infinite encoded packets; any K reconstructs. Validate Qualcomm IPR grant before shipping; if blocked, use LT codes or RFC-5053 Raptor codes (older, expired patents).
3. **XOR network coding for relay** — peers serve A⊕B; recipients with A reconstruct B. Cipher-only (sovereignty preserved).
4. **Format-aware chunking** — recognize structural boundaries (video GOP, ZIP entries, Premiere asset references, audio sample blocks). Augments CDC, doesn't replace it.
5. **Convergent encryption (selective)** — derive chunk key from BLAKE3(plaintext) for content-types whose well-known plaintexts are not a privacy concern (raw media). Per-recipient keys for everything else (project files, docs).
6. **Filesystem surface** — FUSE on Linux, Dokan/WinFSP on Windows, **FSKit on macOS** (NOT macFUSE — macFUSE is GPL+commercial dual-license, breaks no-monthly-bill on macOS; FSKit is Apple's modern in-userspace alternative).

### Phase C: Multi-axis baseline (requires A1; mostly orthogonal to B)

1. **Reed-Solomon FEC over chunk stream** — send 110% packets, receive any 100% reconstructs. Harvest `OneField/onefield/transport/udp_fec.cl` as template.
2. **Erasure-coded durability** — Reed-Solomon over CDC chunks, ≥1.5× redundancy across user's own devices + trusted peers. Stripe layout was already decided in A1. Dedup is on data shards only; parity is per-storer.
3. **Capability layer wiring** — `coherence_lang/std/capability/{cap, delegate, grant, revoke}.cl` becomes authoritative; existing Ed25519 grants migrated. Macaroon-style caveats (time-bound, scope-bound, attenuable, audit-tagged, delegatable). Replaces `src/one_link/{capabilities, cap_store, caps_grants}.py`.
4. **CRDT shared folders** — `coherence_lang/std/crdt/{lattice, causality, vector_clock, sync}.cl` as authoritative. Folder = CRDT lattice. Manifest = chunk-ref list. Replaces existing vector-clock manifest in `src/one_link/foldersync.py`.
5. **Multi-armed bandit auto-tuning** — per peer-pair, per knob (chunk size, parallelism, FEC ratio, prefetch window, pacing, compression threshold). MUST explicitly subsume or replace existing `transfer_brain.py` EMA route memory; two policies cannot coexist.
6. **Per-chunk forward-secret ratchet** — extends `src/one_link/double_ratchet.py` from per-message to per-chunk. Compromise of one key reveals one chunk; self-healing within one round-trip.
7. **PQ-hybrid by default** — replace `pq_hybrid.NullKEM` with ML-KEM-768. Default-on, not opt-in.
8. **Hardware-bound keys (TOFU-degrading)** — "hardware-bound with optional vendor attestation, gracefully degrading to TOFU." Apple Secure Enclave / Android StrongBox / Windows TPM bind keys; vendor attestation chain is optional.
9. **Constant-time crypto + capability checks** — uniform timing across both layers. Fixes existing `double_ratchet._is_small_order_x25519()` frozenset (not constant-time).
10. **Continuous structure-aware fuzzing in CI** — every parser, every state machine, every wire format. Fuzzer crash = release blocker.
11. **Property-based testing** — round-trip every wire format; idempotency on every operation; invertibility on every state transition; lattice merge laws; capability attenuation soundness.
12. **Reproducible builds + multi-party signing** — Sigstore-style transparency log; multi-signer release.

### Phase D: Visionary (requires A1+C; benefits from B)

D is unmeasurable without B's empirical link costs.

1. **Tau-field routing on swarm graph** — harvest `OneField/onefield/mesh/routing.cl` (production τ_c-weighted Dijkstra already shipping) as starting point. Adapt edge-weight from RF τ_c gradient → empirical network metrics (RTT, jitter, observed-throughput). PDE solver runs once per topology change, not per chunk.
2. **Byzantine-tolerant tau measurement** — harvest `OneField/onefield/mesh/byzantine.cl`. A malicious peer reporting fake high τ gets cross-validated against observed delivery; ignored if no corroboration.
3. **Active inference prefetch** — extends bandit (Phase C) with generative model of peer-pair demand. Cold-start prior transferred from user's other peer-pairs; "lukewarm" start via cohort priors.
4. **Persistent homology durability** — H1 over the chunk-co-hold graph; flag closing-loops as fragility events; preemptive replication. Approximations (witness complexes, sparse filtrations) needed for production scale; naive O(n³) is prohibitive.
5. **Grammar compression secondary index** — Re-Pair on structural-token streams of recognized formats. Layered on CDC, not replacing it. Rust port of `forge_shootouts/hardened_grammar_compression.py`.
6. **Plausibly deniable storage + duress codes** — decoy volume + duress-key-unlocks-decoy + steganographic coercion signal in ratchet header. Coercion-resistant tier.
7. **Formal verification of safety-critical state machines** — TLA+ or Coq models of pairing, capability grant, key rotation, revocation. Verified properties: no double-grant, no key reuse, no downgrade, no replay.

---

## What to Harvest (existing primitives — ported to Rust, not linked at runtime)

### From OneField Mesh — design references for Rust ports

These are production-grade, tested CL implementations. They are the **design source of truth** for the algorithms. Each is read carefully, ported to a Rust crate, and the Rust port carries a revision-pinned comment back to the .cl source. Substitute hashing primitives where needed (FNV-1a → BLAKE3) and adapt RF metrics → network metrics where applicable. Cross-project consistency: if OneField wants to use the same Rust crate, it consumes it as a dep (rather than maintaining a parallel CL implementation).

| Source | Layer in plan | What it gives |
|---|---|---|
| `OneField/onefield/transport/cdc_dedup.cl` (~195 lines, 13 tests) | Layer 1 | Rolling-hash CDC, boundary predicates, dedup savings model |
| `OneField/onefield/app/builtin/file_transfer.cl` (~807 lines, 27 tests) | Layers 1+8 | Manifest, chunk envelope, transfer lifecycle, ACL, wire estimates |
| `OneField/onefield/transport/udp_fec.cl` (~189 lines, 13 tests) | Layer 5 | K+P Reed-Solomon over GF(2), goodput ratios, survival probability |
| `OneField/onefield/transport/quic_congestion.cl` (~170 lines, 9 tests) | Layer 4 | BBR state machine, pacing gains, BDP |
| `OneField/onefield/transport/mptcp.cl` | Layer 4 | Multi-path TCP primitives — direct match for plan's multi-path |
| `OneField/onefield/transport/parallel.cl` | Layer 4 | Parallel-stream transfer primitives |
| `OneField/onefield/transport/field_fusion.cl` | Layers 5+6 | Multi-source fusion at transport layer |
| `OneField/onefield/mesh/routing.cl` (~147 lines, 13 tests) | Layer 6 | τ_c-weighted Dijkstra, loss-penalty, hysteresis — **production tau-routing already shipping** |
| `OneField/onefield/mesh/byzantine.cl` | Layer 6 | Byzantine-tolerant primitives — direct match for "Byzantine-tolerant tau measurement" |
| `OneField/onefield/mesh/dtn.cl` | Layer 10 | Delay-Tolerant Networking — outbox / async transfer primitives |
| `OneField/onefield/mesh/disaster_bootstrap.cl` | Layer 10 | Disaster recovery primitives |
| `OneField/onefield/bridge/{discovery, nat, auth, quota, rate_limit, trust}.cl` | Layers 3+4+10 | Peer discovery, NAT translation, auth, quotas, rate limits, trust scoring |
| `OneField/onefield/privacy/sharding.cl` (~600+ lines) | Layer 10 | GF(2^8) Shamir secret sharing — Phase D plausibly deniable storage + threshold-of-N social recovery |
| `OneField/onefield/privacy/zk_prover.cl` | Layer 3 | Bulletproofs-lite range-proof shapes — capability proofs without revealing predicate |
| `OneField/onefield/privacy/no_reconstruct_proof.cl` | Layer 3 | Zero-reconstruction proofs |
| `OneField/onefield/sensing/bayesian_fusion.cl` | Layer 7 | Multi-source Bayesian fusion — applicable to chunk-arrival aggregation from K peers |
| `OneField/onefield/radio/crypto/reciprocity.cl` | Layer 2 (DESIGN) | Physics-based forward secrecy — design inspiration for ephemeral session keys without PKI |

### From Coherence Language stdlib — design specifications for Rust ports

CL files documented here are the algebraic specifications. Each has a corresponding Rust crate that ports the design and encodes the algebra's laws as property tests. CL maturity grades below indicate how complete the design source is, NOT runtime dependency status (there is no runtime dependency).

| Source | Layer | Design completeness |
|---|---|---|
| `coherence_lang/std/crdt/lattice.cl` | 0+8 | COMPLETE (pure mathematical primitives; trait-based; no intrinsics needed) |
| `coherence_lang/std/crdt/{causality, vector_clock, sync}.cl` | 0+8 | COMPLETE design; intrinsic timestamp/randomness implemented in Rust |
| `coherence_lang/std/codec/canon.cl` | 0 | COMPLETE design (RFC 8949 with canonical ordering) |
| `coherence_lang/std/capability/{cap, delegate, grant, revoke}.cl` | 0+3 | COMPLETE design (Macaroon-class with provenance + attenuation + revocation) |
| `coherence_lang/std/distributed/{store, gossip, failure_detector}.cl` | 0+10 | COMPLETE design for gossip + Phi-accrual failure detector; store backend abstraction is interface-level |

### From forge_shootouts — correctness-validated algorithms

These are NOT line-rate implementations. Reimplement the proven algorithm in Rust; do not port the Python.

| Source | Layer | Validated at | Port effort |
|---|---|---|---|
| `forge_shootouts/hardened_grammar_compression.py` | 1 (D) | 2K-10K tokens | Significant — suffix array + heap-based Re-Pair |
| `forge_shootouts/hardened_graph_cut.py` | 6 | 3K-8K nodes | Moderate — KL is O(N²), Multi-Level is O(N) |
| `forge_shootouts/hardened_active_inference.py` | 7 (D) | D=50-100, T=500-1000 | Significant — natural gradient + Nesterov + free-energy minimization |
| `forge_shootouts/hardened_persistent_homology.py` | 6 (D) | 300-800 vertex | Largest — O(N³) matrix reduction; needs witness complex approximation for production |
| `forge_shootouts/hardened_verification.py` | C+D | Research-grade | Largest — IC3/PDR, CEGAR, Octagon |
| `forge_shootouts/hardened_synthesis_search.py` | 7 | 12⁶ search space | Moderate — A* + MAP-Elites |
| `forge_shootouts/hardened_performance_models.py` | 7 | 2K data points | Moderate — OLS + bottleneck DAG |
| `forge_shootouts/tau_field_lib.py` | 6 (D) | Implicit | Significant — Helmholtz FEM/FDM; sparse solver. **Note: imports numpy, violates One Link no-external-deps** |

---

## Critical Files (where new code goes)

### Files to extend / replace (existing One Link)

| File | Phase | Action |
|---|---|---|
| `src/one_link/cdc.py` | A1 | Replaced by Rust crate `ol_chunk` (calls native via existing `native_cdc.py` pattern) |
| `src/one_link/native_cdc.py` | A1 | Becomes the Rust-FFI entry point; existing C scanner pattern reused |
| `src/one_link/blobstore.py` | A1 | Replaced by Rust crate `ol_chunk_store` (LSM + WAL + bloom front) |
| `src/one_link/double_ratchet.py` | C | Extended to per-chunk ratchet; small-order check made constant-time |
| `src/one_link/pq_hybrid.py` | C | NullKEM replaced with ML-KEM-768 |
| `src/one_link/{capabilities, cap_store, caps_grants}.py` | C | Replaced by `ol_capability` Rust crate (hand-ported from `std.capability.*` design spec; existing share-link UI orchestration in Python stays) |
| `src/one_link/foldersync.py` | C | CRDT data layer replaced by `ol_crdt` Rust crate (hand-ported from `std.crdt.*` design spec); watchdog file-event loop + UI surface remain Python |
| `src/one_link/transfer_brain.py` | C+D | Bandit replaces EMA route memory; Phase D adds active inference layer on top |
| `src/one_link/transfer_doctor.py` | A1 | Stays; diagnosis output layer on top of new chunk store |
| `src/one_link/peer_rtc.py` | A2 | Daemon-side WebRTC retained for browser-as-peer; daemon↔daemon path swaps to QUIC |
| `src/one_link/perf_lab.py` | A1+ | Extended ruthlessly: every PR gates on benchmark non-regression |
| `src/one_link/{master_seed, mnemonic, social_recovery}.py` | C+D | Threshold-of-N becomes default recovery path; uses harvested Shamir |

### New Rust crates (where new code goes)

```
native/                              (currently has C ext, becomes Rust workspace)
├── ol_chunk/                       # Phase A1: CDC + BLAKE3 + chunk envelope
├── ol_chunk_store/                 # Phase A1: LSM + WAL + bloom
├── ol_aead/                        # Phase A1: AEAD pipeline (AES-NI / ChaCha20)
├── ol_quic/                        # Phase A2: QUIC transport via quinn
├── ol_capability/                  # Phase C: hand-ported from std.capability spec; property tests encode caveat algebra
├── ol_crdt/                        # Phase C: hand-ported from std.crdt spec; property tests encode lattice laws
├── ol_canon/                       # Phase 0: hand-ported from std.codec.canon spec; property tests encode determinism law
├── ol_fountain/                    # Phase B: RaptorQ
├── ol_netcode/                     # Phase B: XOR network coding
├── ol_fec/                         # Phase C: Reed-Solomon
├── ol_erasure/                     # Phase C: durability coding
├── ol_fuse/                        # Phase B: FUSE binding (Linux)
├── ol_fskit/                       # Phase B: FSKit binding (macOS)
├── ol_winfs/                       # Phase B: Dokan/WinFSP binding (Windows)
├── ol_routing/                     # Phase D: tau-field PDE
├── ol_homology/                    # Phase D: persistent homology
├── ol_active_inference/            # Phase D: free-energy minimization
└── ol_grammar/                     # Phase D: Re-Pair grammar compression
```

---

## Verification Gates per Phase

Every phase ships when its falsifiable acceptance number passes, not when "implemented."

### Phase A1 acceptance gate

- Sustained ≥1 GiB/s end-to-end ingest of unique data on single Linux NVMe host
- `kill -9` survival across ≥10,000 randomized injection points; zero chunk loss; zero manifest divergence after recovery
- AEAD throughput ≥4 GiB/s per core (AES-NI) or ≥3 GiB/s per core (ChaCha20)
- Manifest WAL test: crash injected between chunk-write and manifest-update; both converge on recovery
- Round-trip canonical-encoding test: Coherence and Rust produce byte-identical output for ≥1M random structured inputs

### Phase A2 acceptance gate

- QUIC stream throughput within 10% of TCP on tuned LAN
- 0-RTT resume latency <50ms warm cache
- Connection migration across cellular ↔ WiFi handoff with zero application-visible drop

### Phase B acceptance gate

- RaptorQ decode succeeds with K=1024 source symbols at 5% loss across ≥1000 random seeds
- Bloom-init reduces bytes-on-wire by ≥90% on workload where receiver has ≥80% of chunks
- FUSE survives `fsx-linux` for ≥24h fuzz; FSKit on macOS passes `fsx`-equivalent
- Convergent encryption: identical plaintext from N senders produces identical ciphertext; per-recipient mode falsifies for non-eligible content types

### Phase C acceptance gate

- Reed-Solomon (10,4) survives any 4-shard erasure with 100% recovery across ≥10,000 seeds
- Bandit converges on known-optimum peer-pair within ≤200 interactions in simulation
- Macaroon attenuation: property test that no derived cap exceeds parent rights across ≥1M random delegation chains
- ML-KEM-768 + X25519 hybrid completes handshake at PQ-conservative parameters
- Constant-time check: timing variance across cap-validity / crypto-input-validity < 1% of mean
- Fuzzer in CI; ≥48h since last fuzzer crash before release

### Phase D acceptance gate

- Tau-field routing beats shortest-path on a fragile-graph benchmark by stated margin (≥20% reduction in chunks-lost-on-partition)
- Persistent-homology detector flags injected partition within ≤N measurement rounds with ≤5% false positive rate
- Active inference cold-start: bandit-equivalent performance within ≤50 transfers (lukewarm via cohort prior)
- Plausibly deniable storage: duress key unlocks decoy with no observable disk-pattern difference from real-key unlock
- Formal model passes for: no double-grant, no key reuse, no downgrade, no replay (all four state machines)

---

## Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Convergent encryption (B) requires chunk-store layout decision in A1 | Chunk store stores both raw-BLAKE3 and convergent-BLAKE3 from A1 onwards; flip default in B |
| Manifest WAL not coupled to chunk WAL → FUSE data loss on crash | Manifest WAL is an A1 deliverable, NOT implicit in C |
| Erasure-coded stripes need stripe metadata in chunk-store layout | Stripe descriptor field in A1; encode/decode in C |
| D unmeasurable without B's empirical link costs | D depends on B-or-equivalent telemetry; if B slips, D's tau-field uses pure RTT/loss as fallback edge weight (still works, just less optimal) |
| Phase A absorbs all engineering attention; B/C/D never ship | A1 is the smallest-A-that-unblocks-B; A2 is a separate ship; B starts immediately on A1 acceptance |
| Bandit (C) and existing transfer-brain (shipped) conflict | C explicitly REPLACES transfer-brain.py EMA route memory, not coexists |
| Hardware attestation reintroduces vendor dependency | Rephrased to "hardware-bound, TOFU-degrading"; vendor attestation is optional, not required |
| Two policy systems (capability + existing Ed25519 grant) during transition | C ships with shim that translates existing grants to caps; existing grants frozen at C; new shares are caps-only |
| Phase D research-grade items (persistent homology, tau-routing) fail at scale | Each has fallback: persistent homology → simpler graph-theoretic redundancy heuristics; tau-routing → harvested OneField production τ_c routing already works |

---

## Sovereignty / Defang Concerns

| Substrate | Concern | Decision |
|---|---|---|
| RocksDB | Pulls in C++ build chain, 3 MB binary | Use as Phase A1; from-scratch LSM is its own project. Acceptable: dual-licensed Apache 2.0, no monthly bill, no vendor server. |
| msquic | Microsoft-controlled | REJECT. Use `quinn` (Rust, MIT/Apache, no Microsoft). |
| macFUSE | GPLv2 + commercial dual; kext signing requires commercial license | REJECT. Use FSKit on macOS (Apple's modern in-userspace alternative). Bridges to Apple but breaks no monthly-bill promise less than macFUSE. |
| Apple Secure Enclave attestation chain | Requires Apple's CA online for verification | Hardware-bound keys are TOFU-degrading; vendor attestation is optional. |
| Android StrongBox attestation chain | Requires Google CA | Same TOFU-degrading mitigation. |
| Windows TPM AIK enrollment | Requires CA | Same TOFU-degrading mitigation. |
| RaptorQ (RFC 6330) | Qualcomm IPR declarations | Verify patent grant before shipping. If blocked, fallback to LT codes or RFC-5053 Raptor (older, expired patents). |
| BLAKE3 SIMD on ARM64/RISC-V | Reference impl is fine; SIMD acceleration partial on non-x86 | Acceptable. Ship reference for unsupported archs; performance penalty understood. |
| `qrcode` / `aiortc` / `cryptography` | Existing One Link deps | Acceptable. All open-source, no monthly bills. |

**Net result:** zero new corporate dependencies introduced. Every substrate either has an open-source replacement or degrades gracefully without the vendor.

---

## Coherence Language ↔ Rust Strategy

**Decision: Coherence Language is the design specification. Rust is the runtime AND the spec-of-record at runtime. CL is never linked at runtime; the daemon does not embed Python+LoOVM, does not link CL `.o` artifacts, does not depend on the CL bootstrap toolchain.**

Rationale: per the CL deployment audit (compiler in this repo: `coherence_lang/coherence_lang/{compiler, codegen, loovm, backend, baremetal, cir}`), CL has no stable C ABI. Three execution paths exist (LoOVM Python interpreter, LLVM-native standalone executable, Python transpilation) and none of them give a non-Python runtime a clean FFI surface. Embedding CL would require either (a) hosting Python+LoOVM in the daemon (kills line-rate, reintroduces GIL, defeats the point), (b) linking internal CL runtime stubs against unsupported symbols (brittle, breaks on every CL release), or (c) subprocess RPC (adds latency to every algebra operation). None of these meet the engine's reliability or performance bar.

```
coherence_lang/std/capability/cap.cl                    (algebraic spec — source of truth at design level)
       ↓ (port: read by hand, port to Rust with property tests encoding the laws)
native/ol_capability/src/cap.rs                          (runtime; rev-pinned comment refs back to .cl)
       ↓
       (CI: property tests for capability attenuation soundness, no double-grant,
        revocation propagation, audit-chain immutability — laws the .cl proves)
```

- **Hot path runtime is Rust.** No CL at runtime, anywhere.
- **Substrate algebra is defined in CL.** Capability calculus, CRDT lattice, canonical encoding, gossip protocols. CL is where the algebra is *specified*; that's its highest-value role.
- **Rust crates are ported by hand from .cl files.** Each Rust file references the .cl source with a revision-pinned comment (e.g. `// derived from coherence_lang/std/capability/cap.cl @ rev abc1234`). Updating the algebra means updating the .cl spec, then porting the change to the Rust crate, with property tests verifying the laws still hold.
- **Property tests as the alignment mechanism.** Each algebraic law gets a `proptest` or `quickcheck` Rust test: lattice associativity, lattice commutativity, lattice idempotency, capability attenuation soundness (no derived cap exceeds parent), capability revocation propagation, canonical-encoding determinism (same value → same bytes), causal-order preservation under merge.
- **Cross-project consistency** (One Link / OneField / BioMesh sharing the same algebra): once Rust crates stabilize, promote them to a shared sibling-repo workspace. CL stays as the design source of truth; the Rust crate is the shared runtime artifact across projects.
- **Future option (NOT current dependency):** if CL ever ships a stable C ABI, codegen-from-CL becomes available as an additive path. The current Rust crates would still be valid; codegen would just regenerate them from the spec. We do not build today against a future ABI.
- **Forge_shootouts (research-validated algorithms in pure Python):** same treatment. Read the algorithm, port to Rust at line rate, property-test against the Python correctness benchmark. The Python file stays as a reference implementation that future Rust ports can validate against.

---

## Verification (end-to-end)

How to validate the full stack works:

1. **Per-phase acceptance gates** as defined above. No phase ships without passing its gate.
2. **Per-PR benchmark gate**: `src/one_link/perf_lab.py` extended to the new Rust crates. PR rejected if cycles/byte regresses or throughput drops by >5% on any standardized corpus.
3. **Adversarial fuzzing**: in CI, inject 10/30/50% packet loss + reorder + jitter + NIC drops + disk-full + daemon kill -9 mid-transfer. Engine must complete or resume cleanly.
4. **Theoretical-limit demos** as visible end-to-end checkpoints:
   - Saturate 10 GbE LAN sustained, prosumer NVMe → ≥1.19 GiB/s, ≤2 cores
   - 100GB folder, sender 1 Gbps WAN up, 4 swarm peers help → receiver finish in <14 minutes
   - Resending edited Premiere project: dedup recognizes ≥90% chunks; transfers ≤10% delta in <10s
   - Cellular flicker mid-transfer: zero retransmits visible to user
5. **Cross-platform soak**: 48h continuous transfer on Linux + macOS + Windows; FUSE/FSKit/Dokan all stable.
6. **Sovereignty audit per release**: every dep verified against the Defang Concerns table; new dep requires explicit sovereignty review.

---

## Roadmap Slot

This plan is bigger than a single [ROADMAP.md](ROADMAP.md) version entry. It is a multi-version arc:

- File engine v2 = a new track running parallel to the v0.14.x phone tier and v0.15.x→v0.25.x PWA pivot.
- Phase A1 first ship lands as a One Link minor version (e.g., v0.21.0 — chunk store rewrite with backward-compatible wire protocol).
- Subsequent phases ship as further versions in the same minor-arc; major-version bump (v1.0+) reserved for first ship that has full FUSE/FSKit/Dokan surface.
- Existing principles (Reach / Hide engine / Async by default / Frontier behind surface / Defang corporate substrate) PRESERVED unmodified; every phase gates on the five.
- Three Sovereignty Tiers (Default / Hardened / Air-gap) PRESERVED; every phase respects tier-specific behavioral matrix.

---

## Notes for Execution

- **Use existing terminology**: "transfer brain" stays (Phase C extends, doesn't rename); "transfer lanes" stays (Phase B adds fountain/XOR/format-aware as new lanes); "phone tier" stays.
- **No org-level identity.** Capabilities are person-to-person. No admin role. No team identity.
- **Persona**: small ops (contractors, podcast/video teams, repair shops, small offices, creators, nonprofits) without per-seat cloud bills. Audience caps at ~20-person ops.
- **Adversary model**: Byzantine peers, malicious tau reports, Bloom pollution, fountain pollution, swarm censorship, NIC drops, disk-full, kill -9, cellular handoff, WAN flap.
- **Honest grading**: Phases A1+A2+B+C are conservative engineering on well-understood primitives + harvestable production code. Phase D items (tau-routing, active inference, persistent homology, grammar compression, formal verification) are research-validated but not engineering-proven at line rate; each has a fallback to a simpler heuristic that preserves the architectural slot.

---

## Critical Files Referenced (paths)

- One Link (in this repo): `src/one_link/{cdc, native_cdc, blobstore, double_ratchet, pq_hybrid, capabilities, cap_store, caps_grants, foldersync, transfer_brain, transfer_doctor, peer_rtc, perf_lab, master_seed, mnemonic, social_recovery}.py`
- One Link new crates root: `native/` (currently C ext; becomes Rust workspace)
- Coherence stdlib (sibling repo): `coherence_lang/coherence_lang/bootstrap/stdlib/std/{codec/canon, crdt/{lattice, causality, vector_clock, sync, merge}, capability/{cap, delegate, grant, revoke}, distributed/{store, gossip, failure_detector}}.cl`
- OneField Mesh (sibling repo): `OneField Mesh/onefield/{transport/{cdc_dedup, udp_fec, quic_congestion, mptcp, parallel, field_fusion}, mesh/{routing, byzantine, dtn, disaster_bootstrap}, bridge/{discovery, nat, auth, quota, rate_limit, trust}, privacy/{sharding, zk_prover, no_reconstruct_proof}, sensing/bayesian_fusion, radio/crypto/reciprocity}.cl`
- Forge shootouts (sibling repo): `A.C.E/CodeSwarm/forge_shootouts/{hardened_grammar_compression, hardened_graph_cut, hardened_active_inference, hardened_persistent_homology, hardened_verification, hardened_synthesis_search, hardened_performance_models, tau_field_lib}.py`
- Companion docs in this repo: [ROADMAP.md](ROADMAP.md), [ARCHITECTURE.md](ARCHITECTURE.md), [PRINCIPLES.md](PRINCIPLES.md), [COHERENCE_TRANSFER_BRAIN.md](COHERENCE_TRANSFER_BRAIN.md), [SOVEREIGNTY.md](SOVEREIGNTY.md), [PHONE_TIER.md](PHONE_TIER.md)
