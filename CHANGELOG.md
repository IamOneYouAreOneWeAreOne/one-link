# One Link CHANGELOG

Per-release notes for One Link. Each entry summarises the ADRs landed
in that release; full architectural rationale lives in
[`docs/decisions/`](docs/decisions/).

The version scheme is semver-aligned but pre-1.0: 0.x.y means alpha,
breaking wire changes allowed between minor versions. Wire-format
compatibility with prior peers is preserved via capability negotiation
where practical (`NATIVE_TRANSFER_V1`, `DOUBLE_RATCHET_V1`).

---

## [0.21.0-alpha] — 2026-05-11 — File engine v2

**Headline**: complete implementation of [`FILE_ENGINE_V2_PLAN.md`](docs/FILE_ENGINE_V2_PLAN.md)
Phase A1 + A2 + B + C + D + Coherence ↔ Rust codegen scaffold.
16 Rust crates in `native/`; production-ready native chunk-store
transport pipeline with full daemon cutover.

### Phase A1: chunk store foundation (ADRs 0001–0008)

- `ol_chunk` — content-addressed FastCDC v2020 (8/64/256 KiB) + BLAKE3
  chunk addressing + chunk envelope.
- `ol_chunk_store` — LSM-indexed content-addressed chunk log + bloom-
  filter front + WAL-coupled durability.
- `ol_aead` — per-chunk multi-frame AEAD (AES-256-GCM / ChaCha20-
  Poly1305) backed by `ring` (BoringSSL-derived assembly).
- `ol_wal` — crash-only write-ahead log with CRC32-Castagnoli per-
  record + tail-truncation recovery.
- `one_link_native` — pyo3 binding crate exposing every native crate
  as `one_link_native.<submodule>` (abi3-py311+).

### Phase A2: transport (ADR-0009, ADR-0010)

- `ol_quic` — QUIC transport via `quinn` 0.11. Self-signed identity-
  bound TLS via `rustls` + `aws-lc-rs`. Multi-stream, multi-path, 0-
  RTT, connection migration. Replaces WebRTC/DTLS-SRTP for daemon↔
  daemon; WebRTC retained for browser-as-peer.

### Phase B: genius layer (ADRs 0011–0016)

- `ol_bloom` — Bloom-filter transfer init. Receiver sends Bloom of
  chunk hashes; sender XORs against manifest; ships only the true delta.
- `ol_fountain` — RaptorQ fountain codes (RFC 6330).
- `ol_fec` — Reed-Solomon FEC over GF(2^8) with SSSE3 PSHUFB SIMD.
- `ol_erasure` — Erasure-coded durability with stripe descriptor
  metadata.

### Phase C: multi-axis baseline (ADRs 0017–0027)

- **ADR-0017** PQ-hybrid KEM (ML-KEM-768 + X25519 via BLAKE3 X-Wing
  combiner). `ol_pqkem` crate.
- **ADR-0019** Multi-armed bandit auto-tuning (Beta-Bernoulli Thompson
  sampling). `ol_bandit` crate.
- **ADR-0020** Per-chunk forward-secret ratchet (BLAKE3 keyed-hash
  chain). `ol_ratchet` crate.
- **ADR-0021** Capability layer — macaroon-style HMAC-chained caveats
  over BLAKE3. `ol_capability` crate. **1M-iter attenuation soundness
  gate** (`child.accepts(ctx) ⇒ parent.accepts(ctx)`) passes in
  5.94 s with 0 violations.
- **ADR-0022** CRDT shared folders — vector clock + OR-set + LWW
  register composition. `ol_crdt` crate. **1M-iter lattice-laws gate**
  (commutativity + associativity + idempotency) passes in 7.46 s.
- **ADR-0023** Hardware-bound keys, TOFU-degrading. `ol_hwkey` crate.
- **ADR-0024** Phase C-3 wiring status — shadow / dual-issue posture
  for the 5 daemon migration primitives.
- **ADR-0025** Chunk-store transport pipeline — composed
  `NativeTransferSession` (KEM + ratchet + CDC + AEAD + ChunkStore).
  Bench: native is **1.14–1.44× faster than legacy** at every size
  16 KiB → 64 MiB after the BoringSSL fast-path default.
- **ADR-0026** `NATIVE_TRANSFER_V1` capability + `FILE_NATIVE_CHUNK`
  wire format. Capability-gated; default-on for capable peers
  (rollback via `ONE_LINK_NATIVE_TRANSFER=0`).
- **ADR-0027** Shadow → authoritative cutovers: bandit drives route
  picks in `AdaptiveTransferBrain.decide()`; folder mirror active
  cross-check + divergence counter; macaroon advertised on
  `CAPABILITY_GRANT` wire as `macaroon_b64`.

### Phase D: visionary layer (ADRs 0028, 0033)

- **ADR-0028 #1** Tau-field routing — `ol_routing` crate. τ_c-
  weighted Dijkstra + hysteresis-gated next-hop swap. Harvest from
  `OneField/onefield/mesh/routing.cl`. **Acceptance gate**: 100%
  chunk-loss reduction on fragile-graph benchmark (plan: ≥20%).
- **#2** Byzantine-tolerant tau — `ol_routing::byzantine` module.
  BFT thresholds (`floor((N-1)/3)`) + random-geometric graph density
  + `tau_claim_corroborated` (catches malicious peers reporting fake
  high τ_c).
- **#3** Active inference prefetch — `ol_prefetch` crate. Time-
  weighted co-occurrence predictor over (peer, file_id) access
  traces. **Acceptance gate**: cold-start convergence ≤50 iters;
  cohort prior transfer converges in 1 iter.
- **#4** Persistent homology durability — `ol_homology` crate. H0
  components + bridge detection via DFS; composite `fragility_score`
  for replication priority. **Acceptance gate**: partition flag in 1
  round, 0% FP on 100 random 4-regular graphs (plan: ≤5% FP).
- **#5** Grammar compression — `ol_grammar` crate. Re-Pair on byte
  streams.
- **#6** Plausibly deniable storage — `ol_duress` crate. `DuressGate`
  with constant-time real-vs-decoy decision + covert ratchet-header
  signal. **CT timing gate**: 1.014× wall-clock variance (plan:
  <1.20×). The validation pass caught + fixed a real side-channel
  (1.448× → 1.014×).
- **#7** Formal verification — TLA+ specification at
  `docs/formal/Capability.tla` modelling the capability grant + revoke
  + attenuation state machine. Verified safety invariants:
  `NoKeyReuse`, `NoDoubleGrant`, `NoReplay`, `ClockMonotonic`.
- **Coherence ↔ Rust codegen scaffold** — `ol_codegen` crate. Minimal
  CL `struct` grammar parser + Rust struct + canonical-LE encoder
  emitter. **Byte-equivalence CI gate**: 1M random struct shapes
  round-trip in 1.79 s.

### Python adapters

Every native crate the daemon needs to call surfaces as
`one_link_native.<submodule>` + a thin `*_native.py` wrapper:

- `chunk_native.py`, `chunk_store_native.py`, `wal_native.py`,
  `aead_native.py`, `quic_native.py` (Phase A1+A2)
- `fountain_native.py`, `fec_native.py`, `bloom_native.py`,
  `pqkem_native.py`, `erasure_native.py`, `bandit_native.py`,
  `ratchet_native.py` (Phase B+C)
- `capability_native.py`, `crdt_native.py`, `hwkey_native.py` (Phase C-3)
- `routing_native.py`, `prefetch_native.py`, `homology_native.py`
  (Phase D, new in 0.21.0)

PEP 561 type stubs ship at `stubs/one_link_native-stubs/`.

### Daemon production integrations (this release)

- `Daemon._observe_prefetch(peer_fp, blob_hex)` hook in `send_file()`
  success path + receiver-side ACK so the prefetch predictor sees
  both ends of every transfer.
- `Daemon.native_diagnostics()` returns prefetch/routing/homology
  availability + native-transfer-v1 advertisement + macaroon-dual-
  issue state for operator inspection.
- `Daemon._pick_best_relay()` sorts relay candidates by τ_c-weighted
  cost (no-op pass-through until per-relay metrics surface lands).

### Testing & verification

- **506 Rust workspace tests** pass / 0 failed
- **107 Python unit tests** pass / 0 failed
- **2,952 Python daemon regression tests** pass / 0 failed
- **Total: 3,565 / 0 failed**
- 9 fuzz targets cover wire formats + state machines + Phase D
  primitives (auto-discovered by nightly CI workflow)
- Property tests via `proptest` across every Phase D crate

### Backward compatibility

- Legacy peers (no `NATIVE_TRANSFER_V1` in caps) transparently stay
  on `FILE_CHUNK` / `FILE_BIN_CHUNK`.
- All daemon migrations are additive — `pq_hybrid.HybridKEM`,
  `caps_grants.encode_grant`, `crdt.merge_manifest_entries`,
  `transfer_brain.AdaptiveTransferBrain` legacy paths all stay
  authoritative or available as fallbacks.

### Rollback flags

- `ONE_LINK_NATIVE_TRANSFER=0` — disable FILE_NATIVE_CHUNK, force
  legacy FILE_CHUNK / FILE_BIN_CHUNK.
- `ONE_LINK_BANDIT_ROUTE_PICKER=0` — disable bandit-driven route
  selection in `AdaptiveTransferBrain.decide()`, fall back to legacy
  multi-route Pareto.

---

## [0.20.6] — 2026-05-08

iOS Configuration Profile (.mobileconfig) endpoint for self-signed
cert trust. Unblocks iPhone HTTPS pair flow.

## [0.20.5] — 2026-05-09

Multi-agent security audit — 5 CRITICAL + 21 HIGH + 24 MED findings.
Documented in `docs/SECURITY_AUDIT_v0.20.5.md`.

## [Earlier history]

See git log for v0.7.0 through v0.20.4. Highlights:
- v0.7.0–v0.7.6: Linked mesh + security pass + per-device drawer +
  transfer resume + reply/quote + reactions + read receipts.
- v0.8.x: CRDT shared folders, group events, social recovery.
- v0.10.x: System tray, dashboard, performance lab.
- v0.14.x: Phone tier.
- v0.15.x–v0.20.x: PWA pivot architecture.
