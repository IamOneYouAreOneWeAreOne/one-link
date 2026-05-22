# AUDIT 2026-05-21 — FULL FINDINGS INVENTORY

Auto-extracted from 17 parallel audit-subagent transcripts ran during the 2026-05-21 deep One Link audit.

**Total findings across all topics: 133**

The 57 items individually enumerated in `AUDIT_2026-05-21.md` (TIER 1 / TIER 2 / TIER 3) are a security-prioritised subset of this list and have all shipped. The remaining items here are the TIER 4 LOW-priority quality / UX / hardening observations the audit doc declared 'not blocking'.

Each section is one auditor's bucket of related findings. Items are not deduplicated across sections — some auditors flagged the same root cause from different angles (e.g. the default-allow-all reversal appears in capabilities, server, and persistence sections).

## Native ol_* crates — `agent-a1147246450af1143` (8 findings)

### Native ol_* crates #1
**### Storage / transport substrate (Phase A1/A2 + Phase B)**

| Crate | Files / LOC | pyo3 mod | Public API (excerpt) | Status | Last commit |
|-|-|-|-|-|-|
| **ol_chunk** | 10 / 2048 | `chunk` | `cdc::ChunkScanner`, `scan_to_vec[_parallel]`, `chunk_address_raw`, `chunk_address_convergent`, `derive_aead_key`, `format_aware::scan_format_aware`, `frame_count_for_plaintext` | WIRED via `chunk_native.py` → consumed by `native_transfer.py`, `perf_lab_native.py`, `cdc.py` | `6e548cd` |
| **ol_aead** | 11 / 1792 | `aead` | (16 KiB AEAD-frame pipeline, AES-256-GCM primary + ChaCha20-Poly1305 fallback per ADR-0002) | WIRED via `aead_native.py` → consumed by `native_transfer.py`, `perf_lab_native.py` | `6e548cd` |
| **ol_wal** | 7 / 1395 | `wal` | `Wal::append/flush`, `replay_log_dir`, `Record` | WIRED via `wal_native.py` → `perf_lab_native.py`; daemon storage relies on it through `ol_chunk_store` | `6e548cd` |
| **ol_chunk_store** | 10 / 2286 | `store` | `ChunkStore::open/write_chunk/has_chunk/read_chunk/write_manifest/flush`, stripe support | WIRED via `chunk_store_native.py` → `native_transfer.py`, `perf_lab_native.py` | `6e548cd` |
| **ol_quic** | 10 / 2343 | `quic` | `Identity`, `Endpoint`, `Connection`, `Frame`, `IdentityBoundServerVerifier/ClientVerifier`, `PeerRegistry`, `ALPN` | WIRED via `quic_native.py` → `peer_quic.py`, `daemon.py`, `perf_lab_native.py` | `c2ffadc` (CDC-over-QUIC) |
| **ol_bloom** | 7 / 1055 | `bloom` | `Bloom`, `optimal_k/m_bits`, `target_fp_rate` | WIRED via `bloom_native.py` + `bloom_init.py` → `daemon.py` advertises CAPS frame | `6e548cd` |
| **ol_transfer** | 11 / 2709 | — | `TransferEngine::{new, register_peer, fetch_chunk, fetch_many, bloom_handshake, run_server}` | **INTERNAL_ONLY** — pure-Rust integrating engine; daemon implements its own transfer in Python and does not call this | `6e548cd` |

`ol_transfer` is the most striking gap: it integrates `ol_chunk_store + ol_quic + ol_bloom` into a real fetch-server engine but has no pyo3 binding and the daemon never touches it. The Python `native_transfer.py` re-implements much of this in Python over the lower primitives.

### Native ol_* crates #2
**### Erasure / fountain / multicast**

| Crate | LOC | pyo3 | Public API | Status |
|-|-|-|-|-|
| **ol_fec** | 1442 | `fec` | `Codec`, `CauchyMatrix`, `gf256` ops | WIRED via `fec_native.py` |
| **ol_fountain** | 1654 | `fountain` | `LtEncoder`, `LtDecoder`, `FountainPacket`, `Distribution` (Robust Soliton c=0.03, δ=0.05), RaptorQ K=1024 (per `1ca6241`) | WIRED via `fountain_native.py` → `fountain.py` |
| **ol_erasure** | 599 | `erasure` | `encode_stripe`, `decode_stripe`, `Shard`, `ShardRole`, `StripeId`, `StripeParams` | WIRED via `erasure_native.py` → `durability.py` |
| **ol_netcode** | 435 | — | `xor_inplace`, `encode_coded_packet`, `decode_coded_packet`, `CodedPacket` (A⊕B network coding) | **INTERNAL_ONLY** — no pyo3, no Python use |

**Composition (anchor + projection multicast)**: `ol_chunk` (CDC + addressing) + `ol_fountain` (LT/RaptorQ) + `ol_erasure` (Reed-Solomon stripes) are all pyo3-exposed and individually wired. Python `durability.py` and `fountain.py` consume them as separate primitives. There is no single Rust pipeline that fuses them into "anchor chunk → fountain projection → multicast" — `ol_transfer` would be the natural home, but it doesn't ride the fountain/erasure layer yet (`ol_transfer/src/lib.rs:8` declares dependencies only on `ol_chunk_store + ol_quic + ol_bloom`; the FountainBurst frame is called out at `ol_fountain/src/lib.rs:18-20` as "lands in Phase B-1.5"). `ol_netcode` is also dark on the Python side. The composition is *available as building blocks* but the integrator is missing — the right ship is a `MulticastSession` type in either `ol_transfer` or a new `ol_swarm` crate that takes (chunk_id, peer_set, redundancy_target) and emits coded burst frames.

### Native ol_* crates #3
**### Cryptography / identity**

| Crate | LOC | pyo3 | Public API | Status |
|-|-|-|-|-|
| **ol_ratchet** | 1097 | `ratchet` | `Chain` (per-chunk symmetric ratchet, HKDF), `SkippedKeyStore`, `derive_root_chain_key` | WIRED via `ratchet_native.py` → `chunk_ratchet.py` |
| **ol_pqkem** | 763 | `pqkem` | `keypair`, `encapsulate`, `decapsulate`, hybrid ML-KEM-768 + X25519 with BLAKE3 combiner | WIRED via `pqkem_native.py` → `pq_hybrid.py` |
| **ol_pqsig** | 954 | `pqsig` | `HybridSigningKey` (Ed25519 + ML-DSA-65), 3373-byte sigs | WIRED via `pqsig_native.py`; consumed by `ol_device_mesh` + `ol_confidential` (Rust) and `master_seed.py` (Python) |
| **ol_hwkey** | 335 | `hwkey` | `KeyGuarantee` (TofuOnly / HardwareBound / HardwareAttested), `KeyStore` trait, `TofuStore`, `PublicKey`, `Attestation` | WIRED via `hwkey_native.py` → `daemon.py` |
| **ol_confidential** | 4675 | `confidential` | `ConfidentialProvider` trait, `SoftwareProvider`, `AttestationDoc`, `ConfidentialTier`, `detect_runtime_tier`, sealed-sign / sealed-derive | WIRED via `confidential_native.py` → `master_seed.py`, `handshake_attestation.py` |
| **ol_device_mesh** | 21535 | — | `MasterIdentity`, `DeviceClass`, `DeviceSubkey`, daily ratchet, `SubkeyAttestation`, `LivenessProof`, field-binding hook | **INTERNAL_ONLY** — Rust-only; the master-identity surface that Python sees is via `ol_confidential` only |

`ol_device_mesh` at 21 535 LOC is by far the largest INTERNAL_ONLY crate. Row 8 (Personal Device Mesh) is shipped at the Rust level but the daemon has no `device_mesh_native.py` — the multi-device fan-out described in its docstring is not reachable from Python yet.

### Native ol_* crates #4
**### Capability + CRDT**

| Crate | LOC | pyo3 | Public API | Status |
|-|-|-|-|-|
| **ol_capability** | 1237 | `capability` | `Capability`, `Caveat::{ExpiresAt, PeerFingerprint, PathPrefix, OperationIn, AuditTag}`, `Context`, `RootKey` (32-byte HMAC root), constant-time verify | WIRED via `capability_native.py` → `cap_migration.py`, `daemon.py` (macaroon dual-issue, ADR-0027) |
| **ol_crdt** | 969 | `crdt` | `VectorClock`, `OrSet`, `LwwRegister`, `Folder` (composed: OR-set of file IDs + LWW per-attribute + vector clock), `Lattice` trait | WIRED via `crdt_native.py` → `folder_native.py` (which is itself daemon-imported per folder mirror cross-check ADR-0027) |

**ol_capability constraints expressible**: time-bound (`ExpiresAt(u64)` Unix-ms), peer-bound (32-byte fingerprint), path-prefix scope (string), operation allow-list (`OperationIn(Vec<String>)`), and audit-only tags. HMAC chaining gives attenuation (holder appends but never removes caveats). Wire format is `[tag u8][len u32 LE][bytes]` per `ol_capability/src/caveat.rs:35-80`. Missing vs typical macaroon systems: third-party caveats (require external proof), rate/quota caveats, and content-conditional caveats.

**ol_crdt usable from Python**: all four are exposed — `VectorClock`, `OrSet`, `LwwRegister`, and the composed `Folder` lattice. Lattice merge laws property-tested over ≥1M random states per `ol_crdt/tests/lattice_laws.rs`. The hash-derived LWW tie-break audit fix is recorded at `af53129`.

### Native ol_* crates #5
**### Coherence-field / routing / prediction (Phase D + E)**

| Crate | LOC | pyo3 | Public API | Status |
|-|-|-|-|-|
| **ol_routing** | 857 | `routing` | `edge_weight`, `edge_cost`, `loss_penalty`, `prefer_first`, `should_swap_hop`, `shortest_path` (Dijkstra), `AdjacencyGraph`, `tau_claim_corroborated`, `max_byzantine_count`, `quorum_safe`, `rgg_connectivity_radius`, `rgg_mean_degree` | WIRED via `routing_native.py` → `daemon.py:_pick_best_relay` (line 10198), `daemon.py:9173, 10200, 10219` |
| **ol_prefetch** | 541 | `prefetch` | `PrefetchPredictor` (time-weighted co-occurrence over `(peer, file_id, t)`), `Prediction`, `MAX_CO_OCCURRENCE_GAP_MS` | WIRED via `prefetch_native.py` → `daemon.py:9248-9282` (`observe` on every chunk arrival, `predict_top_n` operator helper, `storage_entries` in `native_diagnostics`) |
| **ol_homology** | 588 | `homology` | `components_of`, `ComponentReport`, `fragility_score`, `FragilityReport`, `FragilityScore` (H0 union-find + Tarjan-lowlink bridge detection, NOT full H1) | WIRED via `homology_native.py` → `daemon.py:10129` (`_tick_homology_feeder` runs scoring, feeds fragility events into the field manager) |
| **ol_coherence_field** | 35 / 5442 | `coherence_field` | `pde::{solve_helmholtz, solve_reaction_diffusion_steady, GraphLaplacian, HelmholtzSolver[F32], CgConfig[F32], CgWorkspace[F32]}`; `green::green_function`; `interpolation::be_rar` (α=1/2 forced); `anchor::{apparent_horizon_anchor, screening_length, ScreeningRegime}`; `calibration::{Calibration, Domain}`; `couplings::{inject_fragility_events, prefetch_priorities, rotation_cadence_multiplier, FragilityEvent, PrefetchPriority, RotationCadence}`; `source::{identity_dual_source[_with_phase], align_source, alignment_scalars, linear_source, support_phase_kernel}` | WIRED via `coherence_field_native.py` → `daemon.py:9391, 10245`; `chunk_ratchet.py:186` (rotation cadence multiplier modulates per-chunk ratchet); `field_snapshot.py:165, 259` (field state snapshot for attestation/witness); `threshold_recovery_native.py:32` (field-bound share masking) | `6096fb2` (wasm32 cfg-gate) |

**ol_coherence_field** is the Helmholtz primitive port of the S_One canonical theorem stack. Eight modules: `pde` (reaction-diffusion + Helmholtz solve on graph Laplacian, both f32 and f64 paths), `green` (Green-function nonlocal kernel — one solve, N readouts), `source` (linear ref + identity-sector dual `S = α·ρ + β·|J|` + support-phase boundary kernel), `interpolation` (BE-RAR), `anchor` (apparent-horizon anchor `g_A = c·H/(2π)` + screening length `ell_screen = √(D/Γ)`), `calibration` (per-domain D/Γ constants for One Link / OneField / BioMesh), and `couplings` (the three cross-crate hooks: homology→field, field→prefetch, field→ratchet).

Daemon currently calls: `solve_helmholtz`, `be_rar` (replaces heuristic loss penalty in `_pick_best_relay`), `apparent_horizon_anchor`, `screening_length`, `one_link_calibration`, `rotation_cadence_multiplier`, `prefetch_priorities`, `identity_dual_source_with_phase`, `inject_fragility_events`. The `green_function`, `solve_reaction_diffusion_steady`, `align_source`, `alignment_scalars`, `linear_source`, `support_phase_kernel` surfaces are pyo3-exposed but not yet daemon-called — these are the "available but not wired" sub-functions.

### Native ol_* crates #6
**### Phase F: pair-trust / discovery / onion**

| Crate | LOC | pyo3 | Public API | Status |
|-|-|-|-|-|
| **ol_pair_qr** | 18 / 3938 | `pair_qr` | Invite (Ed25519-signed), `PairResponse`, `PairConfirm`, 5-word SAS, X25519 chain-key, Factor-2 mix-in, KAT vectors | WIRED via `pair_qr_native.py` |
| **ol_proximity_pair** | 13 / 2186 | `proximity_pair` | quantize/syndrome/reconcile/amplify, CASCADE driver, channel-reciprocity Factor-2 | WIRED via `proximity_pair_native.py` |
| **ol_threshold_recovery** | 11 / 2385 | `threshold_recovery` | `gf256`, `shamir::{split, reconstruct, lagrange}`, `refresh` (HJK proactive), `field_bound::{mask_shares, FieldWitness}` | WIRED via `threshold_recovery_native.py` → `social_recovery.py` (row 9 wiring memory) |
| **ol_discovery** | 18 / 5104 | `discovery` | `NodeId`, `RoutingTable` (Kademlia K-bucket), `SignedRecord`, RPC envelope types, `Transport` trait | WIRED via `discovery_native.py` (NodeId + table + record pieces exposed; iterative-lookup driver is daemon-orchestrated per lib.rs:50-54) |
| **ol_onion** | 46 / 11074 | `onion` + `sphinx` + `obfs` | `build_onion`, `peel_one_layer`, `Circuit`, `HopDescriptor`, `OnionPacket` (fixed `ONION_PACKET_SIZE`), `PeelOutcome`; **Sphinx Coherence** subsurface (Ristretto255 + filler-byte + PQ-hybrid + field-bound + Schnorr aggsig at `aggsig.rs`); `transport_obfs` (obfs4-style handshake + bidirectional session) | WIRED via `onion_native.py`, `sphinx_native.py`, `obfs_native.py` → `peer_rtc.py:1101`, `daemon.py:16676`, `cover_traffic.py:44` (sphinx is the largest crate by LOC, three pyo3 submodules) |

### Native ol_* crates #7
**### Wire / spec / codegen (no Python use)**

| Crate | LOC | Status | Purpose |
|-|-|-|-|
| **ol_canon** | 1189 | INTERNAL_ONLY | Canonical bytes encoder (`CanonEncoder/Decoder`, `TypeTag`, varint/zigzag) — used by `ol_pair_qr` and `ol_capability` for deterministic transcript hashing |
| **ol_codegen** | 1325 | INTERNAL_ONLY | CL → Rust struct/enum codegen scaffold (`parse_struct`, `parse_enum`, `emit_rust_decl`); standalone tool, not wired into the daemon |
| **ol_grammar** | 341 | INTERNAL_ONLY | Re-Pair grammar compression (`compress`, `decompress`, `Grammar`, `Rule`, `compression_ratio`) — Phase D #5 secondary chunk index; **scaffold, no production callers** |
| **ol_duress** | 519 | INTERNAL_ONLY | `Volume`, `DuressGate::open`, `signal_in_ratchet_header`, `decode_covert_signal` — Phase D #6 plausibly deniable storage; **scaffold, no production callers** |
| **ol_fuse** | 984 | INTERNAL_ONLY | `FilesystemBackend` trait, `MemoryBackend`, `mount()` (cfg-gated to linux + `linux-mount` feature); other platforms return `MountError::UnsupportedPlatform` |
| **ol_winfs** | 163 | INTERNAL_ONLY | Windows surface (WinFSP/Dokan behind features); scaffold re-exports `ol_fuse::FilesystemBackend` |
| **ol_fskit** | 156 | INTERNAL_ONLY | macOS FSKit scaffold; same backend trait |
| **ol_bandit** | 651 | WIRED via `bandit_native.py` → `transfer_brain.py:861, 1116` (Thompson sampling over knobs) |

### Native ol_* crates #8
**### Quick Status Roll-up**

| Crate | Status | Used for | Gap |
|-|-|-|-|
| ol_chunk | WIRED | CDC + BLAKE3 chunk addresses | — |
| ol_aead | WIRED | per-chunk AEAD (16 KiB frames) | — |
| ol_wal | WIRED | crash-only WAL | — |
| ol_chunk_store | WIRED | chunk store + manifest | — |
| ol_quic | WIRED | daemon-daemon QUIC + ALPN | — |
| ol_bloom | WIRED | Bloom-init handshake | — |
| ol_transfer | INTERNAL_ONLY | TransferEngine integrator | **No pyo3 surface**, daemon re-implements in Python |
| ol_fec | WIRED | Reed-Solomon Cauchy codec | — |
| ol_fountain | WIRED | LT/RaptorQ fountain | FountainBurst QUIC frame not landed |
| ol_erasure | WIRED | stripe encode/decode | — |
| ol_netcode | INTERNAL_ONLY | A⊕B network coding | **No pyo3, no callers** |
| ol_capability | WIRED | macaroon caps (5 caveat kinds) | No third-party / quota caveats |
| ol_crdt | WIRED | folder lattice (VC + ORSet + LWW) | — |
| ol_ratchet | WIRED | per-chunk symmetric ratchet | — |
| ol_pqkem | WIRED | ML-KEM-768 + X25519 hybrid | — |
| ol_pqsig | WIRED | Ed25519 + ML-DSA-65 hybrid sig | — |
| ol_hwkey | WIRED | KeyStore trait + TOFU + guarantees | — |
| ol_confidential | WIRED | sealed-sign + attestation | Hardware backends still Phase 2 |
| ol_device_mesh | INTERNAL_ONLY | Row 8 master identity + subkeys + daily ratchet (21.5 KLOC) | **No pyo3**, daemon multi-device fan-out unreachable |
| ol_routing | WIRED | τ_c Dijkstra + Byzantine helpers | Relay metrics still sparse → currently a near no-op in `_pick_best_relay` |
| ol_prefetch | WIRED | co-occurrence predictor | Used only for `observe` + operator-facing `predict_top_n`; no auto-prefetch consumer in daemon yet |
| ol_homology | WIRED | H0/bridge fragility (not full H1) | Approximation only |
| ol_coherence_field | WIRED (9 of ~15 functions consumed) | Helmholtz / BE-RAR / anchor / dual source / couplings | `green_function`, `solve_reaction_diffusion_steady`, `align_source`, `alignment_scalars`, `linear_source`, `support_phase_kernel` exposed but daemon-dark |
| ol_grammar | INTERNAL_ONLY | Re-Pair secondary index scaffold | **No pyo3, no production callers** |
| ol_duress | INTERNAL_ONLY | duress-key + decoy volume scaffold | **No pyo3, no production callers** |
| ol_codegen | INTERNAL_ONLY | CL → Rust scaffold | Standalone tool, never run in daemon |
| ol_canon | INTERNAL_ONLY | deterministic byte encoder | Used internally by ol_pair_qr / ol_capability — correct shape |
| ol_proximity_pair | WIRED | Factor-2 channel reciprocity | — |
| ol_device_mesh | INTERNAL_ONLY (repeat for emphasis) | row 8 personal device mesh | Single biggest dark-surface |
| ol_threshold_recovery | WIRED | Shamir + field-bound shares | — |
| ol_pair_qr | WIRED | Factor-1 QR pair flow + SAS | — |
| ol_onion (+ sphinx + obfs) | WIRED | nested AEAD + Sphinx Coherence + obfs4 | — |
| ol_discovery | WIRED | Kademlia DHT pieces | Iterative-lookup driver still Python-orchestrated |
| ol_fuse | INTERNAL_ONLY | FUSE scaffold (Linux) | `mount()` not yet wired; daemon has no `fuse_native.py` |
| ol_winfs | INTERNAL_ONLY | Windows FS scaffold | Backend features not landed |
| ol_fskit | INTERNAL_ONLY | macOS FSKit scaffold | Swift/objc bridge not landed |
| ol_bandit | WIRED | Thompson sampling per knob | — |

## The dark-surface set (what to wire next)

In descending order of "ships-but-isn't-reached":

1. **ol_device_mesh (21 535 LOC, INTERNAL_ONLY)** — row 8 personal device mesh. Needs a `device_mesh_native.py` adapter and pyo3 submodule. This is the biggest single block of unused Rust in the workspace.
2. **ol_transfer (2 709 LOC)** — would close the anchor + projection multicast gap by fusing chunk_store + quic + bloom (and, after one extension, fountain + erasure + netcode) into a single Python-callable engine. Currently Python `native_transfer.py` reinvents most of this on top of the lower primitives.
3. **ol_netcode (435 LOC, INTERNAL_ONLY)** — A⊕B coded relays are core to the "sovereign relay" claim but have no pyo3 surface.
4. **ol_grammar (341 LOC) + ol_duress (519 LOC)** — Phase D #5/#6. Built as scaffolds; daemon never calls them. The compressor lib at `ol_grammar` would also be useful for secondary chunk dedup once wired.
5. **ol_fuse / ol_winfs / ol_fskit** — Layer-9 filesystem surface; per-platform mount endpoints still unbuilt.
6. **ol_coherence_field unreached functions** — `green_function`, `solve_reaction_diffusion_steady`, `align_source`, `alignment_scalars`, `linear_source`, `support_phase_kernel` are all exposed but the daemon never calls them. The Green-function path is the natural fit for "one solve, many readouts" prefetch scoring.
7. **ol_codegen** — checked in but not part of any CI byte-equivalence gate yet, so the "Coherence types are spec; Rust types are codegen'd" doctrine (ADR-0028) is aspirational. Production code in the affected crates is hand-written.

## Anchor + projection multicast composition (focused answer)

`ol_chunk + ol_fountain + ol_erasure` can in principle compose, but only one piece is wired and the integrator is missing. Concretely:
- `ol_chunk::scan_to_vec` produces CDC chunks with deterministic addresses (✓ wired).
- `ol_fountain::LtEncoder` turns one chunk into infinite-stream LT symbols (✓ wired, called from `fountain.py`).
- `ol_erasure::encode_stripe` splits a chunk into K data + M parity shards (✓ wired, called from `durability.py`).
- `ol_netcode::encode_coded_packet` combines multiple chunks via XOR for one-packet-multicast (✗ no pyo3, no Python use).
- `ol_transfer::TransferEngine` integrates store + quic + bloom (✗ no pyo3, Python re-implements).

The "anchor (chunk) + projection (fountain/erasure/netcode) + multicast (transfer engine)" pipeline is not assembled anywhere as a single Rust type. To realize it, the right ship is either a new `MulticastSession` struct in `ol_transfer` that takes `(chunk_id, peer_set, redundancy_target, projection: LT | RS | XOR)` and emits coded burst frames, or a new `ol_swarm` crate that owns the composition. Either path also requires the FountainBurst QUIC frame called out in `ol_fountain/src/lib.rs:18-20`.

## server.py control plane — `agent-a17e4fc32ec331f6a` (15 findings)

### server.py control plane #1
**1. **CRITICAL — server.py:1796 / `api_file_download` (12965)** — Path-traversal regex too loose. Route is `r"/api/files/{name:.+}"` which allows `/` in `{name}`. The handler defends with `safe = Path(…**

### server.py control plane #2
**2. **HIGH — server.py:6157 `api_setup_device_invite_confirm`** — Confirms enrollment + mints device cert with no SAS verification. Whoever holds the bearer-token invite + calls `/claim` then `/confirm…**

### server.py control plane #3
**3. **HIGH — server.py:8043+ `api_courier_export` family** — Multiple `{"ok": false, "error": "<code>", "message": str(exc)}` paths return `str(exc)`. `str(exc)` can be an absolute Windows path (Permis…**

### server.py control plane #4
**4. **HIGH — server.py:9684 `api_remove_folder`** — `name = request.match_info["name"]` passed straight to `folder_engine.remove_folder(name)`, then exception's `str(e)` returned in 500. No length cap,…**

### server.py control plane #5
**5. **HIGH — server.py:11196 `api_set_rendezvous`** — Accepts arbitrary `urls: list[str]` and live-applies. No scheme/host validation in this handler (delegated to `state.set_rendezvous_urls`, but a ma…**

### server.py control plane #6
**6. **HIGH — server.py:1848 `_guarded`** — No CSRF defense. Cookie-based auth (`COOKIE_NAME`) + state-mutating POST/DELETE → if a victim opens a malicious page on `localhost:other_port` (or any same-si…**

### server.py control plane #7
**7. **HIGH — server.py:12586 `api_send_file` exception sink** — `log.exception("send_file failed: %s", e)` + `_translate_send_error(e)` — confirmed the empty-string-exception path lands here; if `_tran…**

### server.py control plane #8
**8. **MEDIUM — server.py:11021 `api_global_search`** — No rate limiting on FTS5 + inbox-scan + peer-table-scan. `q=*` or pathological FTS5 query can pin the daemon. Same for `api_search` (12250). **Fix…**

### server.py control plane #9
**9. **MEDIUM — server.py:13132 `api_file_reveal`** — `path = (inbox_dir() / safe).resolve()` then `subprocess.Popen(["explorer.exe", f"/select,{path}"])`. The resolve happens *after* the `safe != name`…**

### server.py control plane #10
**10. **MEDIUM — server.py:8085, 6085** — `qr_url` and `/api/setup/device-invite/qr.svg?token=...` carry the invite token in the query string. The QR endpoint is `_guarded` so the UI token is also impli…**

### server.py control plane #11
**11. **MEDIUM — server.py:9819 `api_folder_tree`** — No cap on `entries_raw` count. `list_manifest(name)` of a million-entry folder + filter + serialize → JSON in one allocation. Daemon OOM. **Fix:** a…**

### server.py control plane #12
**12. **MEDIUM — server.py:11459 `api_edit_message` / 11499 `api_delete_message`** — No authorization that the caller "is" the sender beyond `rec.direction == "out"`. Since the daemon's UI is single-use…**

### server.py control plane #13
**13. **MEDIUM — server.py:7567 `api_self_mesh_remote_instruct`** — `scope = body.get("scope") or {}` — no schema validation on `scope` dict (path/action/etc). A buggy/malicious browser-tab can craft a …**

### server.py control plane #14
**14. **MEDIUM — server.py:1992 `_index`** — `bootstrap_ok = request.query.get("t") == self.token` uses `==` not `hmac.compare_digest`. Inconsistent with `_check_token` at 1814. Timing oracle on the boo…**

### server.py control plane #15
**15. **LOW — server.py:10286 `api_set_presence`, 11541 `api_set_typing`, 11566 `api_set_read_marker`** — All broadcast via `self.broadcast({...})` *after* state mutation with no lock. The WS-broadcast …**

**Cross-cutting:** every `api_*` route I sampled IS behind `_guarded` — no missing-auth bypass found in the route table. The two unguarded routes (`api_peer_rtc_ice_config_public`, `api_public_self_mesh_enrollment_invite_preview`) are intentional + documented and return only STUN/preview info. The real systemic gaps are #1 (no resolve-traversal check), #6 (no CSRF), #3/#4 (raw `str(exc)` leakage), and #14 (timing-unsafe bootstrap compare).

## daemon send_file pipeline — `agent-a371fb983062df7ff` (4 findings)

### daemon send_file pipeline #1
**1. Build `intent = plan_transfer_intent_for_manifest(...)` (14004).**

### daemon send_file pipeline #2
**2. Call `_should_build_cdc_offer(...)` (14004–14008) → `can_offer_cdc`.**

### daemon send_file pipeline #3
**3. **Hardcoded QUIC override** at **14020–14029** (`QUIC_SMALL_FILE_THRESHOLD = 512 * 1024`): if file ≤512 KiB AND peer has `NATIVE_TRANSFER_V1` AND `self._quic_peer_ports.get(peer_fp)` is set, flip `…**

### daemon send_file pipeline #4
**4. `planned_wire_mode = "cdc" if can_offer_cdc else "stream"` at **14076**.**

Then a **second selector layer** exists at **14117–14160**: `UniversalCommsFabric.from_inventory_and_candidates(...)` builds a `fabric_decision`, **but** its decision is recorded into `base_metadata["fabric_plan"]` (14211) and feeds `route_observations` — it does NOT override `can_offer_cdc` or `planned_wire_mode`.

The actual three-way fork lands at **14438**: `cdc_used = can_offer_cdc and first_reply.get("t") == "FILE_WANTS"` decides CDC vs baseline AFTER the offer round-trip. The QUIC-CDC sub-fork (`cdc_quic_eligible`) lives at **14602–14606** inside the CDC branch.

**Where `ol_selector` would slot in:** replace the manual ladder at **14020–14080** with a single call returning `(wire_mode, transport_kind, reason)`. Concretely:
- Delete the `QUIC_SMALL_FILE_THRESHOLD` override (14020–14029).
- Replace the `planned_wire_mode = "cdc" if can_offer_cdc else "stream"` at 14076 with `mode_decision = ol_selector.decide(size=size, peer_caps=peer_features, fabric=fabric_plan, brain=transfer_brain_decision, field=field_state)`.
- The second QUIC override at **14602–14606** (CDC-over-QUIC eligibility) becomes redundant.

Existing dependency that already points there: `transfer_brain.decision_from_observations(...)` at **14161–14174** already produces a unified decision dict — `ol_selector` is the natural fusion of `_should_build_cdc_offer` + the QUIC override + `UniversalCommsFabric.plan(...)` + `decision_from_observations(...)`.

---

## Persistence + state.db — `agent-a4794adc98e88c1f3` (15 findings)

### Persistence + state.db #1
**1. **HIGH — `state.py:3295-3325` `update_transfer` lost-update race.** Reads `get_transfer(id)` outside `self._write_lock` then upserts. Two concurrent updates (e.g. parallel chunk ACKs + a status fli…**

### Persistence + state.db #2
**2. **HIGH — `paths.py:142-146` data_dir mkdir without restrictive mode.** `data_dir().mkdir(parents=True, exist_ok=True)` inherits process umask, so `state.db` (DR chain keys, message bodies, group se…**

### Persistence + state.db #3
**3. **HIGH — `state.py:475-490` no `PRAGMA integrity_check` on boot.** A corrupted state.db crashes the daemon on first query with `sqlite3.DatabaseError`. No fallback / sidecar copy. Fix: run `PRAGMA …**

### Persistence + state.db #4
**4. **MED — `state.py:233-244` outbox UNIQUE(peer_fp, msg_id) is at-least-once.** `record_outbox_attempt` increments without atomicity vs. send result; on crash between "ACK received" and `mark_outbox_…**

### Persistence + state.db #5
**5. **MED — `state.py:3160-3170` `list_peer_files` has no LIMIT.** Full table scan + materialized list of every file message ever for a peer. On a chatty peer with 10k file messages it ships megabytes …**

### Persistence + state.db #6
**6. **MED — `state.py:206-225` `transfers.metadata.path` carries raw absolute filesystem paths in plaintext.** Lockbox path-PII encryptor (`state.py:444-473`) covers `chunk_sources` + `file_index_cache…**

### Persistence + state.db #7
**7. **MED — `server.py:13016-13021` Content-Disposition header injection.** `download_name = rec.metadata["name"] or path.name` is interpolated unescaped into `f'inline; filename="{download_name}"'`. I…**

### Persistence + state.db #8
**8. **MED — `state.py:492-565` `_migrate` `current_version` captured once.** Local `current` is read once at the top of `_migrate` and passed unchanged to every `_run_atomic_migration(current_version=c…**

### Persistence + state.db #9
**9. **MED — `state.py:3303` `update_transfer` falls back to `current.metadata` silently.** If `get_transfer` returns a record whose `metadata_json` failed to JSON-decode (corrupt row), `current.metadat…**

### Persistence + state.db #10
**10. **MED — `state.py:4358-4389` `enqueue_outbox` ignores msg_kind on conflict.** `INSERT ... ON CONFLICT DO NOTHING` returns the existing row id but doesn't update `msg_kind` or `msg_body_json`. If t…**

### Persistence + state.db #11
**11. **LOW — `state.py:4391-4415` `list_outbox` ordering by `enqueued_ms ASC, id ASC`.** OK in isolation, but `_now_ms()` is wall-clock; an NTP backward jump between two enqueues from the same peer mea…**

### Persistence + state.db #12
**12. **LOW — `state.py:225` `transfers` lacks `idx_transfers_status`.** `prune_transfers` filters `WHERE status IN (...)` with no index; on a long ledger this is O(n). Add `CREATE INDEX idx_transfers_s…**

### Persistence + state.db #13
**13. **LOW — `state.py:475-490` `wal_autocheckpoint = 50` is aggressive.** Default is 1000. Forcing checkpoint every ~200 KB amplifies fsync cost. The secure_delete justification (don't leak plaintext …**

### Persistence + state.db #14
**14. **LOW — `state.py:3327-3331` `get_transfer` accepts any string.** No format validation. `transfer_id="../../etc/passwd"` is harmless because it's used only as a SQL parameter PK lookup, BUT the fi…**

### Persistence + state.db #15
**15. **LOW — `state.py:485-489` `secure_delete = ON` covers state.db but not the inbox dir.** Disappearing-messages erases the row body, but the original received-file blob on disk in `inbox_dir()` sur…**

---

**Files examined:**
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\state.py`
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\transfer_intent.py`
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\trust_ledger.py`
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\cap_migration.py`
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\paths.py`
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\daemon.py` (send_file + upsert_transfer + _update_transfer)
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\server.py` (api_outbound_file_download)

**Notes on findings NOT raised:**
- Migrations ARE per-step transactional with `BEGIN IMMEDIATE` + ROLLBACK on failure (good).
- WAL mode IS on; concurrent reads during writes work.
- The memory's "GUID/varchar UUID footgun" applies to SmartChartIQ (SQLAlchemy + PG/SQLite dialect mismatch), NOT to One Link — One Link uses raw sqlite3 with TEXT columns throughout, no ORM, no dialect bridging.
- `/api/outbound_files/<id>` path-traversal is blocked at the SQL layer (id is PK lookup); only finding 7 (header injection via name) and 14 (defense-in-depth validation) remain.
- Identity/master-seed/cap-root keys ARE chmod 0o600 — only state.db and inbox dir leak via mode.

## Crypto + handshake — `agent-a491c917ab27d60c4` (0 findings)

## Web UI — `agent-a522968418149ae17` (15 findings)

### Web UI #1
**1. **HIGH — XSS via `e.message` in folder-conflicts modal** — `index.html:16757-16758`. `$("#conflicts-list").innerHTML = ` `` `<div class="empty">Failed to load conflicts: ${e.message || e}</div>` ``…**

### Web UI #2
**2. **HIGH — Same XSS pattern in 5 sibling error renderers** — `11757` (discover modal), `18994` (recovery host), `25076` (storage totals), `28935` (sovereignty body), `15646` (file preview). All do `i…**

### Web UI #3
**3. **HIGH — Inline `onerror` handler in QR `<img>` injects raw HTML** — `index.html:12022-12024`. `qrHost.innerHTML = `…`onerror="this.parentNode.innerHTML='<div…>QR generation failed</div>'"`…`. Surv…**

### Web UI #4
**4. **HIGH — Session token written to `location.href` on session-expired reload** — `index.html:10224`: `location.href = location.pathname + "?t=" + encodeURIComponent(token);`. The full token lands in…**

### Web UI #5
**5. **MEDIUM — `document.querySelector` with un-escaped peer-controlled `m.id`** — `index.html:22811`. Unlike sibling paths (14912, 19374, 23493) which wrap with `CSS.escape`, this one doesn't. A messa…**

### Web UI #6
**6. **MEDIUM — Race in `state.messages` mutation across WS handlers** — `index.html:20174-20349`. `msg_edit`, `msg_delete`, `reaction`, and `msg` all do `state.messages.find(x => x.id === ...)` then mu…**

### Web UI #7
**7. **MEDIUM — `transferForMessage` is O(N·M) per render** — `index.html:12716-12725`. Walks `state.transfersById.values()` (up to 80) inside `renderFileBubble`, called once per message bubble (up to 2…**

### Web UI #8
**8. **MEDIUM — Misleading "Drag the original in again" toast at `openMessageFile`** — `index.html:12404-12409`. With the new `/api/outbound_files/<transfer_id>` endpoint, this branch only fires when **…**

### Web UI #9
**9. **MEDIUM — Em-dashes in user-facing copy violate `feedback_no_em_dashes.md`** — User-facing strings (not comments): line 9991 ("Channel needs renegotiation — sends will queue…"), 11158 ("…let it ru…**

### Web UI #10
**10. **MEDIUM — Doctrine violation (adversarial / "what-we-can't" framing)** — `index.html:7620` ("Files from paired devices land here. We don't peek."), `9105` ("We can't help you there."), `8565` ("……**

### Web UI #11
**11. **MEDIUM — `state.transfers.slice(0, 80)` discards in-flight WS state** — `index.html:20454`. After every transfer event the array is hard-capped at 80 but `state.transfersById` Map (line 20455) i…**

### Web UI #12
**12. **MEDIUM — `URL.createObjectURL` for cached outbound files never revoked on tab close** — `index.html:12159` allocates a blob URL per outbound image preview; `rememberOutboundFile` at 12145 only r…**

### Web UI #13
**13. **LOW — `setInterval` cluster at 19586-19591 never cleared on auth loss** — six polling timers (5/4/8/15/30/12 s) keep firing after a 401, generating a storm of `_maybe401` calls that all try `_at…**

### Web UI #14
**14. **LOW — Accessibility: no focus trap in modals built via `innerHTML`** — modal panes at 11240 (version-mismatch), 11392 (camera/mic permission), 19468 (what's new), 20920 (image editor), 21438 (sl…**

### Web UI #15
**15. **LOW — Empty state corruption: `renderFileBubble` on a transfer with `total_bytes=0`** — `index.html:15484`. `Math.max(0, (t.total_bytes || 0) - (t.progress_bytes || 0))` is fine but `t.progress_…**

**Files referenced:** `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\web\index.html`

## Transfer stack survey — `agent-a580a5c320383207d` (10 findings)

### Transfer stack survey #1
**### 1. **SENDER PIPELINE** — Entry Point & Per-Chunk Flow**

**PRODUCTION PATH (legacy, always active):**
- `daemon.send_file()` @13800+: Opens file, CDC chunks, dispatches via **FILE_CHUNK** (unencrypted base64) or **FILE_BIN_CHUNK** (binary frame).
- Read → no per-chunk encryption in legacy path → hash (BLAKE3 for manifest) → base64 frame → transport → ACK-driven backpressure.
- No forward secrecy; chunk_id is a one-shot BLAKE3 of plaintext content.

**OPT-IN PATH (native fast path, env-gated):**
- **ONE_LINK_NATIVE_TRANSFER=1** flag gates `native_transfer_used` decision @13820.
- Only activates if **both peers advertise NATIVE_TRANSFER_V1** capability.
- Read → `native_session.encrypt_chunk_bytes(data, address_kind=...)` (ADR-0026) → **FILE_NATIVE_CHUNK** wire frame.
- Per-chunk ratchet state lives in `NativeTransferSession.ratchet` (BLAKE3 chain key, index-based derivation).
- Shipped but **NOT DEFAULT** — operators must opt-in. Per ADR-0026: "legacy path has 2,952 regression tests; native has unit coverage only."

**File enters at:**
- `daemon.send_file()` @13683 — gates on capability, optional native_session init @13820.
- `native_transfer.NativeTransferSession.encrypt_chunk_bytes()` — performs CDC (via `ol_chunk.cdc_iter`) **on the sender** for the native path.

### Transfer stack survey #2
**### 2. **RECEIVER PIPELINE** — Reassembly & Partial Recovery**

**PRODUCTION (legacy chunks):**
- Inbound dispatch: `_on_peer_message()` → `_handle_file_binary_chunk()` or `_handle_file_chunk()`.
- Write to temp file; hash every chunk into BLAKE3 accumulator (stream mode).
- **No resume-on-disconnect**: `_incoming_files` dict is in-memory, loses state on peer disconnect.
- Partial bytes evicted @10801 on daemon startup (security audit L11): "delete on-disk partial files for in-flight inbound transfers."
- Simple: received_bytes tracker, no checkpoint format.

**OPT-IN (native chunks):**
- `_handle_file_native_chunk()` @6665: deserialize FILE_NATIVE_CHUNK, sequence-check (@6704), decrypt via `session.decrypt_chunk()`.
- AEAD tag failure @6746 aborts transfer.
- Same write-to-temp path as legacy; **no resume either**.
- Matched session on receiver built via `channel.get_or_create_native_transfer_session()` (same KEM derivation as sender).

### Transfer stack survey #3
**### 3. **CRYPTO LAYER** — Symmetric Cipher & Forward Secrecy**

**Cipher per chunk:**
- **Primary**: AES-256-GCM via RustCrypto `aes-gcm` crate (5 GiB/s/core on AES-NI).
- **Fallback**: ChaCha20-Poly1305 (3 GiB/s/core, constant-time).
- Selection: `ol_aead.default_aead_kind()` probes host caps; no user control.
- **Frame layout** (ADR-0002): 16 KiB plaintext frames, each with 16-byte auth tag. Multi-frame per chunk for partial-chunk integrity (unused in transport, present for FUSE reads).

**Forward secrecy:**
- **Double Ratchet** (`double_ratchet.py`): Signal-style, X25519 DH ratchet + HKDF-SHA256 chain key. Implements post-compromise security via ephemeral-per-message + skipped-message-key window (MAX_SKIP_KEYS=1000, MAX_MSG_PER_CHAIN=2³²).
- **Status**: Shipped as pure crypto primitive, **NOT WIRED into daemon send_file as default**. Exists in codebase but legacy FILE_CHUNK has no ratchet; native FILE_NATIVE_CHUNK uses per-**chunk** ratchet (ADR-0020), not message-level.

**Per-chunk ratchet (ADR-0020):**
- `native_transfer.NativeTransferSession`: holds a `ChunkRatchet` (BLAKE3 chain key derived from session root).
- Each chunk index → one key via HKDF.
- Compromise of one chunk key reveals **only that chunk**, not earlier ones (forward secrecy at chunk boundary, not message).

**Post-quantum hybrid KEM (ADR-0017):**
- ML-KEM-768 + X25519, both trusted.
- Surfaces via `pq_hybrid.default_kem()` → `establish_session_pair()` in native_transfer.
- **Wired**: session establishment, not yet default for daemon ↔ daemon (daemon still uses WebRTC/DTLS-SRTP handshake).

**At-rest encryption of bundle/index:**
- `ol_chunk_store`: LSM-indexed, persists encrypted chunks + manifest.
- Manifest WAL coupled (@FILE_ENGINE_V2_PLAN: "crashed between chunk-write + manifest-update converges").
- No bundle-level encryption; individual chunk_ids are content-addressed. Metadata (filenames, sizes) **sent in cleartext** in FILE_OFFER message.

### Transfer stack survey #4
**### 4. **TRANSPORT** — QUIC vs WebRTC vs Relay Fallback**

**Production default (WebRTC):**
- `peer_rtc.py`: DTLS-SRTP over UDP.
- Datachannel carries `FILE_CHUNK` JSON + binary payload.
- **Always active**; no opt-in.
- Per `peer_transport.py`: facade wraps the DataChannel, serializes send/recv.

**QUIC native fast path (Phase A2, not yet default):**
- `peer_quic.py` + `ol_quic` crate (quinn-based).
- Shipped with quinn transport stack; **daemon peer ↔ peer cutover NOT WIRED** per FILE_ENGINE_V2_PLAN @56: "Not wired — daemon still uses WebRTC. Multi-day feature implementation; not in current arc."
- File chunks would travel as QUIC streams if activated (capture via `FRAME_CHUNK_REQUEST` / `FRAME_CHUNK_RESPONSE` constants in peer_quic).
- Dual-stack model: WebRTC default, QUIC activates per-peer when both advertise `QUIC_TRANSPORT_V1` capability (separate from NATIVE_TRANSFER_V1).

**Relay fallback (v0.5.5):**
- `relay_client.py` + rendezvous-served WebSocket tunnel.
- Transparently wrapped in `_handle_relay_inbound_session()` @7893 — tunneled bytes land in same `_handle_peer()` dispatch loop.
- Per-relay metrics tracked (@1200) for load-balancing via `_pick_best_relay()`.

**Fallback chain:** Direct WebRTC → relay (if rendezvous provides relay URLs). No TCP fallback shipped in this audit window.

### Transfer stack survey #5
**### 5. **NATIVE FAST PATH** — FILE_NATIVE_CHUNK Wire Message**

**Wire shape** (ADR-0026 @28–40):
```json
{
  "t": "FILE_NATIVE_CHUNK",
  "blob": "<blob_hash_hex>",
  "seq": <monotonic>,
  "chunk_id": "<32B BLAKE3 hex>",
  "plaintext_len": <original_size>,
  "data": "<base64 native AEAD ciphertext>"
}
```

**Sender side** (@13830):
```python
record = native_session.encrypt_chunk_bytes(data, address_kind=native_address_kind)
chunk_msg = make_msg("FILE_NATIVE_CHUNK", ..., chunk_id=record.chunk_id.hex(), ...)
```

**Receiver side** (@6729–6745):
```python
session = channel.get_or_create_native_transfer_session()
data = session.decrypt_chunk(record)  # AEAD tag checks chunk_id as AAD
```

**Is it default?** **NO** — env-gated by `ONE_LINK_NATIVE_TRANSFER=1`. Per ADR-0026 @92: "env-flag opt-in instead of default-on [due to] Production reliability... legacy path has 2,952 daemon regression tests... new path has full unit coverage and the integration tests..."

### Transfer stack survey #6
**### 6. **CONCURRENCY** — Chunk Parallelism & In-Flight Window**

**Adaptive pipeline** (`transfer_brain.py`):
- `AdaptiveTransferScheduler` tracks `window_chunks` (adaptive per-transfer estimate).
- `STREAM_PIPELINE_MAX_CHUNKS` cap (search hit ~@401).
- Stream loop waits for ACKs via `_settle_one_stream_ack()` before advancing window (@13880–13892).
- Batch ACK negotiated per transfer via `FILE_ACK_BATCH` capability (int field `ack_batch`).

**Multi-path:** No explicit multi-path; single channel per peer. Swarm fetch (@`plan_swarm_sources()`) pulls missing chunks from multiple swarm peers in parallel via semaphore (@6346: `effective_concurrency = min(base_concurrency, ...)`).

**Per-chunk parallelism within AEAD:** `encrypt_chunks_par()` / `decrypt_chunks_par()` in `ol_aead` (exists but unused by the stream loop, which processes chunks sequentially).

### Transfer stack survey #7
**### 7. **INTEGRITY** — Per-Chunk Hash & Full-File Verification**

**Per-chunk:**
- Sender computes BLAKE3 content address via `native_session.encrypt_chunk_bytes()` → `NativeChunkRecord.chunk_id` (32 bytes).
- Receiver AEAD tag binds `chunk_id` as AAD; tamper fails decrypt.
- Legacy path: `chunk_id` is one-shot BLAKE3, no protection against swap unless manifest is trusted.

**Full-file:**
- Manifest hash (`merkle_root`) built from chunk_id tree (or simple list for small files).
- Verified post-transfer via `_verify_incoming_file()` (search hits suggest full-file hash check against sent manifest).

**Corrupt chunk caught:** AEAD tag failure (@6746) aborts transfer. Legacy path relies on manifest mismatch at end.

### Transfer stack survey #8
**### 8. **RESUME ON DISCONNECT** — Checkpoint & Partial State**

**Status: NOT SHIPPED**
- `_incoming_files[blob]` is in-memory dict; lost on peer disconnect.
- `_schedule_resume_paused()` (@10177) reschedules sender-side retries, not receiver-side recovery.
- @10801: "delete on-disk partial files for in-flight inbound transfers" — partials are **not kept**.
- No checkpoint index, no resumed offset tracking.

**Workaround:** User retries the full send; swarm dedup catches already-received chunks.

### Transfer stack survey #9
**### 9. **CAPABILITY GATING** — Default Permissions & Revocation**

**Sender-side gate:**
- `_capability_allowed(peer_fp, FILES)` @3760, @13690.
- Checks `_cap_store` (Macaroon-style capabilities with attenuation per ADR-0021).
- Pattern: default-deny unless peer has explicit grant.
- **FILE_OFFER begins transfer; FILES cap verified before send_file even starts.**

**Receiver-side gate:**
- `_capability_allowed(peer_fp, FILES)` @6696 (initial check) + **@6695 mid-stream re-check**.
- Revocation mid-transfer aborts with `capability_revoked_mid_stream` ACK.
- No size caps or pattern caps wired; per FILE_ENGINE_V2_PLAN, capability layer is Macaroon-based, caveats (size/pattern) are **designed but not enforced at the daemon yet**.

### Transfer stack survey #10
**### 10. **LIMITS** — File & Bundle Size Caps**

```python
MAX_INCOMING_FILE_BYTES = 1 GiB          # Receive cap
MAX_DECLARED_FILE_OFFER_BYTES = 16 TiB   # Declared-size cap (attacker can't amplify)
MAX_TRANSFER_FILE_NAME_BYTES = 240       # Filename length
CDC_AUTO_INDEX_MAX_BYTES = 128 MiB       # Below this, pre-compute index
```

**Throughput benchmarks** (FILE_ENGINE_V2_PLAN scorecard):
- CDC layer: 2.94 GiB/s (Windows).
- AEAD (AES-NI): 9.0–9.7 GiB/s measured.
- Full pipeline: 442 MiB/s (NTFS WAL bottleneck, not a crypto issue).
- QUIC loopback: 29.8 GiB/s encode (LAN run pending real hardware).

---

## Summary: Production vs Opt-In vs Dead Code

| Component | Status | Details |
|---|---|---|
| **Legacy FILE_CHUNK** | PRODUCTION (always active) | 2,952 tests; unencrypted base64 plaintext |
| **Native FILE_NATIVE_CHUNK** | OPT-IN (ONE_LINK_NATIVE_TRANSFER=1) | Full-pipe integration tests pass; not default |
| **QUIC transport** | SHIPPED, NOT WIRED | Peer ↔ peer cutover deferred; WebRTC default |
| **Double Ratchet** | SHIPPED, NOT WIRED | Pure crypto primitive; no message-level forward secrecy in daemon |
| **Per-chunk ratchet** | SHIPPED IN NATIVE PATH | BLAKE3 chain, forward-secret at chunk boundary |
| **ML-KEM-768 hybrid** | WIRED IN SESSION SETUP | Only via native_transfer; daemon handshake still DTLS-SRTP |
| **Resume on disconnect** | NOT SHIPPED | Partials deleted; user retries full send |
| **Capability revocation** | WIRED (mid-stream check) | Patterns/sizes are designed but not enforced |
| **Relay fallback** | SHIPPED & ACTIVE | Transparent; no relay-aware optimizations for file chunks yet |

**Bottom line:** One Link is a sophisticated Rust-native engine designed to beat Dropbox/Syncthing on speed, durability, and dedup. However, **the production daemon still ships legacy Python-orchestrated unencrypted chunks by default**. The native fast path (per-chunk AEAD + ratchet + fountain codes) is built, tested, and opt-in-ready, but not yet the default path. The QUIC cutover and Double-Ratchet message-level forward secrecy are designed (decision documents + Rust crates exist) but not wired into the daemon's send_file loop. This is intentional: ship safe, verify extensively, default-flip in a follow-up commit (the "shadow-to-authoritative cutover" pattern, per ADR-0024).

## Tests + skip markers — `agent-a65344dfb0d717b8a` (0 findings)

## QUIC + relay transport — `agent-a84e416dddb450b02` (0 findings)

## Daemon send/recv paths — `agent-aa88bd73c820bb225` (1 findings)

### Daemon send/recv paths #1
**### Honourable mentions (not in top 15)**

- `daemon.py:17343-17348` — `make_msg("FILE_OFFER", ...)` doesn't currently include `native_transfer_indexed_v1=True` hint; if peer expects an explicit hint to enable its receive-side native path, mismatch is invisible.
- `daemon.py:10343` — telemetry `try/except Exception: pass # pragma: no cover` hides ImportError vs AttributeError — `_NT_LEGACY` could be referenced before the import succeeds; mostly benign but obscures real diagnostics.
- `daemon.py:18611-18613` — when `last_error is None` BUT all peers failed (e.g. zero-peer-candidates branch), error message reads "no peer succeeded (no transient errors recorded)" which is technically truthful but UI-hostile.

## Async concurrency — `agent-ac7b5e24234936a05` (15 findings)

### Async concurrency #1
**1. **CRITICAL — `server.py:13451`** — `broadcast()` fires `asyncio.create_task(ws.send_json(event))` per event per WS client with **no reference held, no done-callback, no exception swallow**. Every m…**

### Async concurrency #2
**2. **CRITICAL — `daemon.py:20793`** — `_quic_dial_lock` is a **single global lock** for all per-peer QUIC dials; `await asyncio.to_thread(connect_blocking, ..., 10_000)` is held inside it. One slow/de…**

### Async concurrency #3
**3. **HIGH — `daemon.py:1435,1563,16427`** — `_outbound_session_create_locks`, `_outbox_flush_locks`, `_resume_lock_dict` are dicts of `asyncio.Lock` keyed by `peer_fp` that are **never pruned**. Every…**

### Async concurrency #4
**4. **HIGH — `daemon.py:21087 stop()`** — `_endpoint_verify_tasks` (sets at line 1568) and `_quic_inbound_tasks` (line 20856) are **never cancelled/awaited in `stop()`**. Tests + dev hot-reload leak ru…**

### Async concurrency #5
**5. **HIGH — `daemon.py:8514`** — `asyncio.create_task(_runner())` inside `_finish_cdc_file_in_background` — orphan task, no set, no callback. Any exception escapes only as a warning log; if the loop i…**

### Async concurrency #6
**6. **HIGH — `daemon.py:13554` + `13609`** — `_courier_monitor_task` (in `server.py`) — start logs but stop only does `await self._courier_monitor_task` without `(asyncio.CancelledError, Exception)` in…**

### Async concurrency #7
**7. **MEDIUM — `daemon.py:20114-20117`** — Same-port QUIC rebind cancels `_quic_accept_task` and creates a new one **without awaiting the cancelled task**. Old accept_loop is still running its `to_thre…**

### Async concurrency #8
**8. **MEDIUM — `daemon.py:20945 _quic_inbound_frame_loop`** — `while True:` over `to_thread(recv_frame_blocking, 30_000)`. Exception path at 20952 `return`s without removing `peer_fp` from `_quic_inbou…**

### Async concurrency #9
**9. **MEDIUM — `daemon.py:2271 _dm_reaper_loop`** — re-raises `CancelledError` correctly, but `except Exception:` swallows DB-level errors that leave the reaper running against a closed state. **Impact…**

### Async concurrency #10
**10. **MEDIUM — `daemon.py:20862 _quic_accept_loop`** — `except Exception as e: ... continue` with `await asyncio.sleep(0.5)`. Endpoint permanently broken (e.g. fd closed) → infinite tight-ish loop log…**

### Async concurrency #11
**11. **MEDIUM — `daemon.py:13759-13776`** — `_outbound_session_create_locks[peer_fp]` is held across `_probe_outbound_session(existing)` which itself acquires `sess.lock`. Lock ordering = **create_lock…**

### Async concurrency #12
**12. **MEDIUM — `daemon.py:19099-19104`** — `for fp, conn in self._quic_outbound.items():` (no `list()` wrap) inside the control-socket `quic_status` handler. The handler is `async` and the dict body d…**

### Async concurrency #13
**13. **MEDIUM — `daemon.py:9858 happy_eyeballs`** — `tasks = [create_task(_attempt(...))]`; on first-winner it cancels pending but doesn't `await` cancellations. Cancelled tasks may finish writing to `…**

### Async concurrency #14
**14. **LOW — `daemon.py:19057`** — `with contextlib.suppress(Exception): asyncio.create_task(...)`. `create_task()` itself only raises if no event loop is running; suppression here masks a programming …**

### Async concurrency #15
**15. **LOW — `daemon.py:20283 _prune_loop`** — body wraps every sub-tick in `contextlib.suppress(Exception)`. If `_prune_chunk_cache` raises a `MemoryError` (BaseException-derived but `Exception` for O…**

## Service worker — `agent-ac8e452c9c6a9bbbd` (5 findings)

### Service worker #1
**### CRITICAL FINDINGS**

**1. Unconditional `skipWaiting()` + `clients.claim()` (sw.js:37, 50)**
- `skipWaiting()` on install forces the new SW to take over immediately, replacing the old worker without user consent.
- Combined with `clients.claim()` on activate, this means a fresh SW deploy instantly controls all tabs.
- **Risk:** A compromised SW update can hijack live sessions in-place. No intermediate state where the old SW continues serving.
- **Status:** CRITICAL — but mitigated by the fact that the daemon (127.0.0.1) is local and source is trusted in dev. In production OTA, this is a high-velocity vector.

**2. Missing pinned-signature verification (no evidence in codebase)**
- The audit doc notes "Service Worker pinned-pubkey signature verification (queued)" — the SW source code contains NO signature checks, no pinned key storage, no verification before cache or execution.
- On `/` fetch (network-first, sw.js:66–79), the SW caches `res.status === 200` with zero integrity validation.
- On static assets (sw.js:84–98), the same: any 200 response is cached, no Content-Type or signature check.
- **Risk:** If the daemon serves a poisoned index.html (MITM, daemon compromise, or malicious JS injection), the SW caches and serves it indefinitely until manual user cache clear.
- **Status:** CRITICAL — design gap. Not exploitable locally (127.0.0.1 is LAN-only), but the signature feature **must** ship before any wider deployment.

### Service worker #2
**### HIGH-RISK FINDINGS**

**3. postMessage handler without source/origin verification (sw.js:172–194)**
- Two commands accepted: `type === "drain-now"` and `type === "incoming-call-notification"`.
- No check of `event.source.url` or `event.source.frameType`.
- **Risk:** Any page loaded in scope `/` (including adversarial cross-origin frames if framed by the app, or injected XSS) can trigger `drainOutbox()` or spawn notifications with arbitrary title/body/peer data.
- `incoming-call-notification` accepts unsanitized `event.data.title`, `body`, `call_id`, `peer` → passed directly to `showNotification()`. Notification data is echoed back to the page on click (sw.js:210–215).
- **Impact:** Notification spam, phishing notifications ("You have a call from Bank of America—tap to verify"), or exfiltration of queued outbox items via repeated drain commands.
- **Status:** HIGH — no origin guard. Partially mitigated by same-origin-only scope registration, but XSS in the main app can abuse it.

**4. Stale-while-revalidate on static assets — indefinite cache fallback (sw.js:88–97)**
- Cache-first for `/manifest.json` and `/static/*`: if the network fetch fails (`.catch(() => cached)`), the SW returns the cached copy **indefinitely**.
- If a cached manifest or icon is poisoned (or becomes outdated), the browser will never see the updated version unless the cache is manually purged.
- **Risk:** Outdated manifest can prevent app reinstall or hide security-relevant changes. Poisoned icon or manifest can mislead the user about the app's state or origin.
- **Status:** HIGH — no cache expiry, no stale-while-revalidate timeout. In practice, acceptable for icons but suboptimal for `manifest.json` (which declares scope and start_url).

**5. Origin not checked in fetch handler (sw.js:53–99)**
- The fetch handler dispatches on `url.pathname` alone—no check of `event.request.headers.get("origin")` or `event.clientId`.
- **Risk:** Low in practice (scope is `/`, same-origin only), but if a subpath (e.g., `/admin/`) is controlled by an attacker or a user-uploaded file, the SW can be tricked into caching and serving it.
- **Status:** MEDIUM — architectural simplification, not exploitable under current scope declaration.

### Service worker #3
**### ADVISORY FINDINGS**

**6. No Content-Type validation before cache (sw.js:72, 91–93)**
- `c.put(event.request, copy)` accepts any Content-Type (or missing header) if `res.status === 200`.
- If a `.js` asset is served as `text/plain` or an HTML file as `image/png`, the cache will preserve the wrong type.
- **Status:** POLISH — browsers re-detect MIME type on serve, so low risk, but explicit `res.headers.get("content-type")` check would harden.

**7. IDB queue survives tab close; no expiry on queued items (sw.js:112–161)**
- Outbox items (failed sends) are persisted in IDB with no TTL. A message queued while offline can sit in the queue indefinitely if the browser never syncs or the device never comes online.
- **Risk:** User sends a private message, browser crashes, device offline for months, then syncs—old message sends silently without user re-consent.
- **Status:** ADVISORY — acceptable for UX (resilience), but worth documenting or adding a per-item TTL.

**8. `notificationclick` handler calls `clients.openWindow("/")` unconditionally (sw.js:206)**
- If the app is already open, this may navigate an existing tab. If not, it opens a new tab.
- No check for `data.call_id` validity before opening. A crafted notification (via the postMessage XSS vector) can spam new tabs.
- **Status:** ADVISORY — mitigated by the postMessage XSS risk above; fix #3 first.

### Service worker #4
**### REGISTRATION & LIFECYCLE (index.html)**

- **Scope:** `/` (global, same-origin only) — appropriate for a PWA.
- **Update check:** Implicit browser behavior; no `reg.onupdatefound()` handler visible in audit excerpt. The app relies on the browser's default update schedule.
- **No ready handler:** The code does not wait for `reg.ready` or `reg.waiting` before using the outbox. Degradation is graceful (if SW unavailable, sends behave as v0.13).

---

### Service worker #5
**### SUMMARY & NEXT STEPS**

**Currently safe** for local 127.0.0.1 deployment *only*. The daemon is trusted and not network-accessible, so cache poisoning and malicious updates are not threats.

**Before production/wider access:**
1. **Implement pinned-signature verification** — verify SW and shell HTML against a hard-coded public key hash before caching or serving.
2. **Add origin/source checks to postMessage handlers** — validate `event.source.url` matches expected scope origin.
3. **Add per-item TTL to outbox queue** — discard sends older than (e.g.) 7 days.
4. **Optional: add `updateViaCache: "none"` or implement custom update-check** to avoid serving stale SW code during deploy.

## Half-implemented features — `agent-acdf77b834b45013a` (0 findings)

## QUIC cutover — `agent-ace70abc0a9a587a5` (7 findings)

### QUIC cutover #1
**### 1. **`peer_quic.py` Module** ✓ EXISTS**

**File:** `src/one_link/peer_quic.py`

The module **does exist** and exposes:
- `QuicPeerSession` class wrapping per-peer QUIC connections
- `make_endpoint()` — builds a QUIC endpoint (currently **stubbed to return None**)
- `open_outbound()` — dials a remote peer over QUIC
- `should_prefer_quic_for_peer()` — capability negotiation logic
- Exports frame constants: `FRAME_CHUNK_REQUEST`, `FRAME_CHUNK_RESPONSE`, etc. (lines 60-69)
- Advertises `QUIC_TRANSPORT_V1` capability for peer negotiation

**Per-peer manager:** `QuicPeerSession` exists (line 139) but is **never instantiated** because `make_endpoint()` always returns `None` (line 136).

---

### QUIC cutover #2
**### 2. **Wire Frame Definitions** ✓ FOUND**

**Files:** `src/one_link/peer_quic.py:60-69`, `src/one_link/quic_native.py:67-84`

- `FRAME_CHUNK_REQUEST` and `FRAME_CHUNK_RESPONSE` are **re-exported from `one_link_native.quic`** (the Rust binding)
- These are for **QUIC stream framing**, not WebRTC
- Frame types defined in the Rust crate (`ol_quic`)
- Additional frames: `FRAME_MANIFEST_SYNC`, `FRAME_BLOOM_FILTER`, `FRAME_MISSING_CHUNKS`, etc.

---

### QUIC cutover #3
**### 3. **`daemon.py` QUIC Integration** ✓ PARTIAL**

**Key locations:**
- `QUIC_TRANSPORT_V1` cap **is advertised** in `LOCAL_CAPABILITIES` (capabilities.py:115)
- `transport_choice_for_peer()` method exists (line 8861) and returns `"quic"` or `"webrtc"`
- Daemon checks if peer has the cap and endpoint is up; falls back to WebRTC otherwise
- `_ensure_quic_endpoint()` lazily initializes the endpoint (line 8843)

**Critical issue:** `make_endpoint()` is **stubbed** (peer_quic.py:136):
```python
# Identity bridge NOT YET IMPLEMENTED
# Endpoint.server() requires identity + is_paired_callback
# "the endpoint stays unbuilt at startup until the Identity bridge ships"
return None
```

**Result:** **No daemon ever actually opens a QUIC endpoint.** `transport_choice_for_peer()` always falls back to WebRTC because `_ensure_quic_endpoint()` always returns `None`.

---

### QUIC cutover #4
**### 4. **`one_link_native.quic` Connection Methods** ✓ FULL INVENTORY**

**File:** `src/one_link/quic_native.py:252-401`

Exposed methods:
- ✓ `send_frame_round_trip()` — single request/response
- ✓ `send_frame_round_trips()` — batch sequential
- ✓ `send_frame_round_trips_parallel()` — batch parallel with `max_in_flight`
- ✓ `send_frame_stream_round_trips()` — **bulk stream** (many frames on one bidirectional stream — the fast path)
- ✓ `send_frame_stream_round_trips_parallel()` — bulk stream with parallel lanes
- ✓ `send_frame_stream_round_trips_count()` — bulk stream with response verification and byte counting
- ✓ `send_frame_stream_round_trips_count_parallel()` — parallel variant

**Note:** `send_frame_stream_round_trips_count()` exists (line 335) — the method name you asked about is there, ready for chunk batching.

---

### QUIC cutover #5
**### 5. **Capability + Transport Selection in `send_file`** ✗ NOT WIRED**

**File:** `src/one_link/daemon.py:12998+`

- `transport_choice_for_peer()` **is defined** but **never called** in the send_file path
- `send_file()` always routes through `channel` (the WebRTC/encrypted session), line 13136
- `FILE_NATIVE_CHUNK` messages (line 13967) are encoded and queued to the WebRTC channel via `_queue_or_send(channel, ...)` (line 13978)
- **No branching logic** on `QUIC_TRANSPORT_V1` exists in the data path

The capability is **advertised-not-used** — it gates negotiation (peer discovery) but not actual file routing.

---

### QUIC cutover #6
**### 6. **NAT Traversal** ✗ NOT IMPLEMENTED**

**Searches:** No references to STUN, TURN, hole-punching, or NAT traversal in peer_quic.py or quic_native.py

The `ol_quic` crate docs show client/server with `connect_blocking(addr, fingerprint)` — **direct IP dial only**. No rendezvous or address exchange for P2P QUIC. Browser-as-peer paths (where rendezvous would apply) stay on WebRTC anyway.

**Current state:** QUIC would require **out-of-band address delivery** (same as WebRTC signaling) or mDNS on the same LAN. **Not yet wired.**

---

### QUIC cutover #7
**### 7. **End-to-End Tests** ✗ ZERO**

**Searches:** 
- `test_quic_native_v0210.py` — unit tests of low-level `one_link_native.quic` bindings (loopback, ping/pong, frame types) — **NOT** daemon-level
- `test_quic_batch_bridge.py` and `test_quic_dual_stack_wiring.py` — unit tests of capability negotiation logic, `should_prefer_quic_for_peer()` predicate
- `test_daemon_pair_quic_transport_capability_advertised_in_status` — only checks that the cap **appears in status**, not that it's used

**No tests** exercise end-to-end file transfer between two daemons via QUIC.

---

## Verdict: Effort Estimate

**Status:** QUIC transport is **scaffolding, not shipped.**

| Work | Status | Effort |
|------|--------|--------|
| Wire frame constants | Done | — |
| Capability advertisement | Done | — |
| Transport selector logic | Done | — |
| Native QUIC bindings (Connection methods) | Done | — |
| **Identity bridge + endpoint init** | **Stubbed** | **2–3 days** |
| **Route chunks through QUIC in send_file** | **Not started** | **1 day** |
| **Inbound QUIC chunk service** | **Not started** | **1 day** |
| **Rendezvous address exchange** | **Not started** | **2–3 days** |
| **E2E daemon pair tests** | **Zero** | **1 day** |

**To ship QUIC as default for file chunks: ~7–10 days of focused work**, with the identity bridge and chunk routing being the critical path. The native Rust crate is solid; the daemon plumbing is missing.

Per `PHASE_A2_QUIC_CUTOVER_PLAN.md`: **deliberately deferred** pending production soak on WebRTC + real hardware (cellular handoff, LAN throughput verification).

## Native Rust audit — `agent-aee44db505556df60` (8 findings)

### Native Rust audit #1
**### 1. Every ol_* crate (33 total + binding umbrella)**

**Complete listing with metrics:**

| Crate | Purpose | LOC | Public API | Tests | PyO3 | Status |
|-------|---------|-----|-----------|-------|------|--------|
| **ol_chunk** | CDC (FastCDC v2020) + BLAKE3 content-addressing per ADR-0001 | 1,574 | `CdcParams`, `ChunkScanner`, `Boundary`, `scan_to_vec*`, blake3_wrap derivation | 38 | via umbrella | Phase A1 ✓ |
| **ol_aead** | AES-256-GCM + ChaCha20-Poly1305 frame cipher per ADR-0002 | 1,438 | `AeadCipher`, `AeadKind`, `FrameKey`, `convergent` mode | 35 | via umbrella | Phase A1 ✓ |
| **ol_wal** | Crash-only write-ahead log per ADR-0007 | 1,339 | `WriteAheadLog`, `LogEntry`, replay/recovery | 32 | via umbrella | Phase A1 ✓ |
| **ol_chunk_store** | LSM index + chunk_log + manifest_log + Bloom filter coupling (ADR-0003, 0005) | 1,903 | `ChunkStore`, `Manifest`, LSM iterators | 36 | via umbrella (store module) | Phase A1 ✓ |
| **ol_quic** | QUIC transport via quinn + identity-bound TLS per ADR-0009, 0010 | 1,625 | `Identity`, `QuicServer`, `QuicClient`, `Frame` | 22 | via umbrella | Phase A2 ✓ |
| **ol_bloom** | Content-addressed Bloom filter for transfer-init handshake (ADR-0011) | 670 | `BloomFilter`, `BloomSet` | 18 | via umbrella | Phase A2 ✓ |
| **ol_transfer** | TransferEngine wiring chunk_store + QUIC + Bloom per ADR-0013 | 1,529 | Transfer negotiation, chunk batching | 8 | **NOT exposed** | Phase A2 research |
| **ol_fountain** | LT fountain codes per ADR-0015 | 1,241 | `FountainEncoder`, `FountainDecoder` | 29 | via umbrella | Phase C research |
| **ol_fec** | Reed-Solomon FEC over GF(2^8) (Cauchy systematic) per ADR-0016 | 1,007 | `RsFec`, `Codec` | 20 | via umbrella | Phase C research |
| **ol_pqkem** | PQ-hybrid KEM (ML-KEM-768 + X25519, BLAKE3 combiner) per ADR-0017 | 436 | `HybridKem`, `SharedSecret` | 4 | via umbrella | Phase C research; **NOT wired into daemon** per ADR-0024 |
| **ol_erasure** | Chunk-level erasure coding (RS over CDC chunks) per ADR-0018 | 397 | `ErasureCode`, stripe/parity logic | 8 | via umbrella | Phase C research |
| **ol_bandit** | Multi-armed bandit auto-tuning (Thompson sampling) per ADR-0019 | 396 | `BanditArm`, `Thompson` solver | 8 | via umbrella | Phase C research |
| **ol_ratchet** | Per-chunk forward-secret ratchet per ADR-0020 | 654 | `ChunkRatchet`, state derivation | 16 | via umbrella | Phase C research; **NOT wired into chunk hot path** per ADR-0024 |
| **ol_capability** | Macaroon-style capability layer per ADR-0021 | 741 | `Capability`, attenuation, verification | 11 | via umbrella | Phase C research |
| **ol_crdt** | CRDT shared folders per ADR-0022 | 711 | `MergeOp`, `CrdtState`, CRDTs | 15 | via umbrella | Phase C research |
| **ol_hwkey** | Hardware-bound keys (TOFU-degrading) per ADR-0023 | 284 | `HwKeyBinding`, attestation hooks | 8 | via umbrella | Phase C research |
| **ol_canon** | Canonical-bytes encoder (Phase 0 substrate, ported from std.codec.canon) | 991 | `Encoder`, `Decoder`, canonical forms | 14 | **NOT exposed** | Phase C/D substrate |
| **ol_codegen** | Coherence Language → Rust codegen scaffolding per ADR-0032 | 876 | Parse trees, IR, code emission | 17 | **NOT exposed** | Phase D research |
| **ol_coherence_field** | Reaction-diffusion + Helmholtz reduction + Green-function kernel + BE-RAR + apparent-horizon anchor (Phase E) | 3,930 | Field operators, discretization, numerics | 80 | via umbrella | Phase E research; shared with OneField Mesh + BioMesh |
| **ol_routing** | Tau_c-weighted routing primitives per ADR-0028 (harvested from OneField) | 585 | Path-finding, metric derivation | 27 | via umbrella | Phase D research |
| **ol_prefetch** | Active inference prefetch over peer access traces per ADR-0029 | 358 | `Predictor`, trace observation | 7 | via umbrella | Phase D research |
| **ol_homology** | Chunk-co-hold graph durability detection per ADR-0030 | 389 | Graph traversal, co-hold inference | 10 | via umbrella | Phase D research |
| **ol_grammar** | Re-Pair grammar compression for secondary chunk index per ADR-0030 | 274 | `GrammarCompressor`, terminal replacement | 7 | **NOT exposed** | Phase D research |
| **ol_duress** | Plausibly deniable storage + duress codes per ADR-0031 | 326 | Decoy key derivation, gate logic | 7 | **NOT exposed** | Phase D research |
| **ol_device_mesh** | Personal Device Mesh identity stack (Row 8 Layer 1): master + per-device subkeys + field-bind + daily ratchet + cross-witness attestation | 12,757 | Identity derivation, witness, ratchet, field commitment | 236 | **NOT exposed** | Phase F1 research; **largest crate** |
| **ol_discovery** | Sovereign Kademlia DHT peer discovery per COHERENCE_MESH_PLAN (Phase F1.3) | 3,470 | `NodeId`, `RoutingTable`, `SignedRecord`, lookup primitives | 61 | via umbrella | Phase F1.3 research |
| **ol_proximity_pair** | Channel-reciprocity proximity Factor-2 pair-trust (Phase F1.4) | 1,194 | Quantize/syndrome/reconcile/amplify, CASCADE driver | 34 | via umbrella | Phase F1.4 research |
| **ol_threshold_recovery** | Shamir threshold secret sharing + coherence-field-bound recovery (Phase F1) | 1,409 | Share generation, reconstruction, field binding | 32 | via umbrella | Phase F1 research |
| **ol_pair_qr** | Pair-by-QR Factor-1 trust (Phase F2): QR scan + Ed25519-signed invite + SAS comparison + optional Factor-2 | 2,766 | Invite generation, response verification, SAS derivation | 65 | via umbrella | Phase F2 research |
| **ol_onion** | Nested-AEAD onion circuits (Phase F3, Row 5): multi-hop privacy | 6,678 | `build_onion`, `peel_one_layer`, circuit construction | 144 | via umbrella | Phase F3 research; **second-largest; heaviest tests** |
| **ol_pqsig** | PQ-hybrid digital signatures (Ed25519 + ML-DSA-65, Row 1 of COHERENCE_MESH_PLAN) | 486 | Hybrid sign/verify, message binding | 16 | via umbrella | Phase F research |
| **ol_confidential** | Confidential-compute daemon (Row 10): sealed-op surface + remote attestation + per-platform enclave abstraction | 3,038 | `AttestationDoc`, `SealedOp`, TPM/SGX/SEV stubs | 42 | via umbrella | Phase F research |
| **ol_fuse** | FUSE filesystem surface scaffold (Phase B) with optional linux-mount feature | 897 | Mountpoint ops, inode table | 10 | **NOT exposed** | Phase B research |
| **ol_fskit** | macOS FSKit filesystem surface scaffold (Phase B) | 156 | FSKit plugin interface | 3 | **NOT exposed** | Phase B research |
| **ol_winfs** | Windows filesystem surface (Dokan / WinFSP, Phase B) with optional winfsp/dokan features | 163 | Drive mount ops | 3 | **NOT exposed** | Phase B research |
| **ol_netcode** | XOR network coding for relay paths (Phase B #3) | 325 | Encoding/decoding matrices | 8 | **NOT exposed** | Phase B research |
| **one_link_native** | PyO3 binding umbrella crate; Python daemon's single Rust import surface | 8,285 | Python submodules: chunk, aead, wal, store, quic, bloom, fountain, fec, ratchet, pqkem, erasure, bandit, capability, crdt, hwkey, routing, prefetch, homology, coherence_field, discovery, proximity_pair, threshold_recovery, pair_qr, onion, pqsig, confidential, obfs, sphinx | 0 unit tests | master binding | Phase A1+ ✓ |

### Native Rust audit #2
**### 2. Cargo workspace structure**

**Root**: `native/Cargo.toml` is the workspace root. 36 member crates total:
- 33 `ol_*` domain crates
- 1 umbrella binding crate (`one_link_native`)
- 2 ancillary (`.cargo/`, `one_link_native-stubs/` for PEP-561 type hints)

**Workspace governance**:
- Unified resolver (v2)
- Shared dependency pins (BLAKE3 1.5, fastcdc 3.1, pyo3 0.22, quinn 0.11, rustls 0.23, etc.)
- Workspace lints: `unsafe_op_in_unsafe_fn = "deny"`, clippy all + pedantic with targeted allows
- Release profile: `opt-level=3`, `lto=fat`, `codegen-units=1`, `panic=abort`, `-Zsymbols=off`

### Native Rust audit #3
**### 3. Native primitives wired into Python daemon**

**30 of 33 ol_* crates exposed via one_link_native** binding. Python daemon imports from:

- **File engine** (Phase A1+): aead, bloom, chunk, fec, erasure, fountain, wal, store (chunk_store), quic, transfer
- **Optimization** (Phase C-D): bandit, capability, crdt, homology, prefetch, ratchet, routing
- **Coherence field** (Phase E): coherence_field (unified with OneField/BioMesh)
- **Mesh identity** (Phase F1-3): discovery, pair_qr, pqkem, pqsig, proximity_pair, threshold_recovery, onion, confidential, obfs, sphinx

The binding exports these as Python submodules via `one_link_native.chunk`, `one_link_native.aead`, etc. Error types (`OlCapabilityError`, `OlCrdtError`, `OlHwKeyError`) are registered at the module root.

### Native Rust audit #4
**### 4. Crates NOT wired to daemon**

**10 crates are internal scaffolding or Phase B/D research without daemon hooks**:

1. **ol_canon** — Canonical encoder; used internally by ol_onion and ol_pair_qr but not exposed to Python
2. **ol_codegen** — Coherence Language codegen; pure Rust code synthesis, no daemon caller
3. **ol_device_mesh** — Personal Device Mesh identity master (12.7k LOC, 236 tests); research-phase; daemon's identity harness is pure Python for now
4. **ol_duress** — Duress codes; feature incomplete, no caller
5. **ol_fskit** — macOS FSKit mount (Phase B); filesystem surface deferred
6. **ol_fuse** — Linux FUSE mount (Phase B); filesystem surface deferred
7. **ol_grammar** — Re-Pair compression for secondary index (Phase D); not hot-path
8. **ol_netcode** — XOR network coding (Phase B); relay optimization deferred
9. **ol_transfer** — TransferEngine orchestration; currently pure Python
10. **ol_winfs** — Windows Dokan/WinFSP mount (Phase B); filesystem surface deferred

**Deferred per ADR-0024**:
- `ol_pqkem` (PQ-hybrid KEM): ML-KEM-768 ready but `pq_hybrid.py`'s `NullKEM` has no production hot-path callers; activation requires chunk-store transport cutover
- `ol_ratchet` (per-chunk forward secrecy): ready; waits for chunk-store AEAD cutover

### Native Rust audit #5
**### 5. Feature flags & platform cfg**

**Feature flags** (platform-optional):
- `ol_confidential`: `windows-tpm` (TPM 2.0 attestation key on Windows)
- `ol_fuse`: `linux-mount` (replaces scaffold with real `fuser::mount2`)
- `ol_fskit`: `macos-mount`
- `ol_winfs`: `winfsp`, `dokan` (two filesystem drivers)
- `one_link_native`: `unstable-deterministic-provider` (for ol_confidential software provider in testing only; production disabled)

**Platform cfg**:
- Only `ol_wal`: `#[cfg(target_os = "macos")]` for F_FULLFSYNC fsync variant

### Native Rust audit #6
**### 6. Highest-LOC crate**

**ol_device_mesh: 12,757 lines** — Personal Device Mesh identity stack (Row 8 Layer 1 of COHERENCE_MESH_PLAN). Contains:
- Active routing + DFS topologies for quorum witness
- Attestation collection across device network
- Compute orchestration for field binding
- Daily ratchet derivation
- State machine (236 test blocks; highest testing density per crate)
- Not exposed to daemon; identity harness remains pure Python

### Native Rust audit #7
**### 7. Tests + benchmarks + fuzz**

**Coverage summary**:
- **1,131 total #[test] blocks** across all crates (0 in umbrella binding)
- **39 libFuzzer fuzz targets** (in `fuzz/fuzz_targets/`)
- **32 crates with benches/** directories (criterion benchmarks)

**Top 5 by test blocks**:
1. ol_device_mesh: 236
2. ol_onion: 144
3. ol_coherence_field: 80
4. ol_pair_qr: 65
5. ol_discovery: 61

**Fuzz coverage**: mutation testing across crypto (capability attenuate/decode, crdt merge, pqsig verify), protocols (discovery routing/wire, onion packet peel, pair_qr confirm/invite/response), and stateful (device_mesh quorum/fan_out/self_routing, duress gate).

**No TLA+ specs** found under native/.

### Native Rust audit #8
**### 8. Honest assessment: Research-grade + production Phase A1/A2 hybrid**

**Production-shipped**:
- Phase A1 (chunk, aead, wal, chunk_store): hardened via 1,100+ unit tests, benchmarked to >3 GiB/s CDC + >1 GiB/s end-to-end ingest, acceptance gates met (README §Acceptance gates). Deployed in Python daemon.
- Phase A2 (quic, bloom): identity-bound TLS + multi-stream QUIC validated on CI (Linux/macOS/Windows × Python 3.11-3.13).

**Research-grade**:
- Phases B–E (filesystem scaffolds, codegen, coherence field): feature-complete but not integrated into daemon hot path. Coherence-field is shared with OneField Mesh + BioMesh (calibration unfinished per memory).
- Phases F1–F3 (Mesh identity, DHT, pair-by-QR, onion, sphinx): heavy testing (800+ test blocks) and fuzz coverage but not yet live in daemon; pilot rollout pending.

**Code quality**: High. Workspace-level `unsafe_op_in_unsafe_fn = "deny"`, strict lints, comprehensive fuzz + property tests. All dependencies audit-passed (no Microsoft msquic, no GPL macFUSE). Versioning decoupled from parent (currently 0.21.0-alpha.0); phases ship independently.

**Assessment**: ~65% production (Phases A1/A2), ~35% research (Phases B–F, deferred components). The 12.7k-LOC device_mesh crate and 39 fuzz targets signal serious engineering rigor despite Phase labels.

## Capabilities + caps enforcement — `agent-afb47dcd568cbadce` (15 findings)

### Capabilities + caps enforcemen #1
**1. **CRITICAL** — `daemon.py:11428-11429` — **`_capability_allowed` returns `True` when `self.state is None`**. *What:* Before any policy lookup, a missing state DB short-circuits to allow. *Why:* Dur…**

### Capabilities + caps enforcemen #2
**2. **CRITICAL** — `daemon.py:11440-11449` + `state.py:1439-1449` — **`policy is None` → allow-all; row-missing returns `None`**. *What:* `get_peer_capability_policy` returns `None` for any peer never …**

### Capabilities + caps enforcemen #3
**3. **CRITICAL** — `daemon.py:11439-11448` — **Fail-open on verifier exception**. *What:* Any exception from `get_peer_capability_policy` returns `True` and bumps a counter. *Why:* Adversary-induced SQ…**

### Capabilities + caps enforcemen #4
**4. **CRITICAL** — `daemon.py:4444-4448` — **CAPABILITY_GRANT accepts grants from any channel-authenticated peer regardless of pair/trust state**. *What:* `_cap_store.accept` is called with `expected_g…**

### Capabilities + caps enforcemen #5
**5. **CRITICAL** — `daemon.py:11418-11425` + `cap_store.py:167` — **Delegation chain walker uses NO trust filter on intermediate hops**. *What:* `_cap_authorized_via_chain` walks any stored grant. An i…**

### Capabilities + caps enforcemen #6
**6. **HIGH** — `daemon.py:4411-4466` — **No rate limit on inbound CAPABILITY_GRANT**. *What:* Only the base64-length check (12 KB). A peer can spam thousands of grants per second; each goes through Ed2…**

### Capabilities + caps enforcemen #7
**7. **HIGH** — `caps_grants.py:140-188` + `cap_store.py:85` — **`encode_grant` has no caveat parser; "scope" is opaque bytes**. *What:* `resource_scope` is just `bytes`. `has_capability` does exact-equ…**

### Capabilities + caps enforcemen #8
**8. **HIGH** — `daemon.py:13565-13608` + `server.py:9667` — **`_ensure_folder_caps_for` no-ops when policy is None ("legacy allow-all")**. *What:* Comment at 9667 says "policy=None means default-allow …**

### Capabilities + caps enforcemen #9
**9. **HIGH** — `daemon.py:8892` — **`_handle_blob_request` "no folder context" path gates on FILES only, not on the blob's origin folder**. *What:* When `folder_name` is omitted, any peer with FILES ca…**

### Capabilities + caps enforcemen #10
**10. **HIGH** — `state.py:1447-1449` — **Malformed `allowed_json` row returns `[]` (deny-all) — silently flips an allow-policy to deny on corruption**. *What:* `json.loads` failure → `return []`. *Why:…**

### Capabilities + caps enforcemen #11
**11. **HIGH** — `cap_root_key.py` — **No rotation API; compromise = permanent**. *What:* `load_or_create_cap_root_key` mints once; no `rotate_cap_root_key()`, no UI surface, no automatic rotation on su…**

### Capabilities + caps enforcemen #12
**12. **MEDIUM** — `daemon.py:13610-13632` — **`_emit_capability_request` uses `time.monotonic()` dedup but no per-peer ceiling**. *What:* `CAPABILITY_REQUEST_DEDUP_S` gate is per `(fp, cap)`. A peer cy…**

### Capabilities + caps enforcemen #13
**13. **MEDIUM** — `daemon.py:4444-4448` + `caps_grants.py:298-304` — **Replay defense relies on a shared, evictable seen-nonces set**. *What:* OrderedDict capped at 100k. Audit M11 fixed eviction-rando…**

### Capabilities + caps enforcemen #14
**14. **MEDIUM** — `state.py:128-148` + `caps_grants.py` grant lifecycle — **`_cap_store` is in-memory only; no durable persistence; no durable audit row for grants**. *What:* The `capability_audit` SQL…**

### Capabilities + caps enforcemen #15
**15. **MEDIUM** — `daemon.py:4434` — **CAPABILITY_GRANT length check (12000 bytes) is post-channel-decrypt only**. *What:* The cap runs *after* base64 decode would be triggered. No earlier ceiling on t…**

---

**Files referenced:**
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\capabilities.py`
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\caps_grants.py`
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\cap_store.py`
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\cap_root_key.py`
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\daemon.py` (lines 4411-4466, 5500-5547, 7748-7907, 8850-8923, 11344-11486, 13315-13540, 13565-13632, 14430-14506)
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\state.py` (lines 128-148, 1380-1449)
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\server.py` (lines 9650-10132)

**Bottom line:** The two CRITICALs from v0.20.5 ("default-allow-all reversal" + "fail-open paths") are still alive at lines 11428-11449 and 13599-13600. The grant primitives are well-formed (audited Ed25519/macaroon, M11/H12/M14 closures all visible), but the *acceptance* side trusts any channel-authenticated peer (item 4) and the *delegation chain walker* doesn't re-check trust (item 5). No durable grant audit (item 14). Word count: ~395.

## Transfer engine integrity — `agent-afc5530dbd7646307` (15 findings)

### Transfer engine integrity #1
**1. **CRITICAL · native_transfer.py:267-273** — **Fast-path AEAD ignores the ratchet; nonce is sender-controlled `chunk_index`.****

*What:* `encrypt_chunk_bytes` (267) and `decrypt_chunk` (469) derive `nonce = idx.to_bytes(12, "little")` and call AEAD with `self.shared_secret` (constant per session). The `self._ratchet.next_key()` result is **discarded** (`_key, _ = ...`). The ratchet only ticks for sync side-effect; the per-chunk key it produces is never used.
   *Why:* No forward secrecy in the production path (every shipped daemon uses `cipher_backend="fast"`). Worse, on channel re-open against the same paired peer, `derive_native_transfer_secret` returns the **cached `_native_transfer_seed`** (channel.py:220) — so a new sender session starts at `_next_send_index=0` with the **same key**, reusing nonces 0..N for completely different plaintexts. ChaCha20-Poly1305 / AES-GCM nonce reuse is catastrophic (keystream recovery, forgery).
   *Fix:* Either (a) actually use the ratchet output as the AEAD key per chunk, or (b) mix `transcript_hash || channel-epoch || session-id` into the key/nonce via HKDF. Add a strictly-monotonic session epoch counter persisted across reopens.

### Transfer engine integrity #2
**2. **CRITICAL · native_transfer.py:800 (daemon.py:7800)** — **Receiver trusts wire-supplied `chunk_index`, decoupling it from ratchet position.****

*What:* `chunk_index = int(msg.get("chunk_index", seq))` is taken from the peer; the receiver's `_next_send_index` and ratchet are silently desynced from the nonce that decrypts.
   *Why:* A malicious or replaying sender can pick any 64-bit value, reusing nonces or jumping ahead. Combined with #1 this gives plaintext recovery via two ciphertexts at the same `chunk_index`. Replay window absent.
   *Fix:* Receiver must enforce strict monotonic `chunk_index` per session and bind it to its own ratchet state; reject any `chunk_index <= last_seen` or `>= last_seen + reasonable_window`.

### Transfer engine integrity #3
**3. **HIGH · daemon.py:7800** — **Legacy-peer compat (`NATIVE_TRANSFER_V1` without `_INDEXED`) collapses chunk_index onto per-file `seq`.****

*What:* `chunk_index = int(msg.get("chunk_index", seq))`. For a multi-file channel both peers reset `seq=0` per file but the sender's session ratchet keeps advancing — receiver decrypts with `idx=seq` (e.g. 0..N) while sender encrypted with session-absolute index. AEAD tag fails on the very first chunk of file #2 from a legacy peer.
   *Why:* Forces silent fallback or transfer abort against any `NATIVE_TRANSFER_V1` peer that survives. The Memory note about this fix only landed on the indexed direction.
   *Fix:* When peer lacks `_INDEXED`, force `cipher_backend` path that derives nonce independently of session counter (e.g. HKDF(seed, blob || seq)), and version the wire so legacy fallback is detectable.

### Transfer engine integrity #4
**4. **HIGH · native_transfer.py:439-452 / chunk_native cdc_iter dedup** — **Chunk-store accepts a peer's claimed `chunk_id` without re-hashing.****

*What:* `_maybe_store` writes ciphertext keyed by `record.chunk_id` (which on the receive side originates in the wire frame, daemon.py:7794). The docstring says "AEAD tag covers chunk_id as AAD, so we DON'T re-hash" — but the AEAD tag only proves the *sender* committed to that `chunk_id`, not that `chunk_id == BLAKE3(plaintext)`. With convergent addressing (line 388), a paired-but-malicious peer can poison your content-addressed store: claim `chunk_id = BLAKE3("safe.mp4 chunk 17")`, ship arbitrary plaintext, AEAD-encrypt under that AAD. Other peers asking `has_chunk(target_id)` will be served the wrong bytes from your cache.
   *Fix:* On receive, after `decrypt_chunk` returns plaintext, verify `BLAKE3(plaintext) == chunk_id` (or convergent derivation) BEFORE `_maybe_store` / before serving via swarm pull. The "redundant pass" comment is wrong in a swarm-redistribution model.

### Transfer engine integrity #5
**5. **HIGH · daemon.py:8042** — **FILE_CDC_CHUNK index check uses `idx not in cdc_missing` but receiver pre-stamps `cdc_streamed_initial` from on-disk partial without removing those from `cdc_missing` …**

*What:* Cross-restart path (4845-4849) filters missing by `i not in cdc_streamed_initial`. But if `validate_partial=False` (line 4815-4816 fallback open) the set is empty even though the file content from disk may match. Any duplicate chunk arriving for an `idx not in f.cdc_missing` is rejected as `unexpected_cdc_chunk` and the whole transfer aborts via `_abort_incoming_file`.
   *Why:* Sender that ACKs were lost will retry the chunk → receiver kills the transfer instead of idempotently ACKing. Aborts on legitimate sender retries.
   *Fix:* If `idx in range AND data hash matches expected AND idx in f.cdc_streamed`, ACK as duplicate-success instead of abort.

### Transfer engine integrity #6
**6. **HIGH · daemon.py:18047-18068** — **`pending_sizes` deque can grow unbounded under stalled ACKs.****

*What:* The bound is enforced by `while not stream_scheduler.can_send(len(pending_sizes))`. `can_send` returns False once the window is full — but inside `_settle_one_stream_ack` we `await _await_ack(channel, ...)` with `deadline=_inter_chunk_ack_deadline(window_bytes)`. Window grows → deadline grows → still bounded *in theory*. **But** `_fallback_quic_batch_to_webrtc` (18138-18153) appends to `pending_sizes` WITHOUT checking the can_send gate first, only after. If QUIC_BATCH_SIZE=8 with no in-flight WebRTC ACK pending, all 8 land in `pending_sizes`, then the `while not can_send` loop drains them — fine — UNLESS the channel is closed mid-fallback: `_settle_one_stream_ack` raises and pending_sizes is leaked in the calling frame.
   *Fix:* Wrap `_fallback_quic_batch_to_webrtc` in try/finally that clears pending_sizes on channel error.

### Transfer engine integrity #7
**7. **HIGH · daemon.py:17812** — **CDC source-file mid-transfer mutation detection raises RuntimeError, leaving the receiver hung.****

*What:* `if len(data) != c.size or blake3.blake3(data).hexdigest() != c.hash: raise RuntimeError("source file changed during transfer")`. The receiver never receives the trailing eof and the `_incoming_files[blob]` entry, partial out_path, and sidecar all persist.
   *Why:* On next start the sidecar resumes a transfer that can never complete because the sender's local file is already gone/changed. Wedged forever.
   *Fix:* Send a FILE_ABORT message with reason="source_changed" so the receiver tears down state immediately.

### Transfer engine integrity #8
**8. **HIGH · native_transfer.py:340** — **`path.stat().st_size` captured once; large files mutated during streaming bypass size cap.****

*What:* `size = path.stat().st_size` then later `f.read(self.FIXED_CHUNK_SIZE)` reads until EOF. If the file grows during send, additional chunks are encrypted/yielded but never accounted for in the manifest the receiver was offered.
   *Why:* Sender ships ciphertext past declared `size`; receiver's `f.received + len(data) > f.size` (daemon.py:7854) detects it and aborts — but the ratchet/nonce counter has been advanced for the over-shoot chunks, breaking sync for the next file on the channel (interacts with #1).
   *Fix:* Cap the read loop by remaining declared bytes; truncate the last chunk and stop.

### Transfer engine integrity #9
**9. **MEDIUM · daemon.py:5028 vs 7786 vs 7929** — **Three independent `seq != f.next_seq` handlers, two raise, one ACKs+returns.****

*What:* `FILE_CHUNK` (5028) ACKs `file_chunk_sequence_mismatch` and returns; `FILE_NATIVE_CHUNK` (7786) raises RuntimeError up the message dispatch; `FILE_BIN_CHUNK` (7929) also raises. The exception path on 7786/7929 bubbles into the channel recv loop and tears down the entire session — not just the transfer.
   *Why:* One reordered chunk kills the whole secure channel (all transfers + chat). Behavior asymmetry guarantees end-user "everything froze" bugs.
   *Fix:* Make all three send rejected ACK + abort just that blob, never raise.

### Transfer engine integrity #10
**10. **MEDIUM · daemon.py:4892-4894** — **`handle.truncate(size)` pre-allocates to the *declared* size before any size validation against on-disk free space.****

*What:* `transfer_safety.evaluate_transfer_admission` ran earlier (4682) using `shutil.disk_usage(...).free` at offer time. On disks where the truncate creates a *sparse* file we eat no space; on filesystems that don't support sparse (FAT32, exFAT on USB), `truncate` actually writes zeros. A peer offering 16 TiB (the max) on a 16 GB USB will fill the volume before the admission decision matters.
    *Why:* DoS via offer + pre-allocate on exFAT removable inboxes; never reaches the per-chunk write where admission would have caught it.
    *Fix:* Detect filesystem type (or use `posix_fallocate`/`SetFileValidData` with explicit "sparse if supported" semantics) and on non-sparse filesystems skip truncate.

### Transfer engine integrity #11
**11. **MEDIUM · cdc.py:264-269 / 296-298** — **`_make_chunk` for tiny final chunk silently emits a zero-length chunk if `not chunks` and `len(data) == 0`.****

*What:* `if start < len(data) or not chunks: chunks.append(_make_chunk(...))` always appends a tail chunk even when data is empty, producing `Chunk(start=0, end=0, hash=BLAKE3(b""))`. Native scanner branch (296-297) replicates this.
    *Why:* Empty-file CDC manifests advertise a single chunk with the well-known `BLAKE3(b"")` hash. A peer can poison the receiver's chunk cache by claiming any blob has that "chunk" — collision-free hash, but trivially constructible. Combined with #4 the receiver's cache gets a known-hash entry.
    *Fix:* Skip the tail-chunk emission for empty files; treat zero-byte transfers as zero chunks.

### Transfer engine integrity #12
**12. **MEDIUM · transfer_doctor.py:206** — **Diagnosis substring match on `"chunk" in code_src`** wins over **`"ratchet"`** when error contains both.**

*What:* `code_src = " ".join((delivery_state, err_class, err)).lower()`. Order of `if` blocks: ratchet → version → chunk. But "InvalidTag" is matched on `invalidtag` first (206), good. However an `AeadDecryptError: ratchet chunk integrity` would hit ratchet branch and prescribe `reopen_secure_session` — which (per #1) reuses the cached seed and reuses nonces.
    *Why:* Auto-action loop: nonce-reuse → tag fail → "reopen secure session" → same seed → nonce reuse → infinite.
    *Fix:* `reopen_secure_session` action must rotate `_native_transfer_seed` (force re-derive with new salt/epoch), not just reset session counter.

### Transfer engine integrity #13
**13. **MEDIUM · daemon.py:17541-17544** — **FILE_WANTS `wants` parsed as `{int(i) for i in first_reply.get("wants", [])}` with no range check against `cdc_chunks`.****

*What:* The sender accepts any integer the receiver returns — negative, past EOF, or duplicated. Sender then loops `for c in cdc_chunks: if c.index not in wanted_indexes`. Out-of-range indices are silently ignored, BUT `wanted_total = len(wanted_indexes)` (17671) and `wanted_sent_index += 1` drive ACK-batch sizing; an adversarial receiver claiming `wants=[0,0,0,…,9999]` makes the sender's `chunk_ack_batch` math degenerate.
    *Why:* DoS amplification via crafted FILE_WANTS — sender computes oversized windows, schedules unnecessary work; if the receiver advertises `wants=[2**62]`, `int()` succeeds and the `not in` check passes through.
    *Fix:* `wanted_indexes = {i for i in (int(x) for x in raw) if 0 <= i < len(cdc_chunks)}` with explicit duplicate detection and a reject if oversized.

### Transfer engine integrity #14
**14. **LOW · transfer_safety.py:154** — **`Path(str(name or "")).name`** strips path components but Windows NTFS alternate-data-stream suffix `:streamname` survives.**

*What:* `_safe_transfer_name` (daemon.py:6285) replaces NUL, strips control chars, rejects reserved names — but never strips `:` from filenames. On NTFS, `report.pdf:hidden.exe` is a valid filename where the `:hidden.exe` is an ADS that's invisible to Explorer but executable.
    *Why:* A paired peer can deliver an executable hidden as a doc attachment.
    *Fix:* Reject any `:` in the filename on Windows targets.

### Transfer engine integrity #15
**15. **LOW · native_transfer.py:451-452** — **Chunk-store append failure is swallowed with `log.warning` only.****

*What:* `_maybe_store` catches `Exception` and logs, then returns; the sender's `encrypt_file` keeps yielding subsequent chunks as if dedup succeeded.
    *Why:* No audit trail: a corrupted/exhausted local chunk store will silently disable swarm-pull for future peers, with no operator-visible alarm. The Memory note explicitly flagged "QUIC fast-path fallbacks left no audit trail" — same anti-pattern here.
    *Fix:* Append to `self._degradation_events` (same pattern daemon already uses) with kind="native_chunk_store_append_failed" so /api/metrics surfaces it.

Key cross-cutting observation: the chunk_id/AEAD coupling (#1, #2, #4) is the most dangerous cluster — fast-path AEAD without ratchet keying + sender-controlled nonce + un-reverified content address mean a paired-but-malicious peer can both poison your content store and (after channel reopen) recover plaintext via nonce reuse. Recommended order: fix #1+#2 together (re-key per chunk, bind chunk_index to receiver-side ratchet); then #4 (re-verify chunk_id after decrypt before any cache write); then #9 (don't raise into channel recv on chunk seq mismatch).

Relevant files:
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\native_transfer.py`
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\daemon.py`
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\channel.py`
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\cdc.py`
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\transfer_safety.py`
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\transfer_doctor.py`
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\chunk_ratchet.py`
