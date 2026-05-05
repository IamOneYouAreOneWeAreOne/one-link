# One Link Sovereign Network Blueprint

Status: in_progress

One Link should feel simple enough for a non-technical person to use, while
remaining powerful enough to become a real people-owned network layer. The
product promise is direct: no accounts, no mandatory company server, no
telemetry, no rent to keep talking to people near you.

## Imported Ideas

OneField Mesh contributes the transport doctrine:

- Content-defined chunking: split files by content, not offsets, so related
  files can skip bytes the receiver already has.
- Merkle drift sync: compare one root hash first, then descend only into
  divergent manifest leaves.
- Evidence gates: the app should only claim what it can prove from local state,
  peer signatures, hashes, and explicit trust decisions.
- Pluggable transports: LAN TCP today, then QUIC, RF, audio, or other direct
  transports without changing identity or trust semantics.

coherence_lang bootstrap contributes the state discipline:

- Vector clocks for causal ordering without a central authority.
- CRDT-style merge rules for folder and group state.
- Session-protocol thinking for auditable wire conversations.
- Capability thinking: devices should receive explicit powers, not ambient
  authority over everything.

## Product Shape

The first screen stays human: peers, messages, files, pairing. The advanced
machinery should be visible through audit surfaces, not exposed as complexity.

Current active foundation:

- Ed25519 device identity and fingerprint
- X25519 plus ChaCha20-Poly1305 encrypted sessions
- mDNS LAN discovery
- local-only token-gated UI
- BLAKE3 content-addressed file store
- vector-clock manifest merge primitives
- single-instance daemon lock

Live protocol features:

- `one_link.cdc`: content-defined chunking and dedup planning
- `one_link.merkle`: Merkle manifest drift detection
- `one_link.sovereign`: auditable doctrine/capability surface
- `FILE_WANTS` / `FILE_CDC_CHUNK`: receivers ask for only the CDC chunks
  missing from their local chunk cache
- `MANIFEST_PUSH.merkle_root`: folder sync can fast-path already-matching
  roots and avoid needless blob requests
- `one_link.capabilities`: peers persist advertised powers such as chat,
  files, CDC transfer, folder sync, and future transports
- `one_link.sessions`: explicit protocol catalog for chat, file transfer,
  folder sync, and pairing
- Adaptive compression: CDC chunks use zlib level 1 only when it actually
  reduces wire bytes.
- Cache accounting and GC: the receiver chunk cache exposes size/count in
  audit and prunes least-recently-touched chunks over budget.
- Benchmark gate: `scripts/bench_transfer_primitives.py` measures CDC
  indexing throughput, dedup hit rate, Merkle drift latency, and compression
  throughput.

## Next Frontier

1. Add per-peer user-facing controls for each capability.
2. Add group/session capabilities for future rooms and multi-device swarms.
3. Keep the audit endpoint as a truth surface for "no telemetry" and "no
   mandatory relay" claims.
