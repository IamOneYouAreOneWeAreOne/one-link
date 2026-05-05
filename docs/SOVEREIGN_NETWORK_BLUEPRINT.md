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

New primitives added in this pass:

- `one_link.cdc`: content-defined chunking and dedup planning
- `one_link.merkle`: Merkle manifest drift detection
- `one_link.sovereign`: auditable doctrine/capability surface

## Next Frontier

1. Wire CDC into file transfer as an optional offer: sender advertises chunk
   hashes, receiver asks for missing chunks only.
2. Use Merkle roots for folder sync so peers can detect drift with one digest.
3. Add per-peer capabilities: chat, file receive, folder sync, future group
   authority.
4. Promote the current peer message list into explicit session protocols.
5. Keep the audit endpoint as a truth surface for "no telemetry" and "no
   mandatory relay" claims.
