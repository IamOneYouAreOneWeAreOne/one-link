# ADR-0022: CRDT-backed shared folders

**Status:** ACCEPTED (Phase C-3)
**Phase:** C (item #4: CRDT shared folders)
**Depends on:** ADR-0021 (capability layer wiring for share grant)
**Supersedes:** `One_link/src/one_link/foldersync.py` (Phase A1 vector-clock manifest)

---

## Context

The Phase C plan (line 137) calls for CRDT-backed shared folders replacing the daemon's existing vector-clock manifest in `foldersync.py`. The Phase C acceptance gate (line 290):

> Property-based testing — lattice merge laws

i.e. property tests that `merge` is **commutative**, **associative**, and **idempotent** across random states.

The original plan envisioned `coherence_lang/std/crdt/*.cl` as the spec with Rust types codegen'd. Because the codegen tool is its own substantial scope and the CL CRDT files in `coherence_lang/coherence_lang/bootstrap/stdlib/std/crdt/` are PROTOTYPE-status (e.g. `causality.cl`, `vector_clock.cl`, `sync.cl` block on `intrinsic_unix_timestamp_ms`), we ship `ol_crdt` as a **native Rust implementation** with the CL files retained as design references — same posture as ADR-0021.

## Decision

**Ship `ol_crdt`: a lattice library composing a vector clock, OR-set, and LWW register into a `Folder` CRDT.**

### Lattice composition

```
Folder = (VectorClock, OrSet<FileId>, BTreeMap<FileId, FileEntry>)
FileEntry = (LwwRegister<String>, LwwRegister<u64>, LwwRegister<u64>)
            ──────────────────── ──────────────── ────────────────
            display_name         size_bytes        last_modified_ms
```

Each sub-lattice satisfies the merge laws, and the product of merge-law lattices is itself a merge-law lattice — the Folder merge is pointwise.

### Sub-lattices

**VectorClock** — `BTreeMap<ReplicaId, u64>` with `tick` (increment local) and `compare` (Before / After / Equal / Concurrent). Merge is pointwise max.

**OR-set (observed-remove set)** — each `add(element)` carries a unique `Tag` (16-byte BLAKE3 of `replica_id || counter`). `remove(element)` tombstones every tag currently observed for that element. Concurrent `add` and `remove` of the same element resolves **add-wins** because the concurrent add has a fresh tag the remove never saw.

**LWW register** — `(value, timestamp, replica_id)`. Merge prefers higher `timestamp`; ties resolved by lexicographically larger `replica_id` (deterministic across all replicas → commutative).

### Acceptance gate

> Lattice merge laws property test.

`ol_crdt/tests/lattice_laws.rs` property-tests across **1,000,000 random (a, b, c) folder triples**:

1. **Commutativity**: `a ⊔ b == b ⊔ a` (structural-hash equality).
2. **Associativity**: `(a ⊔ b) ⊔ c == a ⊔ (b ⊔ c)`.
3. **Idempotency**: `a ⊔ a == a`.

The random folder generator covers four state-shape buckets:

| Bucket | Operations |
|---|---|
| 0 | Pure adds (stress add-only path). |
| 1 | Adds + removes (tombstone path). |
| 2 | Adds + removes + concurrent re-adds (add-wins regression). |
| 3 | Also LWW-attribute battles (concurrent renames of same FileId). |

Iter count is configurable via `OL_CRDT_GATE_ITERS`; CI default is 10,000 (≤500 ms) and the gate run is 1,000,000 (≤9 s on a tuned x86 host). On commit `<SHA>` all three laws hold across 1,000,000 random states (0 violations).

## Consequences

**Positive:**
- Mergeable folders mean any two replicas converge regardless of network ordering — the foundation for the plan's "every state change is CRDT-mergeable" doctrine.
- Add-wins OR-set means the typical user mental model ("I just dragged that file in") wins against a concurrent remove on another device. No file disappears under racing edits.
- LWW with replica-id tiebreaker is **fully deterministic**; no peer needs a real-time clock, only a monotonic counter.

**Negative:**
- Tombstone storage grows with remove history. Garbage collection requires a quorum-style "every replica has observed every tombstone" check; not implemented in this drop — folder state grows monotonically until manual `prune`.
- LWW loses concurrent updates on the same attribute (one wins by replica-id tiebreaker). For attributes where loss is unacceptable (file contents themselves) we don't use LWW — file contents are content-addressed chunks (ADR-0001) and the chunk store is monotonic.

## References

- Shapiro, Preguiça, Baquero, Zawirski, "A comprehensive study of Convergent and Commutative Replicated Data Types" (INRIA RR-7506, 2011).
- ADR-0021 (capability layer for folder grants).
- `FILE_ENGINE_V2_PLAN.md` line 137 (item #4) + 290 (acceptance gate).
