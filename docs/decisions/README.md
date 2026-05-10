# Architecture Decision Records — File Engine v2

Architecture Decision Records (ADRs) for the One Link file engine v2 rebuild
([../FILE_ENGINE_V2_PLAN.md](../FILE_ENGINE_V2_PLAN.md)). Each ADR locks in a
load-bearing decision that downstream code commits to. ADRs do not have
calendar dates — they have phase assignments and acceptance gates.

## Phase A1 ADRs (foundation)

These eight decisions fix the engine's substrate before any code lands.
Changing one without an ADR amendment is a protocol break.

| # | Decision | Phase | Depends on |
|---|---|---|---|
| [0001](0001-cdc-kernel.md) | Content-defined chunking — FastCDC + Gear-256 + AVX-512/NEON | A1 | — |
| [0002](0002-aead-frame.md) | AEAD primitive (AES-256-GCM / ChaCha20-Poly1305) + 16 KiB frame size within chunks | A1 | 0001 |
| [0003](0003-on-disk-format.md) | chunk_log + manifest_log + LSM index on-disk format | A1 | 0001, 0002 |
| [0004](0004-stripe-layout.md) | Reed-Solomon (10, 4) over GF(2^8); content-hash-based stripe boundaries | A1 (encoded in header), C (encoder/decoder) | 0001, 0003 |
| [0005](0005-manifest-wal-coupling.md) | Two-log atomic commit with chunk_log_anchor; group commit | A1 | 0003 |
| [0006](0006-blake3-derive-scheme.md) | BLAKE3 domain-separated derivation scheme; registered context list | A1 | — |
| [0007](0007-crash-only-wal-format.md) | Per-record CRC32-Castagnoli; replay invariants; rotation policy | A1 | 0003, 0005, 0006 |
| [0008](0008-ffi-contract.md) | Python ↔ Rust FFI via pyo3 + maturin; abi3 wheel; GIL-release contract | A1 | — |

## Future-phase ADRs (reserved numbering)

ADRs 0009-0019 reserved for Phase B (information layer + filesystem surface).
ADRs 0020-0029 reserved for Phase C (multi-axis baseline).
ADRs 0030-0039 reserved for Phase D (visionary).

Each future ADR will be added when its phase begins. Phase B will need at
minimum: Bloom filter parameters, RaptorQ symbol size + IPR resolution, XOR
network coding combination policy, FUSE/FSKit/Dokan FFI surface,
format-aware chunking codec list, convergent encryption content-type policy.

## ADR template

New ADRs follow this skeleton:

```markdown
# ADR-NNNN: Decision title

**Status:** PROPOSED | ACCEPTED | SUPERSEDED | DEPRECATED
**Phase:** A1 / A2 / B / C / D
**Depends on:** other ADRs (or "nothing")
**Supersedes:** prior ADR if any

## Context
What problem this decision addresses; what's at stake.

## Decision
The exact rule the engine follows. Precise enough that two engineers reading
this independently produce compatible implementations.

## Consequences
- Positive
- Negative

## Verification
Falsifiable acceptance criteria.

## References
External literature, prior art, related ADRs.
```

## Amendment process

1. Open a PR adjusting the affected ADR. Status flips from ACCEPTED to
   AMENDED-PENDING; PR description states what compatibility break (if any)
   the amendment introduces.
2. Acceptance gate for the amendment includes regression tests against any
   existing on-disk data the change affects. If a chunk_log format change is
   needed, a migration path or a versioned format tag must accompany.
3. On merge, status returns to ACCEPTED; the prior ADR remains in git
   history (do not rewrite). If the change is large enough, supersede the
   ADR with a new number and mark the old as SUPERSEDED.
