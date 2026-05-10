# ADR-0014: Format-Aware Chunking — ZIP entry boundaries + video GOP boundaries

**Status:** ACCEPTED (Phase B acceptance number)
**Phase:** B
**Depends on:** ADR-0001 (CDC kernel), ADR-0003 (chunk_record `format_aware` flag)
**Augments, does not replace:** ADR-0001

---

## Context

Pure content-defined chunking (FastCDC + Gear-256) is content-blind: it finds boundaries by rolling-hash patterns, no matter what bytes flow through it. That's the right default — it gives ~30-60% dedup on heterogeneous corpora and survives unknown formats gracefully. It's not the right *only* answer for files whose structural boundaries are misaligned with FastCDC's hash boundaries:

- **ZIP archives (`.zip`, `.docx`, `.xlsx`, `.pptx`, `.odt`, `.apk`, `.jar`, `.epub`, `.kra`).** A ZIP file is a sequence of local-file-header + compressed-payload + central-directory entries. When the user edits one file inside an `.xlsx` (the most common "small ops" workflow), only that entry's bytes change. Pure FastCDC sees the whole ZIP as a byte stream and slides its hash window, so a 1 KiB edit in a 50 MiB archive can shift every chunk boundary downstream of the edit. Dedup drops to ~0%.
- **Video (Matroska / MP4 / WebM).** Group-of-Pictures (GOP) boundaries are the natural sync points: each GOP starts with an I-frame, then has P/B-frames that depend on it. Trimming the head of a video or replacing the soundtrack changes specific GOPs; pure CDC misses the structure.
- **Premiere / Logic / Resolve project files.** Already mostly XML-or-JSON + binary asset references; structural boundaries are well-defined.

Phase A1 already wired a `FORMAT_AWARE` flag into the chunk_record flags byte (ADR-0003) precisely so this layer could slot in without a format break.

## Decision

**Augment the CDC kernel with a format detector + boundary injector.**

The boundary injector runs *before* the CDC kernel and emits **forced boundary offsets** based on the detected format. The CDC kernel then runs over each segment between forced boundaries independently, never crossing them. Result: a ZIP entry that changes never affects the chunk boundaries of any other ZIP entry.

### Detection (cheap, conservative)

Format detection runs on the leading bytes of each input stream + path-extension hint:

| Format | Magic | Path hint | Action |
|---|---|---|---|
| ZIP-family | `PK\x03\x04` at offset 0 | `.zip` / `.docx` / `.xlsx` / `.pptx` / `.odt` / `.apk` / `.jar` / `.epub` / `.kra` | Inject one forced boundary at the start of every local-file-header. |
| MP4 / Matroska | `ftyp` box / EBML header | `.mp4` / `.m4v` / `.mkv` / `.webm` | Inject one forced boundary at the start of every track-encoded GOP (where the demuxer signals a sync sample). |
| Everything else | — | — | Pure CDC. |

**Conservative principle:** if format detection is ambiguous (e.g. a file claims `.zip` extension but the leading bytes don't match), fall back to pure CDC. False-positive format-aware chunking is worse than missing a structural boundary — it can shred dedup in the wrong direction.

### ZIP boundary injection

ZIP local-file-header signature is `0x04034B50` (little-endian `PK\x03\x04`). Walk the input forward; at every occurrence, emit a forced-boundary at that byte offset. Constraints:

- **Cap minimum chunk size** at 8 KiB (ADR-0001 min). If two LFH signatures are <8 KiB apart, only the first becomes a boundary; the second is absorbed into the larger CDC region. This keeps tiny-entry archives (some `.epub` per-chapter splits) from producing degenerate ~100-byte chunks.
- **Don't trust LFH signatures inside compressed payloads.** A compressed payload can contain the byte sequence `PK\x03\x04` by chance. We require the LFH parse to also have plausible (`version_needed`, `compression_method`, `last_mod_time`) — a cheap 8-byte sanity check. False positives on this gate are rare (~10^-9 per byte) and the worst case is a missed dedup, not corruption.
- **Path-extension hint optional but preferred.** If the file extension doesn't suggest ZIP, we still try the magic match but skip the deep scan unless the hit rate looks promising (first 256 KiB has ≥2 valid-looking LFHs).

### Video GOP boundary injection

For Phase B v1 we ship ZIP-family only. **Video GOP detection is deferred to Phase B-2** because:

- Robust GOP detection needs a real demuxer (Matroska EBML parser, MP4 box parser, H.264 NAL unit parser). Each adds 3-10K LoC of attack surface and bumps the supply-chain footprint.
- Open-source demuxers (matroska-rs, mp4parse-rust) exist and are credible, but adding three of them in one phase is over-scoping per stress-test #1.
- Pure CDC on video already achieves ~70% dedup on the small-ops workload (podcaster edits the last 30 seconds → only the last GOP changes). GOP-awareness lifts this to ~95%; the gap matters less than ZIP-family does (where pure CDC is closer to 0% on insertions).

Phase B v1 ships with a placeholder `VideoFormatScanner` trait whose default implementation returns no boundaries. Phase B-2 plugs in the demuxer-backed implementation.

### Wire compatibility

When a format-aware boundary was used, the resulting `ChunkRecord` sets the `FORMAT_AWARE` flag bit. Receivers don't have to understand the format to read the chunk — the boundary is already chosen on the sender side and the chunk's bytes are self-describing.

The `ChunkRecord.chunk_id` is still `BLAKE3(plaintext)` (or convergent-derived) — the BLAKE3 hash doesn't care how the boundary was chosen. So a peer that already has the chunk (regardless of how *it* was chunked) gets a clean dedup hit. **This is the core property: format-aware sender + format-blind receiver still benefit from dedup.**

### Falsifiable acceptance number

**Bytes-on-wire reduction ≥80% for the canonical "1 KiB edit in 50 MiB .xlsx" workload.**

Test corpus: starting `.xlsx` of size 50 MiB. Apply a single-cell edit that touches ~1 KiB of one inner XML. Pure-CDC engine transfers ~50 MiB of fresh chunks (the edit cascades). Format-aware engine transfers ≤10 MiB (the one entry's chunks + a tiny number of CDC follow-up chunks).

This is the verification gate. Phase B doesn't ship without it.

## Consequences

**Positive:**
- Restores dedup on the "edit one file in a ZIP" workflow that dominates small-ops file sharing (every Office doc, every Android `.apk` upload, every `.epub`).
- Conservative detection (magic + path hint, conservative fallback) protects against false positives shredding dedup the wrong way.
- The `FORMAT_AWARE` flag is informational; receivers without format awareness still dedup correctly.

**Negative:**
- ZIP-LFH walking is O(N) on input bytes; adds ~1 cycle per byte on the ingest hot path. Negligible against CDC + BLAKE3 + AEAD.
- Misdetection on a binary file that happens to look ZIP-shaped → degraded dedup on that file (no corruption, just missed opportunity). Acceptable.
- Adds ~200 LoC of ZIP parser to Rust supply chain. We do *not* depend on a full ZIP library — only the LFH walker, ~80 LoC. The full ZIP library footprint (`zip` crate, ~3K LoC) is rejected.

## Verification

1. **Pure-CDC equivalence on non-ZIP input**: feed a 100 MiB random binary; format-aware path must produce byte-identical chunk boundaries to pure CDC.
2. **ZIP-LFH detection on real archives**: 100 random `.zip`/`.docx`/`.xlsx` files from a public corpus → each LFH signature in the file becomes a forced boundary (or is absorbed by the 8 KiB min).
3. **Single-cell-edit dedup**: starting `.xlsx` size 50 MiB; edit one cell; rebuild; measure unique-bytes between the two runs. **Target: ≤10 MiB unique bytes.**
4. **Wire-flag round-trip**: encode a format-aware chunk with the flag set; decode → flag preserved.
5. **Falsified-magic resilience**: random bytes that *contain* `PK\x03\x04` at non-LFH positions → conservative parser rejects them (no spurious boundary, no corruption).
6. **Fuzz**: 24h `cargo-fuzz` on the LFH walker → zero crashes.

## References

- ZIP spec (PKWARE APPNOTE 6.3.10): https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
- ADR-0001 (CDC kernel) — the kernel format-aware chunking augments.
- ADR-0003 (on-disk format) — the `FORMAT_AWARE` flag bit.
