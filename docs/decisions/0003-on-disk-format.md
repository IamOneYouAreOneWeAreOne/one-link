# ADR-0003: Chunk Store On-Disk Format

**Status:** ACCEPTED (Phase A1 acceptance number — do not revisit without ADR amendment)
**Phase:** A1 (items #4 crash-only WAL, #5 LSM index, #8 manifest WAL)
**Depends on:** ADR-0001 (chunk sizes), ADR-0002 (frame structure)

---

## Context

The chunk store is the engine's durability surface. Per the plan stress-test #1 and #3, the on-disk format must support:

1. **Crash-only recovery.** `kill -9` at any byte must leave the store consistent. Replay reconstructs intent from the WAL.
2. **Both raw-BLAKE3 AND convergent-BLAKE3 chunk addressing from day one.** Phase B can flip the Bloom-init default to convergent encryption without breaking existing manifests.
3. **Stripe layout from day one.** Reed-Solomon erasure coding ships in Phase C; the on-disk format must already be able to record stripe membership without a format break.
4. **Per-chunk ratchet-key-id field from day one.** Phase C per-chunk ratchet integrates without format break.
5. **Bloom filter front for the LSM index.** Sub-microsecond chunk-presence checks.
6. **Mmap-friendly reads.** Hot path reads chunks via mmap; pre-allocated, page-aligned writes via `fallocate` / `SetEndOfFile`.

This format is the load-bearing constraint for the entire engine. Get it wrong and every later layer pays the cost of working around it.

## Decision

**Three on-disk components, all crash-only:**

```
<data_dir>/store/
├── chunk_log/               # Append-only chunk content WAL (the durability log)
│   ├── 000001.clog          # 256 MiB per file; rotates by size
│   ├── 000002.clog
│   └── ...
├── manifest_log/            # Append-only manifest WAL (tied to chunk_log via WAL Coupling)
│   ├── 000001.mlog
│   └── ...
└── index/                   # LSM index over chunk_log + manifest_log
    ├── memtable.wal         # In-memory table backing log
    ├── L0/000001.sst        # Sorted string tables, level 0 (newest, possibly overlapping)
    ├── L1/...               # Compacted, non-overlapping
    └── bloom/               # Bloom filter front (one per SST)
```

### chunk_log record format (on-disk, little-endian):

```
+--------+------------------------------------------------------------------+
| Offset | Field                                                            |
+--------+------------------------------------------------------------------+
| 0      | record_kind: u8                                                  |
|        |   0x01 = ChunkBlob                                                |
|        |   0x02 = StripeParity                                             |
|        |   0xFE = TombstoneRef (chunk reclaimed; address still valid)     |
|        |   0xFF = Sentinel (rotation marker)                               |
| 1      | flags: u8                                                        |
|        |   bit 0: address_kind (0=raw-BLAKE3, 1=convergent-BLAKE3)         |
|        |   bit 1: aead_kind (0=AES-256-GCM, 1=ChaCha20-Poly1305)           |
|        |   bit 2: compressed (0=raw, 1=zstd-encoded plaintext before AEAD) |
|        |   bit 3: format_aware (0=CDC, 1=format-aware boundary)            |
|        |   bit 4-7: reserved (must be zero)                                |
| 2      | reserved: u16 (must be zero)                                     |
| 4      | length_plaintext: u32 (8 KiB - 256 KiB per ADR-0001)             |
| 8      | length_ciphertext: u32 (plaintext + one tag, or one tag/frame)   |
| 12     | chunk_id_full: [u8; 32] (BLAKE3-256 of plaintext OR convergent)  |
| 44     | ratchet_key_id: [u8; 16] (HKDF derivation seed; ADR-0006)        |
| 60     | stripe_descriptor: StripeDescriptor (24 bytes; ADR-0004)          |
| 84     | AEAD ciphertext: atomic chunk + 16-byte tag, or 16 KiB frames + 16-byte tag each |
| ...    | (streaming frame_count = ceil(length_plaintext / 16384))          |
+--------+------------------------------------------------------------------+
| End    | record_crc32c: u32 (CRC32-Castagnoli of header + frames)         |
+--------+------------------------------------------------------------------+
```

Header is fixed 84 bytes. Body is `length_ciphertext` bytes. Trailer is 4 bytes CRC.

### manifest_log record format:

```
+--------+------------------------------------------------------------------+
| 0      | record_kind: u8                                                  |
|        |   0x10 = ManifestVersion (a CRDT op on a folder)                  |
|        |   0x11 = CapabilityGrant                                          |
|        |   0x12 = CapabilityRevoke                                         |
|        |   0x13 = MerkleRevocationLogEntry                                 |
|        |   0x14 = ShareLink                                                |
|        |   0xFF = Sentinel                                                 |
| 1      | flags: u8 (reserved=0)                                           |
| 2      | length: u16 (record body length, max 64 KiB)                     |
| 4      | hlc_timestamp: u64 (hybrid logical clock)                        |
| 12     | actor_id: [u8; 32] (peer fingerprint; CRDT actor identifier)     |
| 44     | chunk_log_anchor: u64 (`clog_file_id:u32 || clog_offset:u32`; legacy high-word-zero anchors mean file 1; ADR-0005) |
| 52     | body: [u8; length] (canonically-encoded record per std.codec.canon)
| ...    |                                                                  |
+--------+------------------------------------------------------------------+
| End    | record_crc32c: u32                                               |
+--------+------------------------------------------------------------------+
```

### Index SST format:

Standard sorted-string-table layout, key = chunk_id_full (32 bytes), value = (clog_file_id, clog_offset, length_ciphertext, ratchet_key_id, stripe_descriptor). Each SST has a sidecar Bloom filter (10 bits/key, ~1% false positive rate, ~1.25 MB per million chunks).

### Atomicity contract:

Every write follows this sequence:
1. Append AEAD-encrypted chunk frames + header + CRC to `chunk_log/NNNNNN.clog` via `write()` then `fdatasync()`.
2. Append manifest record (with `chunk_log_anchor = pack(clog_file_id, clog_offset_just_written)`) to `manifest_log/NNNNNN.mlog` then `fdatasync()`.
3. Update in-memory index (memtable). Memtable is durable via the chunk_log+manifest_log; no separate memtable WAL needed (eliminates one durability path = simpler crash recovery).
4. When memtable ≥ 64 MiB, flush to L0 SST. Flush is a non-durability operation (chunk_log + manifest_log are still authoritative); SST is rebuildable from them.

### Recovery contract (crash-only):

1. On boot, scan all `chunk_log/*.clog` files. For each record, verify CRC; reject torn/corrupt records (last record of last file is the only legitimate truncation point). Build chunk_id → location map in memory.
2. Scan all `manifest_log/*.mlog` files. For each record, verify CRC; decode and verify the complete `(chunk_log file id, offset)` anchor (otherwise the manifest commit happened *after* a chunk write that was lost; reject the manifest record). Pre-rotation legacy anchors with a zero high word map to file 1.
3. Rebuild memtable from manifest_log records newer than the most recent flushed SST.
4. Rebuild SSTs that are missing or whose CRC sidecar fails.

No "graceful shutdown" path. No "did the file get fully synced" ambiguity. The CRC is the truth.

## Consequences

**Positive:**
- Both-address support (bit 0 of flags) means convergent encryption ships in B without format break.
- Stripe descriptor reserved from day one (24 bytes always); EC encode/decode in C plugs in without rewriting the chunk_log format.
- Ratchet-key-id reserved from day one; per-chunk forward-secret ratchet in C plugs in.
- Crash-only by design: no graceful shutdown to break, no "shutdown_clean.txt" sentinel to forge.
- Mmap-friendly: chunk frames are aligned to 16 KiB plaintext boundaries within a chunk; the 84-byte header is small enough to fit in a single page even for max-size chunks.
- Manifest WAL coupling via `chunk_log_anchor` resolves stress-test #1: a manifest commit that references a chunk write that didn't make it to disk is detectable and rejected on recovery.
- LSM index is rebuildable from the logs; bloom filter sidecar is rebuildable from the SST. Loss of either is recoverable.
- Compatible with reproducible builds: all on-disk integers are little-endian by spec; CRC32-Castagnoli is deterministic.

**Negative:**
- 84-byte chunk header is overhead at 0.13% for 64 KiB chunks. Acceptable.
- Two-WAL design (chunk_log + manifest_log) doubles the syncs per logical write. Mitigated by group commit (ADR-0007): N concurrent writes batch into one fdatasync per WAL.
- `chunk_log_anchor` couples manifest commits to specific chunk-log file/offset coordinates. If we ever introduce log compaction that rewrites coordinates, the anchor must be re-mapped. Mitigation: log compaction operates only on full files and rewrites anchors atomically.

## Verification

1. **Crash injection gate**: kill -9 the writer at every byte offset of a 1 GiB workload (>10,000 random offsets). Recovery must produce a chunk store consistent with "every chunk whose record CRC validates is durable; every chunk whose record CRC fails or is torn is reject-on-load."
2. **Both-address gate**: write 1 M chunks half raw-BLAKE3, half convergent. Read back: both addressable, neither corrupts the other.
3. **Stripe descriptor compatibility**: in A1, stripe descriptor is always zero (no EC yet). In C, when EC encoder fills the field, A1-vintage chunks (zero descriptor) coexist with C-vintage chunks (filled descriptor) without index migration.
4. **Mmap read amplification**: a 64 KiB read at random offset within a 64 KiB chunk decrypts ≤32 KiB (one or two AEAD frames). Measured via instrumented decrypt counter.
5. **Recovery convergence**: write 10K chunks with WAL coupling; kill -9 between chunk_log and manifest_log appends; recovery rejects the orphaned chunk write OR forward-applies the matching manifest, but never produces a divergent state.

## References

- LSM tree (LevelDB / RocksDB design): O'Neil et al., "The Log-Structured Merge-Tree," 1996.
- Crash-only software: Candea + Fox, HotOS 2003.
- WAL group commit: PostgreSQL `wal_writer` design.
- CRC32-Castagnoli: hardware-accelerated on x86 (CRC32 instruction) and ARM64 (CRC32 extension).
- BLAKE3: Reference https://github.com/BLAKE3-team/BLAKE3.
- Sorted string tables: Bigtable paper, Chang et al., OSDI 2006.
