# ADR-0005: Manifest WAL Coupled to Chunk WAL

**Status:** ACCEPTED (Phase A1 acceptance number — must ship in A1, not C)
**Phase:** A1 (item #4 crash-only WAL, item #8 manifest WAL)
**Depends on:** ADR-0003 (chunk_log + manifest_log on-disk format)

---

## Context

Per the FILE_ENGINE_V2_PLAN.md stress-test critique #1: "Manifest WAL not coupled to chunk WAL → FUSE data loss on crash." Mitigation: manifest WAL is an A1 deliverable, NOT implicit in C.

The FUSE consistency hazard is concrete: the kernel returns `write()` success to userspace before the engine's WAL has fsync'd. If the daemon crashes between (a) appending the chunk to chunk_log and (b) appending the matching manifest entry to manifest_log, the engine boots with a chunk that has no manifest reference (orphan), or worse — boots with a manifest reference to a chunk that was lost in a torn write.

Without WAL coupling, the engine ships a FUSE that loses data on crash and may not detect it for hours or days.

This ADR specifies how the two logs are coupled atomically.

## Decision

**Two-phase commit with chunk_log_anchor cross-reference, both fdatasync'd before the operation completes. Recovery rejects orphans on either side.**

### Write protocol (per logical write of a new chunk):

```
phase 1: append chunk to chunk_log
  1.1 serialize ChunkRecord {header + frames + crc} into a buffer
  1.2 atomic append to chunk_log/NNNNNN.clog at offset O via write()
  1.3 fdatasync(chunk_log_fd)
  1.4 record (clog_file_id=NNNNNN, clog_offset=O, length_ciphertext=L) for phase 2

phase 2: append manifest entry to manifest_log (with the chunk_log_anchor referencing phase 1's location)
  2.1 pack `(NNNNNN:u32, O:u32)` into the existing u64 anchor field, then serialize ManifestRecord {hlc + actor + chunk_log_anchor + body + crc}
  2.2 atomic append to manifest_log/NNNNNN.mlog
  2.3 fdatasync(manifest_log_fd)

phase 3 (memtable update; not durability-critical, rebuildable from logs):
  3.1 insert into memtable: chunk_id -> (NNNNNN, O, L, ratchet_key_id, stripe_descriptor)
  3.2 increment write counter for memtable flush threshold check
```

### Crash points and outcomes:

| Crash before | Recovery sees | Action |
|---|---|---|
| 1.3 fdatasync chunk_log | Chunk record may be torn; CRC will fail | Reject torn record; treat as if write never happened. Manifest entry never appended. Consistent. |
| 1.3 done, before 2.2 | Chunk record valid in chunk_log; no matching manifest record | Orphan chunk: visible in chunk_log scan but no manifest references it. Recovery: leave chunk in place; mark as "unreferenced" in memtable. GC reclaims later. |
| 2.3 fdatasync manifest_log | Manifest record may be torn; CRC will fail | Reject torn record; matching chunk in chunk_log is now an orphan (same as above). Consistent. |
| After 2.3 | Both records valid; recovery succeeds normally | Memtable rebuilt from logs. |

**Key invariant**: a manifest record's `chunk_log_anchor` references a specific `(clog_file_id, clog_offset)` that was already fsync'd before the manifest record itself was appended. The packed layout is `file_id:u32 || offset:u32`; old high-word-zero values are read as file-1 offsets. Recovery validates both components, so an equal offset in a different rotated file cannot satisfy the reference. If the chunk log lacks that exact valid CRC'd record, the manifest record is rejected.

### Group commit (performance):

A naive impl does 2 fdatasyncs per logical write. At ~1 ms per fsync on NVMe, this caps writes at 500/s/thread. Group commit batches:

```
fn write_batch(ops: Vec<ChunkWrite>) -> Result<()> {
    // Phase 1 batch: append all chunk records, single fdatasync
    for op in &ops {
        serialize(&op.chunk_record).append_to(chunk_log)?;
    }
    fdatasync(chunk_log_fd)?;

    // Phase 2 batch: append all manifest records, single fdatasync
    for op in &ops {
        serialize(&op.manifest_record).append_to(manifest_log)?;
    }
    fdatasync(manifest_log_fd)?;

    // Phase 3 batch: memtable updates
    for op in &ops {
        memtable.insert(op.chunk_id, op.location);
    }

    Ok(())
}
```

A batch of 100 writes is 2 fdatasyncs total instead of 200. Throughput goes from 500/s/thread to 50,000+/s/thread (limited by NVMe IOPS, not fsync count).

Concurrent writers: a coordinator thread accumulates pending writes for ≤1 ms or until N writes accumulate, whichever first. Writers block on a Future that resolves when their batch's phase 2 fdatasync returns. This bounds latency at 1 ms while amortizing fdatasync cost.

### Fsync semantics on each platform:

- **Linux**: `fdatasync(2)` = data + size metadata, no atime/mtime. Sufficient.
- **macOS**: `F_FULLFSYNC` via `fcntl()` is the only way to get genuine durability past disk write cache. Plain `fsync(2)` lies. Use `F_FULLFSYNC` on the chunk_log and manifest_log fds.
- **Windows**: `FlushFileBuffers()` is sufficient when the file is opened with `FILE_FLAG_WRITE_THROUGH` AND the underlying disk has its write cache disabled OR honors FUA. We open both logs with `FILE_FLAG_WRITE_THROUGH | FILE_FLAG_NO_BUFFERING` for chunk_log (8 KiB-aligned writes only) and `FILE_FLAG_WRITE_THROUGH` for manifest_log.

### What's NOT durability-critical (and thus doesn't need fsync):

- Memtable updates: rebuildable from chunk_log + manifest_log.
- SST flushes: rebuildable from memtable + logs.
- Bloom filter sidecars: rebuildable from SSTs.
- LSM compactions: rebuildable from L0 SSTs.

This minimizes the durability syscall count to exactly 2 per batch.

## Consequences

**Positive:**
- FUSE consistency hazard closed in A1, not deferred.
- Crash recovery is monotonic: any state recovery sees is consistent with some prefix of operations actually committed.
- Group commit amortizes fdatasync cost; throughput target (≥10K logical writes/s/thread on NVMe) is reachable.
- Two separate log files mean parallel writers can append concurrently to chunk_log without blocking on manifest_log writers (and vice versa) — only the fdatasync is serialized.
- Recovery is simple: linear scan + CRC validation + anchor cross-reference. No complex log-structured-merge replay logic.

**Negative:**
- Two fdatasync per batch instead of one. Acceptable; group commit makes this near-free.
- Orphan chunks accumulate (chunks whose manifest commit failed). GC must scan for them periodically. Mitigation: chunk_log records carry a reference-count flag updated by manifest_log scans on boot; orphans (refcount=0) are reclaimed by background GC.
- Anchor-based recovery means we cannot reorder log files post-write (would invalidate anchors). Mitigation: chunk_log files are append-only and immutable until reclaimed by full-file GC; never edited.

## Verification

1. **Crash injection gate (the canonical Phase A1 acceptance test)**: kill -9 the writer at every byte offset of a 100K-write workload (random crash points). Recovery convergence: manifest references valid chunks; chunks without manifest are flagged as orphans (not durable for the user, but the engine state is consistent).
2. **Group commit throughput gate**: 100K logical writes (chunks of 64 KiB) sustained at ≥10K writes/s/thread on local NVMe.
3. **Fsync guarantee gate**: power-fail injection (fault-injection layer simulating cache loss). Recovery state matches "operations whose batch fsync returned" — never anything more.
4. **macOS F_FULLFSYNC verification**: on macOS, plain fsync is not sufficient; tested via fault-injection that simulates dirty disk-cache loss.
5. **Anchor cross-validation**: synthetic test with a manifest_log record whose chunk_log_anchor points to a torn/missing chunk_log offset. Recovery MUST reject the manifest record.

## References

- Crash-only software: Candea + Fox, HotOS 2003.
- WAL group commit: PostgreSQL `wal_writer.c`.
- macOS F_FULLFSYNC: Apple `fsync(2)` man page; CockroachDB and SQLite use this for durability.
- Linux fdatasync: `man 2 fdatasync`; faster than `fsync` for our case (no metadata changes).
- "Files Are Hard": Pillai et al., OSDI 2014 — taxonomy of crash-consistency bugs we are designing to avoid.
