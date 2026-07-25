# ADR-0007: Crash-Only WAL Format and Replay Invariants

**Status:** ACCEPTED (Phase A1 acceptance number)
**Phase:** A1 (item #4: crash-only WAL)
**Depends on:** ADR-0003 (chunk_log + manifest_log on-disk format), ADR-0005 (WAL coupling protocol), ADR-0006 (BLAKE3 derive scheme)

---

## Context

Per the FILE_ENGINE_V2_PLAN.md, Phase A1 acceptance gate: "kill -9 survival across ≥10,000 randomized injection points; zero chunk loss; zero manifest divergence after recovery."

A WAL that's almost-crash-only ships subtle bugs for years. This ADR specifies the exact replay invariants and the exact failure modes the WAL handles.

The WAL must:

1. Never lose a write whose batch's fdatasync returned success.
2. Never resurrect a write that was rolled back / never committed.
3. Detect and reject torn writes (kernel buffer page-size bounds; physical sector tearing).
4. Detect and reject corrupted records (bit-flips on disk, RAM corruption during write).
5. Allow safe rotation of log files (close old, open new) without losing in-flight writes.
6. Allow safe truncation of the tail of the most-recent log file when CRC fails on the last record.
7. Replay deterministically: two independent recovery runs of the same crashed state produce byte-identical recovered states.

## Decision

**WAL format: append-only, length-prefixed records with CRC32-Castagnoli trailer. Replay scans linearly, validates CRCs, stops at first invalid record per file. File rotation creates a new file once size threshold is hit; old files are immutable until reclaimed by full-file GC.**

### Per-file structure:

```
+---------+--------------------------------------------------------+
| Offset  | Field                                                  |
+---------+--------------------------------------------------------+
| 0       | magic: [u8; 8] = b"OL-CLOG1" or b"OL-MLOG1"           |
| 8       | format_version: u32 = 1                                |
| 12      | log_kind: u32 (1 = chunk_log, 2 = manifest_log)        |
| 16      | created_unix_micros: u64 (informational only; not load-bearing for recovery) |
| 24      | reserved: [u8; 40] (zero-filled, must verify zero)     |
| 64      | first_record: ...                                      |
| ...     | (records)                                              |
| EOF     | (last record may be torn; see truncation rules)        |
+---------+--------------------------------------------------------+
```

The 64-byte file header is fsync'd at file creation, before the first record is written.

### Per-record structure:

```
+---------+--------------------------------------------------------+
| 0       | record_kind + flags (per-log-kind, see ADR-0003)       |
| ...     | record header fields (per ADR-0003)                    |
| ...     | record body                                            |
| End     | record_crc32c: u32 (CRC of header + body)              |
+---------+--------------------------------------------------------+
```

CRC is the **last 4 bytes** of every record. To compute, the writer:

1. Builds the in-memory record buffer with CRC bytes set to zero placeholder.
2. Computes CRC32C over header + body.
3. Writes CRC bytes into the placeholder.
4. Issues a single `pwrite()` of the complete record at the next append offset.
5. Increments append offset by record length.

**Why not "write header, write body, write trailer separately"?** Because partial writes can interleave with concurrent writers and the kernel may flush a partial record to disk after a power-fail. A single `pwrite()` of the complete buffer is atomic at the syscall level (Linux: `pwrite` is atomic up to PIPE_BUF, but for files it's atomic relative to other syscalls in the same fd; we serialize writes through a single writer thread per log file, eliminating intra-file concurrency).

**Why not store CRC in a header field at the start?** Streaming writers cannot CRC before they know the length; CRC at the end means we know everything before computing it. Also matches LevelDB / RocksDB / BadgerDB convention.

### Page-aligned writes (Windows, optionally Linux O_DIRECT):

On Windows with `FILE_FLAG_NO_BUFFERING`, writes must be sector-aligned (typically 512 bytes or 4 KiB). Records are not naturally sector-sized. Solution: writer pads each record's tail to the next 512-byte boundary with zero bytes (between the CRC32C trailer and the next record start). Padding bytes are not part of any record and not CRC'd; recovery skips zero-byte runs between records.

On Linux without O_DIRECT, no padding needed; the kernel page cache handles unaligned writes.

### Replay algorithm:

```rust
fn replay_log(log_path: &Path) -> Result<Vec<Record>> {
    let mut file = OpenOptions::new().read(true).open(log_path)?;
    let header = read_file_header(&mut file)?;
    verify_magic_and_version(&header)?;

    let mut records = Vec::new();
    let mut offset = 64;  // After file header

    loop {
        match read_record_at(&mut file, offset) {
            Ok(record) => {
                if record.crc_valid() {
                    records.push(record);
                    offset += record.on_disk_len();
                } else {
                    // CRC failed: torn or corrupt record. This is the truncation point.
                    log::warn!("WAL {} truncating at offset {} due to CRC failure", log_path.display(), offset);
                    file.set_len(offset)?;  // Truncate tail
                    file.sync_all()?;
                    break;
                }
            }
            Err(ReadError::ShortRead) => {
                // Reached real EOF; expected for the last file.
                break;
            }
            Err(ReadError::ZeroPadding) => {
                // Skipping a zero-byte run between records (Windows-aligned writes).
                offset = next_record_start_after_zeros(&mut file, offset)?;
            }
            Err(other) => return Err(other),
        }
    }

    Ok(records)
}
```

The truncation policy: a CRC failure can only happen on the LAST record of the LAST file (because earlier records were already fsync'd before later ones started). If a CRC failure is detected mid-file, recovery treats everything from that offset forward as torn and truncates. Subsequent appends start at the truncated offset.

**Critical invariant:** the writer NEVER appends after a sealed file. A file is sealed when the writer rotates. Once sealed, the file is immutable; recovery may truncate its tail (only the last sealed file in the most-recent rotation), but no new bytes are ever written.

### Rotation:

```
chunk_log/000001.clog (sealed, 256 MiB, immutable)
chunk_log/000002.clog (sealed, 256 MiB, immutable)
chunk_log/000003.clog (active, currently appending, ≤256 MiB)
```

Rotation policy: before an append would exceed 256 MiB, allocate the next file:

1. Allocate next file: `open("000004.clog", O_CREAT | O_WRONLY | O_APPEND)`, write file header, fsync.
2. Direct subsequent appends to new file.
3. Flush and fsync the old file's pending group, then switch the single writer to the new fd.

`Wal::append` performs this transition transparently. The single writer may block on the one durability barrier that seals the old group; callers never receive a routine "cap exceeded" error and therefore cannot accidentally turn the per-file limit into a lifetime write limit. The returned append position includes both file id and byte offset.

### Replay determinism:

Two replay runs over the same on-disk state must produce byte-identical recovered state. Sources of nondeterminism to eliminate:

- **Iteration order over files**: recovery sorts log files by file_id (numeric, ascending). Always.
- **Concurrent replay threads**: replay is single-threaded per log. No interleaving.
- **HLC reconstruction**: HLC values come from the manifest_log records themselves (each record carries an hlc_timestamp). Replay does not generate new HLCs; it only replays what was written.
- **Memtable rebuild**: memtable insertion order = log replay order = record-write order = deterministic.
- **SST flush threshold**: threshold is content-addressed (memtable size in bytes), not time-based. Same-content recovery → same flush points.

Property test: replay the same log files 100× in a fresh process; compare in-memory state byte-for-byte. Any divergence = bug.

### What's outside the WAL:

- **SSTs** are not WAL records; they're a derived index built by flushing memtable. Lost SSTs are rebuildable from logs. SSTs have their own CRCs but are not replayed; they're either valid-and-loaded or invalid-and-rebuilt.
- **Bloom filter sidecars** are derived from SSTs; lost sidecars are rebuilt.
- **Memtable** is purely in-memory; rebuilt from logs.

The only durability path is the WAL. Everything else is rebuildable.

## Consequences

**Positive:**
- Crash safety property is mechanically verifiable: replay produces a state consistent with some prefix of writes that successfully fsync'd. No "almost crash-safe" gray zone.
- Single CRC trailer per record matches LevelDB/RocksDB/BadgerDB convention; tooling (custom inspectors, fuzzers) is portable.
- Rotation is transparent and never blocks writers.
- Truncation only on the most-recent file's tail; never edits sealed files.
- Determinism gate is testable: 100× replay → byte-identical state.

**Negative:**
- 4 bytes per record CRC overhead. Negligible.
- Windows alignment requires zero-padding (up to 511 bytes per record). Acceptable; aligns sector writes correctly for `FILE_FLAG_NO_BUFFERING`.
- Per-record CRC is computed over the entire record body, which is up to 256 KiB for chunks. CRC32C hardware-accelerated on x86 (≥10 GiB/s) and ARM64; not a hot-path concern.
- 256 MiB rotation size means ~4-8K records per chunk_log file (depending on chunk size). Recovery linear-scans this; ~50 ms per file on NVMe. Acceptable for boot times.

## Verification

1. **Determinism gate**: replay same logs 100× in fresh processes; in-memory recovered state must be byte-identical across all runs.
2. **CRC integrity gate**: random bit-flip injection on log files (1 bit-flip per file, 10K trials); recovery MUST reject the flipped record (and all subsequent records in that file). State recovered = state up to the corruption point.
3. **Rotation transparency gate**: write 1 GiB of records spanning 4 rotations; replay produces all records in original write order.
4. **Concurrent rotation gate**: writer thread does rotation while another thread queues new writes; queued writes land in the post-rotation file with no loss.
5. **Tail truncation gate**: synthesize a torn last record (write a partial record, simulate crash); recovery truncates exactly to the boundary of the previous valid record.
6. **Page-fault injection (Windows)**: simulate write that loses last sector before fsync; recovery truncates correctly.
7. **macOS F_FULLFSYNC gate**: with simulated dirty disk-cache loss, only records whose F_FULLFSYNC returned are recovered.

## References

- LevelDB log format: `db/log_format.h` (similar concept, simpler).
- RocksDB WAL: `db/log_writer.cc` (record-batch design we model after).
- BadgerDB value log: similar layout with checksums.
- Linux O_DIRECT semantics: `man 2 open` section on O_DIRECT.
- Windows FILE_FLAG_NO_BUFFERING: MSDN; our alignment policy follows the documented constraints.
- "Files Are Hard": Pillai et al., OSDI 2014.
- BLAKE3 derive_key for content-addressing — see ADR-0006.
