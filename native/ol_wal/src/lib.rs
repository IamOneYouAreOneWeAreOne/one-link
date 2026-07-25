//! `ol_wal` — crash-only write-ahead log per [ADR-0007].
//!
//! The chunk store and manifest store both sit on top of this log family.
//! Per ADR-0007 the log:
//!
//! - **Append-only** with **per-record CRC32-Castagnoli** trailer (CRC32C is
//!   hardware-accelerated on x86 (SSE4.2) and ARM64 (CRC32 extension);
//!   the [`crc32c`] crate dispatches at runtime).
//! - **64-byte file header** containing magic bytes, format version, and
//!   log kind, fsync'd at file creation.
//! - **256 MiB rotation** to a new file once the active file's size cap is
//!   reached. Old files are **immutable** until reclaimed by full-file GC.
//! - **CRC failure on the LAST record of the LAST file is the canonical
//!   truncation point.** Recovery sets the file length to the offset of
//!   the last valid record.
//! - **Group commit**: writers batch into a single [`Wal::flush`] call
//!   per group, so N concurrent writes amortize a single fdatasync /
//!   `F_FULLFSYNC` / `FlushFileBuffers`.
//! - **Replay is deterministic**: linear scan + CRC validation + version /
//!   magic check. Two independent recovery runs over the same on-disk
//!   state produce byte-identical recovered records.
//!
//! ## API surface
//!
//! - [`Wal`] — the writer handle. Wraps the active file fd, holds the
//!   pending batch, exposes [`Wal::append`] (buffer-only, no fsync) and
//!   [`Wal::flush`] (durable barrier).
//! - [`replay_log_dir`] — the canonical recovery entry point. Scans
//!   every `*.wal` file under a directory, validates each record's
//!   CRC, and yields a `Vec<Record>` in append order.
//! - [`Record`] — the public record shape: `kind` byte + `flags` byte +
//!   user payload. Higher-level crates (`ol_chunk_store`) layer their
//!   own typed records on top.
//!
//! ## Per-record on-disk layout
//!
//! ```text
//! +------+-------+-------+----------+--- payload ---+----------+
//! | kind | flags | rsvd  | length   | <length bytes>| crc32c   |
//! | u8   | u8    | u16=0 | u32 LE   |               | u32 LE   |
//! +------+-------+-------+----------+---------------+----------+
//! ```
//!
//! The 8-byte fixed header + variable payload + 4-byte CRC trailer is
//! written via a SINGLE `pwrite()` to be atomic against torn writes
//! within a single syscall.
//!
//! [ADR-0007]: ../../../docs/decisions/0007-crash-only-wal-format.md

#![doc(html_root_url = "https://docs.rs/ol_wal/0.21.0")]

pub mod error;
pub mod file;
pub mod record;
pub mod replay;
pub mod wal;

pub use error::WalError;
pub use file::{LogKind, FILE_HEADER_LEN, MAGIC_CHUNK_LOG, MAGIC_MANIFEST_LOG, ROTATION_SIZE};
pub use record::{
    crc_valid as crc_valid_record, Record, RecordHeader, MAX_PAYLOAD_LEN, RECORD_HEADER_LEN,
    RECORD_TRAILER_LEN,
};
pub use replay::{replay_log_dir, replay_log_file, ReplayOutcome};
pub use wal::{AppendPosition, Wal};

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
