//! Crash-only WAL replay per [ADR-0007](../../../docs/decisions/0007-crash-only-wal-format.md).
//!
//! [`replay_log_dir`] is the canonical recovery entry point: it sorts
//! every `*.wal` file in the directory by file id, validates each file's
//! header, then linearly scans every record's CRC. The first CRC failure
//! within a file is the truncation point: that file's tail is
//! lopped to the offset of the previous valid record (because crash
//! recovery, by definition, can only corrupt the *last* record of the
//! *last* file — earlier records are already fsync'd before later ones
//! start).
//!
//! Determinism: two replay runs over the same on-disk state produce
//! identical [`ReplayOutcome`] values. The fixture in
//! `tests/replay_determinism.rs` enforces this.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::error::WalError;
use crate::file::{parse_header, LogKind, FILE_HEADER_LEN};
use crate::record::{
    crc_valid, parse_header as parse_record_header, Record, RECORD_HEADER_LEN, RECORD_TRAILER_LEN,
};

/// Result of replaying a single WAL file or an entire log directory.
#[derive(Debug, Clone)]
pub struct ReplayOutcome {
    /// Records recovered, in append order.
    pub records: Vec<Record>,
    /// Total bytes scanned across all files.
    pub bytes_scanned: u64,
    /// Files truncated during recovery (path + new length). Empty when
    /// the log was crash-clean.
    pub truncated: Vec<(PathBuf, u64)>,
}

impl Default for ReplayOutcome {
    fn default() -> Self {
        Self {
            records: Vec::new(),
            bytes_scanned: 0,
            truncated: Vec::new(),
        }
    }
}

/// Replay a single WAL file. Returns recovered records, the file's final
/// size after any tail truncation, and the bytes scanned.
///
/// # Errors
///
/// - I/O errors.
/// - Header validation errors (bubble up; an unparseable header is fatal
///   for the whole log: the operator must investigate manually).
pub fn replay_log_file(path: &Path, expected_kind: LogKind) -> Result<(ReplayOutcome, u64), WalError> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let file_len = file.metadata()?.len();
    let mut outcome = ReplayOutcome::default();

    if file_len < FILE_HEADER_LEN {
        // A torn header is fatal — refuse to load. The operator must
        // remove the empty/torn file by hand; doing so silently could
        // mask a real failure.
        return Err(WalError::InvalidHeaderReserved {
            path: path.to_string_lossy().to_string(),
        });
    }

    let mut header = [0u8; FILE_HEADER_LEN as usize];
    file.read_exact(&mut header)?;
    let kind = parse_header(&header, &path.to_string_lossy())?;
    if kind != expected_kind {
        return Err(WalError::MagicMismatch {
            path: path.to_string_lossy().to_string(),
            got_hex: format!("{:?}", kind),
            expected_hex: format!("{:?}", expected_kind),
        });
    }
    outcome.bytes_scanned += FILE_HEADER_LEN;

    let mut cursor = FILE_HEADER_LEN;
    let mut truncated_at: Option<u64> = None;

    while cursor < file_len {
        // Read record header.
        let mut hbuf = [0u8; RECORD_HEADER_LEN];
        file.seek(SeekFrom::Start(cursor))?;
        match file.read_exact(&mut hbuf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Torn record header in the tail; truncate.
                truncated_at = Some(cursor);
                break;
            }
            Err(e) => return Err(WalError::Io(e)),
        }
        let header = match parse_record_header(&hbuf, cursor) {
            Ok(h) => h,
            Err(_) => {
                // Bad reserved bytes mid-stream → corruption; truncate.
                truncated_at = Some(cursor);
                break;
            }
        };
        let total_record_len = (RECORD_HEADER_LEN + header.length as usize + RECORD_TRAILER_LEN) as u64;
        if cursor + total_record_len > file_len {
            // Torn payload or trailer in the tail.
            truncated_at = Some(cursor);
            break;
        }
        // Read the whole record body for CRC verification.
        let mut record_bytes = vec![0u8; total_record_len as usize];
        file.seek(SeekFrom::Start(cursor))?;
        file.read_exact(&mut record_bytes)?;
        if !crc_valid(&record_bytes) {
            // CRC failure within the file → tail corruption; truncate.
            truncated_at = Some(cursor);
            break;
        }
        let payload = record_bytes
            [RECORD_HEADER_LEN..RECORD_HEADER_LEN + header.length as usize]
            .to_vec();
        outcome.records.push(Record {
            kind: header.kind,
            flags: header.flags,
            payload,
        });
        cursor += total_record_len;
        outcome.bytes_scanned += total_record_len;
    }

    let final_len = if let Some(at) = truncated_at {
        // Truncate the file's tail to drop the corrupt record.
        file.set_len(at)?;
        file.sync_all()?;
        outcome.truncated.push((path.to_path_buf(), at));
        at
    } else {
        file_len
    };

    Ok((outcome, final_len))
}

/// Replay every WAL file in `dir`, in ascending file-id order.
///
/// Truncation can only occur on the LAST record of the LAST file (per
/// ADR-0007 invariant). If recovery encounters a CRC failure earlier
/// than that, this function returns whatever was recovered up to the
/// failure plus a [`ReplayOutcome::truncated`] entry recording the
/// truncation; the caller decides whether to refuse to start.
///
/// # Errors
///
/// - I/O errors.
/// - Header validation errors on any file.
pub fn replay_log_dir(dir: &Path, expected_kind: LogKind) -> Result<ReplayOutcome, WalError> {
    let mut file_ids: Vec<u64> = Vec::new();
    if !dir.exists() {
        return Ok(ReplayOutcome::default());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(stem) = name.strip_suffix(".wal") {
            if let Ok(id) = stem.parse::<u64>() {
                file_ids.push(id);
            }
        }
    }
    file_ids.sort_unstable();

    let mut combined = ReplayOutcome::default();
    for id in file_ids {
        let path = dir.join(format!("{id:06}.wal"));
        let (outcome, _final_len) = replay_log_file(&path, expected_kind)?;
        combined.records.extend(outcome.records);
        combined.bytes_scanned += outcome.bytes_scanned;
        combined.truncated.extend(outcome.truncated);
    }
    Ok(combined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Record;
    use crate::wal::Wal;
    use std::io::Write;
    use tempfile::tempdir;

    fn rec(kind: u8, flags: u8, payload: &[u8]) -> Record {
        Record {
            kind,
            flags,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn replay_empty_dir() {
        let dir = tempdir().unwrap();
        let outcome = replay_log_dir(dir.path(), LogKind::ChunkLog).unwrap();
        assert_eq!(outcome.records.len(), 0);
    }

    #[test]
    fn replay_single_record() {
        let dir = tempdir().unwrap();
        {
            let mut wal = Wal::create(dir.path(), LogKind::ChunkLog).unwrap();
            wal.append(&rec(0x01, 0x05, b"hello")).unwrap();
            wal.flush().unwrap();
        }
        let outcome = replay_log_dir(dir.path(), LogKind::ChunkLog).unwrap();
        assert_eq!(outcome.records.len(), 1);
        assert_eq!(outcome.records[0].kind, 0x01);
        assert_eq!(outcome.records[0].flags, 0x05);
        assert_eq!(outcome.records[0].payload, b"hello");
        assert_eq!(outcome.truncated.len(), 0);
    }

    #[test]
    fn replay_multiple_records_in_order() {
        let dir = tempdir().unwrap();
        {
            let mut wal = Wal::create(dir.path(), LogKind::ManifestLog).unwrap();
            for i in 0u8..10 {
                wal.append(&rec(0x10, i, &[i; 16])).unwrap();
            }
            wal.flush().unwrap();
        }
        let outcome = replay_log_dir(dir.path(), LogKind::ManifestLog).unwrap();
        assert_eq!(outcome.records.len(), 10);
        for (i, r) in outcome.records.iter().enumerate() {
            assert_eq!(r.flags, i as u8);
            assert_eq!(r.payload, vec![i as u8; 16]);
        }
    }

    #[test]
    fn replay_across_rotated_files_preserves_order() {
        let dir = tempdir().unwrap();
        {
            let mut wal = Wal::create(dir.path(), LogKind::ChunkLog).unwrap();
            wal.append(&rec(0x01, 0xAA, b"in file 1")).unwrap();
            wal.flush().unwrap();
            wal.rotate().unwrap();
            wal.append(&rec(0x01, 0xBB, b"in file 2")).unwrap();
            wal.flush().unwrap();
            wal.rotate().unwrap();
            wal.append(&rec(0x01, 0xCC, b"in file 3")).unwrap();
            wal.flush().unwrap();
        }
        let outcome = replay_log_dir(dir.path(), LogKind::ChunkLog).unwrap();
        assert_eq!(outcome.records.len(), 3);
        assert_eq!(outcome.records[0].flags, 0xAA);
        assert_eq!(outcome.records[1].flags, 0xBB);
        assert_eq!(outcome.records[2].flags, 0xCC);
    }

    #[test]
    fn rejects_wrong_log_kind() {
        let dir = tempdir().unwrap();
        {
            let mut wal = Wal::create(dir.path(), LogKind::ChunkLog).unwrap();
            wal.append(&rec(0x01, 0x00, b"x")).unwrap();
            wal.flush().unwrap();
        }
        let result = replay_log_dir(dir.path(), LogKind::ManifestLog);
        assert!(matches!(result, Err(WalError::MagicMismatch { .. })));
    }

    #[test]
    fn truncates_tail_on_crc_failure() {
        let dir = tempdir().unwrap();
        let path = {
            let mut wal = Wal::create(dir.path(), LogKind::ChunkLog).unwrap();
            wal.append(&rec(0x01, 0x00, b"first")).unwrap();
            wal.append(&rec(0x01, 0x00, b"second")).unwrap();
            wal.flush().unwrap();
            dir.path().join("000001.wal")
        };
        // Corrupt the LAST byte of the file (in the second record's CRC).
        {
            let mut f = OpenOptions::new().write(true).open(&path).unwrap();
            let len = f.metadata().unwrap().len();
            f.seek(SeekFrom::Start(len - 1)).unwrap();
            f.write_all(&[0xFF]).unwrap();
            f.sync_all().unwrap();
        }
        let outcome = replay_log_dir(dir.path(), LogKind::ChunkLog).unwrap();
        assert_eq!(outcome.records.len(), 1);
        assert_eq!(outcome.records[0].payload, b"first");
        assert_eq!(outcome.truncated.len(), 1);
    }

    #[test]
    fn truncates_tail_on_short_payload() {
        let dir = tempdir().unwrap();
        let path = {
            let mut wal = Wal::create(dir.path(), LogKind::ChunkLog).unwrap();
            wal.append(&rec(0x01, 0x00, b"complete")).unwrap();
            wal.flush().unwrap();
            dir.path().join("000001.wal")
        };
        // Append a torn record header (8 bytes that pretends to have a
        // 100-byte payload but no actual payload follows).
        {
            let mut f = OpenOptions::new().write(true).append(true).open(&path).unwrap();
            f.write_all(&[
                0x99u8, 0x00, // kind, flags
                0x00, 0x00, // reserved
                100u8, 0x00, 0x00, 0x00, // length = 100 (but no payload follows)
            ])
            .unwrap();
            f.sync_all().unwrap();
        }
        let outcome = replay_log_dir(dir.path(), LogKind::ChunkLog).unwrap();
        // Recovery sees the first record, then tries to read the torn
        // header → length=100 but no body → truncate.
        assert_eq!(outcome.records.len(), 1);
        assert_eq!(outcome.truncated.len(), 1);
    }

    #[test]
    fn determinism_across_repeated_replays() {
        let dir = tempdir().unwrap();
        {
            let mut wal = Wal::create(dir.path(), LogKind::ChunkLog).unwrap();
            for i in 0u8..50 {
                wal.append(&rec(0x01, i, &[i; 32])).unwrap();
            }
            wal.flush().unwrap();
        }
        let a = replay_log_dir(dir.path(), LogKind::ChunkLog).unwrap();
        let b = replay_log_dir(dir.path(), LogKind::ChunkLog).unwrap();
        assert_eq!(a.records, b.records);
    }
}
