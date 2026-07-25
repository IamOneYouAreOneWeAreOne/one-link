//! Crash-only WAL replay per [ADR-0007](../../../docs/decisions/0007-crash-only-wal-format.md).
//!
//! [`replay_log_dir`] is the canonical recovery entry point: it sorts
//! every `*.wal` file in the directory by file id, validates each file's
//! header, then linearly scans every record's CRC. Only a torn or invalid
//! final record in the final file is crash-repairable. Corruption in a
//! sealed file, or before another complete record, is reported without
//! truncating evidence: crash recovery cannot legitimately explain it.
//!
//! Determinism: two replay runs over the same on-disk state produce
//! identical [`ReplayOutcome`] values. The fixture in
//! `tests/replay_determinism.rs` enforces this.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::error::WalError;
use crate::file::{parse_header, LogKind, FILE_HEADER_LEN, FILE_HEADER_LEN_USIZE};
use crate::record::{
    crc_valid, parse_header as parse_record_header, Record, RECORD_HEADER_LEN, RECORD_TRAILER_LEN,
};

/// Result of replaying a single WAL file or an entire log directory.
#[derive(Debug, Clone, Default)]
pub struct ReplayOutcome {
    /// Records recovered, in append order.
    pub records: Vec<Record>,
    /// Total bytes scanned across all files.
    pub bytes_scanned: u64,
    /// Files truncated during recovery (path + new length). Empty when
    /// the log was crash-clean.
    pub truncated: Vec<(PathBuf, u64)>,
}

/// Replay a single WAL file. Returns recovered records, the file's final
/// size after any tail truncation, and the bytes scanned.
///
/// # Errors
///
/// - I/O errors.
/// - Header validation errors (bubble up; an unparseable header is fatal
///   for the whole log: the operator must investigate manually).
pub fn replay_log_file(
    path: &Path,
    expected_kind: LogKind,
) -> Result<(ReplayOutcome, u64), WalError> {
    replay_log_file_with_policy(path, expected_kind, true)
}

fn replay_log_file_with_policy(
    path: &Path,
    expected_kind: LogKind,
    allow_tail_repair: bool,
) -> Result<(ReplayOutcome, u64), WalError> {
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

    let mut header = [0u8; FILE_HEADER_LEN_USIZE];
    file.read_exact(&mut header)?;
    let kind = parse_header(&header, &path.to_string_lossy())?;
    if kind != expected_kind {
        return Err(WalError::MagicMismatch {
            path: path.to_string_lossy().to_string(),
            got_hex: format!("{kind:?}"),
            expected_hex: format!("{expected_kind:?}"),
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
                if !allow_tail_repair {
                    return Err(non_tail_corruption(path, cursor));
                }
                truncated_at = Some(cursor);
                break;
            }
            Err(e) => return Err(WalError::Io(e)),
        }
        let Ok(header) = parse_record_header(&hbuf, cursor) else {
            // Bad reserved bytes mid-stream → corruption; truncate.
            if !allow_tail_repair
                || file_len.saturating_sub(cursor)
                    > (RECORD_HEADER_LEN + crate::record::MAX_PAYLOAD_LEN + RECORD_TRAILER_LEN)
                        as u64
            {
                return Err(non_tail_corruption(path, cursor));
            }
            truncated_at = Some(cursor);
            break;
        };
        let payload_len = usize::try_from(header.length)
            .expect("supported targets can represent every u32 payload length");
        let total_record_len_usize = RECORD_HEADER_LEN + payload_len + RECORD_TRAILER_LEN;
        let total_record_len = u64::try_from(total_record_len_usize)
            .expect("bounded WAL record length is representable as u64");
        let record_end = cursor
            .checked_add(total_record_len)
            .ok_or_else(|| non_tail_corruption(path, cursor))?;
        if record_end > file_len {
            // Torn payload or trailer in the tail.
            if !allow_tail_repair {
                return Err(non_tail_corruption(path, cursor));
            }
            truncated_at = Some(cursor);
            break;
        }
        // Read the whole record body for CRC verification.
        let mut record_bytes = vec![0u8; total_record_len_usize];
        file.seek(SeekFrom::Start(cursor))?;
        file.read_exact(&mut record_bytes)?;
        if !crc_valid(&record_bytes) {
            // CRC failure within the file → tail corruption; truncate.
            if !allow_tail_repair || record_end != file_len {
                return Err(non_tail_corruption(path, cursor));
            }
            truncated_at = Some(cursor);
            break;
        }
        let payload = record_bytes[RECORD_HEADER_LEN..RECORD_HEADER_LEN + payload_len].to_vec();
        outcome.records.push(Record {
            kind: header.kind,
            flags: header.flags,
            payload,
        });
        cursor = record_end;
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

fn non_tail_corruption(path: &Path, offset: u64) -> WalError {
    WalError::NonTailCorruption {
        path: path.to_string_lossy().into_owned(),
        offset,
    }
}

/// Replay every WAL file in `dir`, in ascending file-id order.
///
/// Truncation can only occur on the last record of the last file (per
/// ADR-0007 invariant). Corruption anywhere else fails closed with
/// [`WalError::NonTailCorruption`] and leaves the file unchanged.
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
    let final_index = file_ids.len().saturating_sub(1);
    for (index, id) in file_ids.into_iter().enumerate() {
        let path = dir.join(format!("{id:06}.wal"));
        let (outcome, _final_len) =
            replay_log_file_with_policy(&path, expected_kind, index == final_index)?;
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

    fn flip_byte(path: &Path, offset: u64) {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0x80;
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();
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
            let expected = u8::try_from(i).expect("test range fits in u8");
            assert_eq!(r.flags, expected);
            assert_eq!(r.payload, vec![expected; 16]);
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
        let len = path.metadata().unwrap().len();
        flip_byte(&path, len - 1);
        let outcome = replay_log_dir(dir.path(), LogKind::ChunkLog).unwrap();
        assert_eq!(outcome.records.len(), 1);
        assert_eq!(outcome.records[0].payload, b"first");
        assert_eq!(outcome.truncated.len(), 1);
    }

    #[test]
    fn corruption_in_sealed_file_is_never_truncated() {
        let dir = tempdir().unwrap();
        let first_len = {
            let mut wal = Wal::create(dir.path(), LogKind::ChunkLog).unwrap();
            wal.append(&rec(0x01, 0xA1, b"sealed record")).unwrap();
            wal.flush().unwrap();
            let len = wal.active_file_size();
            wal.rotate().unwrap();
            wal.append(&rec(0x01, 0xA2, b"active record")).unwrap();
            wal.flush().unwrap();
            len
        };
        let first_path = dir.path().join("000001.wal");
        flip_byte(&first_path, first_len - 1);

        let error = replay_log_dir(dir.path(), LogKind::ChunkLog).unwrap_err();
        assert!(matches!(
            error,
            WalError::NonTailCorruption {
                offset: FILE_HEADER_LEN,
                ..
            }
        ));
        assert_eq!(first_path.metadata().unwrap().len(), first_len);
    }

    #[test]
    fn corruption_before_complete_record_is_never_truncated() {
        let dir = tempdir().unwrap();
        let first = rec(0x01, 0xB1, b"first record");
        let path = {
            let mut wal = Wal::create(dir.path(), LogKind::ChunkLog).unwrap();
            wal.append(&first).unwrap();
            wal.append(&rec(0x01, 0xB2, b"second record")).unwrap();
            wal.flush().unwrap();
            dir.path().join("000001.wal")
        };
        let original_len = path.metadata().unwrap().len();
        let first_crc_end = FILE_HEADER_LEN + first.on_disk_len() as u64;
        flip_byte(&path, first_crc_end - 1);

        let error = replay_log_dir(dir.path(), LogKind::ChunkLog).unwrap_err();
        assert!(matches!(
            error,
            WalError::NonTailCorruption {
                offset: FILE_HEADER_LEN,
                ..
            }
        ));
        assert_eq!(path.metadata().unwrap().len(), original_len);
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
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
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
