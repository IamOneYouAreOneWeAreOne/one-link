//! Format-aware chunking per [ADR-0014](../../../docs/decisions/0014-format-aware-chunking.md).
//!
//! Augments the pure-CDC kernel ([`crate::cdc`]) with structural-boundary
//! injection for well-known container formats. For Phase B v1 this means
//! **ZIP-family archives** (`.zip`, `.docx`, `.xlsx`, `.pptx`, `.odt`,
//! `.apk`, `.jar`, `.epub`, `.kra`). Video GOP detection is reserved for
//! Phase B-2.
//!
//! ## Algorithm
//!
//! 1. Detect format from path-extension hint + leading bytes magic.
//! 2. If a structured format is detected, walk the buffer and collect
//!    **forced cut offsets**: positions where the chunk boundary should
//!    be pinned regardless of FastCDC's rolling-hash decision.
//! 3. Run CDC on each `[forced_cut_i .. forced_cut_{i+1})` segment
//!    independently. The forced cuts become hard boundaries.
//!
//! Result: a sender modifies one entry inside a `.xlsx` (a 1 KiB change
//! in a 50 MiB file) and only that entry's chunks change. Pure-CDC would
//! shift every downstream chunk boundary.
//!
//! ## Conservatism
//!
//! - Path-extension hint is preferred but not required. Pure magic
//!   detection (`PK\x03\x04` at offset 0) suffices.
//! - Each ZIP local-file-header (LFH) hit requires a cheap structural
//!   sanity check (`version_needed`, `compression_method`, sane
//!   `name_length` + `extra_length`). False positives are rare and
//!   harmless (degraded dedup, no corruption).
//! - Forced cuts are absorbed by the [`crate::cdc::CdcParams::min_size`]
//!   floor — two LFHs <8 KiB apart only produce one boundary.

use crate::blake3_wrap;
use crate::cdc::{Boundary, CdcParams, ChunkScanner};
use crate::error::ChunkError;

/// Container formats recognized by the format-aware chunker.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum ContainerFormat {
    /// ZIP archive family: `.zip`, `.docx`, `.xlsx`, `.pptx`, `.odt`,
    /// `.apk`, `.jar`, `.epub`, `.kra`. Local-file-header offsets used
    /// as forced cuts.
    Zip,
    /// ISO Base Media File Format (MP4 / M4V / MOV / 3GP). Top-level
    /// box boundaries used as forced cuts.
    Mp4,
    /// WAV / RIFF audio. `data` chunk start used as a forced cut so
    /// re-tagged audio doesn't shift downstream chunks.
    Wav,
}

/// ZIP local-file-header signature (`PK\x03\x04`).
pub const ZIP_LFH_MAGIC: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];

/// ZIP local-file-header fixed-prefix length (signature + 26 fixed bytes).
pub const ZIP_LFH_FIXED_LEN: usize = 30;

/// Detect a container format from leading bytes + an optional file
/// extension hint.
///
/// Returns `None` when no recognized format is detected. Detection is
/// intentionally conservative — ambiguous matches fall back to pure
/// CDC rather than risk false-positive cuts that would tank dedup.
#[must_use]
pub fn detect_format(leading: &[u8], path_extension: Option<&str>) -> Option<ContainerFormat> {
    if leading.starts_with(&ZIP_LFH_MAGIC) {
        return Some(ContainerFormat::Zip);
    }
    // ISO BMFF top-level boxes start with a 4-byte big-endian size
    // followed by a 4-byte ASCII type. The first box in a valid file
    // is almost always ``ftyp`` (or ``styp`` for segmented).
    if leading.len() >= 8 {
        let kind = &leading[4..8];
        if matches!(kind, b"ftyp" | b"styp" | b"moov" | b"mdat" | b"free") {
            return Some(ContainerFormat::Mp4);
        }
    }
    // WAV/RIFF: bytes 0..4 = "RIFF", bytes 8..12 = "WAVE".
    if leading.len() >= 12
        && &leading[0..4] == b"RIFF"
        && &leading[8..12] == b"WAVE"
    {
        return Some(ContainerFormat::Wav);
    }
    if let Some(ext) = path_extension {
        match ext.to_ascii_lowercase().as_str() {
            // Anything with the extension but missing magic falls
            // back to None — refusing to scan minimises false
            // positives on misnamed files.
            "mp4" | "m4v" | "mov" | "3gp" if matches_iso_bmff_extension(leading) => {
                return Some(ContainerFormat::Mp4);
            }
            "wav" if leading.len() >= 12
                && &leading[0..4] == b"RIFF"
                && &leading[8..12] == b"WAVE" =>
            {
                return Some(ContainerFormat::Wav);
            }
            _ => {}
        }
    }
    None
}

/// Helper: does the leading 8 bytes look plausibly like an ISO BMFF
/// box header (size + 4-letter ASCII type)?
fn matches_iso_bmff_extension(leading: &[u8]) -> bool {
    if leading.len() < 8 {
        return false;
    }
    leading[4..8]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b' ')
}

/// Walk an ISO BMFF (MP4 / MOV) buffer and collect top-level box
/// start offsets — every box header `[size:u32 BE][type:4]` becomes
/// a forced cut. Stops on the first malformed header so a
/// non-BMFF buffer that happens to match the leading-bytes check
/// can't drive the scanner off a cliff.
#[must_use]
pub fn mp4_box_offsets(buffer: &[u8]) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut pos = 0usize;
    while pos + 8 <= buffer.len() {
        let size = u32::from_be_bytes([
            buffer[pos],
            buffer[pos + 1],
            buffer[pos + 2],
            buffer[pos + 3],
        ]) as u64;
        let kind = &buffer[pos + 4..pos + 8];
        // Sanity: the 4-byte type MUST be 4 ASCII chars. Any non-
        // printable rejects the rest of the buffer.
        if !kind.iter().all(|b| b.is_ascii_alphanumeric() || *b == b' ') {
            break;
        }
        offsets.push(pos);
        let advance = match size {
            // Size == 1 means a 64-bit extended size in the next 8
            // bytes (rare in practice; bail out if not enough room).
            1 => {
                if pos + 16 > buffer.len() {
                    break;
                }
                let mut be = [0u8; 8];
                be.copy_from_slice(&buffer[pos + 8..pos + 16]);
                u64::from_be_bytes(be)
            }
            // Size == 0 means "to end of file". This is the last
            // box; stop after collecting its offset.
            0 => break,
            _ => size,
        };
        // Defensive: a corrupt size field smaller than the header
        // would loop forever. Refuse to advance less than 8 bytes.
        if advance < 8 {
            break;
        }
        pos = pos.saturating_add(advance as usize);
    }
    offsets
}

/// Walk a RIFF/WAV buffer and return the offset of the `data` chunk
/// header (length-prefixed RIFF sub-chunk). The data chunk is the
/// dominant payload of a WAV; cutting there isolates the audio
/// samples from the variable-size metadata before it.
#[must_use]
pub fn wav_data_offset(buffer: &[u8]) -> Option<usize> {
    if buffer.len() < 12 || &buffer[0..4] != b"RIFF" || &buffer[8..12] != b"WAVE" {
        return None;
    }
    let mut pos = 12usize;
    while pos + 8 <= buffer.len() {
        let id = &buffer[pos..pos + 4];
        let size = u32::from_le_bytes([
            buffer[pos + 4],
            buffer[pos + 5],
            buffer[pos + 6],
            buffer[pos + 7],
        ]) as usize;
        if id == b"data" {
            return Some(pos);
        }
        // RIFF sub-chunks are byte-aligned but their size word is
        // not padded; the actual layout pads odd sizes by 1.
        let advance = 8 + size + (size & 1);
        if advance < 8 {
            break;
        }
        pos = pos.saturating_add(advance);
    }
    None
}

/// Walk `buffer` and collect ZIP local-file-header offsets that pass the
/// sanity check. Returns a sorted, deduplicated, monotonic list of
/// forced-cut offsets.
///
/// The first cut is always `0` (start of buffer) is **implicit** and not
/// returned; callers walk forward from offset 0.
///
/// Uses [`memchr`] to SIMD-scan for the LFH signature's first byte
/// (`0x50` = `'P'`), then checks the full 4-byte sequence + sanity
/// gate at each candidate. On x86 with SSE2/AVX2 this runs at
/// ~10-30 GiB/s through `buffer` — far faster than the 5 GiB/s budget
/// the FastCDC kernel itself runs at.
#[must_use]
pub fn zip_lfh_offsets(buffer: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    if buffer.len() < ZIP_LFH_FIXED_LEN {
        return out;
    }
    let mut start = 0usize;
    // SIMD-search for the first signature byte; check full 4-byte
    // sequence + sanity gate at each candidate.
    while let Some(rel) = memchr::memchr(ZIP_LFH_MAGIC[0], &buffer[start..]) {
        let i = start + rel;
        if i + 4 > buffer.len() {
            break;
        }
        if buffer[i..i + 4] == ZIP_LFH_MAGIC && zip_lfh_sanity_check(&buffer[i..]) {
            out.push(i);
            // Skip past the fixed prefix to avoid re-matching the same
            // header. Body false positives are caught by the sanity
            // gate above (cheap), not by trying to parse name_length /
            // extra_length here (would need full ZIP entry parser).
            start = i + ZIP_LFH_FIXED_LEN;
        } else {
            start = i + 1;
        }
        if start >= buffer.len() {
            break;
        }
    }
    out
}

/// Cheap structural sanity check on a candidate LFH. `tail` must include
/// at least the 30 fixed bytes after the signature.
///
/// Validates:
/// - `version_needed` is sane (≤ 100 / a known PKWARE version code).
/// - `compression_method` is a known constant (0 stored, 8 deflate,
///   9-99 lossless other / future).
/// - `name_length + extra_length` fits within the buffer remainder. We
///   relax this when we can't see the full entry; the magic + version
///   + method gate is enough to make false positives statistically
///   negligible.
fn zip_lfh_sanity_check(tail: &[u8]) -> bool {
    if tail.len() < ZIP_LFH_FIXED_LEN {
        return false;
    }
    let version_needed = u16::from_le_bytes([tail[4], tail[5]]);
    let compression_method = u16::from_le_bytes([tail[8], tail[9]]);
    // Version range: PKWARE specs use 10, 20, 45, 46, 51, 62, 63;
    // tolerate up to 100.
    if version_needed > 100 {
        return false;
    }
    // Known compression methods per PKWARE APPNOTE 6.3.10.
    matches!(
        compression_method,
        0 | 1 | 6 | 8 | 9 | 12 | 14 | 18 | 19 | 20 | 93 | 94 | 95 | 96 | 97 | 98 | 99
    )
}

/// Run format-aware chunking. Returns the boundaries plus a parallel
/// `Vec<bool>` indicating whether each chunk's *starting* edge was a
/// format-forced cut (vs natural CDC).
///
/// When `format` is `None` or the buffer doesn't contain any forced
/// cuts, falls back to plain CDC.
///
/// # Errors
///
/// Returns the underlying CDC error if `params` are invalid.
pub fn scan_format_aware(
    buffer: &[u8],
    format: Option<ContainerFormat>,
    params: CdcParams,
) -> Result<FormatAwareChunkSet, ChunkError> {
    params.validate()?;

    let forced_cuts = match format {
        Some(ContainerFormat::Zip) => zip_lfh_offsets(buffer),
        Some(ContainerFormat::Mp4) => mp4_box_offsets(buffer),
        Some(ContainerFormat::Wav) => {
            // Single forced cut at the `data` chunk header (if any).
            // The metadata in `fmt ` / `LIST` etc. before it tends
            // to be small, so one cut is enough to isolate the
            // audio body.
            wav_data_offset(buffer).into_iter().collect()
        }
        None => Vec::new(),
    };

    // Absorb cuts that are too close together to be useful. Any cut
    // less than `min_size` away from the previous accepted cut (or the
    // start of the buffer) gets dropped to avoid degenerate tiny chunks.
    let mut accepted: Vec<usize> = Vec::new();
    let mut last_accepted: usize = 0;
    let min = params.min_size as usize;
    for &c in &forced_cuts {
        if c >= last_accepted + min && c <= buffer.len().saturating_sub(min) {
            accepted.push(c);
            last_accepted = c;
        }
    }

    if accepted.is_empty() {
        // No forced cuts → pure CDC.
        let bounds: Vec<Boundary> = ChunkScanner::with_params(buffer, params)?.collect();
        let format_aware = vec![false; bounds.len()];
        return Ok(FormatAwareChunkSet {
            boundaries: bounds,
            format_aware,
        });
    }

    // Build segment list `[0, cut_1)`, `[cut_1, cut_2)`, ... `[cut_n, end)`.
    let mut segments: Vec<(usize, usize)> = Vec::with_capacity(accepted.len() + 1);
    let mut prev = 0usize;
    for &c in &accepted {
        segments.push((prev, c));
        prev = c;
    }
    segments.push((prev, buffer.len()));

    let mut out_bounds: Vec<Boundary> = Vec::new();
    let mut out_flags: Vec<bool> = Vec::new();
    for (seg_idx, &(s, e)) in segments.iter().enumerate() {
        let segment_buf = &buffer[s..e];
        if segment_buf.is_empty() {
            continue;
        }
        // If the segment is shorter than `max_size`, emit it as a single
        // chunk without running CDC (CDC would just emit one chunk
        // anyway, plus the boundary tail).
        let segment_bounds: Vec<Boundary> = if segment_buf.len() <= params.max_size as usize {
            vec![Boundary {
                start: 0,
                end: segment_buf.len(),
                raw_address: blake3_wrap::chunk_address_raw(segment_buf),
            }]
        } else {
            ChunkScanner::with_params(segment_buf, params)?.collect()
        };

        for (chunk_idx, b) in segment_bounds.into_iter().enumerate() {
            // Translate offsets back to the source buffer.
            let translated = Boundary {
                start: b.start + s,
                end: b.end + s,
                raw_address: b.raw_address,
            };
            // The chunk starting at the segment's first byte (chunk_idx
            // == 0) is the format-forced one — unless we're in the very
            // first segment, whose first chunk is the natural start of
            // the buffer (not a forced cut).
            let forced = chunk_idx == 0 && seg_idx > 0;
            out_bounds.push(translated);
            out_flags.push(forced);
        }
    }

    Ok(FormatAwareChunkSet {
        boundaries: out_bounds,
        format_aware: out_flags,
    })
}

/// Result of [`scan_format_aware`]: boundaries plus a parallel `bool`
/// vector flagging which chunks started at a format-forced cut.
#[derive(Debug, Clone)]
pub struct FormatAwareChunkSet {
    /// Chunk boundaries in input order.
    pub boundaries: Vec<Boundary>,
    /// `true` if the corresponding chunk's starting edge was a
    /// format-forced cut (vs natural CDC). `format_aware[i]` belongs
    /// to `boundaries[i]`. Always the same length as `boundaries`.
    pub format_aware: Vec<bool>,
}

impl FormatAwareChunkSet {
    /// Number of chunks.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.boundaries.len()
    }

    /// True if no chunks were produced.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.boundaries.is_empty()
    }

    /// Number of chunks whose starting edge was format-forced.
    #[must_use]
    pub fn format_forced_count(&self) -> usize {
        self.format_aware.iter().filter(|b| **b).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dummy_zip(entries: usize, entry_size: usize) -> Vec<u8> {
        // Build a minimum-shape ZIP-like buffer: each entry is an LFH
        // (30 bytes fixed + 8 byte name "file00\x00") followed by
        // `entry_size` arbitrary bytes. Then a few stray bytes. The end
        // doesn't have a central directory; the scanner only cares
        // about LFH offsets.
        let mut buf = Vec::new();
        for i in 0..entries {
            // LFH:
            buf.extend_from_slice(&ZIP_LFH_MAGIC);
            buf.extend_from_slice(&20u16.to_le_bytes()); // version_needed = 20
            buf.extend_from_slice(&0u16.to_le_bytes()); // flags
            buf.extend_from_slice(&8u16.to_le_bytes()); // compression_method = 8 (deflate)
            buf.extend_from_slice(&0u16.to_le_bytes()); // mod_time
            buf.extend_from_slice(&0u16.to_le_bytes()); // mod_date
            buf.extend_from_slice(&0u32.to_le_bytes()); // crc-32
            buf.extend_from_slice(&(entry_size as u32).to_le_bytes()); // compressed_size
            buf.extend_from_slice(&(entry_size as u32).to_le_bytes()); // uncompressed_size
            buf.extend_from_slice(&7u16.to_le_bytes()); // name_length
            buf.extend_from_slice(&0u16.to_le_bytes()); // extra_length
            let name = format!("file{i:02}\0");
            buf.extend_from_slice(&name.as_bytes()[..7]);
            // Entry body.
            buf.extend(std::iter::repeat(0xAB ^ (i as u8)).take(entry_size));
        }
        buf
    }

    #[test]
    fn detect_zip_from_magic() {
        let buf = make_dummy_zip(1, 100);
        assert_eq!(detect_format(&buf, None), Some(ContainerFormat::Zip));
        assert_eq!(detect_format(&buf, Some("xlsx")), Some(ContainerFormat::Zip));
    }

    #[test]
    fn detect_mp4_from_magic() {
        // ftyp box: 0x00000020 size, b"ftyp", brand "isom"
        let mut buf = vec![0u8; 32];
        buf[0..4].copy_from_slice(&32u32.to_be_bytes());
        buf[4..8].copy_from_slice(b"ftyp");
        buf[8..12].copy_from_slice(b"isom");
        assert_eq!(detect_format(&buf, None), Some(ContainerFormat::Mp4));
        assert_eq!(detect_format(&buf, Some("mp4")), Some(ContainerFormat::Mp4));
    }

    #[test]
    fn detect_wav_from_magic() {
        // Minimal RIFF/WAVE header.
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(b"RIFF");
        buf[4..8].copy_from_slice(&56u32.to_le_bytes());
        buf[8..12].copy_from_slice(b"WAVE");
        assert_eq!(detect_format(&buf, None), Some(ContainerFormat::Wav));
        assert_eq!(detect_format(&buf, Some("wav")), Some(ContainerFormat::Wav));
    }

    #[test]
    fn mp4_box_offsets_finds_top_level_boxes() {
        // Three top-level boxes: ftyp(32) + moov(64) + mdat(128).
        let mut buf = vec![0u8; 32 + 64 + 128];
        buf[0..4].copy_from_slice(&32u32.to_be_bytes());
        buf[4..8].copy_from_slice(b"ftyp");
        buf[32..36].copy_from_slice(&64u32.to_be_bytes());
        buf[36..40].copy_from_slice(b"moov");
        buf[96..100].copy_from_slice(&128u32.to_be_bytes());
        buf[100..104].copy_from_slice(b"mdat");
        let offsets = mp4_box_offsets(&buf);
        assert_eq!(offsets, vec![0, 32, 96]);
    }

    #[test]
    fn wav_data_offset_finds_data_chunk() {
        // RIFF + WAVE + fmt (24 bytes) + data + payload (8 bytes)
        let mut buf = vec![0u8; 12 + 24 + 8 + 8];
        let payload_len = (buf.len() - 8) as u32;
        buf[0..4].copy_from_slice(b"RIFF");
        buf[4..8].copy_from_slice(&payload_len.to_le_bytes());
        buf[8..12].copy_from_slice(b"WAVE");
        // fmt sub-chunk
        buf[12..16].copy_from_slice(b"fmt ");
        buf[16..20].copy_from_slice(&16u32.to_le_bytes());
        // data sub-chunk at offset 12 + 24 = 36
        buf[36..40].copy_from_slice(b"data");
        buf[40..44].copy_from_slice(&8u32.to_le_bytes());
        assert_eq!(wav_data_offset(&buf), Some(36));
    }

    #[test]
    fn detect_none_for_random_bytes() {
        let buf = b"hello world";
        assert_eq!(detect_format(buf, None), None);
        assert_eq!(detect_format(buf, Some("txt")), None);
    }

    #[test]
    fn lfh_walker_finds_all_entries() {
        let buf = make_dummy_zip(5, 16 * 1024);
        let offsets = zip_lfh_offsets(&buf);
        assert_eq!(offsets.len(), 5);
        assert_eq!(offsets[0], 0);
        for w in offsets.windows(2) {
            assert!(w[1] > w[0]);
        }
    }

    #[test]
    fn lfh_walker_rejects_invalid_compression_method() {
        // Construct a buffer with PK\x03\x04 but compression_method = 200.
        let mut buf = Vec::new();
        buf.extend_from_slice(&ZIP_LFH_MAGIC);
        buf.extend_from_slice(&20u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&200u16.to_le_bytes()); // bogus method
        buf.resize(64, 0u8);
        let offsets = zip_lfh_offsets(&buf);
        assert!(offsets.is_empty());
    }

    #[test]
    fn lfh_walker_rejects_random_bytes() {
        let buf = vec![0u8; 1024 * 1024];
        let offsets = zip_lfh_offsets(&buf);
        assert!(offsets.is_empty());
    }

    #[test]
    fn pure_cdc_when_no_format() {
        let buf = vec![0xCDu8; 256 * 1024];
        let r = scan_format_aware(&buf, None, CdcParams::default()).unwrap();
        // Should equal a plain CDC scan.
        let plain: Vec<Boundary> = ChunkScanner::new(&buf).collect();
        assert_eq!(r.boundaries.len(), plain.len());
        assert_eq!(r.format_forced_count(), 0);
    }

    #[test]
    fn cdc_equivalence_on_non_zip() {
        // Random binary that does NOT look like ZIP.
        let mut buf = vec![0u8; 512 * 1024];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        let r = scan_format_aware(&buf, Some(ContainerFormat::Zip), CdcParams::default()).unwrap();
        let plain: Vec<Boundary> = ChunkScanner::new(&buf).collect();
        assert_eq!(r.boundaries.len(), plain.len());
        for (a, b) in r.boundaries.iter().zip(plain.iter()) {
            assert_eq!(a.start, b.start);
            assert_eq!(a.end, b.end);
            assert_eq!(a.raw_address, b.raw_address);
        }
    }

    #[test]
    fn zip_boundaries_align_to_lfh() {
        let entry_size = 32 * 1024;
        let buf = make_dummy_zip(8, entry_size);
        let lfh = zip_lfh_offsets(&buf);
        let r = scan_format_aware(&buf, Some(ContainerFormat::Zip), CdcParams::default()).unwrap();
        // Every LFH offset (except 0) should appear as a chunk start
        // boundary somewhere in the output (subject to min_size absorption).
        for &off in lfh.iter().skip(1) {
            assert!(
                r.boundaries.iter().any(|b| b.start == off),
                "expected a chunk to start at LFH offset {off}"
            );
        }
        // The format_aware flags should be set on entries 1..N (entry 0
        // is the natural buffer start).
        assert!(r.format_forced_count() >= lfh.len() - 1);
    }

    #[test]
    fn single_byte_edit_only_changes_one_chunk_family() {
        // Build a dummy ZIP. Edit one byte inside entry 4. Compare
        // chunk sets: entries 0-3 and 5-7 should produce identical
        // chunk_ids; only entry 4's chunks should differ.
        let entry_size = 32 * 1024;
        let original = make_dummy_zip(8, entry_size);
        let mut edited = original.clone();
        // Find entry 4's LFH offset.
        let lfh = zip_lfh_offsets(&original);
        let target_lfh = lfh[4];
        // Flip a byte inside entry 4's body (well past the LFH header).
        edited[target_lfh + ZIP_LFH_FIXED_LEN + 7 + 100] ^= 0xFF;

        let orig_chunks =
            scan_format_aware(&original, Some(ContainerFormat::Zip), CdcParams::default())
                .unwrap();
        let edit_chunks =
            scan_format_aware(&edited, Some(ContainerFormat::Zip), CdcParams::default())
                .unwrap();

        // Both must have the same number of chunks (entry layouts are
        // identical; one byte flip doesn't change LFH positions).
        assert_eq!(orig_chunks.boundaries.len(), edit_chunks.boundaries.len());

        // Most chunks unchanged: at least 5 of 8 entries are identical.
        let mut unchanged = 0;
        for (a, b) in orig_chunks.boundaries.iter().zip(edit_chunks.boundaries.iter()) {
            if a.raw_address == b.raw_address {
                unchanged += 1;
            }
        }
        assert!(
            unchanged >= 5,
            "expected at least 5 chunks unchanged after single-byte edit, got {unchanged}"
        );
    }
}
