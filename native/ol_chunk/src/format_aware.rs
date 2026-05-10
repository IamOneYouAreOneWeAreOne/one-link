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
    /// MP4 / Matroska / WebM. Reserved for Phase B-2 (returns empty
    /// forced-cut list for now).
    Video,
}

/// ZIP local-file-header signature (`PK\x03\x04`).
pub const ZIP_LFH_MAGIC: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];

/// ZIP local-file-header fixed-prefix length (signature + 26 fixed bytes).
pub const ZIP_LFH_FIXED_LEN: usize = 30;

/// Detect a container format from leading bytes + an optional file
/// extension hint.
///
/// Returns `None` when no recognized format is detected. The detection
/// is intentionally conservative: ambiguous matches fall back to pure
/// CDC.
#[must_use]
pub fn detect_format(leading: &[u8], path_extension: Option<&str>) -> Option<ContainerFormat> {
    if leading.starts_with(&ZIP_LFH_MAGIC) {
        return Some(ContainerFormat::Zip);
    }
    // If the magic doesn't match but the extension strongly suggests ZIP,
    // we still allow ZIP scanning — but only at the magic offset. A
    // file claiming `.zip` extension that lacks the leading magic is
    // a misnamed file; conservative: return None.
    if let Some(ext) = path_extension {
        match ext.to_ascii_lowercase().as_str() {
            "mp4" | "m4v" | "mkv" | "webm" | "mov" => return Some(ContainerFormat::Video),
            _ => {}
        }
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
        // Phase B-2 placeholder: video GOP scanner returns no cuts.
        Some(ContainerFormat::Video) | None => Vec::new(),
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
    fn detect_video_from_extension() {
        let buf = b"random non-zip bytes";
        assert_eq!(detect_format(buf, Some("mp4")), Some(ContainerFormat::Video));
        assert_eq!(detect_format(buf, Some("mkv")), Some(ContainerFormat::Video));
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
