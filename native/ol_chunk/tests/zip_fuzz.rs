//! Proptest fuzz coverage for the ZIP local-file-header walker.
//!
//! Any byte stream — random garbage, partially-formed headers,
//! truncated content — must either yield a list of offsets or pass
//! through without crashing. The walker MUST NOT panic.

use ol_chunk::{
    detect_format, scan_format_aware, zip_lfh_offsets, CdcParams, ContainerFormat,
};
use proptest::prelude::*;

proptest! {
    #[test]
    fn lfh_walker_total_over_random_bytes(bytes in prop::collection::vec(any::<u8>(), 0..16 * 1024)) {
        let offsets = zip_lfh_offsets(&bytes);
        // Every offset must be within bounds.
        for o in &offsets {
            prop_assert!(*o + 4 <= bytes.len());
        }
        // Offsets must be strictly increasing.
        for w in offsets.windows(2) {
            prop_assert!(w[1] > w[0]);
        }
    }

    #[test]
    fn detect_format_total(bytes in prop::collection::vec(any::<u8>(), 0..256), ext_idx in 0u8..20) {
        let exts = ["zip", "txt", "mp4", "docx", "pem", "xlsx", "png", "unknown"];
        let ext = if ext_idx < exts.len() as u8 {
            Some(exts[ext_idx as usize])
        } else {
            None
        };
        let _ = detect_format(&bytes, ext);
    }

    #[test]
    fn scan_format_aware_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..64 * 1024)) {
        // Scan as Zip-typed input — even if magic doesn't match.
        let _ = scan_format_aware(&bytes, Some(ContainerFormat::Zip), CdcParams::default());
        let _ = scan_format_aware(&bytes, None, CdcParams::default());
    }
}
