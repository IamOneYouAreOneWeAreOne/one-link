//! The `Dispatcher` pick/compress/decompress surface.

use crate::error::CompressError;

/// Codecs supported by the dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// No compression. Wire payload == input bytes (plus 1-byte tag).
    None,
    /// LZ4 block format (fast, ~3 GiB/s decode, ~1.5x ratio).
    Lz4,
    /// zstd level 3 (balanced — ~500 MiB/s, ~2-3x ratio).
    ZstdBalanced,
    /// zstd level 9 (slower, ~1.1x better ratio — for background).
    ZstdAggressive,
}

impl Algorithm {
    /// One-byte tag prepended to compressed output.
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Lz4 => 1,
            Self::ZstdBalanced => 2,
            Self::ZstdAggressive => 3,
        }
    }

    /// Parse a tag byte back to an algorithm.
    pub fn from_tag(tag: u8) -> Result<Self, CompressError> {
        match tag {
            0 => Ok(Self::None),
            1 => Ok(Self::Lz4),
            2 => Ok(Self::ZstdBalanced),
            3 => Ok(Self::ZstdAggressive),
            _ => Err(CompressError::UnknownTag { tag }),
        }
    }
}

/// The event kind hint the dispatcher uses to pick a codec.
///
/// Same vocabulary as `ol_decide::EventKind` but defined locally so
/// this crate stays decoupled from the decide trait.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
    /// Chat / text message — short, often emoji-heavy, low entropy.
    Msg,
    /// File transfer chunk — high entropy after the codec, anyway.
    File,
    /// CRDT sync / acknowledgement — small, repeating-structure JSON.
    Sync,
    /// Heartbeat / keepalive — tiny payloads.
    Heartbeat,
    /// Background sync / bulk index — speed less critical than ratio.
    Background,
}

/// Hint from the caller that the payload is already compressed (by
/// the application layer or the file format itself). When true, the
/// dispatcher returns [`Algorithm::None`] regardless of size — there's
/// nothing to be gained from a second pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreCompressed {
    /// Payload is already at high entropy (zip / mp4 / jpg etc).
    Yes,
    /// Plain bytes; compression may help.
    No,
}

/// The dispatcher. Stateless; one instance for the whole daemon.
#[derive(Debug, Default, Clone, Copy)]
pub struct Dispatcher;

impl Dispatcher {
    /// Construct.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Pick the algorithm appropriate for this `(kind, size, hint)`.
    ///
    /// Returns [`Algorithm::None`] for anything that won't compress
    /// well (tiny / already-compressed). Returns lz4 for fast sync
    /// paths and zstd for bulk transfer.
    #[must_use]
    pub fn pick(&self, kind: EventKind, size: usize, precompressed: PreCompressed) -> Algorithm {
        if precompressed == PreCompressed::Yes {
            return Algorithm::None;
        }
        match kind {
            EventKind::Msg => {
                if size < 4_096 {
                    Algorithm::None
                } else {
                    // A long message (paste / quote) is worth compressing.
                    Algorithm::Lz4
                }
            }
            EventKind::Heartbeat => Algorithm::None,
            EventKind::Sync => {
                if size < 8_192 {
                    Algorithm::Lz4
                } else {
                    Algorithm::ZstdBalanced
                }
            }
            EventKind::File => {
                if size < 1_048_576 {
                    Algorithm::Lz4
                } else {
                    Algorithm::ZstdBalanced
                }
            }
            EventKind::Background => Algorithm::ZstdAggressive,
        }
    }

    /// Compress `bytes` using `algo`. The output is tag-prefixed so
    /// `decompress` can route it without out-of-band metadata.
    ///
    /// # Errors
    /// zstd I/O errors propagate as [`CompressError::Zstd`].
    pub fn compress(&self, algo: Algorithm, bytes: &[u8]) -> Result<Vec<u8>, CompressError> {
        let mut out = Vec::with_capacity(bytes.len() + 8);
        out.push(algo.tag());
        match algo {
            Algorithm::None => {
                out.extend_from_slice(bytes);
            }
            Algorithm::Lz4 => {
                let payload = lz4_flex::block::compress_prepend_size(bytes);
                out.extend_from_slice(&payload);
            }
            Algorithm::ZstdBalanced => {
                let payload = zstd::stream::encode_all(bytes, 3)?;
                out.extend_from_slice(&payload);
            }
            Algorithm::ZstdAggressive => {
                let payload = zstd::stream::encode_all(bytes, 9)?;
                out.extend_from_slice(&payload);
            }
        }
        Ok(out)
    }

    /// Decompress a tagged payload. `max_size` is a defensive cap on
    /// the decompressed length — protects against decompression-bomb
    /// inputs (a 1 MiB compressed payload that expands to 1 GiB).
    ///
    /// # Errors
    /// Returns [`CompressError::UnknownTag`] for unrecognized tags,
    /// [`CompressError::PayloadTooShort`] for empty inputs, decoder
    /// errors for malformed payloads, and
    /// [`CompressError::OutputTooLarge`] if the output exceeds `max_size`.
    pub fn decompress(&self, payload: &[u8], max_size: usize) -> Result<Vec<u8>, CompressError> {
        if payload.is_empty() {
            return Err(CompressError::PayloadTooShort { len: 0 });
        }
        let algo = Algorithm::from_tag(payload[0])?;
        let body = &payload[1..];
        let out = match algo {
            Algorithm::None => body.to_vec(),
            Algorithm::Lz4 => lz4_flex::block::decompress_size_prepended(body)?,
            Algorithm::ZstdBalanced | Algorithm::ZstdAggressive => zstd::stream::decode_all(body)?,
        };
        if out.len() > max_size {
            return Err(CompressError::OutputTooLarge {
                decompressed: out.len(),
                max: max_size,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dispatcher() -> Dispatcher {
        Dispatcher::new()
    }

    // ───── pick() — codec selection ──────────────────────────────────

    #[test]
    fn pick_msg_small_returns_none() {
        let d = dispatcher();
        assert_eq!(
            d.pick(EventKind::Msg, 200, PreCompressed::No),
            Algorithm::None
        );
    }

    #[test]
    fn pick_msg_large_returns_lz4() {
        let d = dispatcher();
        assert_eq!(
            d.pick(EventKind::Msg, 5_000, PreCompressed::No),
            Algorithm::Lz4
        );
    }

    #[test]
    fn pick_heartbeat_always_none() {
        let d = dispatcher();
        assert_eq!(
            d.pick(EventKind::Heartbeat, 64, PreCompressed::No),
            Algorithm::None
        );
        assert_eq!(
            d.pick(EventKind::Heartbeat, 8_000, PreCompressed::No),
            Algorithm::None
        );
    }

    #[test]
    fn pick_sync_small_lz4_large_zstd() {
        let d = dispatcher();
        assert_eq!(
            d.pick(EventKind::Sync, 200, PreCompressed::No),
            Algorithm::Lz4
        );
        assert_eq!(
            d.pick(EventKind::Sync, 50_000, PreCompressed::No),
            Algorithm::ZstdBalanced
        );
    }

    #[test]
    fn pick_file_small_lz4_large_zstd() {
        let d = dispatcher();
        assert_eq!(
            d.pick(EventKind::File, 100_000, PreCompressed::No),
            Algorithm::Lz4
        );
        assert_eq!(
            d.pick(EventKind::File, 5_000_000, PreCompressed::No),
            Algorithm::ZstdBalanced
        );
    }

    #[test]
    fn pick_background_always_aggressive() {
        let d = dispatcher();
        assert_eq!(
            d.pick(EventKind::Background, 100, PreCompressed::No),
            Algorithm::ZstdAggressive
        );
        assert_eq!(
            d.pick(EventKind::Background, 5_000_000, PreCompressed::No),
            Algorithm::ZstdAggressive
        );
    }

    #[test]
    fn pick_precompressed_always_none() {
        let d = dispatcher();
        for kind in [
            EventKind::Msg,
            EventKind::File,
            EventKind::Sync,
            EventKind::Heartbeat,
            EventKind::Background,
        ] {
            assert_eq!(d.pick(kind, 5_000_000, PreCompressed::Yes), Algorithm::None);
        }
    }

    // ───── compress / decompress round-trip ──────────────────────────

    fn round_trip(algo: Algorithm, input: &[u8]) -> Vec<u8> {
        let d = dispatcher();
        let compressed = d.compress(algo, input).unwrap();
        // Tag byte must match.
        assert_eq!(compressed[0], algo.tag());
        d.decompress(&compressed, usize::MAX).unwrap()
    }

    #[test]
    fn round_trip_none() {
        let input = b"hello world";
        assert_eq!(round_trip(Algorithm::None, input), input);
    }

    #[test]
    fn round_trip_lz4() {
        let input = b"hello hello hello hello hello hello hello hello world";
        assert_eq!(round_trip(Algorithm::Lz4, input), input);
    }

    #[test]
    fn round_trip_zstd_balanced() {
        let input = vec![42u8; 4096];
        assert_eq!(round_trip(Algorithm::ZstdBalanced, &input), input);
    }

    #[test]
    fn round_trip_zstd_aggressive() {
        let input = vec![42u8; 16_384];
        assert_eq!(round_trip(Algorithm::ZstdAggressive, &input), input);
    }

    #[test]
    fn round_trip_random_payload() {
        // A non-degenerate payload (no easy run-length advantage).
        let input: Vec<u8> = (0..1024u32).flat_map(|x| x.to_le_bytes()).collect();
        for algo in [
            Algorithm::None,
            Algorithm::Lz4,
            Algorithm::ZstdBalanced,
            Algorithm::ZstdAggressive,
        ] {
            assert_eq!(round_trip(algo, &input), input, "{algo:?}");
        }
    }

    #[test]
    fn round_trip_empty_payload() {
        for algo in [
            Algorithm::None,
            Algorithm::Lz4,
            Algorithm::ZstdBalanced,
            Algorithm::ZstdAggressive,
        ] {
            assert_eq!(round_trip(algo, b""), b"", "{algo:?}");
        }
    }

    // ───── decompress validation ─────────────────────────────────────

    #[test]
    fn decompress_empty_rejected() {
        let d = dispatcher();
        assert!(matches!(
            d.decompress(b"", 1024),
            Err(CompressError::PayloadTooShort { len: 0 })
        ));
    }

    #[test]
    fn decompress_unknown_tag_rejected() {
        let d = dispatcher();
        let r = d.decompress(&[99u8, 0, 0, 0], 1024);
        assert!(matches!(r, Err(CompressError::UnknownTag { tag: 99 })));
    }

    #[test]
    fn decompress_caps_oversize_output() {
        let d = dispatcher();
        // Big repeating payload → zstd compresses tiny.
        let input = vec![7u8; 100_000];
        let compressed = d.compress(Algorithm::ZstdBalanced, &input).unwrap();
        let r = d.decompress(&compressed, 50_000);
        assert!(matches!(
            r,
            Err(CompressError::OutputTooLarge {
                decompressed: 100_000,
                max: 50_000
            })
        ));
    }

    // ───── Algorithm tag round-trip ─────────────────────────────────

    #[test]
    fn algorithm_tag_round_trip() {
        for algo in [
            Algorithm::None,
            Algorithm::Lz4,
            Algorithm::ZstdBalanced,
            Algorithm::ZstdAggressive,
        ] {
            assert_eq!(Algorithm::from_tag(algo.tag()).unwrap(), algo);
        }
    }
}
