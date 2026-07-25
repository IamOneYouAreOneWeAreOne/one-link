//! Chunk-log record format per [ADR-0003](../../../docs/decisions/0003-on-disk-format.md).
//!
//! The `chunk_log` file (managed by [`ol_wal`]) stores records of this
//! shape inside the WAL payload. The WAL header (kind + flags + length +
//! CRC) wraps a 80-byte chunk-record header followed by the AEAD
//! ciphertext bytes. From the perspective of [`ol_wal`]:
//!
//! ```text
//! WAL record:
//!   kind  = ChunkRecordKind (0x01 ChunkBlob, 0x02 StripeParity, 0xFE Tombstone)
//!   flags = ChunkRecord flags (address kind, AEAD kind, compression, format-aware)
//!   payload = [ChunkRecordHeader (80 bytes) || ciphertext (length_ciphertext bytes)]
//! ```
//!
//! `ChunkRecordHeader` layout:
//!
//! ```text
//! +--------+------------------------------------------------------------------+
//! | Offset | Field                                                            |
//! +--------+------------------------------------------------------------------+
//! | 0      | length_plaintext: u32 LE                                         |
//! | 4      | length_ciphertext: u32 LE                                        |
//! | 8      | chunk_id_full: [u8; 32] (BLAKE3-256, raw or convergent)         |
//! | 40     | ratchet_key_id: [u8; 16]                                         |
//! | 56     | stripe_descriptor: 24 bytes (per ADR-0004)                       |
//! +--------+------------------------------------------------------------------+
//! Total: 80 bytes.
//! ```

use crate::error::ChunkStoreError;
use crate::stripe::{StripeDescriptor, STRIPE_DESCRIPTOR_LEN};

/// Length of the chunk-record header in bytes.
pub const CHUNK_RECORD_HEADER_LEN: usize = 80;

/// Maximum ciphertext body that still fits in one bounded WAL record.
pub const MAX_CHUNK_CIPHERTEXT_LEN: usize = ol_wal::MAX_PAYLOAD_LEN - CHUNK_RECORD_HEADER_LEN;

// ─── kind / flags enums ──────────────────────────────────────────────

/// Kind byte for the chunk-log WAL record.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum ChunkRecordKind {
    /// 0x01: a chunk's encrypted content.
    ChunkBlob,
    /// 0x02: a Reed-Solomon parity shard (Phase C onwards).
    StripeParity,
    /// 0xFE: a tombstone reference. The `chunk_id` was reclaimed; the
    /// address still resolves to "missing on purpose."
    TombstoneRef,
}

impl ChunkRecordKind {
    /// On-disk byte.
    #[inline]
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::ChunkBlob => 0x01,
            Self::StripeParity => 0x02,
            Self::TombstoneRef => 0xFE,
        }
    }

    /// Decode from the on-disk byte.
    #[must_use]
    pub const fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::ChunkBlob),
            0x02 => Some(Self::StripeParity),
            0xFE => Some(Self::TombstoneRef),
            _ => None,
        }
    }
}

/// Whether the `chunk_id_full` is the raw BLAKE3 of the plaintext or
/// the convergent-encryption derived address. Per
/// [ADR-0006](../../../docs/decisions/0006-blake3-derive-scheme.md).
///
/// Default is `Raw` for fresh chunks; per-recipient keys for project /
/// document / non-media content. `Convergent` is opt-in per the Phase B
/// rollout plan — gated by an explicit caller decision based on the
/// content type (raw media = safe to converge; project files = not).
/// See [`convergent_default_for_content_type`] for the production
/// dispatch helper.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Default)]
pub enum ChunkAddressKind {
    /// `BLAKE3.hash(plaintext)`. The conservative default — per-
    /// recipient keys; identical plaintext from two senders produces
    /// different chunk IDs.
    #[default]
    Raw,
    /// `BLAKE3.derive_key("ol-chunk-addr-convergent-v1", plaintext)`.
    /// Opt-in for content types whose well-known plaintexts aren't a
    /// privacy concern (raw media). Enables cross-sender dedup.
    Convergent,
}

/// Coarse content-type classifier for the convergent-default dispatch.
/// Returns `Convergent` for content types where two senders sharing
/// the same file SHOULD produce the same chunk IDs (so the dedup
/// dividend is realised), and `Raw` for everything else.
///
/// Conservative by design: only formats with low correlation between
/// plaintext + recipient identity get convergent. Project files /
/// documents / private payloads stay on raw-BLAKE3.
///
/// Phase B integration point: the chunk-store ingest path consults
/// this helper, NOT a hardcoded enum, so the policy can evolve
/// without re-spinning every call site.
#[must_use]
pub fn convergent_default_for_content_type(extension: Option<&str>) -> ChunkAddressKind {
    let Some(ext) = extension else {
        return ChunkAddressKind::Raw;
    };
    match ext.to_ascii_lowercase().as_str() {
        // Raw media: the plaintext is the same for every recipient
        // (a JPEG byte stream is fixed), so convergent IDs enable
        // cross-sender dedup without leaking anything that isn't
        // already public.
        "mp4" | "m4v" | "mov" | "3gp" | "mkv" | "webm" | "avi" | "mp3" | "wav" | "flac" | "ogg"
        | "opus" | "aac" | "m4a" | "jpg" | "jpeg" | "png" | "gif" | "webp" | "heic" | "h264"
        | "264" | "avc" => ChunkAddressKind::Convergent,
        // Everything else: project files, docs, archives, code,
        // unknown types. Default to raw-BLAKE3.
        _ => ChunkAddressKind::Raw,
    }
}

/// Which AEAD primitive was used to encrypt the ciphertext.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum ChunkAeadKind {
    /// AES-256-GCM (primary on x86 / ARM64 with hardware accel).
    AesGcm256,
    /// ChaCha20-Poly1305 (fallback / non-AES platforms).
    ChaCha20Poly1305,
}

/// Bit positions in the chunk-record flags byte per [ADR-0003].
pub mod flag_bits {
    /// 0 = raw-BLAKE3, 1 = convergent-BLAKE3.
    pub const ADDRESS_KIND: u8 = 0b0000_0001;
    /// 0 = AES-256-GCM, 1 = ChaCha20-Poly1305.
    pub const AEAD_KIND: u8 = 0b0000_0010;
    /// 0 = no compression, 1 = zstd applied to plaintext before AEAD.
    pub const COMPRESSED: u8 = 0b0000_0100;
    /// 0 = standard CDC, 1 = format-aware boundary used.
    pub const FORMAT_AWARE: u8 = 0b0000_1000;
    /// Bits 4-7 reserved; must be zero.
    pub const RESERVED: u8 = 0b1111_0000;
}

// ─── the record itself ──────────────────────────────────────────────

/// A complete chunk-log record (header + ciphertext) ready to be wrapped
/// in a [`ol_wal::Record`] and appended to the `chunk_log`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ChunkRecord {
    /// Top-level kind (`ChunkBlob` / `StripeParity` / `TombstoneRef`).
    pub kind: ChunkRecordKind,
    /// Whether `chunk_id` is raw or convergent BLAKE3.
    pub address_kind: ChunkAddressKind,
    /// Which AEAD encrypted the ciphertext.
    pub aead_kind: ChunkAeadKind,
    /// Whether the plaintext was zstd-compressed before AEAD.
    pub compressed: bool,
    /// Whether a format-aware boundary was used (vs pure CDC).
    pub format_aware: bool,
    /// Length of the chunk plaintext in bytes (8 KiB - 256 KiB per ADR-0001).
    pub length_plaintext: u32,
    /// 32-byte BLAKE3 chunk address.
    pub chunk_id: [u8; 32],
    /// 16-byte `ratchet_key_id` (per ADR-0006 Rule 4).
    pub ratchet_key_id: [u8; 16],
    /// Stripe descriptor (24 bytes per ADR-0004; `NONE` in Phase A1).
    pub stripe_descriptor: StripeDescriptor,
    /// AEAD ciphertext bytes. Atomic sessions add one 16-byte tag; streaming
    /// sessions add one tag per 16 KiB frame.
    pub ciphertext: Vec<u8>,
}

impl ChunkRecord {
    /// Validate all size and cross-field invariants without allocating.
    pub fn validate(&self) -> Result<(), ChunkStoreError> {
        if self.length_plaintext as usize > ol_aead::frame::MAX_CHUNK_PLAINTEXT_LEN {
            return Err(ChunkStoreError::MalformedRecord {
                offset: 0,
                reason: "length_plaintext exceeds chunk pipeline maximum",
            });
        }
        if self.ciphertext.len() > MAX_CHUNK_CIPHERTEXT_LEN {
            return Err(ChunkStoreError::MalformedRecord {
                offset: 0,
                reason: "ciphertext exceeds WAL record maximum",
            });
        }
        self.stripe_descriptor.validate()?;
        match (self.kind, self.stripe_descriptor.stripe_role) {
            (ChunkRecordKind::StripeParity, crate::stripe::StripeRole::Parity)
            | (
                ChunkRecordKind::ChunkBlob,
                crate::stripe::StripeRole::Data | crate::stripe::StripeRole::NotStriped,
            )
            | (ChunkRecordKind::TombstoneRef, crate::stripe::StripeRole::NotStriped) => {}
            _ => {
                return Err(ChunkStoreError::InvalidStripeDescriptor(
                    "record kind and stripe role disagree",
                ));
            }
        }
        if matches!(self.kind, ChunkRecordKind::TombstoneRef) {
            if self.length_plaintext != 0 || !self.ciphertext.is_empty() {
                return Err(ChunkStoreError::MalformedRecord {
                    offset: 0,
                    reason: "tombstone must have zero lengths",
                });
            }
        } else if !self.compressed {
            let plaintext_len = self.length_plaintext as usize;
            // The negotiated native-transfer backend is intentionally not an
            // on-disk flag: both layouts use the same AEAD kind and the store
            // is an opaque ciphertext cache. The production fast path seals an
            // atomic chunk with one tag, while the native streaming path seals
            // each 16 KiB frame independently. Accept those two exact shapes
            // and reject every ambiguous/truncated/extended length.
            let expected_atomic = plaintext_len + ol_chunk::AEAD_TAG_LEN;
            let expected_streaming = plaintext_len
                + ol_chunk::frame_count_for_plaintext(plaintext_len) * ol_chunk::AEAD_TAG_LEN;
            if self.ciphertext.len() != expected_atomic
                && self.ciphertext.len() != expected_streaming
            {
                return Err(ChunkStoreError::MalformedRecord {
                    offset: 0,
                    reason: "uncompressed ciphertext length has no supported AEAD framing",
                });
            }
        }
        Ok(())
    }

    /// Compute the flags byte from the boolean fields.
    #[inline]
    #[must_use]
    pub fn flags_byte(&self) -> u8 {
        let mut f = 0u8;
        if matches!(self.address_kind, ChunkAddressKind::Convergent) {
            f |= flag_bits::ADDRESS_KIND;
        }
        if matches!(self.aead_kind, ChunkAeadKind::ChaCha20Poly1305) {
            f |= flag_bits::AEAD_KIND;
        }
        if self.compressed {
            f |= flag_bits::COMPRESSED;
        }
        if self.format_aware {
            f |= flag_bits::FORMAT_AWARE;
        }
        f
    }

    /// Decode the boolean fields back from a flags byte.
    fn parse_flags(
        flags: u8,
    ) -> Result<(ChunkAddressKind, ChunkAeadKind, bool, bool), ChunkStoreError> {
        if flags & flag_bits::RESERVED != 0 {
            return Err(ChunkStoreError::MalformedRecord {
                offset: 0,
                reason: "reserved flag bits non-zero",
            });
        }
        let address_kind = if flags & flag_bits::ADDRESS_KIND != 0 {
            ChunkAddressKind::Convergent
        } else {
            ChunkAddressKind::Raw
        };
        let aead_kind = if flags & flag_bits::AEAD_KIND != 0 {
            ChunkAeadKind::ChaCha20Poly1305
        } else {
            ChunkAeadKind::AesGcm256
        };
        let compressed = flags & flag_bits::COMPRESSED != 0;
        let format_aware = flags & flag_bits::FORMAT_AWARE != 0;
        Ok((address_kind, aead_kind, compressed, format_aware))
    }

    /// Encode to a (`kind_byte`, `flags_byte`, `payload_bytes`) tuple suitable
    /// for [`ol_wal::Record`] construction.
    pub fn encode(&self) -> Result<(u8, u8, Vec<u8>), ChunkStoreError> {
        self.validate()?;
        let mut payload = Vec::with_capacity(CHUNK_RECORD_HEADER_LEN + self.ciphertext.len());
        payload.extend_from_slice(&self.length_plaintext.to_le_bytes());
        let length_ciphertext =
            u32::try_from(self.ciphertext.len()).map_err(|_| ChunkStoreError::MalformedRecord {
                offset: 0,
                reason: "ciphertext length cannot be represented on disk",
            })?;
        payload.extend_from_slice(&length_ciphertext.to_le_bytes());
        payload.extend_from_slice(&self.chunk_id);
        payload.extend_from_slice(&self.ratchet_key_id);
        payload.extend_from_slice(&self.stripe_descriptor.encode());
        debug_assert_eq!(payload.len(), CHUNK_RECORD_HEADER_LEN);
        payload.extend_from_slice(&self.ciphertext);
        Ok((self.kind.as_u8(), self.flags_byte(), payload))
    }

    /// Decode from a (`kind_byte`, `flags_byte`, `payload_bytes`) tuple.
    ///
    /// # Errors
    ///
    /// - [`ChunkStoreError::MalformedRecord`] if the payload is too short
    ///   or the `length_ciphertext` field doesn't match the actual
    ///   payload remainder.
    pub fn decode(kind: u8, flags: u8, payload: &[u8]) -> Result<Self, ChunkStoreError> {
        let kind = ChunkRecordKind::from_u8(kind).ok_or(ChunkStoreError::MalformedRecord {
            offset: 0,
            reason: "unknown chunk-record kind",
        })?;
        if payload.len() < CHUNK_RECORD_HEADER_LEN {
            return Err(ChunkStoreError::MalformedRecord {
                offset: 0,
                reason: "payload shorter than chunk-record header",
            });
        }
        let length_plaintext = u32::from_le_bytes(payload[0..4].try_into().expect("4 bytes"));
        let length_ciphertext = u32::from_le_bytes(payload[4..8].try_into().expect("4 bytes"));
        let mut chunk_id = [0u8; 32];
        chunk_id.copy_from_slice(&payload[8..40]);
        let mut ratchet_key_id = [0u8; 16];
        ratchet_key_id.copy_from_slice(&payload[40..56]);
        let mut stripe_buf = [0u8; STRIPE_DESCRIPTOR_LEN];
        stripe_buf.copy_from_slice(&payload[56..80]);
        let stripe_descriptor = StripeDescriptor::decode(&stripe_buf)?;
        let (address_kind, aead_kind, compressed, format_aware) = Self::parse_flags(flags)?;
        let ciphertext_start = CHUNK_RECORD_HEADER_LEN;
        let ciphertext_end = ciphertext_start + length_ciphertext as usize;
        if payload.len() != ciphertext_end {
            return Err(ChunkStoreError::MalformedRecord {
                offset: 0,
                reason: "length_ciphertext does not match payload length",
            });
        }
        let ciphertext = payload[ciphertext_start..ciphertext_end].to_vec();
        let record = Self {
            kind,
            address_kind,
            aead_kind,
            compressed,
            format_aware,
            length_plaintext,
            chunk_id,
            ratchet_key_id,
            stripe_descriptor,
            ciphertext,
        };
        record.validate()?;
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stripe::{StripeDescriptor, StripeRole};

    fn sample_record() -> ChunkRecord {
        ChunkRecord {
            kind: ChunkRecordKind::ChunkBlob,
            address_kind: ChunkAddressKind::Raw,
            aead_kind: ChunkAeadKind::AesGcm256,
            compressed: false,
            format_aware: false,
            length_plaintext: 1024,
            chunk_id: [0x42u8; 32],
            ratchet_key_id: [0x99u8; 16],
            stripe_descriptor: StripeDescriptor::NONE,
            ciphertext: vec![0xABu8; 1040],
        }
    }

    #[test]
    fn round_trip_default() {
        let r = sample_record();
        let (kind, flags, payload) = r.encode().unwrap();
        let parsed = ChunkRecord::decode(kind, flags, &payload).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn round_trip_convergent_chacha_compressed_format_aware() {
        let mut r = sample_record();
        r.address_kind = ChunkAddressKind::Convergent;
        r.aead_kind = ChunkAeadKind::ChaCha20Poly1305;
        r.compressed = true;
        r.format_aware = true;
        let (kind, flags, payload) = r.encode().unwrap();
        // Verify all four flag bits are set.
        assert_eq!(
            flags,
            flag_bits::ADDRESS_KIND
                | flag_bits::AEAD_KIND
                | flag_bits::COMPRESSED
                | flag_bits::FORMAT_AWARE
        );
        let parsed = ChunkRecord::decode(kind, flags, &payload).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn convergent_default_for_raw_media_extensions() {
        for ext in &["mp4", "MP4", "mov", "h264", "wav", "flac", "jpg", "png"] {
            assert_eq!(
                convergent_default_for_content_type(Some(ext)),
                ChunkAddressKind::Convergent,
                "extension {ext} should map to Convergent"
            );
        }
    }

    #[test]
    fn convergent_default_for_non_media_extensions_returns_raw() {
        for ext in &["docx", "xlsx", "pdf", "zip", "rs", "py", "txt", "json"] {
            assert_eq!(
                convergent_default_for_content_type(Some(ext)),
                ChunkAddressKind::Raw,
                "extension {ext} should map to Raw"
            );
        }
        assert_eq!(
            convergent_default_for_content_type(None),
            ChunkAddressKind::Raw
        );
    }

    #[test]
    fn round_trip_with_stripe_descriptor() {
        let mut r = sample_record();
        r.stripe_descriptor = StripeDescriptor {
            stripe_id_lo64: 0x1234_5678_9ABC_DEF0,
            stripe_role: StripeRole::Data,
            stripe_index: 3,
            stripe_k: 10,
            stripe_m: 4,
            cohort_id_lo64: 0xCAFE_BABE_F00D_BAAD,
        };
        let (kind, flags, payload) = r.encode().unwrap();
        let parsed = ChunkRecord::decode(kind, flags, &payload).unwrap();
        assert_eq!(parsed, r);
        assert!(!parsed.stripe_descriptor.is_not_striped());
    }

    #[test]
    fn rejects_reserved_flag_bits() {
        let r = sample_record();
        let (kind, mut flags, payload) = r.encode().unwrap();
        flags |= 0b1000_0000; // poison reserved bit
        let result = ChunkRecord::decode(kind, flags, &payload);
        assert!(matches!(
            result,
            Err(ChunkStoreError::MalformedRecord { .. })
        ));
    }

    #[test]
    fn rejects_unknown_kind() {
        let r = sample_record();
        let (_kind, flags, payload) = r.encode().unwrap();
        let result = ChunkRecord::decode(0x99, flags, &payload);
        assert!(matches!(
            result,
            Err(ChunkStoreError::MalformedRecord { .. })
        ));
    }

    #[test]
    fn rejects_payload_too_short() {
        let result = ChunkRecord::decode(0x01, 0, &[0u8; 10]);
        assert!(matches!(
            result,
            Err(ChunkStoreError::MalformedRecord { .. })
        ));
    }

    #[test]
    fn rejects_length_ciphertext_mismatch() {
        let r = sample_record();
        let (kind, flags, mut payload) = r.encode().unwrap();
        // Truncate ciphertext but leave header claiming the full length.
        payload.pop();
        let result = ChunkRecord::decode(kind, flags, &payload);
        assert!(matches!(
            result,
            Err(ChunkStoreError::MalformedRecord { .. })
        ));
    }

    #[test]
    fn accepts_atomic_and_streaming_aead_shapes_but_no_intermediate_length() {
        let mut record = sample_record();
        record.length_plaintext = 32 * 1024;

        record.ciphertext = vec![0x11; record.length_plaintext as usize + 16];
        assert!(
            record.encode().is_ok(),
            "atomic one-tag shape must be valid"
        );

        record.ciphertext = vec![0x22; record.length_plaintext as usize + 32];
        assert!(record.encode().is_ok(), "two-frame shape must be valid");

        record.ciphertext = vec![0x33; record.length_plaintext as usize + 17];
        assert!(matches!(
            record.encode(),
            Err(ChunkStoreError::MalformedRecord { .. })
        ));
    }

    #[test]
    fn encode_rejects_record_kind_stripe_role_mismatch() {
        let mut record = sample_record();
        record.kind = ChunkRecordKind::StripeParity;
        assert!(matches!(
            record.encode(),
            Err(ChunkStoreError::InvalidStripeDescriptor(_))
        ));
    }

    #[test]
    fn tombstone_round_trip() {
        let mut r = sample_record();
        r.kind = ChunkRecordKind::TombstoneRef;
        r.length_plaintext = 0;
        r.ciphertext = Vec::new();
        let (kind, flags, payload) = r.encode().unwrap();
        let parsed = ChunkRecord::decode(kind, flags, &payload).unwrap();
        assert_eq!(parsed.kind, ChunkRecordKind::TombstoneRef);
    }
}
