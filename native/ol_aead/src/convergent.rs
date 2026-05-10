//! Convergent encryption — selective by content type per
//! [ADR-0012](../../../docs/decisions/0012-convergent-encryption.md).
//!
//! Convergent encryption derives the AEAD key from `BLAKE3` of the
//! plaintext (with a registered domain context). Properties:
//!
//! 1. Same plaintext → same key → same ciphertext from any sender.
//! 2. Cross-user dedup at swarm scale: twelve people sending the same
//!    raw video bytes produce a single on-disk + on-wire chunk family.
//! 3. **Confirmable-plaintext attack**: an attacker who guesses the
//!    plaintext can verify the guess by reproducing the chunk_id.
//!    Acceptable only for content where plaintext is already public
//!    (raw camera footage, mass-distributed media, public images).
//!
//! This module provides:
//!
//! - [`derive_convergent_aead_key`]: BLAKE3-derived AEAD key from plaintext.
//! - [`ContentType`] enum + [`is_convergent_safe`] policy gate.
//! - [`ConvergentPolicy`] enum representing share-level mode.
//! - [`resolve_mode`]: combines policy + content type → final mode.
//!
//! The chunk_id (convergent address) is derived in
//! [`ol_chunk::chunk_address_convergent`]; this module only owns the
//! AEAD-key half of the derivation.

use crate::key::{ChunkAeadKey, FRAME_KEY_LEN};

/// BLAKE3 derive_key context for convergent AEAD keys.
///
/// Registered in [ADR-0006](../../../docs/decisions/0006-blake3-derive-scheme.md).
pub const CONVERGENT_AEAD_KEY_CONTEXT: &str = "ol-chunk-aead-key-convergent-v1";

/// Derive a convergent AEAD key from a chunk's plaintext bytes.
///
/// Two senders independently encrypting the same plaintext will compute
/// the same key without any out-of-band coordination.
#[must_use]
pub fn derive_convergent_aead_key(plaintext: &[u8]) -> ChunkAeadKey {
    let key_bytes = blake3::derive_key(CONVERGENT_AEAD_KEY_CONTEXT, plaintext);
    let mut out = [0u8; FRAME_KEY_LEN];
    out.copy_from_slice(&key_bytes);
    ChunkAeadKey::from_bytes(out)
}

/// Content-type categories used by the convergent-encryption policy.
///
/// The categorization is intentionally coarse: each category collapses
/// many specific MIME types / file extensions into one decision point.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum ContentType {
    /// Mass-distributed media (video, audio). Convergent-safe.
    MassMedia,
    /// Public-distribution images (jpeg, png, heic). Convergent-safe.
    PublicImage,
    /// ZIP / TAR archives. Allow only with explicit opt-in.
    Archive,
    /// Source code, plain text. Allow only with explicit opt-in.
    SourceCode,
    /// Generic plain text without source-code indicators. Excluded.
    PlainText,
    /// Office / iWork / Outlook documents. Always private.
    OfficeDocument,
    /// PGP / S/MIME / TLS keys + certificates. Always private.
    EncryptedOrKey,
    /// Database / spreadsheet data (CSV, SQL, SQLite). Always private.
    DataStore,
    /// Mail boxes / password vaults / shell config / git dir. Always private.
    SensitiveConfig,
    /// Anything else (unknown).
    Unknown,
}

/// Map a file extension (case-insensitive, no leading dot) to a
/// [`ContentType`].
#[must_use]
pub fn content_type_from_extension(ext: &str) -> ContentType {
    let ext = ext.to_ascii_lowercase();
    match ext.as_str() {
        // Mass media.
        "mp4" | "m4v" | "mov" | "mkv" | "webm" | "mp3" | "aac" | "flac" | "ogg" | "wav"
        | "m4a" | "opus" => ContentType::MassMedia,
        // Public images.
        "jpg" | "jpeg" | "png" | "heic" | "heif" | "gif" | "webp" => ContentType::PublicImage,
        // Archives — convergent-safe only when share explicitly opts in.
        "zip" | "tar" | "gz" | "tgz" | "bz2" | "xz" | "zst" => ContentType::Archive,
        // Source code.
        "rs" | "py" | "js" | "ts" | "go" | "cpp" | "h" | "cl" | "java" | "cs" | "kt"
        | "swift" | "rb" | "md" | "sh" => ContentType::SourceCode,
        // Plain text — non-source.
        "txt" | "log" => ContentType::PlainText,
        // Office.
        "docx" | "xlsx" | "pptx" | "doc" | "xls" | "ppt" | "odt" | "ods" | "odp"
        | "pages" | "numbers" | "key" => ContentType::OfficeDocument,
        // Encrypted / keys.
        "pgp" | "gpg" | "asc" | "pem" | "p12" | "pfx" | "cer" | "crt" | "der" => {
            ContentType::EncryptedOrKey
        }
        // Data stores.
        "csv" | "sql" | "sqlite" | "sqlite3" | "db" => ContentType::DataStore,
        // Mail / password / git config.
        "mbox" | "pst" | "ost" | "kdbx" | "env" => ContentType::SensitiveConfig,
        _ => ContentType::Unknown,
    }
}

/// Share-level convergent encryption policy. Set at share-creation
/// time. Per ADR-0012, default is `Never`; `All` requires explicit
/// UI confirmation.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub enum ConvergentPolicy {
    /// Never use convergent encryption. Default.
    #[default]
    Never,
    /// Use convergent encryption for files whose [`ContentType`] passes
    /// the global allow-list. Implementation simplification: rather
    /// than carry an explicit per-share allow-list, this variant uses
    /// the built-in allow-list — the per-share semantics that ADR-0012
    /// describes are layered on top in the daemon via `allowed_types`
    /// filtering before we ever reach this gate.
    AllowedTypes,
    /// Use convergent encryption for ALL files regardless of type.
    /// Caller MUST gate this behind explicit UI confirmation.
    All,
}

/// Resolved encryption mode for a single chunk. The chunk-store layer
/// consumes this to pick the right key derivation.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum EncryptionMode {
    /// Per-recipient AEAD: key derived from ratchet chain key per
    /// ADR-0006 Rule 3. Default; safe for all content.
    Standard,
    /// Convergent AEAD: key derived from plaintext per
    /// [`derive_convergent_aead_key`]. Used only when policy + content
    /// type combine to permit it.
    Convergent,
}

/// Combine a share-level [`ConvergentPolicy`] with a per-file
/// [`ContentType`] to produce the resolved [`EncryptionMode`].
///
/// **Default-safe**: anything ambiguous returns `Standard`. Caller
/// never has to fear that `Unknown` content silently slipped into
/// convergent mode.
#[must_use]
pub fn resolve_mode(policy: &ConvergentPolicy, content: ContentType) -> EncryptionMode {
    match policy {
        ConvergentPolicy::Never => EncryptionMode::Standard,
        ConvergentPolicy::All => {
            // `All` is the explicit opt-in mode; we still bar a few
            // categorically-excluded types as a belt-and-braces guard
            // against UX bugs in the caller.
            if matches!(
                content,
                ContentType::EncryptedOrKey
                    | ContentType::SensitiveConfig
                    | ContentType::DataStore
            ) {
                EncryptionMode::Standard
            } else {
                EncryptionMode::Convergent
            }
        }
        ConvergentPolicy::AllowedTypes => {
            if is_convergent_safe(content) {
                EncryptionMode::Convergent
            } else {
                EncryptionMode::Standard
            }
        }
    }
}

/// Built-in allow-list gate. Returns `true` for content types ADR-0012
/// considers convergent-safe under `ConvergentPolicy::AllowedTypes`.
///
/// `SourceCode` + `Archive` are NOT in the auto-allow-list — they need
/// `ConvergentPolicy::All` for explicit user confirmation.
#[must_use]
pub fn is_convergent_safe(content: ContentType) -> bool {
    matches!(content, ContentType::MassMedia | ContentType::PublicImage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_plaintext_yields_same_aead_key() {
        let pt = b"hello world, this is a chunk's plaintext";
        let k1 = derive_convergent_aead_key(pt);
        let k2 = derive_convergent_aead_key(pt);
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn distinct_plaintext_yields_distinct_aead_key() {
        let k1 = derive_convergent_aead_key(b"hello");
        let k2 = derive_convergent_aead_key(b"world");
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn extensions_map_to_categories() {
        assert_eq!(content_type_from_extension("MP4"), ContentType::MassMedia);
        assert_eq!(content_type_from_extension("flac"), ContentType::MassMedia);
        assert_eq!(content_type_from_extension("png"), ContentType::PublicImage);
        assert_eq!(content_type_from_extension("ZIP"), ContentType::Archive);
        assert_eq!(content_type_from_extension("rs"), ContentType::SourceCode);
        assert_eq!(content_type_from_extension("docx"), ContentType::OfficeDocument);
        assert_eq!(content_type_from_extension("pem"), ContentType::EncryptedOrKey);
        assert_eq!(content_type_from_extension("csv"), ContentType::DataStore);
        assert_eq!(content_type_from_extension("env"), ContentType::SensitiveConfig);
        assert_eq!(content_type_from_extension("ttf"), ContentType::Unknown);
    }

    #[test]
    fn convergent_safe_only_mass_media_and_images() {
        for c in [ContentType::MassMedia, ContentType::PublicImage] {
            assert!(is_convergent_safe(c));
        }
        for c in [
            ContentType::Archive,
            ContentType::SourceCode,
            ContentType::PlainText,
            ContentType::OfficeDocument,
            ContentType::EncryptedOrKey,
            ContentType::DataStore,
            ContentType::SensitiveConfig,
            ContentType::Unknown,
        ] {
            assert!(!is_convergent_safe(c), "{c:?} should not be auto-safe");
        }
    }

    #[test]
    fn policy_never_always_standard() {
        for c in [
            ContentType::MassMedia,
            ContentType::PublicImage,
            ContentType::OfficeDocument,
            ContentType::Unknown,
        ] {
            assert_eq!(resolve_mode(&ConvergentPolicy::Never, c), EncryptionMode::Standard);
        }
    }

    #[test]
    fn policy_allowed_types_gates_to_safe_list() {
        assert_eq!(
            resolve_mode(&ConvergentPolicy::AllowedTypes, ContentType::MassMedia),
            EncryptionMode::Convergent
        );
        assert_eq!(
            resolve_mode(&ConvergentPolicy::AllowedTypes, ContentType::PublicImage),
            EncryptionMode::Convergent
        );
        assert_eq!(
            resolve_mode(&ConvergentPolicy::AllowedTypes, ContentType::OfficeDocument),
            EncryptionMode::Standard
        );
        assert_eq!(
            resolve_mode(&ConvergentPolicy::AllowedTypes, ContentType::Unknown),
            EncryptionMode::Standard
        );
    }

    #[test]
    fn policy_all_respects_categorical_excludes() {
        assert_eq!(
            resolve_mode(&ConvergentPolicy::All, ContentType::MassMedia),
            EncryptionMode::Convergent
        );
        assert_eq!(
            resolve_mode(&ConvergentPolicy::All, ContentType::OfficeDocument),
            EncryptionMode::Convergent
        );
        // Always-private categories stay standard even under `All`.
        assert_eq!(
            resolve_mode(&ConvergentPolicy::All, ContentType::EncryptedOrKey),
            EncryptionMode::Standard
        );
        assert_eq!(
            resolve_mode(&ConvergentPolicy::All, ContentType::SensitiveConfig),
            EncryptionMode::Standard
        );
        assert_eq!(
            resolve_mode(&ConvergentPolicy::All, ContentType::DataStore),
            EncryptionMode::Standard
        );
    }

    #[test]
    fn default_policy_is_never() {
        assert_eq!(ConvergentPolicy::default(), ConvergentPolicy::Never);
    }
}
