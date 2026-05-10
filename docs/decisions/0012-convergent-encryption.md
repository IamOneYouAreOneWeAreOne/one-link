# ADR-0012: Convergent Encryption — Selective by Content Type

**Status:** ACCEPTED (Phase B acceptance number)
**Phase:** B (the genius layer)
**Depends on:** ADR-0001 (CDC), ADR-0002 (AEAD), ADR-0003 (chunk header flags), ADR-0006 (BLAKE3 derive)

---

## Context

Per-recipient AEAD (the Phase A1 default) makes every sender's ciphertext different even when the plaintext is identical. Twelve people sending the same raw video to the same colorist produces twelve copies on the wire. This is wasted swarm capacity.

Convergent encryption fixes this by deriving the chunk's AEAD key from the chunk's plaintext content (specifically: from `BLAKE3` of the plaintext with a domain separator). Properties:

1. **Same plaintext → same key → same ciphertext, from any sender.**
2. **Same ciphertext → same chunk address (under convergent BLAKE3 derivation).**
3. The swarm dedups across encryption boundaries.

The well-known trade-off: **confirmable-plaintext attacks**. An attacker who guesses the plaintext can compute the convergent address and verify the guess against the ciphertext store. This is acceptable for content where the plaintext is already public (raw camera footage, mass-distributed media) and unacceptable for content where it is not (private messages, secret docs, financial records).

## Decision

**Convergent encryption is enabled selectively, controlled by a per-chunk policy. Default is per-recipient encryption (the safe choice). Convergent mode is enabled only for explicit content-type allowlists at the share-creation boundary.**

### Two encryption modes coexist on disk

The chunk_log header's `address_kind` flag (per [ADR-0003](0003-on-disk-format.md)) already distinguishes:

- **`address_kind = Raw`** (bit 0 = 0): chunk_id = `BLAKE3(plaintext)`. Uses per-recipient AEAD: key derived from the session ratchet chain key per [ADR-0006 Rule 3](0006-blake3-derive-scheme.md). Default.
- **`address_kind = Convergent`** (bit 0 = 1): chunk_id = `BLAKE3.derive_key("ol-chunk-addr-convergent-v1", plaintext)`. Uses convergent AEAD: key derived from the plaintext itself (see derivation below). Optional; enabled selectively.

Both modes coexist. Existing chunks under either mode remain readable. Phase B introduces convergent mode without breaking Phase A1's raw-mode.

### Convergent AEAD key derivation

Per [ADR-0006](0006-blake3-derive-scheme.md), we add a new registered context:

```
"ol-chunk-aead-key-convergent-v1"  → 32-byte AEAD key
```

```
aead_key = BLAKE3.derive_key(
    context = "ol-chunk-aead-key-convergent-v1",
    key_material = plaintext_bytes,
    output_length = 32,
)
```

Notes:
- The derivation input is the **plaintext** (not the chunk_id_full). This ensures two senders independently encrypting the same plaintext compute the same key, even before they communicate.
- AEAD nonce remains constructed per [ADR-0002](0002-aead-frame.md): `chunk_id_lo64 || frame_index_u32`. Under convergent mode, `chunk_id_lo64` is derived from the convergent address, which is a function of the plaintext — so identical plaintext → identical nonce. **This is intentional: nonce + key + plaintext all collide on identical content, producing identical ciphertext.**
- AAD remains `chunk_id_full` (the convergent address). Tampering of AAD invalidates auth tag.

### Content-type policy: who gets convergent mode

The decision is made **at the share creation boundary** (when a folder is shared with a peer / cohort). Each share carries a `convergent_policy` enum:

```rust
enum ConvergentPolicy {
    /// Never use convergent encryption. Default for all new shares;
    /// safe choice for confidential content.
    Never,

    /// Use convergent encryption for files matching the listed MIME
    /// types or extensions. The list is intersected with a built-in
    /// allow-list (see below); types not in the allow-list are silently
    /// downgraded to Raw mode.
    AllowedTypes { mime: Vec<String>, ext: Vec<String> },

    /// Use convergent encryption for ALL files. ONLY use when the
    /// share contains exclusively non-secret content (e.g. a public
    /// website mirror, an open-source code archive). The UI MUST show
    /// a confirmation prompt before enabling this mode.
    All,
}
```

### Built-in allow-list

The allow-list constrains which content types may use convergent encryption regardless of share policy. It exists to prevent users from accidentally enabling convergent mode on private content. Initial allow-list (Phase B v1):

| Category | MIME types | Extensions |
|---|---|---|
| Mass-distributed media | `video/mp4`, `video/quicktime`, `video/x-matroska`, `audio/mpeg`, `audio/aac`, `audio/flac` | `.mp4`, `.mov`, `.mkv`, `.mp3`, `.aac`, `.flac` |
| Public images | `image/jpeg`, `image/png`, `image/heic`, `image/heif` | `.jpg`, `.jpeg`, `.png`, `.heic`, `.heif` |
| Public archives | `application/zip` (when share-level policy explicitly opts in) | `.zip`, `.tar.gz` |
| Open-source / public code | `text/plain` for `.cl`, `.rs`, `.py`, `.js`, `.ts`, `.go`, `.cpp`, `.h`, `.md` (only when share-level policy explicitly opts in) | source extensions |

**Categorically excluded** (always per-recipient, no override):
- `application/pgp-encrypted`, `application/pkcs7-mime` — already encrypted
- `text/csv`, `application/sql`, `application/vnd.sqlite3` — usually private data
- `application/vnd.ms-outlook`, `application/vnd.ms-office`, `application/x-keynote`, `application/vnd.apple.pages` — usually private docs
- Anything matching `.key`, `.pem`, `.p12`, `.kdbx`, `.mbox`, `.pst` — private keys / mail / password stores
- Files in `.env`, `.git/`, `.ssh/` — sensitive config

The allow-list is shipped as a static list; new entries require an ADR amendment.

### Threat model

**What convergent encryption protects against:**
- Network observers seeing the ciphertext: still need the key to read it.
- Storage providers (none in our model, but hypothetically): cannot read content without breaking AEAD.

**What convergent encryption does NOT protect against:**
- **Confirmable-plaintext attacks**: an adversary who suspects "the user has video X" can compute X's convergent address + AEAD key + nonce + ciphertext and verify against the on-disk record. Cost: O(1) per guess. Brute-forcing the entire universe of possible files is infeasible, but for narrow guess sets (a known torrent file, a famous video) it's trivial.
- **Watermarking attacks**: an adversary who can submit content via the share interface can deliberately encode unique markers in the plaintext to track which receivers store which chunks.

These limitations are why convergent mode is opt-in and per-share. The default is per-recipient.

### Migration / coexistence

- Phase A1 chunks (all `Raw` mode) remain readable.
- New shares default to `Never` (no convergent).
- A share's policy can be changed but only forward — flipping `Never` → `AllowedTypes` for an existing share affects only chunks written *after* the change. Existing chunks stay in their original mode.
- The chunk_store memtable indexes both addresses for a chunk under convergent mode (one entry per address kind) so peers asking for either resolve.

### UI / API surface

The CLI / daemon exposes:

```
one-link share new <path> --convergent allow-list
one-link share new <path> --convergent all
one-link share new <path>                 # default: Never
```

The UI shows an icon + tooltip indicating which mode is in effect for a share. Convergent mode is never set silently.

## Consequences

**Positive:**
- Cross-sender dedup: 12 senders → 1 chunk transferred to a common receiver.
- Cross-share dedup: same content shared by two people in different shares dedups locally on the receiver.
- Storage savings: the receiver stores once, not N times.
- Backward compatible: all Phase A1 chunks unchanged.
- Allow-list prevents accidental private-content disclosure via confirmable-plaintext.

**Negative:**
- Confirmable-plaintext exposure on convergent chunks. Documented threat model; opt-in.
- Cohort effects: if Bob and Alice are in different cohorts but both have a convergent chunk Y, an attacker who learns Y's plaintext via Bob's confirmable-plaintext attack also learns Alice has Y. Documented.
- Cannot retroactively re-encrypt chunks. Once stored as convergent, it stays convergent.
- Chunk store memtable has two entries per chunk under convergent mode (raw + convergent addresses both point to the same on-disk record). Adds memory overhead at scale; bounded by the convergent-mode chunk count.

## Verification

1. **Determinism gate**: encrypt the same plaintext via convergent mode from two independent processes; ciphertexts are byte-identical.
2. **Cross-mode round trip**: encrypt under convergent; decrypt under convergent; plaintext recovered. (Raw mode chunks decrypted as raw; cannot decrypt cross-mode.)
3. **Allow-list enforcement**: share policy `AllowedTypes` with `mime = ["text/plain"]` does NOT enable convergent for `.kdbx` files (excluded list takes priority).
4. **Confirmable-plaintext property test**: given a known chunk under convergent mode, an attacker who guesses the plaintext correctly can recompute the ciphertext byte-for-byte. (This is the threat we're documenting, not preventing — the test confirms our threat model is accurate.)
5. **Phase A1 compat gate**: a Phase A1 chunk store (all Raw chunks) opens cleanly under Phase B; mixing Raw and Convergent chunks in one store works.
6. **Share-policy change**: existing chunks under one policy retain it after policy flip.

## References

- Douceur et al. "Reclaiming Space from Duplicate Files in a Serverless Distributed File System" (Farsite 2002) — original convergent encryption paper.
- Tahoe-LAFS uses convergent encryption with mitigations (a per-share-key keyed BLAKE3 instead of bare derive). We adopt the same approach for shares marked `AllowedTypes` (key derivation includes the share's recipient set), which removes confirmable-plaintext for senders outside the share. The `All` mode is bare convergent.
- ADR-0002 (AEAD frame layout) — unchanged.
- ADR-0006 (BLAKE3 derive scheme) — adds `ol-chunk-aead-key-convergent-v1` context.
