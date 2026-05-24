"""Recovery setup — the three real paths the UI offers.

The wizard at Settings -> Setup -> Set recovery used to be a self-
attestation form: a modal that asked the user to type "I have my
recovery info" to confirm something they had no in-app way to
actually do. The CLI shipped `one-link backup show / restore`,
`social_recovery` shipped the Shamir 3-of-5 wrap, and
`backup_bundle` shipped the encrypted `.olbak` exporter — but
none of it was reachable from the UI. The button promised setup
and delivered a flag flip.

This module is the bridge. It exposes the three real recovery
paths over HTTP, lets the UI run a real flow per track, and
records per-track state in settings so the Setup checklist shows
which paths are configured rather than a single global yes/no.

The three tracks
----------------
1. **Recovery phrase** (BIP-39 24 words). The canonical sovereignty
   primitive: paper-only, no transport, restorable on any fresh
   install via `one-link backup restore`. Verified by re-typing
   three random word positions so the user can't muscle-memory
   through.

2. **Trusted contacts** (Shamir 3-of-5 via `social_recovery`). User
   picks N paired peers, daemon mints N wrapped share files each
   sealed to its target guardian's Ed25519 identity, browser
   downloads the share files. User delivers each file to its
   guardian via whatever medium they trust (USB, email, in person).
   We deliberately do NOT auto-ship over the daemon wire — that
   would couple "setup" to "guardian's daemon online and accepts"
   and add a new wire frame. The wrap is sealed; the medium does
   not matter.

3. **Encrypted backup file** (`.olbak` via `backup_bundle`). Daemon
   creates the bundle, streams it to the browser as a download.
   User puts the file somewhere safe (cloud, USB, second device).

Each track sets its own state setting. The legacy
`one_setup_recovery_configured_at_ms` setting stays for back-compat
and is set when ANY track is configured. The Setup checklist
checks each track individually for richer status text.

Security posture
----------------
- All endpoints sit behind `_guarded` (auth + CSRF + rate-limit).
- The phrase endpoint adds `Cache-Control: no-store, no-cache,
  must-revalidate, max-age=0` + `Pragma: no-cache` so the 24
  words never land in browser cache or service-worker storage.
- Verification is per-token rate-limited (5 attempts / 60s) to
  prevent brute-force on the verify path.
- Bundle export streams via `Content-Disposition: attachment` so
  it goes to disk, not into a tab the user might leave open.
- Share files use a custom extension (`.olss`) + base64-encoded
  blobs so they survive being pasted into email / chat.
- No track touches the master seed if it does not exist —
  legacy installs without `master.seed` (pre-mnemonic flow) get
  a clear 503 with a "run `one-link backup init` first" message.
"""
from __future__ import annotations

import base64
import contextlib
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


# ── settings keys (per-track state) ──────────────────────────────────

SETTING_PHRASE_VERIFIED_AT_MS = "one_setup_recovery_phrase_verified_at_ms"
SETTING_BACKUP_LAST_EXPORT_AT_MS = "one_setup_recovery_backup_last_export_at_ms"
SETTING_BACKUP_LAST_EXPORT_SIZE = "one_setup_recovery_backup_last_export_size"
SETTING_SOCIAL_CONFIGURED_AT_MS = "one_setup_recovery_social_configured_at_ms"
SETTING_SOCIAL_GUARDIAN_COUNT = "one_setup_recovery_social_guardian_count"
SETTING_SOCIAL_THRESHOLD_K = "one_setup_recovery_social_threshold_k"
SETTING_LEGACY_CONFIGURED_AT_MS = "one_setup_recovery_configured_at_ms"


# ── data classes ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class TrackState:
    """One row in the recovery status response."""
    track: str
    ready: bool
    available: bool
    last_action_at_ms: int
    extra: dict[str, Any]


@dataclass(frozen=True)
class RecoveryStatus:
    phrase: TrackState
    social: TrackState
    backup: TrackState

    @property
    def any_ready(self) -> bool:
        return self.phrase.ready or self.social.ready or self.backup.ready

    def to_dict(self) -> dict[str, Any]:
        def t(ts: TrackState) -> dict[str, Any]:
            return {
                "track": ts.track,
                "ready": ts.ready,
                "available": ts.available,
                "last_action_at_ms": ts.last_action_at_ms,
                **ts.extra,
            }
        return {
            "phrase": t(self.phrase),
            "social": t(self.social),
            "backup": t(self.backup),
            "any_ready": self.any_ready,
        }


# ── status snapshot ──────────────────────────────────────────────────


def _setting_int(state, key: str) -> int:
    with contextlib.suppress(Exception):
        return int(state.get_setting(key) or 0)
    return 0


def snapshot_status(state, data_dir: Path) -> RecoveryStatus:
    """Build the per-track recovery snapshot the UI renders.

    `available` means the prerequisites are in place to RUN the
    flow now (e.g. a master seed exists for phrase + backup tracks,
    paired peers exist for the social track).
    `ready` means the user has actually completed that track at
    least once.
    """
    from one_link import master_seed
    has_master_seed = master_seed.has_seed(Path(data_dir))

    phrase_verified = _setting_int(state, SETTING_PHRASE_VERIFIED_AT_MS)
    backup_at = _setting_int(state, SETTING_BACKUP_LAST_EXPORT_AT_MS)
    backup_size = _setting_int(state, SETTING_BACKUP_LAST_EXPORT_SIZE)
    social_at = _setting_int(state, SETTING_SOCIAL_CONFIGURED_AT_MS)
    social_count = _setting_int(state, SETTING_SOCIAL_GUARDIAN_COUNT)
    social_k = _setting_int(state, SETTING_SOCIAL_THRESHOLD_K)

    candidates = _social_candidate_count(state)

    return RecoveryStatus(
        phrase=TrackState(
            track="phrase",
            ready=phrase_verified > 0,
            available=has_master_seed,
            last_action_at_ms=phrase_verified,
            extra={"requires_master_seed": True},
        ),
        social=TrackState(
            track="social",
            ready=social_at > 0,
            available=has_master_seed and candidates >= 2,
            last_action_at_ms=social_at,
            extra={
                "guardian_count": social_count,
                "threshold_k": social_k,
                "candidate_count": candidates,
            },
        ),
        backup=TrackState(
            track="backup",
            ready=backup_at > 0,
            available=has_master_seed,
            last_action_at_ms=backup_at,
            extra={"last_export_size_bytes": backup_size},
        ),
    )


def is_any_track_ready(state) -> bool:
    """Lightweight check used by the Setup checklist row."""
    return any(
        _setting_int(state, k) > 0
        for k in (
            SETTING_PHRASE_VERIFIED_AT_MS,
            SETTING_BACKUP_LAST_EXPORT_AT_MS,
            SETTING_SOCIAL_CONFIGURED_AT_MS,
            SETTING_LEGACY_CONFIGURED_AT_MS,
        )
    )


def configured_track_labels(state) -> list[str]:
    """Human-readable track names the Setup checklist surfaces in
    its 'how recovery is set up' summary line."""
    out: list[str] = []
    if _setting_int(state, SETTING_PHRASE_VERIFIED_AT_MS) > 0:
        out.append("recovery phrase")
    if _setting_int(state, SETTING_SOCIAL_CONFIGURED_AT_MS) > 0:
        out.append("trusted contacts")
    if _setting_int(state, SETTING_BACKUP_LAST_EXPORT_AT_MS) > 0:
        out.append("encrypted backup")
    if not out and _setting_int(state, SETTING_LEGACY_CONFIGURED_AT_MS) > 0:
        out.append("manual confirmation")
    return out


# ── track 1: recovery phrase ─────────────────────────────────────────


WORD_COUNT = 24


def load_phrase_words(data_dir: Path) -> Optional[list[str]]:
    """Return the 24 BIP-39 words for the current master seed, or
    None if no seed file exists yet."""
    from one_link import master_seed, mnemonic
    seed = master_seed.load_seed(Path(data_dir))
    if seed is None:
        return None
    try:
        phrase = mnemonic.encode(seed)
    finally:
        # Best-effort. Python bytes are immutable, but this drops
        # our reference; the GC collects on the next pass.
        seed = b"\x00" * len(seed)
        del seed
    return phrase.split()


def pick_verification_indices(rng: secrets.SystemRandom | None = None) -> list[int]:
    """Pick three distinct 1-indexed positions in the 24-word phrase
    that the user must type back to prove they wrote it down. We
    pick from the full range; clustering would hint at "we only
    ever ask about the first few" and be muscle-memorisable across
    sessions.
    """
    r = rng or secrets.SystemRandom()
    return sorted(r.sample(range(1, WORD_COUNT + 1), 3))


def verify_phrase_positions(
    *, data_dir: Path, indices: list[int], words: list[str],
) -> tuple[bool, list[int]]:
    """Check that `words[i]` matches the word at position `indices[i]`
    in the daemon's current 24-word phrase. Returns (ok, mismatch_indices).

    Comparison is case-insensitive + whitespace-stripped. Position
    1 is the first word.
    """
    phrase_words = load_phrase_words(data_dir)
    if phrase_words is None:
        raise FileNotFoundError("no master seed on this install")
    if len(indices) != len(words):
        raise ValueError("indices and words must be same length")
    if not indices:
        raise ValueError("at least one position required")
    mismatches: list[int] = []
    for idx, supplied in zip(indices, words):
        if not (1 <= idx <= WORD_COUNT):
            raise ValueError(f"position out of range: {idx}")
        canon = (supplied or "").strip().lower()
        if canon != phrase_words[idx - 1]:
            mismatches.append(idx)
    return (len(mismatches) == 0, mismatches)


def test_bundle_against_phrase(
    *, phrase: str, bundle_bytes: bytes,
) -> dict[str, Any]:
    """Non-destructive 'will this backup decrypt with this phrase?'
    check. Decodes the phrase via mnemonic.decode (validates the
    BIP-39 checksum), derives the bundle key via the same HKDF the
    exporter used, runs AEAD-decrypt on the bundle in memory, and
    counts plaintext entries. Writes nothing to disk. Useful to
    verify a backup file + paper phrase pair are still valid
    without committing to a destructive restore.

    Result shape:
      {
        "valid_phrase":        True iff phrase decodes cleanly,
        "valid_bundle":        True iff AEAD-decrypt passes,
        "bundle_created_ms":   header's created_ms (only set when
                               valid_bundle is True),
        "file_count":          number of plaintext archive entries
                               (excluding MANIFEST),
        "error":               short human-readable message on
                               failure,
      }
    """
    from one_link import backup_bundle, mnemonic
    out: dict[str, Any] = {
        "valid_phrase": False,
        "valid_bundle": False,
        "bundle_created_ms": 0,
        "file_count": 0,
        "error": "",
    }
    try:
        seed = mnemonic.decode(phrase)
    except (ValueError, TypeError) as e:
        out["error"] = str(e)
        return out
    out["valid_phrase"] = True
    try:
        header, plaintext = backup_bundle.open_bundle(
            seed=seed, bundle_bytes=bundle_bytes,
        )
    except ValueError as e:
        out["error"] = str(e)
        return out
    finally:
        seed = b"\x00" * len(seed)
        del seed
    out["valid_bundle"] = True
    out["bundle_created_ms"] = int(header.created_ms)
    # Count plaintext entries without writing to disk. The bundle's
    # plaintext is a gzip-tar; iterate members so we can report the
    # file count and skip the MANIFEST metadata row.
    try:
        import gzip as _gzip
        import tarfile as _tarfile
        from io import BytesIO as _BytesIO
        names: list[str] = []
        with _gzip.GzipFile(fileobj=_BytesIO(plaintext), mode="rb") as gz:
            with _tarfile.open(fileobj=gz, mode="r") as tf:
                for ti in tf.getmembers():
                    if ti.isfile() and ti.name != "MANIFEST":
                        names.append(ti.name)
        out["file_count"] = len(names)
    except Exception:
        # Bundle decrypted but the inner archive was malformed.
        # Still count valid_bundle=True (the AEAD passed); the
        # zero file_count signals the inner structure is broken.
        pass
    return out


def test_phrase_against_current_seed(
    *, data_dir: Path, phrase: str,
) -> dict[str, Any]:
    """Non-destructive 'did I write down my 24 words correctly?' check.

    Decodes the phrase via mnemonic.decode (validates the BIP-39
    checksum) and, if a master seed exists on this install,
    compares the decoded bytes against the on-disk seed in
    constant time. Returns a small dict the UI renders as a
    green/amber/red status.

    Result shape:
      {
        "valid_checksum": True iff the phrase decodes cleanly,
        "matches_current_identity": True iff bytes equal the
          on-disk master.seed (only meaningful when checksum is
          valid + a seed file exists),
        "has_current_identity": True iff master.seed exists on
          disk (False on a fresh install with no identity yet),
        "error": short human-readable message on checksum failure,
      }

    Does NOT write any state. Does NOT touch identity.key or DRK.
    Safe to call any number of times.
    """
    from one_link import master_seed, mnemonic
    import secrets as _secrets
    out: dict[str, Any] = {
        "valid_checksum": False,
        "matches_current_identity": False,
        "has_current_identity": False,
        "error": "",
    }
    try:
        candidate = mnemonic.decode(phrase)
    except (ValueError, TypeError) as e:
        out["error"] = str(e)
        return out
    out["valid_checksum"] = True
    try:
        current = master_seed.load_seed(Path(data_dir))
    except Exception:
        current = None
    if current is None:
        return out
    out["has_current_identity"] = True
    # secrets.compare_digest is constant-time-ish; the bytes
    # involved are 32 each, and Python's eq would short-circuit on
    # the first differing byte. compare_digest doesn't.
    try:
        out["matches_current_identity"] = _secrets.compare_digest(
            bytes(current), bytes(candidate),
        )
    finally:
        # Best-effort wipe of the candidate seed we just decoded.
        candidate = b"\x00" * len(candidate)
        current = b"\x00" * len(current)
        del candidate
        del current
    return out


def mark_phrase_verified(state, now_ms: Optional[int] = None) -> int:
    """Record that the user successfully verified the phrase."""
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    state.set_setting(SETTING_PHRASE_VERIFIED_AT_MS, str(now_ms))
    state.set_setting(SETTING_LEGACY_CONFIGURED_AT_MS, str(now_ms))
    return now_ms


# ── track 2: encrypted backup file (.olbak) ──────────────────────────


def build_backup_bundle(
    *, data_dir: Path, include_files: bool = False,
) -> bytes:
    """Return the encoded .olbak bundle bytes. Raises FileNotFoundError
    if no master seed exists."""
    from one_link import backup_bundle, master_seed
    seed = master_seed.load_seed(Path(data_dir))
    if seed is None:
        raise FileNotFoundError("no master seed on this install")
    try:
        bundle = backup_bundle.create_bundle(
            seed=seed,
            data_dir=Path(data_dir),
            include_files=include_files,
        )
    finally:
        seed = b"\x00" * len(seed)
        del seed
    return bundle


def mark_backup_exported(
    state, *, size_bytes: int, now_ms: Optional[int] = None,
) -> int:
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    state.set_setting(SETTING_BACKUP_LAST_EXPORT_AT_MS, str(now_ms))
    state.set_setting(SETTING_BACKUP_LAST_EXPORT_SIZE, str(int(size_bytes)))
    state.set_setting(SETTING_LEGACY_CONFIGURED_AT_MS, str(now_ms))
    return now_ms


def backup_filename(now_ms: int | None = None) -> str:
    """Suggest a download filename. Stable shape so the user can
    spot multiple exports by date."""
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    import datetime
    ts = datetime.datetime.fromtimestamp(now_ms / 1000)
    return f"one-link-backup-{ts.strftime('%Y%m%d-%H%M%S')}.olbak"


# ── track 3: trusted contacts (social recovery) ──────────────────────


# Trust values that mean "the user has pinned this peer as theirs"
# in state.set_peer_trust calls across daemon.py. Anything else
# (candidate / rejected / etc.) is not a sensible guardian target.
_GUARDIAN_TRUST_VALUES = {"pinned"}


def _social_candidate_count(state) -> int:
    """Count of paired peers we can plausibly wrap shares to. The
    UI uses this to decide whether to even surface the social track
    ('You need at least 2 trusted contacts before you can set this
    up')."""
    try:
        peers = state.list_peers()
    except Exception:
        return 0
    n = 0
    for p in peers or []:
        if getattr(p, "trust", None) in _GUARDIAN_TRUST_VALUES:
            pub = getattr(p, "pubkey", b"")
            if isinstance(pub, (bytes, bytearray)) and len(pub) == 32:
                n += 1
    return n


def list_social_candidates(state) -> list[dict[str, Any]]:
    """Return the paired-peer roster the UI shows for guardian
    selection. Each entry has id (fingerprint), label, pubkey_b64
    (the Ed25519 32 bytes that share-wrap targets), and a hint so
    the user can spot 'my own iPad' vs 'Bob'."""
    out: list[dict[str, Any]] = []
    try:
        peers = state.list_peers()
    except Exception:
        return out
    for p in peers or []:
        if getattr(p, "trust", None) not in _GUARDIAN_TRUST_VALUES:
            continue
        pub = getattr(p, "pubkey", None)
        if not isinstance(pub, (bytes, bytearray)) or len(pub) != 32:
            continue
        label = getattr(p, "display_name", None) or getattr(p, "short_id", None) or "Trusted device"
        out.append({
            "id": getattr(p, "fingerprint", "") or "",
            "label": str(label),
            "pubkey_b64": base64.b64encode(bytes(pub)).decode("ascii"),
            "hostname": getattr(p, "hostname", "") or "",
            "verified": bool(getattr(p, "verified_at_ms", None)),
            "last_seen_ms": int(getattr(p, "last_seen_ms", 0) or 0),
        })
    return out


def issue_social_shares(
    *,
    data_dir: Path,
    guardians: list[dict[str, Any]],
    threshold_k: int = 3,
) -> list[dict[str, Any]]:
    """Split the master seed into N Shamir shares, each sealed to
    one guardian's Ed25519 pubkey. Returns N share descriptors the
    UI can render + offer as downloads.

    Each guardian dict must carry `label` (display string for the
    UI / share filename) and either `pubkey_b64` (raw 32 bytes
    base64-encoded) or `pubkey_hex`. Returned share descriptors:

        {
          "guardian_label": str,       # what the user picked
          "share_index": int,          # 1..N, matches the Shamir x
          "filename": str,             # suggested .olss filename
          "blob_b64u": str,            # the wrapped share bytes
          "threshold_k": int,          # K = required to combine
          "total_n": int,              # N = total shares issued
          "setup_ms": int,
        }
    """
    from one_link import master_seed, social_recovery
    if not guardians:
        raise ValueError("at least 2 guardians required")
    if threshold_k < 2:
        raise ValueError("threshold_k must be at least 2")
    if threshold_k > len(guardians):
        raise ValueError(
            f"threshold_k={threshold_k} cannot exceed guardian count {len(guardians)}"
        )

    seed = master_seed.load_seed(Path(data_dir))
    if seed is None:
        raise FileNotFoundError("no master seed on this install")
    try:
        # Normalise guardian shape: each needs (label, ed25519 pubkey bytes).
        named_pubs: list[tuple[str, bytes]] = []
        seen_pubs: set[bytes] = set()
        for g in guardians:
            label = str(g.get("label") or "Guardian").strip() or "Guardian"
            pub_b64 = g.get("pubkey_b64")
            pub_hex = g.get("pubkey_hex")
            if pub_b64:
                try:
                    pub = base64.b64decode(str(pub_b64), validate=True)
                except Exception as e:
                    raise ValueError(f"bad pubkey_b64 for {label!r}: {e}")
            elif pub_hex:
                try:
                    pub = bytes.fromhex(str(pub_hex))
                except ValueError as e:
                    raise ValueError(f"bad pubkey_hex for {label!r}: {e}")
            else:
                raise ValueError(f"guardian {label!r} missing pubkey")
            if len(pub) != 32:
                raise ValueError(
                    f"guardian {label!r} pubkey must be 32 bytes, got {len(pub)}"
                )
            if pub in seen_pubs:
                raise ValueError(
                    f"guardian {label!r} pubkey duplicates another guardian"
                )
            seen_pubs.add(pub)
            named_pubs.append((label, pub))

        setup_ms = int(time.time() * 1000)
        pairs = social_recovery.setup_social_recovery(
            seed=seed,
            guardians=named_pubs,
            threshold_k=threshold_k,
        )
    finally:
        seed = b"\x00" * len(seed)
        del seed

    total_n = len(pairs)
    out: list[dict[str, Any]] = []
    for label, share in pairs:
        safe_label = _safe_filename_segment(label)
        filename = (
            f"one-link-share-{share.share_index}-of-{total_n}-{safe_label}.olss"
        )
        out.append({
            "guardian_label": label,
            "share_index": share.share_index,
            "filename": filename,
            "blob_b64u": base64.urlsafe_b64encode(share.encoded).decode("ascii"),
            "threshold_k": share.threshold,
            "total_n": share.total,
            "setup_ms": share.setup_ms,
        })
    return out


def mark_social_configured(
    state,
    *,
    guardian_count: int,
    threshold_k: int,
    now_ms: Optional[int] = None,
) -> int:
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    state.set_setting(SETTING_SOCIAL_CONFIGURED_AT_MS, str(now_ms))
    state.set_setting(SETTING_SOCIAL_GUARDIAN_COUNT, str(int(guardian_count)))
    state.set_setting(SETTING_SOCIAL_THRESHOLD_K, str(int(threshold_k)))
    state.set_setting(SETTING_LEGACY_CONFIGURED_AT_MS, str(now_ms))
    return now_ms


def _safe_filename_segment(s: str) -> str:
    """Reduce a label to a safe filename slug. ASCII letters,
    digits, dash, underscore; spaces collapse to dashes; everything
    else drops. Caps at 32 chars."""
    out_chars: list[str] = []
    for ch in s:
        if ch.isalnum() or ch in {"-", "_"}:
            out_chars.append(ch)
        elif ch == " ":
            out_chars.append("-")
    slug = "".join(out_chars).strip("-_")[:32]
    return slug or "guardian"


# ── settings-reset hook for the existing `reset` setup_action ────────


# ── restore from phrase ──────────────────────────────────────────────


def is_install_clean_for_restore(state) -> tuple[bool, dict[str, int]]:
    """Return (clean, evidence). An install is "clean" if restoring
    a different identity over it does not destroy meaningful user
    state. We count what would be orphaned: pinned peers, sent +
    received messages, groups, shared folders, self-mesh devices.

    A clean install only needs the user to confirm the phrase.
    A dirty install requires `force=True` on the restore call AND
    a stern UI warning that the prior identity will be replaced.
    """
    evidence: dict[str, int] = {}
    try:
        peers = state.list_peers()
        pinned = [p for p in (peers or []) if getattr(p, "trust", None) == "pinned"]
        evidence["pinned_peers"] = len(pinned)
    except Exception:
        evidence["pinned_peers"] = 0
    for fn, key in (
        ("list_groups", "groups"),
        ("list_self_mesh_devices", "self_mesh_devices"),
    ):
        f = getattr(state, fn, None)
        if callable(f):
            try:
                items = f()
                if items is None:
                    evidence[key] = 0
                elif hasattr(items, "__len__"):
                    evidence[key] = len(items)
                else:
                    evidence[key] = sum(1 for _ in items)
            except Exception:
                evidence[key] = 0
        else:
            evidence[key] = 0
    # A "dirty" install has any of these.
    clean = all(v == 0 for v in evidence.values())
    return clean, evidence


def restore_seed_from_phrase(
    *,
    data_dir: Path,
    phrase: str,
    delete_identity_files: bool,
) -> bytes:
    """Decode the 24-word phrase, write the master seed to disk, and
    (when ``delete_identity_files`` is True) clear the existing
    identity.key + DRK so the daemon re-derives both from the
    restored seed on next start.

    Raises ``ValueError`` on bad/incomplete phrase (mnemonic.decode's
    own checksum check), ``FileNotFoundError`` is not raised here -
    callers decide whether to allow overwriting an existing seed.

    Returns the 32-byte decoded seed (for the caller's logging or
    audit; the seed itself is also persisted to disk).
    """
    from one_link import master_seed, mnemonic
    from one_link import paths
    # Decode + verify checksum BEFORE touching disk. mnemonic.decode
    # raises ValueError with a clear message on bad phrase / typo.
    seed = mnemonic.decode(phrase)
    if len(seed) != master_seed.SEED_LEN_BYTES:
        raise ValueError(
            f"decoded seed has wrong length {len(seed)}; "
            f"expected {master_seed.SEED_LEN_BYTES}"
        )
    if delete_identity_files:
        # Wipe identity.key + DRK so the daemon's next start
        # re-derives both from the restored seed.
        for f in (paths.key_path(), Path(data_dir) / "data-root-key.bin"):
            with contextlib.suppress(OSError):
                Path(f).unlink()
    master_seed.store_seed(Path(data_dir), seed)
    return seed


def restore_from_bundle(
    *,
    data_dir: Path,
    phrase: str,
    bundle_bytes: bytes,
    delete_identity_files: bool,
    overwrite: bool,
) -> dict[str, Any]:
    """Combined phrase + .olbak restore. Decodes the phrase to a
    seed, decrypts the bundle (the bundle key derives from the
    seed via HKDF, so the same phrase that restores the identity
    also unlocks the chat history + settings), and extracts the
    plaintext archive into ``data_dir``.

    Returns a small descriptor: which files were written, plus the
    bundle's created_ms timestamp so the UI can confirm "restored a
    backup from 3 days ago."

    Raises ``ValueError`` on bad phrase OR bad bundle (tampered /
    wrong key / truncated).
    """
    from one_link import backup_bundle, master_seed, mnemonic
    from one_link import paths
    seed = mnemonic.decode(phrase)
    if len(seed) != master_seed.SEED_LEN_BYTES:
        raise ValueError(
            f"decoded seed has wrong length {len(seed)}; "
            f"expected {master_seed.SEED_LEN_BYTES}"
        )
    # Decrypt + length-check the bundle BEFORE touching the daemon's
    # state. If decryption fails (wrong seed, tamper) we want the
    # error to surface before we wipe identity.key + DRK.
    header, plaintext = backup_bundle.open_bundle(
        seed=seed, bundle_bytes=bundle_bytes,
    )
    # All-or-nothing: stage extraction to a temp dir, atomically
    # promote. `extract_bundle_to_dir` already does this internally.
    written = backup_bundle.extract_bundle_to_dir(
        plaintext=plaintext,
        target_dir=Path(data_dir),
        overwrite=overwrite,
    )
    # The bundle's MANIFEST always rides as the first entry; users
    # see the real payload list in `written`, so drop the metadata
    # row from the visible list.
    visible = [w for w in written if w != "MANIFEST"]
    if delete_identity_files:
        # Wipe identity.key + DRK so the daemon's next start
        # re-derives both from the restored seed. The bundle
        # already contains master.seed + data-root-key.bin, but
        # identity.key lives in config_dir() and may not be in
        # the bundle on a freshly-recovered install.
        for f in (paths.key_path(), Path(data_dir) / "data-root-key.bin"):
            with contextlib.suppress(OSError):
                Path(f).unlink()
    # Best-effort seed wipe.
    try:
        return {
            "written": visible,
            "file_count": len(visible),
            "bundle_created_ms": int(header.created_ms),
        }
    finally:
        seed = b"\x00" * len(seed)
        del seed


# ── held-share import (guardian-side social recovery) ───────────────


def restore_from_shares(
    *,
    data_dir: Path,
    shares: list[tuple[int, bytes]],
    delete_identity_files: bool,
) -> bytes:
    """Combine K unwrapped Shamir shares into the original master
    seed and persist it. Mirrors restore_seed_from_phrase but takes
    shares instead of a phrase: the recoverer's third path.

    Each share is (share_index, share_bytes) as produced by the
    guardian's unwrap_share call (or the unwrap HTTP endpoint).
    Must supply at least K of N where K is the threshold the
    original split used; the combine step infers K from the
    supplied count.

    Raises ValueError on malformed shares OR on combine failure
    (e.g., shares from different splits, fewer than threshold).
    Returns the 32-byte reconstructed seed (also persisted).
    """
    from one_link import master_seed, social_recovery
    from one_link import paths
    from pathlib import Path as _Path
    if not shares or len(shares) < 2:
        raise ValueError("need at least 2 shares to recover")
    seed = social_recovery.combine_shares(shares)
    if len(seed) != master_seed.SEED_LEN_BYTES:
        raise ValueError(
            f"reconstructed seed has wrong length {len(seed)}; "
            f"expected {master_seed.SEED_LEN_BYTES}"
        )
    try:
        if delete_identity_files:
            for f in (paths.key_path(), _Path(data_dir) / "data-root-key.bin"):
                with contextlib.suppress(OSError):
                    _Path(f).unlink()
        master_seed.store_seed(_Path(data_dir), seed)
        return seed
    finally:
        # Best-effort wipe of our reference; on-disk copy is the
        # canonical source going forward.
        try:
            seed_copy = seed
            seed = b"\x00" * len(seed)
            del seed
            # Wipe the local var too (not perfect; Python bytes are
            # immutable, but this drops our reference).
            del seed_copy
        except Exception:
            pass


def parse_held_share_blob(blob: bytes) -> dict[str, Any]:
    """Parse an incoming .olss wrapped-share file. Returns a dict
    the state.insert_held_share helper can persist directly.

    Validates magic + version + header length. Does NOT verify the
    AEAD tag (that requires the guardian's private key; we defer
    that check until unwrap-time so a guardian can import shares
    on a device that doesn't have their key handy yet)."""
    from one_link import social_recovery
    wrapped = social_recovery.WrappedShare.parse(blob)
    return {
        "share_index": wrapped.share_index,
        "threshold_k": wrapped.threshold,
        "total_n": wrapped.total,
        "setup_ms": wrapped.setup_ms,
        "wrapped_blob": wrapped.encoded,
    }


def reset_all_recovery_state(state) -> None:
    """Wipe the per-track recovery settings. Called from the
    existing `reset` setup_action so the new state vanishes along
    with the rest of the one_setup flags."""
    for key in (
        SETTING_PHRASE_VERIFIED_AT_MS,
        SETTING_BACKUP_LAST_EXPORT_AT_MS,
        SETTING_BACKUP_LAST_EXPORT_SIZE,
        SETTING_SOCIAL_CONFIGURED_AT_MS,
        SETTING_SOCIAL_GUARDIAN_COUNT,
        SETTING_SOCIAL_THRESHOLD_K,
        SETTING_LEGACY_CONFIGURED_AT_MS,
    ):
        with contextlib.suppress(Exception):
            state.delete_setting(key)
