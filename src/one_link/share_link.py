"""One-time share-link tokens for sending files to non-paired peers.

Wave 2g — production-grade primitive for the "send a 2 GB file to
someone not yet on my paired-peer list" flow that magic-wormhole
owns today.

A share-link is a self-signed, single-use, time-bounded
capability:

  * Sender mints it for a specific blob (already on disk).
  * Sender shares the 6-word SAS phrase + a connection URL out
    of band (SMS, chat, email).
  * Recipient enters the words in their daemon UI; the daemon
    posts the resolved token to the sender's listen-URL.
  * Sender validates the token, marks it consumed, accepts the
    inbound transfer via the same FILE_OFFER pipeline used for
    paired-peer transfers.

Security model:

  - **Bearer token**. 32 random bytes of entropy from
    ``secrets.token_bytes``. Anyone who has them can claim the
    share. The SAS phrase is a human-readable encoding of a
    BLAKE3 derivative of the token (8 words × 8 bits = 64 bits
    of identifier; full lookup keys the 32-byte token).
  - **Single use**. The registry marks the entry CONSUMED on
    successful redeem; subsequent redeems with the same token
    return ``"already_redeemed"``.
  - **TTL bounded**. Default 24 hours. Expired entries are
    rejected on redeem AND swept on the next ``prune_expired``.
  - **Sealed to blob**. Each share-link names exactly one
    blob_hex; the sender's redeem path serves that blob and
    nothing else. A token doesn't grant arbitrary capability
    to the sender's filesystem.

Persistence: tokens live under ``data/share_links/`` as JSON
sidecars (one per blob_hex). Survives daemon restart so
recipients can redeem hours later. Mirrored to the in-memory
registry on startup; written atomically via os.replace to
survive a crash mid-mint.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from one_link.identity_sas import SAS_VOCAB

log = logging.getLogger(__name__)


# 8 words × 8 bits = 64 bits of human-readable identifier.
# Plenty for a single-use short-lived token; the FULL token
# remains the 32-byte random secret.
SAS_PHRASE_WORDS = 8

# Bytes of true entropy per share-link token.
TOKEN_LEN = 32

# Default TTL — 24 hours. Operators can override per-mint.
DEFAULT_TTL_SECONDS = 86400

# Sidecar directory under data/.
SIDECAR_SUBDIR = "share_links"

# Schema version.
SCHEMA_VERSION = 1


@dataclass
class ShareLink:
    """One mint. Persisted as JSON; mirrored in
    :class:`ShareLinkRegistry`."""

    blob_hex: str
    name: str
    size: int
    source_path: str
    token_hex: str          # 64 hex chars = 32 bytes
    sas_phrase: str         # 8 words joined by single space
    created_ms: int = field(default_factory=lambda: int(time.time() * 1000))
    expires_at_ms: int = 0
    redeemed_at_ms: Optional[int] = None
    redeemed_by_hint: Optional[str] = None  # peer fingerprint hex when known
    schema_version: int = SCHEMA_VERSION

    def is_consumed(self) -> bool:
        return self.redeemed_at_ms is not None

    def is_expired(self, now_ms: Optional[int] = None) -> bool:
        if now_ms is None:
            now_ms = int(time.time() * 1000)
        return self.expires_at_ms > 0 and now_ms >= self.expires_at_ms

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"))

    @classmethod
    def from_json(cls, text: str) -> "ShareLink":
        raw = json.loads(text)
        known = {f for f in cls.__dataclass_fields__}
        filtered = {k: v for k, v in raw.items() if k in known}
        if filtered.get("schema_version", SCHEMA_VERSION) != SCHEMA_VERSION:
            raise ValueError(
                f"share-link schema {filtered.get('schema_version')} "
                f"unsupported (this daemon understands {SCHEMA_VERSION})"
            )
        return cls(**filtered)


def derive_sas_phrase(token: bytes, *, words: int = SAS_PHRASE_WORDS) -> str:
    """Map a token to ``words`` space-separated SAS_VOCAB words.

    Uses BLAKE3 (via stdlib's ``hashlib`` fallback to BLAKE2b
    when blake3 isn't importable) to derive a stable byte stream
    from the token; ``words`` × 8 bits are taken from the front.
    Symmetric on both ends — sender and recipient compute the
    same words from the same token.
    """
    try:
        import blake3 as _b3
        digest = _b3.blake3(b"ol-share-link-sas\x00" + token).digest(length=words)
    except ImportError:
        digest = hashlib.blake2b(
            b"ol-share-link-sas\x00" + token, digest_size=words,
        ).digest()
    selected = [SAS_VOCAB[b] for b in digest[:words]]
    return " ".join(selected)


def mint_token() -> bytes:
    """Cryptographically-random 32-byte token. ``secrets`` is
    the right source — never ``random``."""
    return secrets.token_bytes(TOKEN_LEN)


# ────────────────────────────────────────────────────────────────────
# On-disk persistence
# ────────────────────────────────────────────────────────────────────

def sidecar_dir(data_root: Path) -> Path:
    return Path(data_root) / SIDECAR_SUBDIR


def sidecar_path(data_root: Path, blob_hex: str) -> Path:
    return sidecar_dir(data_root) / f"{blob_hex}.json"


def persist(data_root: Path, link: ShareLink) -> None:
    """Atomic-write a share-link sidecar. Same pattern as the
    resume sidecar: write tmp, os.replace, no torn files on
    crash."""
    target = sidecar_path(data_root, link.blob_hex)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.parent / f".{os.getpid()}_{secrets.token_hex(8)}.tmp"
    tmp.write_text(link.to_json(), encoding="utf-8")
    os.replace(tmp, target)


def delete(data_root: Path, blob_hex: str) -> None:
    try:
        sidecar_path(data_root, blob_hex).unlink()
    except FileNotFoundError:
        pass
    except OSError as e:
        log.warning("could not delete share-link sidecar for %s: %s",
                    blob_hex[:8], e)


def load(data_root: Path, blob_hex: str) -> ShareLink | None:
    try:
        text = sidecar_path(data_root, blob_hex).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    try:
        return ShareLink.from_json(text)
    except (ValueError, json.JSONDecodeError, TypeError) as e:
        log.warning("malformed share-link sidecar for %s: %s", blob_hex[:8], e)
        return None


def scan(data_root: Path) -> list[ShareLink]:
    """Walk the sidecar directory + return every valid entry.
    Garbage / corrupted files are silently dropped + unlinked
    so the next startup doesn't keep choking on them."""
    out: list[ShareLink] = []
    d = sidecar_dir(data_root)
    if not d.is_dir():
        return out
    try:
        entries = list(d.iterdir())
    except OSError as e:
        log.warning("could not scan share-links in %s: %s", d, e)
        return out
    for entry in entries:
        if not entry.is_file() or entry.suffix != ".json":
            continue
        try:
            text = entry.read_text(encoding="utf-8")
            out.append(ShareLink.from_json(text))
        except (OSError, ValueError, json.JSONDecodeError, TypeError):
            with _suppress_oserror():
                entry.unlink()
    return out


# ────────────────────────────────────────────────────────────────────
# Registry
# ────────────────────────────────────────────────────────────────────

class ShareLinkRegistry:
    """In-memory index of active share-links. Persisted via the
    sidecars above; the registry is reconstructed at daemon start
    via :meth:`load_from_disk`.

    Lookup keys:
      - token_hex (full 64-char) → ShareLink
      - blob_hex → ShareLink (sender side: "I have a link for
        this blob already?")
    """

    def __init__(self, data_root: Path) -> None:
        self.data_root = Path(data_root)
        self._by_token: dict[str, ShareLink] = {}
        self._by_blob: dict[str, ShareLink] = {}

    def load_from_disk(self) -> int:
        """Read every sidecar + populate the in-memory maps.
        Prunes expired entries while scanning. Returns the
        number kept."""
        self._by_token.clear()
        self._by_blob.clear()
        now_ms = int(time.time() * 1000)
        pruned = 0
        for link in scan(self.data_root):
            if link.is_expired(now_ms):
                delete(self.data_root, link.blob_hex)
                pruned += 1
                continue
            self._by_token[link.token_hex] = link
            # Newest entry per blob wins (a re-mint shouldn't
            # leave stale state around).
            if (
                link.blob_hex not in self._by_blob
                or link.created_ms > self._by_blob[link.blob_hex].created_ms
            ):
                self._by_blob[link.blob_hex] = link
        if self._by_token:
            log.info(
                "share-link registry: loaded %d active link(s)%s",
                len(self._by_token),
                f" (pruned {pruned} expired)" if pruned else "",
            )
        elif pruned:
            log.info("share-link registry: pruned %d expired", pruned)
        return len(self._by_token)

    def mint(
        self,
        *,
        blob_hex: str,
        name: str,
        size: int,
        source_path: str,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> ShareLink:
        """Create + persist a new share-link for ``blob_hex``.

        Replaces any prior link for the same blob — re-minting
        invalidates the old token. Returns the new ShareLink.
        """
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        token = mint_token()
        token_hex = token.hex()
        sas_phrase = derive_sas_phrase(token)
        now_ms = int(time.time() * 1000)
        link = ShareLink(
            blob_hex=blob_hex,
            name=name,
            size=int(size),
            source_path=str(source_path),
            token_hex=token_hex,
            sas_phrase=sas_phrase,
            created_ms=now_ms,
            expires_at_ms=now_ms + ttl_seconds * 1000,
        )
        # Replace prior entry for this blob.
        prior = self._by_blob.get(blob_hex)
        if prior is not None:
            self._by_token.pop(prior.token_hex, None)
            delete(self.data_root, prior.blob_hex)
        self._by_token[token_hex] = link
        self._by_blob[blob_hex] = link
        persist(self.data_root, link)
        return link

    def lookup_by_token(self, token_hex: str) -> ShareLink | None:
        return self._by_token.get(str(token_hex).lower())

    def lookup_by_blob(self, blob_hex: str) -> ShareLink | None:
        return self._by_blob.get(str(blob_hex).lower())

    def redeem(
        self,
        token_hex: str,
        *,
        by_peer_fp: Optional[str] = None,
    ) -> tuple[ShareLink | None, str]:
        """Atomically attempt to consume the token. Returns
        ``(link, reason)``:

          link is None, reason="not_found"       — unknown token
          link is None, reason="expired"         — TTL elapsed
          link is None, reason="already_redeemed"— prior single-use consumed
          link != None, reason="ok"              — caller may serve the blob

        On success the link is marked consumed and the sidecar
        rewritten so a crash + restart doesn't allow a second
        redeem.
        """
        link = self.lookup_by_token(str(token_hex).lower())
        if link is None:
            return (None, "not_found")
        if link.is_consumed():
            return (None, "already_redeemed")
        if link.is_expired():
            # Sweep the expired entry now that we hit it.
            self._by_token.pop(link.token_hex, None)
            self._by_blob.pop(link.blob_hex, None)
            delete(self.data_root, link.blob_hex)
            return (None, "expired")
        # Consume.
        link.redeemed_at_ms = int(time.time() * 1000)
        link.redeemed_by_hint = by_peer_fp
        persist(self.data_root, link)
        return (link, "ok")

    def revoke(self, blob_hex: str) -> bool:
        """Forget any link for ``blob_hex``. Idempotent. Returns
        True if a link was actually removed."""
        link = self._by_blob.pop(blob_hex, None)
        if link is None:
            return False
        self._by_token.pop(link.token_hex, None)
        delete(self.data_root, link.blob_hex)
        return True

    def prune_expired(self) -> int:
        """Walk active entries, drop any whose TTL elapsed.
        Caller invokes this on a timer (daemon's existing prune
        loop is the natural place). Returns count removed."""
        now_ms = int(time.time() * 1000)
        expired = [
            link.blob_hex for link in self._by_blob.values()
            if link.is_expired(now_ms)
        ]
        for blob in expired:
            self.revoke(blob)
        if expired:
            log.info("share-link registry: pruned %d expired link(s)",
                     len(expired))
        return len(expired)

    def snapshot(self) -> list[dict]:
        """JSON-shaped list for the control API. Excludes the
        raw token_hex (sensitive) — only the SAS phrase + meta."""
        out: list[dict] = []
        for link in sorted(
            self._by_blob.values(), key=lambda x: -x.created_ms,
        ):
            out.append({
                "blob": link.blob_hex,
                "name": link.name,
                "size": link.size,
                "sas_phrase": link.sas_phrase,
                "created_ms": link.created_ms,
                "expires_at_ms": link.expires_at_ms,
                "consumed": link.is_consumed(),
                "expired": link.is_expired(),
            })
        return out

    def __len__(self) -> int:
        return len(self._by_token)


class _suppress_oserror:
    def __enter__(self) -> "_suppress_oserror":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return exc_type is not None and issubclass(exc_type, OSError)
