"""Receiver-side file transfer resume across disconnects.

Background. The CDC chunk-store protocol is naturally idempotent:
each FILE_OFFER carries a manifest of (index, hash, size) entries,
and the receiver answers with FILE_WANTS containing only the indices
whose hashes aren't already in the local chunk cache. Chunks live in
the global cache keyed by BLAKE3 hash, so the cache survives a
peer disconnect, a daemon restart, and an OS reboot.

What was missing pre-resume:

  1. The receiver's IncomingFile entry (the in-memory state tying
     a blob_hex to an out_path and a CDC manifest) was lost on
     daemon restart. After a restart the next FILE_OFFER landed
     fresh — same chunks would be re-checked against the cache,
     but the new transfer wrote to a different unique out_path,
     leaving the previous partial output orphaned on disk and
     producing a duplicate filename for the user.

  2. Within a single daemon lifetime, a sender's retry FILE_OFFER
     also overwrote the existing IncomingFile (same blob, but new
     `out_path` from `_unique_inbox_path`). The in-flight handle's
     output file became orphaned; chunks already in the
     ``cdc_parts`` dict were thrown away (the cache still had
     them, so reassembly worked, but the bookkeeping was wasteful).

This module fixes both by persisting a small JSON sidecar per
in-progress CDC offer. The sidecar carries everything needed to
restore the IncomingFile state from disk — the original FILE_OFFER
metadata (peer_fp, blob_hex, name, size, cdc_chunks) plus the
chosen out_path. The actual chunk bytes don't need to live in the
sidecar; they're already in the chunk cache.

Lifecycle:

  * On FILE_OFFER arrival (CDC mode), the receiver writes the
    sidecar before opening the output file handle. Subsequent
    chunk-write events bump ``updated_ms`` but don't rewrite
    the immutable manifest.

  * On clean completion (``_finish_cdc_file`` succeeds) the
    sidecar is deleted.

  * On abort (capability revoke mid-stream, chunk integrity
    failure, peer revoke) the sidecar is deleted along with the
    partial out_path.

  * On daemon startup, the inbox is scanned for ``<blob>.resume.json``
    sidecars under ``inbox/.resume/``. Validated entries are
    registered in an in-memory ``ResumeRegistry`` that the
    FILE_OFFER handler consults before creating fresh state.

Security model.

  * Sidecar files live under the daemon-owned ``inbox/.resume/``
    directory. The daemon writes them with the same permissions
    as the inbox itself.

  * The sidecar's authority is bounded: it can resurrect a
    pending offer's *manifest* and *out_path*, but every chunk
    that lands afterward still goes through the normal
    per-chunk hash check (the existing
    ``cdc_chunk_integrity_failure`` rejection). A poisoned
    sidecar can only redirect the output filename, not inject
    bytes — the actual chunk bytes are content-addressed.

  * On load, ``peer_fp`` from the sidecar must match the peer
    who eventually sends the corresponding FILE_OFFER. A sidecar
    for peer A cannot be activated by a FILE_OFFER from peer B,
    even if the blob_hex matches.

  * ``out_path`` is validated to live under the active inbox root
    on load; a sidecar that points outside is dropped.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

log = logging.getLogger(__name__)


# Schema version. Bumped only when the on-disk JSON shape changes
# in a way that's incompatible with the previous loader.
SCHEMA_VERSION = 1

# Sidecars live under <inbox>/.resume/. The dot prefix keeps them
# out of any UI inbox listing that filters dotfiles.
SIDECAR_SUBDIR = ".resume"


@dataclass
class ResumeSidecar:
    """One in-progress CDC inbound transfer's persistent state.

    Fields mirror the FILE_OFFER payload plus the chosen out_path.
    Everything else (which chunks have already landed) is recovered
    on resume by re-checking the global chunk cache — so it stays
    out of the sidecar.
    """

    blob_hex: str
    peer_fp: str
    name: str
    size: int
    out_path: str
    cdc_chunks: list[dict[str, Any]]
    created_ms: int = field(default_factory=lambda: int(time.time() * 1000))
    updated_ms: int = field(default_factory=lambda: int(time.time() * 1000))
    schema_version: int = SCHEMA_VERSION

    def touch(self) -> None:
        self.updated_ms = int(time.time() * 1000)

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"))

    @classmethod
    def from_json(cls, text: str) -> "ResumeSidecar":
        raw = json.loads(text)
        # Drop unknown keys defensively (forward-compat with older
        # schemas that wrote extra fields) rather than failing the
        # whole load. Required keys are enforced below.
        known = {f for f in cls.__dataclass_fields__}
        filtered = {k: v for k, v in raw.items() if k in known}
        if filtered.get("schema_version", SCHEMA_VERSION) != SCHEMA_VERSION:
            raise ValueError(
                f"resume sidecar schema {filtered.get('schema_version')} "
                f"unsupported (this daemon understands {SCHEMA_VERSION})"
            )
        return cls(**filtered)


def sidecar_dir(inbox_root: Path) -> Path:
    return Path(inbox_root) / SIDECAR_SUBDIR


def sidecar_path(inbox_root: Path, blob_hex: str) -> Path:
    return sidecar_dir(inbox_root) / f"{blob_hex}.json"


def persist_sidecar(inbox_root: Path, sidecar: ResumeSidecar) -> None:
    """Atomically write a sidecar to disk.

    The write goes via a temp file in the same directory + os.replace
    so a daemon crash during the write can never leave a torn JSON
    blob that the next startup scan would choke on.
    """
    target = sidecar_path(inbox_root, sidecar.blob_hex)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.parent / f".{os.getpid()}_{secrets.token_hex(8)}.tmp"
    payload = sidecar.to_json()
    tmp.write_text(payload, encoding="utf-8")
    os.replace(tmp, target)


def delete_sidecar(inbox_root: Path, blob_hex: str) -> None:
    """Remove the sidecar for ``blob_hex``. Idempotent; missing
    files are silently ignored so the abort + finish paths can call
    this without checking."""
    try:
        sidecar_path(inbox_root, blob_hex).unlink()
    except FileNotFoundError:
        pass
    except OSError as e:
        log.warning("could not delete resume sidecar for %s: %s", blob_hex[:8], e)


def load_sidecar(
    inbox_root: Path, blob_hex: str
) -> ResumeSidecar | None:
    """Read a single sidecar. Returns None on absent / unreadable /
    malformed. Never raises — a corrupted sidecar must not crash the
    daemon."""
    p = sidecar_path(inbox_root, blob_hex)
    try:
        text = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    try:
        return ResumeSidecar.from_json(text)
    except (ValueError, json.JSONDecodeError, TypeError) as e:
        log.warning("malformed resume sidecar at %s: %s", p, e)
        return None


def scan_inbox(inbox_root: Path) -> list[ResumeSidecar]:
    """Walk the sidecar directory and return every loadable entry.

    Sidecars whose ``out_path`` no longer exists (the user cleaned
    their inbox manually, or the partial was unlinked but the
    sidecar wasn't) are dropped on the floor — there's no partial
    to resume into. The orphaned sidecar is also deleted so a fresh
    transfer for the same blob can land cleanly.
    """
    out: list[ResumeSidecar] = []
    d = sidecar_dir(inbox_root)
    if not d.is_dir():
        return out
    try:
        names = list(d.iterdir())
    except OSError as e:
        log.warning("could not scan resume sidecars in %s: %s", d, e)
        return out
    inbox_resolved = Path(inbox_root).resolve()
    for entry in names:
        if not entry.is_file() or entry.suffix != ".json":
            continue
        try:
            sc = ResumeSidecar.from_json(entry.read_text(encoding="utf-8"))
        except (ValueError, json.JSONDecodeError, TypeError, OSError) as e:
            log.warning("dropping malformed sidecar %s: %s", entry, e)
            with _suppress_oserror():
                entry.unlink()
            continue
        # Path-traversal guard: a sidecar that points outside the
        # inbox is hostile or corrupted. Resolve both sides + check
        # the partial sits under the resolved inbox root.
        try:
            op = Path(sc.out_path).resolve()
        except (OSError, RuntimeError):
            log.warning("dropping sidecar with unresolvable out_path: %s", entry)
            with _suppress_oserror():
                entry.unlink()
            continue
        try:
            op.relative_to(inbox_resolved)
        except ValueError:
            log.warning(
                "dropping sidecar pointing outside inbox: %s -> %s",
                entry, op,
            )
            with _suppress_oserror():
                entry.unlink()
            continue
        if not op.is_file():
            log.info(
                "resume sidecar %s has no partial at %s; cleaning up",
                sc.blob_hex[:8], op,
            )
            with _suppress_oserror():
                entry.unlink()
            continue
        out.append(sc)
    return out


class ResumeRegistry:
    """In-memory index of resumable inbound transfers, keyed by
    ``(peer_fp, blob_hex)``.

    The daemon populates this once at startup via :meth:`load_from_inbox`,
    then consults :meth:`pop_match` in the FILE_OFFER handler before
    creating a fresh IncomingFile. A matched entry returns the
    original out_path + manifest so the resumed transfer reuses the
    same disk location.
    """

    def __init__(self, inbox_root: Path) -> None:
        self.inbox_root = Path(inbox_root)
        self._by_key: dict[tuple[str, str], ResumeSidecar] = {}

    def load_from_inbox(self) -> int:
        """Scan the inbox + populate the registry. Returns the
        number of resumable entries loaded."""
        self._by_key.clear()
        for sc in scan_inbox(self.inbox_root):
            self._by_key[(sc.peer_fp, sc.blob_hex)] = sc
        if self._by_key:
            log.info(
                "resume registry: loaded %d in-progress inbound transfer(s)",
                len(self._by_key),
            )
        return len(self._by_key)

    def pop_match(self, peer_fp: str, blob_hex: str) -> ResumeSidecar | None:
        """Return + remove a matching entry. The receiver hands
        ownership of the partial back to the freshly-created
        IncomingFile, so the registry shouldn't hold onto it."""
        return self._by_key.pop((peer_fp, blob_hex), None)

    def register(self, sidecar: ResumeSidecar) -> None:
        """Add (or replace) an entry. Called by the FILE_OFFER
        handler when a brand-new transfer starts, so a later crash
        + restart can pick it back up."""
        self._by_key[(sidecar.peer_fp, sidecar.blob_hex)] = sidecar

    def keys(self) -> Iterable[tuple[str, str]]:
        return self._by_key.keys()

    def __len__(self) -> int:
        return len(self._by_key)


class _suppress_oserror:
    """Context manager twin for ``contextlib.suppress(OSError)`` —
    inlined to avoid pulling contextlib into this module's import
    surface for a single use."""

    def __enter__(self) -> "_suppress_oserror":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return exc_type is not None and issubclass(exc_type, OSError)
