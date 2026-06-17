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

try:
    from blake3 import blake3 as _blake3
except ImportError:  # pragma: no cover - optional dep
    _blake3 = None  # type: ignore[assignment,misc]  # optional dep: rebind imported name to None

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
    # Integrity tag over the canonical JSON of every OTHER field.
    # Lets the loader distinguish "disk corrupted this file" (we'll
    # log + drop, and let the chunk cache + sender retry rebuild the
    # transfer) from "user intentionally deleted it" (which is the
    # same end result but a cleaner mental model in logs).
    #
    # Empty string when written by a pre-Wave-1e daemon — the loader
    # treats absent/empty digest as "legacy sidecar, skip integrity
    # check". New sidecars always carry one.
    digest: str = ""

    def touch(self) -> None:
        self.updated_ms = int(time.time() * 1000)

    def _to_signing_dict(self) -> dict[str, Any]:
        """Dict shape used for the integrity digest: every field
        EXCEPT ``digest`` itself, with a deterministic key ordering
        so the same content always produces the same hash."""
        d = asdict(self)
        d.pop("digest", None)
        return d

    def _compute_digest(self) -> str:
        """BLAKE3 of the canonical signing JSON. Returns empty when
        the blake3 module isn't importable — caller treats that as
        "skip integrity tagging on this install"."""
        if _blake3 is None:
            return ""
        canon = json.dumps(
            self._to_signing_dict(),
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return _blake3(canon).hexdigest()

    def to_json(self) -> str:
        # Recompute the digest at every persist so debounced
        # ``touch()`` rewrites (which bump updated_ms) produce a
        # matching tag. The digest covers updated_ms, so a stale
        # digest from a prior write would fail the load check.
        self.digest = self._compute_digest()
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
        sc = cls(**filtered)
        # Integrity check. A pre-Wave-1e sidecar without a digest
        # field passes through (digest=""); a newer sidecar whose
        # digest doesn't match its content raises ValueError so the
        # caller can log + drop it instead of acting on tampered
        # state.
        if sc.digest:
            expected = sc._compute_digest()
            if expected != sc.digest:
                raise ValueError(
                    f"resume sidecar digest mismatch for blob "
                    f"{sc.blob_hex[:8]}: expected {expected[:16]}, "
                    f"got {sc.digest[:16]}"
                )
        return sc


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


# A sidecar that hasn't been touched in this many days is treated
# as abandoned and pruned at daemon startup. 30 days is enough to
# cover "user laptop sat in a drawer over vacation" without letting
# inboxes accumulate orphan manifests for blobs the sender will
# never come back for.
SIDECAR_TTL_DAYS_DEFAULT = 30


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

    def load_from_inbox(
        self,
        *,
        ttl_days: int = SIDECAR_TTL_DAYS_DEFAULT,
    ) -> int:
        """Scan the inbox + populate the registry. Sidecars whose
        ``updated_ms`` is older than ``ttl_days`` (default 30) are
        pruned along with their partial out_path before the rest are
        registered. Returns the number of entries kept."""
        self._by_key.clear()
        prune_before_ms = int((time.time() - ttl_days * 86400) * 1000)
        pruned = 0
        for sc in scan_inbox(self.inbox_root):
            if sc.updated_ms < prune_before_ms:
                try:
                    Path(sc.out_path).unlink()
                except OSError:
                    pass
                delete_sidecar(self.inbox_root, sc.blob_hex)
                pruned += 1
                continue
            self._by_key[(sc.peer_fp, sc.blob_hex)] = sc
        if self._by_key:
            log.info(
                "resume registry: loaded %d in-progress inbound transfer(s)%s",
                len(self._by_key),
                f" (pruned {pruned} stale)" if pruned else "",
            )
        elif pruned:
            log.info("resume registry: pruned %d stale entry(ies)", pruned)
        return len(self._by_key)

    def snapshot(
        self,
        *,
        cache_check_fn=None,
    ) -> list[dict]:
        """JSON-shaped list of current entries for the status API.

        Each entry is a small dict; the full CDC manifest
        (potentially thousands of entries) is replaced with a count
        so the snapshot stays bounded for the UI / control plane.

        If ``cache_check_fn`` is provided, it's called once per
        entry with the entry's full list of chunk hashes and must
        return the SUBSET that's currently present in the local
        chunk cache. The snapshot enriches each entry with:

          - ``cdc_chunks_cached``: count of chunks already on disk
          - ``cached_bytes``: byte total of those chunks
          - ``progress_ratio``: cached_bytes / size, 0..1, lets the
            UI render "67 % already on disk" before the sender
            even reconnects.
        """
        out: list[dict] = []
        for (peer_fp, blob), sc in sorted(self._by_key.items()):
            entry: dict = {
                "blob": blob,
                "peer_fp": peer_fp,
                "name": sc.name,
                "size": sc.size,
                "out_path": sc.out_path,
                "cdc_chunks_total": len(sc.cdc_chunks),
                "created_ms": sc.created_ms,
                "updated_ms": sc.updated_ms,
            }
            if cache_check_fn is not None and sc.cdc_chunks:
                try:
                    hashes = [str(c["hash"]) for c in sc.cdc_chunks if "hash" in c]
                    present = set(cache_check_fn(hashes))
                    cached_count = 0
                    cached_bytes = 0
                    for c in sc.cdc_chunks:
                        h = str(c.get("hash", ""))
                        if h in present:
                            cached_count += 1
                            try:
                                cached_bytes += int(c.get("size", 0))
                            except (TypeError, ValueError):
                                pass
                    entry["cdc_chunks_cached"] = cached_count
                    entry["cached_bytes"] = cached_bytes
                    entry["progress_ratio"] = (
                        round(cached_bytes / sc.size, 4) if sc.size > 0 else 0.0
                    )
                except Exception as e:
                    # cache_check_fn raised — fall back to no-progress
                    # snapshot. Better to ship a UI without progress
                    # numbers than crash the control endpoint.
                    log.debug("cache_check_fn failed for %s: %s", blob[:8], e)
            out.append(entry)
        return out

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
