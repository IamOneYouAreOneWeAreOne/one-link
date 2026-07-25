"""Folder sync engine.

For each configured folder:
  - Watch the local directory for changes (watchdog).
  - Hash file contents into the blob store.
  - Maintain a CRDT manifest in sqlite (vector-clock per peer).
  - Exchange manifests with peers on connect; request missing blobs.

Wire messages added to the peer protocol (handled in daemon.py):
  FOLDER_MANIFEST  full manifest for a folder
  FOLDER_DELTA     single manifest entry update (for live propagation)
  BLOB_GET         peer requests we send a specific blob
  BLOB_OFFER       we acknowledge BLOB_GET, declare size
  BLOB_CHUNK       streaming chunk of a blob (same pattern as FILE_CHUNK)

The engine is intentionally split from `daemon.py` so the protocol logic
sits in daemon and the file/blob/manifest mechanics sit here.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import secrets
import sqlite3
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Optional

import blake3

from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from one_link.blobstore import BlobStore
from one_link.crdt import ManifestEntry, VectorClock, merge_manifest_entries
from one_link.namespace_durability import publish_file_noreplace, replace_path

# Phase C-3 daemon migration (ADR-0022): the FolderEngine shadow-mirrors
# every add/remove into a native ol_crdt.Folder so the lattice-correct
# merge path is exercised in production before the legacy merge code
# is removed. The mirror is a pure observer — divergence between the
# legacy + native states is logged, never acted on. Activate by
# importing folder_native; if the native module isn't available, the
# mirror becomes a no-op.
try:
    from one_link import folder_native as _folder_native

    _MIRROR_AVAILABLE = _folder_native is not None
except ImportError:  # pragma: no cover
    _folder_native = None  # type: ignore[assignment]
    _MIRROR_AVAILABLE = False
from one_link.merkle import build_tree, manifest_leaf_hashes
from one_link.state import State

log = logging.getLogger("one_link.foldersync")

DEBOUNCE_MS = 250
SCAN_INTERVAL_S = 60.0  # safety net if a watchdog event is dropped


def _is_internal_relpath(rel_path: str) -> bool:
    """Return whether a path is a transient materialization artifact."""

    return any(
        part.startswith(".one-link-") and part.endswith(".tmp")
        for part in str(rel_path).replace("\\", "/").split("/")
    )


def _safe_relpath(folder_root: Path, p: Path) -> Optional[str]:
    """Returns the file's path relative to folder_root using forward slashes,
    or None if p is not inside folder_root."""
    try:
        rel = Path(p).resolve().relative_to(folder_root.resolve())
    except (OSError, RuntimeError, ValueError):
        return None
    return rel.as_posix()


def manifest_root_for_entries(entries: Iterable[dict[str, Any]]) -> str:
    """Return the canonical content Merkle root for manifest wire rows.

    The helper is deliberately shared by the sender, receiver, and the local
    state view.  A receipt must never attest a peer-supplied root without
    independently deriving that root from the exact entries it processed.
    Callers validate the richer row schema before invoking this function.
    """

    rows = [
        (
            str(entry["file_path"]),
            str(entry.get("blob_hash") or ""),
            int(entry.get("size") or 0),
        )
        for entry in entries
    ]
    return build_tree(manifest_leaf_hashes(rows)).root


def _safe_child(root: Path, rel_path: str) -> Optional[Path]:
    """Join a canonical remote path lexically below a resolved root.

    The returned identity intentionally preserves every path component.
    Resolving the candidate would erase an in-root symlink alias before the
    no-follow chain checker has a chance to reject it.
    """
    rel = Path(str(rel_path).replace("\\", "/"))
    if rel.is_absolute() or any(part in ("", ".", "..") for part in rel.parts):
        return None
    try:
        root_resolved = root.resolve()
        candidate = root_resolved.joinpath(*rel.parts)
        candidate.absolute().relative_to(root_resolved)
    except (OSError, RuntimeError, ValueError):
        return None
    return candidate


def _has_symlink_in_chain(path: Path, root: Path) -> bool:
    """v0.20.7 (security audit M22): walk every path component from
    ``path`` back up to (but not including) ``root`` and return True if
    any component is a symlink as visible by lstat NOW. ``_safe_child``
    runs ``resolve`` once which follows symlinks; an attacker who
    swaps a directory component to a symlink between ``_safe_child``
    and the eventual ``open(dst, "wb")`` can redirect a write to
    /etc/passwd or similar.

    This helper closes the TOCTOU window by re-checking immediately
    before write. Not a full TOCTOU fix (the symlink could still race
    in between this check and the open), but it raises the attack
    bar from "swap any time after manifest arrives" to "swap during
    a single ms-scale window between check and write" — much harder
    in practice, and we additionally prefer atomic temp-rename writes
    where the rename target's parent is the resolved root."""
    cur = path.parent
    try:
        root_resolved = root.resolve()
    except (OSError, RuntimeError):
        return True
    # Bound the walk to a sensible depth so a symlinked-loop can't
    # cause us to spin forever.
    for _ in range(64):
        try:
            if cur.is_symlink():
                return True
        except OSError:
            return True  # conservative: refuse if we can't check
        if cur == cur.parent:
            return False
        try:
            if cur.resolve() == root_resolved:
                return False
        except (OSError, RuntimeError):
            return True
        cur = cur.parent
    return True


class _Handler(FileSystemEventHandler):
    """Pushes events into a thread-safe dirty set + a wakeup function."""

    def __init__(self, mark_dirty):
        self.mark_dirty = mark_dirty

    def on_created(self, event):
        if isinstance(event, FileCreatedEvent):
            self.mark_dirty(event.src_path, "modified")

    def on_modified(self, event):
        if isinstance(event, FileModifiedEvent):
            self.mark_dirty(event.src_path, "modified")

    def on_deleted(self, event):
        if isinstance(event, FileDeletedEvent):
            self.mark_dirty(event.src_path, "deleted")

    def on_moved(self, event):
        if isinstance(event, FileMovedEvent):
            self.mark_dirty(event.src_path, "deleted")
            self.mark_dirty(event.dest_path, "modified")


@dataclass
class FolderState:
    name: str
    root: Path
    # ``watchdog.observers.Observer`` is a platform-specific factory
    # (InotifyObserver / FSEventsObserver / WindowsApiObserver) — at
    # runtime it always exposes ``.stop()`` and ``.join()``. mypy
    # can't statically resolve the dispatch, so we type-erase to
    # ``Any`` and rely on the runtime contract.
    observer: Any  # noqa: ANN401 - see comment above
    handler: _Handler


@dataclass(frozen=True)
class _MaterializedProof:
    """Content proof cached only while exact directory-entry evidence holds."""

    blob_hash: str
    evidence: tuple[int, int, int, int, int]


@dataclass(frozen=True)
class _PendingApplyGuard:
    """Stable local generation that a remote publish is allowed to replace."""

    target_blob_hash: str | None
    baseline_blob_hash: str | None
    baseline_evidence: tuple[int, int, int, int, int] | None
    apply_id: str | None = None


class FolderEngine:
    """Per-daemon folder sync controller.

    Construct in the asyncio event loop. The engine owns the blob store,
    state cursor, observer threads, and emits async tasks to push events
    to peers via callbacks.
    """

    def __init__(
        self,
        *,
        state: State,
        blob_store: BlobStore,
        my_fingerprint: str,
        loop: asyncio.AbstractEventLoop,
        on_local_change=None,   # async fn(folder_name, ManifestEntry)
    ):
        self.state = state
        self.blobs = blob_store
        self.me_fp = my_fingerprint
        self.loop = loop
        self.on_local_change = on_local_change

        self._folders: dict[str, FolderState] = {}
        self._dirty_lock = threading.Lock()
        self._dirty: dict[str, dict[str, str]] = {}  # folder_name → path → action
        # Folder scans, remote merges, and blob arrivals can run on different
        # worker/event-loop threads.  A fixed stripe set serializes each path
        # without an attacker growing a lock-per-name map indefinitely.
        self._path_locks = tuple(threading.RLock() for _ in range(256))
        self._manifest_lock = threading.RLock()
        self._proof_lock = threading.RLock()
        self._materialized_proofs: dict[
            tuple[str, str], _MaterializedProof
        ] = {}
        self._pending_apply_guards: dict[
            tuple[str, str], _PendingApplyGuard
        ] = {}
        self._wake: asyncio.Event = asyncio.Event()
        self._stop = asyncio.Event()
        self._task: Optional[asyncio.Task] = None
        self._scan_task: Optional[asyncio.Task] = None
        # Phase C-3: per-folder native ol_crdt.Folder shadow-mirror. Each
        # mirror observes the legacy manifest's lifecycle so the native
        # lattice merge is exercised in production without changing
        # behavior. Divergence between legacy/native paths is logged.
        self._native_mirrors: dict[str, "_folder_native.NativeManifestMirror"] = {}
        self._native_mirror_divergence: int = 0  # surfaced via debug snapshot
        # v0.8.9: divergent-edit conflict hook. Daemon sets this
        # post-init so the UI can render a live banner the moment a
        # conflict row lands. None until daemon.start() wires it.
        self._on_conflict_recorded: Optional[
            Callable[[str, int], None]
        ] = None
        # v0.21.x: file-overwrite collision hook for folder receive.
        # Fires when materialize is about to overwrite a dst that
        # exists with a different size than the incoming entry.
        # Callback signature: (folder_name, file_path, existing_size,
        # incoming_size, incoming_blob_hash) -> None.
        self._on_collision_detected: Optional[
            Callable[[str, str, int, int, str], None]
        ] = None
        # Phase D #3 (ADR-0022): active reconciliation counters. Every
        # ``receive_remote_manifest`` call increments ``_checks`` and,
        # when the native OR-set disagrees with the legacy merge winner,
        # ``_disagreements``. Zero disagreement over a production
        # window is the precondition for flipping the authoritative
        # bit from legacy to native.
        self._native_reconcile_checks: int = 0
        self._native_reconcile_disagreements: int = 0
        # D16 — Authoritative-CRDT swap. When ONE_LINK_FOLDER_CRDT_NATIVE=1
        # is set, ``apply_remote_manifest`` resolves each (local, remote)
        # pair through the native ``ol_crdt.Folder`` lattice rather than
        # the legacy ``merge_manifest_entries``. The cross-check is still
        # run so disagreements are surfaced in operator telemetry — but
        # the native lattice's answer is the winner persisted to sqlite.
        self._crdt_native_authoritative: bool = (
            os.environ.get("ONE_LINK_FOLDER_CRDT_NATIVE", "0") == "1"
            and _MIRROR_AVAILABLE
        )
        # D16 — counts of authoritative-native merges performed and times
        # the native lattice's answer differed from the legacy merger.
        # Disagreements are still applied (native is authoritative when
        # the gate is on); the counter is for visibility.
        self._crdt_native_authoritative_merges: int = 0
        self._crdt_native_authoritative_overrides: int = 0

    @staticmethod
    def _disk_evidence(st: os.stat_result) -> tuple[int, int, int, int, int]:
        ctime_ns = 0 if os.name == "nt" else int(st.st_ctime_ns)
        return (
            int(st.st_dev),
            int(getattr(st, "st_ino", 0)),
            int(st.st_size),
            int(st.st_mtime_ns),
            ctime_ns,
        )

    def _path_lock_index(self, folder_name: str, rel_path: str) -> int:
        digest = blake3.blake3(
            f"{folder_name}\0{rel_path}".encode("utf-8"),
        ).digest(length=2)
        return int.from_bytes(digest, "big") % len(self._path_locks)

    def _path_lock(self, folder_name: str, rel_path: str) -> threading.RLock:
        return self._path_locks[self._path_lock_index(folder_name, rel_path)]

    @contextlib.contextmanager
    def _locked_paths(
        self,
        folder_name: str,
        rel_paths: Iterable[str],
    ) -> Iterator[None]:
        indexes = sorted({
            self._path_lock_index(folder_name, rel_path)
            for rel_path in rel_paths
        })
        locks = [self._path_locks[index] for index in indexes]
        for lock in locks:
            lock.acquire()
        try:
            yield
        finally:
            for lock in reversed(locks):
                lock.release()

    @contextlib.contextmanager
    def _locked_all_paths(self) -> Iterator[None]:
        for lock in self._path_locks:
            lock.acquire()
        try:
            yield
        finally:
            for lock in reversed(self._path_locks):
                lock.release()

    def _invalidate_materialized_proof(
        self,
        folder_name: str,
        rel_path: str,
    ) -> None:
        with self._proof_lock:
            self._materialized_proofs.pop((folder_name, rel_path), None)

    def _record_materialized_proof(
        self,
        folder_name: str,
        rel_path: str,
        blob_hash: str,
        path: Path,
        *,
        expected_evidence: tuple[int, int, int, int, int] | None = None,
    ) -> tuple[int, int, int, int, int] | None:
        try:
            st = path.lstat()
        except OSError:
            self._invalidate_materialized_proof(folder_name, rel_path)
            return None
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            self._invalidate_materialized_proof(folder_name, rel_path)
            return None
        evidence = self._disk_evidence(st)
        if expected_evidence is not None and evidence != expected_evidence:
            self._invalidate_materialized_proof(folder_name, rel_path)
            return None
        with self._proof_lock:
            self._materialized_proofs[(folder_name, rel_path)] = (
                _MaterializedProof(blob_hash=blob_hash, evidence=evidence)
            )
        return evidence

    def _materialized_proof_matches(
        self,
        folder_name: str,
        rel_path: str,
        blob_hash: str,
        path: Path,
    ) -> tuple[int, int, int, int, int] | None:
        with self._proof_lock:
            proof = self._materialized_proofs.get((folder_name, rel_path))
        if proof is None or proof.blob_hash != blob_hash:
            return None
        try:
            st = path.lstat()
        except OSError:
            self._invalidate_materialized_proof(folder_name, rel_path)
            return None
        evidence = self._disk_evidence(st)
        if (
            stat.S_ISLNK(st.st_mode)
            or not stat.S_ISREG(st.st_mode)
            or evidence != proof.evidence
        ):
            self._invalidate_materialized_proof(folder_name, rel_path)
            return None
        return evidence

    # ─── lifecycle ────────────────────────────────────────────────────
    async def start(self) -> None:
        # Bring up watchers for any folders already configured in state
        for f in self.state.list_folders():
            # Recover rename/publish/delete windows before a normal scan can
            # misclassify an interrupted pre-image as a fresh local edit.
            await asyncio.to_thread(
                self.recover_pending_applies,
                folder_name=f["name"],
            )
            try:
                self._start_watch(f["name"], Path(f["local_path"]))
            except (OSError, RuntimeError) as exc:
                # Watchdog can be unavailable because of an OS watch limit or
                # a transient backend failure.  Previously this skipped the
                # initial scan *and* left the folder out of periodic scans,
                # making a configured folder silently inert until restart.
                log.warning(
                    "watch unavailable for folder %s; using periodic scans: %s",
                    f["name"],
                    exc,
                )
                self.register_for_one_shot_no_watcher(
                    f["name"], Path(f["local_path"]),
                )
            try:
                # Initial scan to build manifest from existing files.
                await asyncio.to_thread(
                    self._scan_full,
                    f["name"],
                    Path(f["local_path"]),
                )
            except (OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
                # The folder remains registered, so the periodic scan retries
                # instead of permanently dropping this work item.
                log.warning("initial scan failed for folder %s: %s", f["name"], exc)
        self._task = asyncio.create_task(self._dirty_pump())
        self._scan_task = asyncio.create_task(self._periodic_scan())

    def _stop_observer(
        self,
        folder_name: str,
        fs: FolderState,
        *,
        strict: bool = False,
    ) -> bool:
        """Stop one watchdog observer with visible failure semantics.

        Shutdown/removal are best-effort and log known OS/thread teardown
        failures. Relocation uses ``strict=True`` because changing the state
        row while the old watcher is still live can apply stale events to the
        new root.
        """
        try:
            fs.observer.stop()
            fs.observer.join(timeout=2.0)
            is_alive = getattr(fs.observer, "is_alive", None)
            if callable(is_alive) and is_alive() is True:
                raise TimeoutError("observer did not stop within 2 seconds")
            return True
        except (OSError, RuntimeError) as exc:
            log.warning(
                "could not stop folder observer %s: %s",
                folder_name,
                exc,
                exc_info=True,
            )
            if strict:
                raise
            return False

    async def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        for folder_name, fs in list(self._folders.items()):
            self._stop_observer(folder_name, fs)
        self._folders.clear()
        for t in (self._task, self._scan_task):
            if t is not None and not t.done():
                t.cancel()
                try:
                    await t
                except asyncio.CancelledError:
                    pass
                except (OSError, RuntimeError) as exc:
                    log.warning("folder background task stopped with error: %s", exc)

    # ─── Phase C-3 native mirror (ADR-0022) ──────────────────────────
    def _mirror_for(self, folder_name: str):
        """Lazily build/return the native shadow-mirror for ``folder_name``.

        Returns ``None`` if the native CRDT module isn't available
        (e.g. ``one_link_native`` not built yet). Callers should
        no-op on ``None``."""
        if not _MIRROR_AVAILABLE:
            return None
        existing = self._native_mirrors.get(folder_name)
        if existing is not None:
            return existing
        try:
            replica = self.me_fp.encode("utf-8") if isinstance(self.me_fp, str) else self.me_fp
            mirror = _folder_native.NativeManifestMirror(replica_id=replica)
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("native folder mirror unavailable: %s", exc, exc_info=True)
            return None
        self._native_mirrors[folder_name] = mirror
        return mirror

    def _mirror_observe(self, folder_name: str, entry: ManifestEntry) -> None:
        """Reflect a merge winner into the native shadow-mirror. Pure
        observer — failures are swallowed and counted.

        Phase C-3 (ADR-0027): also ACTIVELY VALIDATES that the native
        folder's view of the entry's presence matches what the legacy
        merge decision produced. Specifically: after a winner is
        observed, the native folder should agree on whether the file
        is present (live) or absent (tombstoned). Divergence is
        logged + counted so operators can confirm zero-disagreement
        over a production window before the full authoritative
        cutover lands."""
        mirror = self._mirror_for(folder_name)
        if mirror is None:
            return
        try:
            if entry.blob_hash is None:
                mirror.remove_entry(entry.file_path)
            else:
                mirror.add_entry(entry)
        except Exception as exc:
            self._native_mirror_divergence += 1
            log.warning(
                "native folder mirror update failed (%s): %s",
                folder_name,
                exc,
                exc_info=True,
            )
            return
        # Active cross-check: the legacy merge decided this entry is
        # the winner. If it's live (blob_hash != None), the native
        # folder should report contains(file_id) == True. If it's a
        # tombstone, native should report False.
        try:
            present_in_native = mirror.contains_path(entry.file_path)
            expected_present = entry.blob_hash is not None
            if present_in_native != expected_present:
                self._native_mirror_divergence += 1
                log.warning(
                    "native folder cross-check divergence for %s/%s: "
                    "native_present=%s legacy_winner=%s",
                    folder_name,
                    entry.file_path,
                    present_in_native,
                    expected_present,
                )
        except Exception as exc:  # pragma: no cover - defensive
            self._native_mirror_divergence += 1
            log.warning(
                "native folder cross-check failed (%s): %s",
                folder_name,
                exc,
                exc_info=True,
            )

    def native_folder_snapshot(self, folder_name: str):
        """Return the native :class:`Folder` mirroring ``folder_name`` —
        useful for diagnostics and the future cutover. ``None`` if
        the mirror isn't initialised or native is unavailable."""
        mirror = self._native_mirrors.get(folder_name)
        return mirror.snapshot() if mirror is not None else None

    def native_mirror_stats(self) -> dict:
        """Return a ``dict`` summary of the native mirror state for
        operator diagnostics: per-folder file counts plus the running
        divergence counter."""
        folders: dict[str, dict] = {}
        for name, mirror in self._native_mirrors.items():
            snap = mirror.snapshot()
            folders[name] = {"present_files": snap.len()}
        return {
            "available": _MIRROR_AVAILABLE,
            "folders": folders,
            "divergence_events": self._native_mirror_divergence,
            "reconcile_checks": getattr(self, "_native_reconcile_checks", 0),
            "reconcile_disagreements": getattr(
                self, "_native_reconcile_disagreements", 0
            ),
            # Audit M15 May 2026: surface the ACK gate so operators
            # can see at a glance whether the authoritative-flip
            # precondition is satisfied (env-var ack count matches
            # observed disagreement count).
            "authoritative_flip_allowed": self.reconcile_authoritative_flip_allowed(),
        }

    def reconcile_authoritative_flip_allowed(self) -> bool:
        """Audit M15 May 2026 — gate that any future code wanting to
        flip the folder-sync authoritative bit from legacy to native
        MUST consult. Returns True ONLY when the operator has set
        ``ONE_LINK_RECONCILE_DISAGREEMENTS_ACKED=<count>`` to a
        value equal to the currently-observed
        ``_native_reconcile_disagreements`` counter — i.e. the
        operator has explicitly looked at the disagreement count
        and accepted it.

        Without this gate, the cutover criterion was operator-
        eyeball-only; a CI pipeline or runtime auto-flip with
        non-zero disagreements would silently corrupt folder state.

        Pattern at the flip site:
            if not foldersync.reconcile_authoritative_flip_allowed():
                # refuse to flip; legacy stays authoritative
                ...
        """
        import os

        observed = getattr(self, "_native_reconcile_disagreements", 0)
        raw = os.environ.get("ONE_LINK_RECONCILE_DISAGREEMENTS_ACKED")
        if raw is None:
            return False
        try:
            acked = int(raw.strip())
        except ValueError:
            return False
        return acked == int(observed)

    def _merge_via_native(
        self,
        local: Optional[ManifestEntry],
        remote: Optional[ManifestEntry],
        *,
        peer_fp: Optional[str],
    ) -> Optional[ManifestEntry]:
        """D16 — Compute the authoritative merge result via
        ``folder_native.merge_entries_via_native``. Falls back to the
        legacy merger if the native module is unavailable or the call
        raises — caller-visible behaviour is then unchanged.

        ``peer_fp`` is the remote peer's fingerprint (hex string when
        available); used to derive a deterministic remote replica id
        so OR-set tags are stable across a peer pair.
        """
        if not _MIRROR_AVAILABLE:
            return merge_manifest_entries(local, remote)
        try:
            replica = (
                self.me_fp.encode("utf-8") if isinstance(self.me_fp, str) else self.me_fp
            )
            peer_replica: Optional[bytes] = None
            if peer_fp:
                peer_replica = (
                    peer_fp.encode("utf-8") if isinstance(peer_fp, str) else peer_fp
                )
            return _folder_native.merge_entries_via_native(
                local, remote,
                replica_id=replica,
                peer_replica_id=peer_replica,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.warning(
                "D16: native authoritative merge failed (%s); falling "
                "back to legacy merger: %s",
                getattr(remote, "file_path", "?"), exc,
            )
            return merge_manifest_entries(local, remote)

    def _native_reconcile_check(
        self,
        folder_name: str,
        local: Optional[ManifestEntry],
        remote: ManifestEntry,
        legacy_winner: Optional[ManifestEntry],
        *,
        peer_fp: Optional[str] = None,
    ) -> None:
        """Run the native OR-set add-wins reconciliation in parallel
        with the legacy ``merge_manifest_entries`` decision and count
        disagreements. Pure observer — never mutates the live
        manifest. Used to validate that the lattice-correct CRDT
        agrees with the legacy merge before any cutover flips the
        authoritative bit.

        ``peer_fp`` — the remote peer's fingerprint hex string, if
        known. Used to derive a stable remote replica id so the
        OR-set's add tags are deterministic across replicas with the
        same view. When ``peer_fp`` is None (rare; legacy callers
        without the parameter), we fall back to a synthesised id that
        is still distinct from the local replica but loses the
        cross-daemon-stable property.

        Disagreement definition: the native folder's view of whether
        the file is *present* (``contains(file_id) == True``) after
        merging the two sides differs from whether the legacy winner
        is live (``winner.blob_hash is not None``). Tombstone-vs-edit
        and concurrent-edit cases are surfaced here so the diff
        budget is visible to operators."""
        if not _MIRROR_AVAILABLE:
            return
        self._native_reconcile_checks = (
            getattr(self, "_native_reconcile_checks", 0) + 1
        )
        try:
            local_entries = [local] if local is not None else []
            remote_entries = [remote]
            replica = (
                self.me_fp.encode("utf-8") if isinstance(self.me_fp, str) else self.me_fp
            )
            local_folder = _folder_native.manifest_entries_to_native_folder(
                local_entries, replica_id=replica
            )
            # Derive the remote replica id from the peer fingerprint
            # if available — keeps OR-set tags deterministic per peer
            # pair. Fall back to a synthesised id when peer_fp is
            # missing; the id still has to differ from the local one
            # so the OR-set tags don't collide.
            if peer_fp:
                remote_replica = (
                    peer_fp.encode("utf-8")
                    if isinstance(peer_fp, str)
                    else peer_fp
                )
            else:
                remote_replica = bytes(
                    ((b + 1) & 0xFF) for b in replica[:32].ljust(32, b"\x00")
                )
            remote_folder = _folder_native.manifest_entries_to_native_folder(
                remote_entries, replica_id=remote_replica
            )
            local_folder.merge(remote_folder)
            fid = _folder_native.file_path_to_id(remote.file_path)
            present_in_native = local_folder.contains(fid)
            legacy_present = (
                legacy_winner is not None and legacy_winner.blob_hash is not None
            )
            if present_in_native != legacy_present:
                self._native_reconcile_disagreements = (
                    getattr(self, "_native_reconcile_disagreements", 0) + 1
                )
                log.warning(
                    "native reconcile disagreement: %s/%s native_present=%s "
                    "legacy_present=%s (local=%s remote=%s)",
                    folder_name,
                    remote.file_path,
                    present_in_native,
                    legacy_present,
                    "alive" if (local and local.blob_hash) else "absent",
                    "alive" if remote.blob_hash else "tombstone",
                )
        except Exception as exc:  # pragma: no cover - defensive
            self._native_mirror_divergence += 1
            log.warning(
                "native reconcile check failed (%s/%s): %s",
                folder_name,
                remote.file_path,
                exc,
                exc_info=True,
            )

    # ─── folder management ────────────────────────────────────────────
    def add_folder(
        self, *, name: str, local_path: Path, shared_with: Iterable[str],
        max_file_bytes: int | None = None,
        ignored_patterns: list[str] | None = None,
        conflict_policy: str = "latest-wins",
    ) -> dict:
        """v0.21.x: ONLY does the fast registration steps — write the
        folder row to state.db + start the filesystem watcher. The
        full disk scan (``_scan_full``) is INTENTIONALLY skipped here
        and must be triggered separately via ``start_initial_scan``.

        Why split: a user picking a large folder (their whole project
        tree, Documents, etc.) used to hang the daemon for minutes
        because _scan_full hashed every file synchronously inside
        this call, blocking the HTTP request the entire time. With
        the split, add_folder returns in milliseconds; the scan
        runs in a background task and surfaces via refreshFolders.

        Watchdog covers any file changes AFTER add_folder returns,
        so even with a delayed initial scan, edits made post-Add are
        picked up immediately. The initial scan only seeds the
        manifest for files that already existed."""
        local_path = Path(local_path).expanduser()
        # v0.21.x: resolve(strict=False) on Windows can mangle paths
        # containing junctions/reparse points that the process can't
        # traverse. abspath() gives us the same normalization without
        # touching the FS, so we still hit a single canonical string
        # in state but mkdir gets a path it can actually create.
        local_path = Path(os.path.abspath(str(local_path)))
        try:
            os.makedirs(str(local_path), exist_ok=True)
        except OSError as e:
            # Re-raise with the path embedded so the accept endpoint's
            # error message shows the user what failed instead of a
            # bare WinError 2.
            raise OSError(
                f"could not create folder at {local_path}: {e}"
            ) from e
        existing = self.state.get_folder(name)
        if existing is not None:
            raise ValueError(f"folder named {name!r} already exists")
        self.state.add_folder(
            name=name, local_path=str(local_path), shared_with=list(shared_with),
            max_file_bytes=max_file_bytes,
            ignored_patterns=list(ignored_patterns or []),
            conflict_policy=conflict_policy,
        )
        try:
            self._start_watch(name, local_path)
        except Exception:
            self.state.remove_folder(name)
            raise
        row = self.state.get_folder(name)
        assert row is not None, "folder row missing immediately after insert"
        return row

    def start_initial_scan(self, name: str) -> bool:
        """Run the slow disk scan for an already-registered folder.
        Idempotent — re-running it just re-reconciles. Safe to call
        from a background thread / executor. Returns True if the scan
        actually ran, False if the folder isn't registered."""
        fs = self._folders.get(name)
        if not fs:
            return False
        self._scan_full(name, fs.root)
        return True

    def remove_folder(self, name: str) -> None:
        with self._manifest_lock, self._locked_all_paths():
            self._remove_folder_locked(name)

    def _remove_folder_locked(self, name: str) -> None:
        # A folder must never be forgotten while its only visible pre-image is
        # still parked under a journal-named recovery leaf.
        self.recover_pending_applies(folder_name=name)
        fs = self._folders.pop(name, None)
        if fs:
            self._stop_observer(name, fs)
        self.state.remove_folder(name)
        for key in tuple(self._pending_apply_guards):
            if key[0] == name:
                self._pending_apply_guards.pop(key, None)
        with self._proof_lock:
            for key in tuple(self._materialized_proofs):
                if key[0] == name:
                    self._materialized_proofs.pop(key, None)

    def relocate_folder(self, name: str, new_local_path: Path) -> dict:
        with self._manifest_lock, self._locked_all_paths():
            return self._relocate_folder_locked(name, new_local_path)

    def _relocate_folder_locked(self, name: str, new_local_path: Path) -> dict:
        """v0.21.x: point an existing folder at a different on-disk
        location. Stops the current watcher, updates state.local_path,
        starts a fresh watcher at the new root. Caller is responsible
        for triggering start_initial_scan if they want the manifest
        re-seeded from the new directory's contents (we don't do it
        automatically — re-scan on a large tree can take minutes).

        Raises:
          - KeyError if the folder isn't registered
          - FileNotFoundError if new_local_path doesn't exist + can't
            be created
          - NotADirectoryError if new_local_path exists but isn't a
            directory
        """
        new_local_path = Path(new_local_path).expanduser().resolve()
        existing = self.state.get_folder(name)
        if not existing:
            raise KeyError(f"no such folder: {name!r}")
        self.recover_pending_applies(folder_name=name)
        for pending in self.state.list_folder_pending_applies(folder_name=name):
            if (
                pending.get("phase") != "planned"
                or pending.get("staging_name") is not None
                or pending.get("recovery_name") is not None
            ):
                raise RuntimeError(
                    "folder relocation blocked by an unrecovered apply artifact"
                )
            self.state.delete_folder_pending_apply(
                folder_name=name,
                file_path=str(pending["file_path"]),
                apply_id=str(pending["apply_id"]),
            )
            self._pending_apply_guards.pop(
                (name, str(pending["file_path"])),
                None,
            )
        old_local_path = Path(existing["local_path"])
        # Validate the target. We accept missing-but-creatable paths
        # (mkdir parents=True) so a user can relocate to a new spot,
        # but we reject things that exist as files etc.
        if new_local_path.exists() and not new_local_path.is_dir():
            raise NotADirectoryError(
                f"target path exists but is not a directory: {new_local_path}"
            )
        try:
            new_local_path.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise FileNotFoundError(
                f"could not create target path {new_local_path}: {e}"
            ) from e
        # Stop the old watcher (if any) BEFORE flipping the row so a
        # late event from the old root can't write to the new manifest.
        fs = self._folders.get(name)
        if fs:
            self._stop_observer(name, fs, strict=True)
            self._folders.pop(name, None)
        # Flip the state row, then start the new watcher. Both operations are
        # inside the rollback boundary: a database write failure after the old
        # observer stopped must restore that observer too.
        try:
            self.state.set_folder_local_path(name, str(new_local_path))
            self._start_watch(name, new_local_path)
        except Exception:
            # Roll the durable row and runtime watcher back together. The old
            # implementation merely re-raised here, leaving the row pointed
            # at the new path with no watcher — a permanent sync stall.
            partial = self._folders.pop(name, None)
            if partial is not None:
                self._stop_observer(name, partial)
            try:
                self.state.set_folder_local_path(name, str(old_local_path))
            finally:
                # Restore runtime liveness even if SQLite itself is unhealthy;
                # the existing durable row normally still points at old_root
                # when the attempted update failed.
                if fs is not None:
                    self._start_watch(name, old_local_path)
            raise
        row = self.state.get_folder(name)
        assert row is not None
        return row

    def share_with(self, name: str, peer_fp: str, mode: str = "rw") -> None:
        self.state.share_folder_with(name, peer_fp)
        self.state.set_folder_peer_permission(name, peer_fp, mode)

    def unshare_with(self, name: str, peer_fp: str) -> None:
        self.state.unshare_folder_with(name, peer_fp)

    # ─── peer protocol callbacks ──────────────────────────────────────
    def manifest_for(self, name: str) -> list[dict]:
        # Local database metadata such as ``folder_name`` and ``updated_ms``
        # is deliberately excluded. Receipt digests bind exactly the portable
        # CRDT projection that the receiver parses and persists.
        return [
            {
                "file_path": row["file_path"],
                "blob_hash": row["blob_hash"],
                "size": row["size"],
                "mtime_ms": row["mtime_ms"],
                "vclock": dict(row.get("vclock") or {}),
            }
            for row in self.state.list_manifest(name)
        ]

    def manifest_root(self, name: str) -> str:
        return manifest_root_for_entries(self.state.list_manifest(name))

    @staticmethod
    def _entry_from_state_row(row: dict | None) -> ManifestEntry | None:
        if row is None:
            return None
        return ManifestEntry(
            file_path=row["file_path"],
            blob_hash=row["blob_hash"],
            size=row["size"],
            mtime_ms=row["mtime_ms"],
            vclock=VectorClock.from_dict(row["vclock"]),
        )

    def _snapshot_local_generation(
        self,
        *,
        folder_name: str,
        rel_path: str,
        local: ManifestEntry | None,
    ) -> tuple[ManifestEntry | None, _PendingApplyGuard]:
        """Index an unobserved local edit and capture replace preconditions."""

        folder = self.state.get_folder(folder_name)
        if not folder:
            raise RuntimeError("folder disappeared during remote merge")
        root = Path(folder["local_path"])
        dst = _safe_child(root, rel_path)
        if dst is None or _has_symlink_in_chain(dst, root):
            raise RuntimeError("unsafe local path blocks remote materialization")
        try:
            before = dst.lstat()
        except FileNotFoundError:
            current = local
            if local is not None and local.blob_hash is not None:
                current = ManifestEntry(
                    file_path=rel_path,
                    blob_hash=None,
                    size=None,
                    mtime_ms=int(time.time() * 1000),
                    vclock=local.vclock.increment(self.me_fp),
                )
            return current, _PendingApplyGuard(
                target_blob_hash=None,
                baseline_blob_hash=None,
                baseline_evidence=None,
            )
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise RuntimeError("non-regular local path blocks remote materialization")
        before_evidence = self._disk_evidence(before)
        actual_hash = self.blobs.put_path(dst)
        after = dst.lstat()
        after_evidence = self._disk_evidence(after)
        if (
            stat.S_ISLNK(after.st_mode)
            or not stat.S_ISREG(after.st_mode)
            or before_evidence != after_evidence
        ):
            raise RuntimeError("local path changed during remote merge planning")
        self.state.record_blob(actual_hash, int(after.st_size))
        current = local
        if local is None or local.blob_hash != actual_hash:
            old_clock = local.vclock if local is not None else VectorClock.empty()
            current = ManifestEntry(
                file_path=rel_path,
                blob_hash=actual_hash,
                size=int(after.st_size),
                mtime_ms=int(after.st_mtime * 1000),
                vclock=old_clock.increment(self.me_fp),
            )
        self._record_materialized_proof(
            folder_name,
            rel_path,
            actual_hash,
            dst,
            expected_evidence=after_evidence,
        )
        return current, _PendingApplyGuard(
            target_blob_hash=None,
            baseline_blob_hash=actual_hash,
            baseline_evidence=after_evidence,
        )

    def _preserve_changed_local_generation(
        self,
        *,
        folder_name: str,
        rel_path: str,
    ) -> None:
        current_row = self.state.get_manifest_entry(folder_name, rel_path)
        current = self._entry_from_state_row(current_row)
        preserved, _baseline = self._snapshot_local_generation(
            folder_name=folder_name,
            rel_path=rel_path,
            local=current,
        )
        if preserved is None or preserved == current:
            active = self._pending_apply_guards.get((folder_name, rel_path))
            self._retire_pending_apply(
                folder_name=folder_name,
                rel_path=rel_path,
                guard=active,
            )
            return
        self.state.upsert_manifest_entries_atomic(
            folder_name=folder_name,
            entries=[preserved.to_dict()],
            pending_applies=[],
        )
        self._mirror_observe(folder_name, preserved)
        if self.on_local_change:
            asyncio.run_coroutine_threadsafe(
                self.on_local_change(folder_name, preserved),
                self.loop,
            )

    def _pending_guard_allows_target(
        self,
        *,
        folder_name: str,
        rel_path: str,
        target_blob_hash: str | None,
        dst: Path,
    ) -> bool:
        key = (folder_name, rel_path)
        guard = self._pending_apply_guards.get(key)
        if guard is None:
            return True
        if guard.target_blob_hash != target_blob_hash:
            return False
        try:
            current = dst.lstat()
        except FileNotFoundError:
            unchanged = guard.baseline_evidence is None
        except OSError:
            unchanged = False
        else:
            unchanged = (
                guard.baseline_evidence is not None
                and not stat.S_ISLNK(current.st_mode)
                and stat.S_ISREG(current.st_mode)
                and self._disk_evidence(current) == guard.baseline_evidence
            )
        if unchanged:
            return True
        try:
            self._preserve_changed_local_generation(
                folder_name=folder_name,
                rel_path=rel_path,
            )
        except Exception as exc:
            log.error(
                "local generation changed and could not be preserved for %s/%s: %s",
                folder_name,
                rel_path,
                exc,
            )
            # Keep both the in-memory guard and durable journal. A later retry
            # must remain unable to overwrite the unpreserved generation.
            return False
        self._pending_apply_guards.pop(key, None)
        return False

    @staticmethod
    def _fsync_parent(path: Path) -> None:
        """Flush a POSIX parent after a namespace mutation.

        Windows namespace mutations in pending-apply paths use
        ``MoveFileExW(MOVEFILE_WRITE_THROUGH)`` through the durability helper.
        """

        if os.name == "nt":
            return
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    @staticmethod
    def _publish_staging_noreplace(staging: Path, dst: Path) -> bool:
        """Publish one staged file without ever replacing an existing name.

        ``os.replace`` has an unavoidable overwrite race between a final
        ``lstat`` and publication.  Windows ``rename`` is atomically
        no-replace; on POSIX, a same-directory hard link provides the same
        property.  The boolean reports whether the staging link remains and
        therefore still needs to be unlinked by the caller.
        """

        return publish_file_noreplace(staging, dst)

    @staticmethod
    def _journal_artifact_path(dst: Path, name: object) -> Path | None:
        if name is None:
            return None
        leaf = str(name)
        if (
            not leaf
            or Path(leaf).name != leaf
            or "/" in leaf
            or "\\" in leaf
            or not leaf.startswith(".one-link-")
            or not leaf.endswith(".tmp")
        ):
            raise ValueError("unsafe pending-apply artifact name")
        return dst.parent / leaf

    def _stable_path_hash(
        self,
        path: Path,
    ) -> tuple[str, tuple[int, int, int, int, int], int] | None:
        """Hash one no-follow regular file while binding path and handle."""

        flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        try:
            lookup_before = path.lstat()
            if stat.S_ISLNK(lookup_before.st_mode):
                return None
            fd = os.open(path, flags)
            with os.fdopen(fd, "rb") as opened:
                before = os.fstat(opened.fileno())
                digest = blake3.blake3()
                for block in iter(lambda: opened.read(1024 * 1024), b""):
                    digest.update(block)
                after = os.fstat(opened.fileno())
            lookup_after = path.lstat()
        except OSError:
            return None
        evidence = self._disk_evidence(before)
        if (
            not stat.S_ISREG(before.st_mode)
            or evidence != self._disk_evidence(after)
            or evidence != self._disk_evidence(lookup_before)
            or evidence != self._disk_evidence(lookup_after)
        ):
            return None
        return digest.hexdigest(), evidence, int(after.st_size)

    def _transition_pending_apply(
        self,
        *,
        guard: _PendingApplyGuard | None,
        phase: str,
        staging_name: str | None,
        recovery_name: str | None,
    ) -> bool:
        if guard is None or guard.apply_id is None:
            return True
        return self.state.transition_folder_pending_apply(
            apply_id=guard.apply_id,
            phase=phase,
            staging_name=staging_name,
            recovery_name=recovery_name,
        )

    def _retire_pending_apply(
        self,
        *,
        folder_name: str,
        rel_path: str,
        guard: _PendingApplyGuard | None = None,
    ) -> None:
        key = (folder_name, rel_path)
        active = guard or self._pending_apply_guards.get(key)
        if active is not None and active.apply_id is not None:
            deleted = self.state.delete_folder_pending_apply(
                folder_name=folder_name,
                file_path=rel_path,
                apply_id=active.apply_id,
            )
            if (
                not deleted
                and self.state.get_folder_pending_apply(folder_name, rel_path)
                is not None
            ):
                raise RuntimeError(
                    "refusing to retire a superseded pending folder apply"
                )
        self._pending_apply_guards.pop(key, None)

    def _pending_row_matches_manifest(self, row: dict[str, Any]) -> bool:
        current = self.state.get_manifest_entry(
            str(row["folder_name"]),
            str(row["file_path"]),
        )
        if current is None:
            return False
        return (
            current.get("blob_hash") == row.get("target_blob_hash")
            and current.get("size") == row.get("target_size")
            and current.get("mtime_ms") == row.get("target_mtime_ms")
            and dict(current.get("vclock") or {})
            == dict(row.get("target_vclock") or {})
        )

    def _ensure_recovery_artifact_in_cas(
        self,
        *,
        row: dict[str, Any],
        recovery: Path,
    ) -> None:
        expected = row.get("baseline_blob_hash")
        if not isinstance(expected, str):
            raise RuntimeError("recovery artifact has no baseline hash")
        self._ensure_preimage_in_cas(expected=expected, recovery=recovery)

    def _ensure_preimage_in_cas(
        self,
        *,
        expected: str,
        recovery: Path,
    ) -> None:
        proof = self._stable_path_hash(recovery)
        if proof is None or proof[0] != expected:
            raise RuntimeError("recovery artifact no longer matches baseline")
        if not self.blobs.has(expected):
            ingested = self.blobs.put_path(recovery)
            if ingested != expected or not self.blobs.has(expected):
                raise RuntimeError("could not preserve recovery artifact in CAS")
        self.state.record_blob(expected, proof[2])

    def _unlink_journal_artifact(self, path: Path | None) -> None:
        if path is None:
            return
        try:
            artifact_stat = path.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISLNK(artifact_stat.st_mode) or not stat.S_ISREG(
            artifact_stat.st_mode,
        ):
            raise RuntimeError("pending-apply artifact is not a regular file")
        path.unlink()
        self._fsync_parent(path)

    def _recover_pending_apply_row(self, row: dict[str, Any]) -> bool:
        """Replay or safely abandon one exact journal generation."""

        folder_name = str(row["folder_name"])
        rel_path = str(row["file_path"])
        folder = self.state.get_folder(folder_name)
        if folder is None:
            self.state.delete_folder_pending_apply(
                folder_name=folder_name,
                file_path=rel_path,
                apply_id=str(row["apply_id"]),
            )
            return True
        root = Path(folder["local_path"])
        dst = _safe_child(root, rel_path)
        if dst is None or _has_symlink_in_chain(dst, root):
            raise RuntimeError("unsafe path blocks pending-apply recovery")
        stage = self._journal_artifact_path(dst, row.get("staging_name"))
        recovery = self._journal_artifact_path(dst, row.get("recovery_name"))
        guard = _PendingApplyGuard(
            target_blob_hash=row.get("target_blob_hash"),
            baseline_blob_hash=row.get("baseline_blob_hash"),
            baseline_evidence=row.get("baseline_evidence"),
            apply_id=str(row["apply_id"]),
        )
        key = (folder_name, rel_path)
        self._pending_apply_guards[key] = guard

        # A newer local/remote generation superseded this operation. Restore
        # an interrupted pre-image only when the live name is absent, retain
        # every other generation in CAS, then retire the stale intent.
        if not self._pending_row_matches_manifest(row):
            if recovery is not None and recovery.exists():
                self._ensure_recovery_artifact_in_cas(row=row, recovery=recovery)
                if not dst.exists() and not dst.is_symlink():
                    replace_path(recovery, dst)
                    self._fsync_parent(dst)
                else:
                    self._unlink_journal_artifact(recovery)
            self._unlink_journal_artifact(stage)
            self._retire_pending_apply(
                folder_name=folder_name,
                rel_path=rel_path,
                guard=guard,
            )
            return True

        live_proof = self._stable_path_hash(dst)
        target_hash = row.get("target_blob_hash")
        if (
            isinstance(target_hash, str)
            and live_proof is not None
            and live_proof[0] == target_hash
            and live_proof[2] == int(row.get("target_size") or 0)
        ):
            recorded = self._record_materialized_proof(
                folder_name,
                rel_path,
                target_hash,
                dst,
                expected_evidence=live_proof[1],
            )
            if recorded is None:
                raise RuntimeError("published target changed during recovery")
            if recovery is not None and recovery.exists():
                self._ensure_recovery_artifact_in_cas(row=row, recovery=recovery)
                self._unlink_journal_artifact(recovery)
            self._unlink_journal_artifact(stage)
            self._retire_pending_apply(
                folder_name=folder_name,
                rel_path=rel_path,
                guard=guard,
            )
            return True

        if recovery is not None and recovery.exists():
            self._ensure_recovery_artifact_in_cas(row=row, recovery=recovery)
            if not dst.exists() and not dst.is_symlink():
                if row.get("operation") == "delete":
                    self._unlink_journal_artifact(recovery)
                    self._unlink_journal_artifact(stage)
                    self._retire_pending_apply(
                        folder_name=folder_name,
                        rel_path=rel_path,
                        guard=guard,
                    )
                    self._invalidate_materialized_proof(folder_name, rel_path)
                    return True
                replace_path(recovery, dst)
                self._fsync_parent(dst)
            elif live_proof is not None and (
                live_proof[0] != row.get("baseline_blob_hash")
            ):
                # A user-created generation won the crash race. Index it;
                # never restore the older pre-image over the live name.
                self._preserve_changed_local_generation(
                    folder_name=folder_name,
                    rel_path=rel_path,
                )
                self._unlink_journal_artifact(recovery)
                self._unlink_journal_artifact(stage)
                self._pending_apply_guards.pop(key, None)
                return True
            else:
                self._unlink_journal_artifact(recovery)

        self._unlink_journal_artifact(stage)
        if not self._transition_pending_apply(
            guard=guard,
            phase="planned",
            staging_name=None,
            recovery_name=None,
        ):
            self._pending_apply_guards.pop(key, None)
            return False

        if row.get("operation") == "delete":
            return self._delete_on_disk(folder_name, rel_path)
        if not isinstance(target_hash, str) or not self.blobs.has(target_hash):
            return False
        entry = ManifestEntry(
            file_path=rel_path,
            blob_hash=target_hash,
            size=int(row.get("target_size") or 0),
            mtime_ms=row.get("target_mtime_ms"),
            vclock=VectorClock.from_dict(dict(row.get("target_vclock") or {})),
        )
        return self._materialize_locked(folder_name, entry)

    def recover_pending_applies(self, *, folder_name: str | None = None) -> int:
        """Replay durable folder filesystem intents before normal scanning."""

        recovered = 0
        rows = self.state.list_folder_pending_applies(folder_name=folder_name)
        for row in rows:
            name = str(row["folder_name"])
            rel_path = str(row["file_path"])
            with self._path_lock(name, rel_path):
                try:
                    if self._recover_pending_apply_row(row):
                        recovered += 1
                except Exception as exc:
                    log.error(
                        "pending folder apply recovery failed for %s/%s: %s",
                        name,
                        rel_path,
                        exc,
                        exc_info=True,
                    )
                    with contextlib.suppress(Exception):
                        latest = self.state.get_folder_pending_apply(
                            name,
                            rel_path,
                        )
                        if latest is not None:
                            self.state.transition_folder_pending_apply(
                                apply_id=str(latest["apply_id"]),
                                phase=str(latest["phase"]),
                                staging_name=latest.get("staging_name"),
                                recovery_name=latest.get("recovery_name"),
                                last_error=f"{type(exc).__name__}: {exc}",
                                increment_attempts=True,
                            )
        return recovered

    def receive_remote_manifest(
        self, *, folder_name: str, entries: list[dict],
        peer_fp: Optional[str] = None,
    ) -> list[dict]:
        """Merge remote entries into local manifest, return list of entries
        whose blobs we now want (winner has a non-None blob_hash we don't
        already have in the local store).

        v0.8.9: when local + remote are CONCURRENT in vclock terms AND
        the live blob_hashes differ (real divergent edit, not just a
        tie-broken delete vs. tombstone), log a manifest_conflicts row
        so the user can see + override the auto-merge via the
        Conflicts UI. The merge still applies — the wire protocol has
        no 'hold' primitive — but the audit row preserves both sides
        so the user can flip the choice."""
        plans: list[
            tuple[
                ManifestEntry,
                Optional[ManifestEntry],
                ManifestEntry,
                _PendingApplyGuard | None,
            ]
        ] = []
        entry_paths = [str(entry["file_path"]) for entry in entries]
        with self._manifest_lock, self._locked_paths(folder_name, entry_paths):
            # Never overwrite a journal row that still names a recovery
            # artifact. Replay it first so a newer manifest generation cannot
            # orphan the only filesystem pre-image after a crash.
            for rel_path in dict.fromkeys(entry_paths):
                pending = self.state.get_folder_pending_apply(
                    folder_name,
                    rel_path,
                )
                if pending is None:
                    continue
                self._recover_pending_apply_row(pending)
                remaining = self.state.get_folder_pending_apply(
                    folder_name,
                    rel_path,
                )
                if remaining is not None and (
                    remaining.get("phase") != "planned"
                    or remaining.get("staging_name") is not None
                    or remaining.get("recovery_name") is not None
                ):
                    raise RuntimeError(
                        "previous folder apply could not reach a replaceable state"
                    )
            for raw_entry in entries:
                remote = ManifestEntry.from_dict(raw_entry)
                local_row = self.state.get_manifest_entry(
                    folder_name,
                    remote.file_path,
                )
                local = self._entry_from_state_row(local_row)
                tentative = merge_manifest_entries(local, remote)
                guard: _PendingApplyGuard | None = None
                local_hash = local.blob_hash if local is not None else None
                needs_snapshot = (
                    tentative is not None
                    and tentative.blob_hash != local_hash
                )
                if tentative is not None and not needs_snapshot:
                    folder = self.state.get_folder(folder_name)
                    if folder is None:
                        raise RuntimeError("folder disappeared during remote merge")
                    root = Path(folder["local_path"])
                    dst = _safe_child(root, remote.file_path)
                    if dst is None or _has_symlink_in_chain(dst, root):
                        raise RuntimeError(
                            "unsafe local path blocks remote reconciliation"
                        )
                    if isinstance(local_hash, str):
                        needs_snapshot = self._materialized_proof_matches(
                            folder_name,
                            remote.file_path,
                            local_hash,
                            dst,
                        ) is None
                    else:
                        try:
                            dst.lstat()
                        except FileNotFoundError:
                            needs_snapshot = False
                        except OSError as exc:
                            raise RuntimeError(
                                "local path unavailable during remote merge"
                            ) from exc
                        else:
                            needs_snapshot = True
                if tentative is not None and needs_snapshot:
                    local, baseline = self._snapshot_local_generation(
                        folder_name=folder_name,
                        rel_path=remote.file_path,
                        local=local,
                    )
                    tentative = merge_manifest_entries(local, remote)
                    if (
                        tentative is not None
                        and tentative.blob_hash != baseline.baseline_blob_hash
                    ):
                        guard = _PendingApplyGuard(
                            target_blob_hash=tentative.blob_hash,
                            baseline_blob_hash=baseline.baseline_blob_hash,
                            baseline_evidence=baseline.baseline_evidence,
                            apply_id=secrets.token_hex(16),
                        )
                legacy_winner = merge_manifest_entries(local, remote)
                self._native_reconcile_check(
                    folder_name,
                    local,
                    remote,
                    legacy_winner,
                    peer_fp=peer_fp,
                )
                if self._crdt_native_authoritative:
                    native_winner = self._merge_via_native(
                        local,
                        remote,
                        peer_fp=peer_fp,
                    )
                    self._crdt_native_authoritative_merges += 1
                    if (
                        (native_winner is None) != (legacy_winner is None)
                        or (
                            native_winner is not None
                            and legacy_winner is not None
                            and native_winner.blob_hash
                            != legacy_winner.blob_hash
                        )
                    ):
                        self._crdt_native_authoritative_overrides += 1
                        log.info(
                            "D16: native lattice overrode legacy merger for %s/%s",
                            folder_name,
                            remote.file_path,
                        )
                    winner = native_winner
                else:
                    winner = legacy_winner
                if winner is not None:
                    if (
                        guard is not None
                        and winner.blob_hash != guard.target_blob_hash
                    ):
                        guard = None
                    plans.append((remote, local, winner, guard))

            self.state.upsert_manifest_entries_atomic(
                folder_name=folder_name,
                entries=[
                    winner.to_dict()
                    for _remote, _local, winner, _guard in plans
                ],
                pending_applies=[
                    {
                        "apply_id": guard.apply_id,
                        "file_path": winner.file_path,
                        "operation": (
                            "materialize"
                            if winner.blob_hash is not None
                            else "delete"
                        ),
                        "target_blob_hash": winner.blob_hash,
                        "target_size": (
                            int(winner.size or 0)
                            if winner.blob_hash is not None
                            else None
                        ),
                        "target_mtime_ms": winner.mtime_ms,
                        "target_vclock": winner.vclock.to_dict(),
                        "baseline_blob_hash": guard.baseline_blob_hash,
                        "baseline_evidence": guard.baseline_evidence,
                        "phase": "planned",
                        "staging_name": None,
                        "recovery_name": None,
                    }
                    for _remote, _local, winner, guard in plans
                    if guard is not None and guard.apply_id is not None
                ],
            )
            for _remote, _local, winner, guard in plans:
                key = (folder_name, winner.file_path)
                if guard is None:
                    self._pending_apply_guards.pop(key, None)
                else:
                    self._pending_apply_guards[key] = guard

        # Audit/mirror/filesystem effects occur only after the full CRDT
        # generation commits. A failure can therefore leave a retryable
        # materialization gap, never a prefix of manifest rows.
        wants: list[dict] = []
        for remote, local, winner, _guard in plans:
            self._maybe_record_conflict(
                folder_name=folder_name,
                local=local,
                remote=remote,
                peer_fp=peer_fp,
            )
            self._mirror_observe(folder_name, winner)
            if winner.blob_hash is not None and not self.blobs.has(winner.blob_hash):
                wants.append(winner.to_dict())
            elif winner.blob_hash is not None:
                self._materialize(folder_name, winner)
            elif local is not None and local.blob_hash is not None:
                self._delete_on_disk(folder_name, winner.file_path)
        return wants

    def _maybe_record_conflict(
        self,
        *,
        folder_name: str,
        local: Optional[ManifestEntry],
        remote: ManifestEntry,
        peer_fp: Optional[str],
    ) -> None:
        """v0.8.9: detect + log a divergent-edit conflict.
        Idempotency lives in state.record_manifest_conflict — if the
        same (local_vclock, remote_vclock) pair was already recorded
        for this path, the helper returns the existing id instead of
        duplicating."""
        if local is None or local.blob_hash is None:
            return
        if remote.blob_hash is None:
            return
        if local.blob_hash == remote.blob_hash:
            return
        if not local.vclock.concurrent_with(remote.vclock):
            return
        # Predict which side merge_manifest_entries will pick so the
        # conflict row records what the auto-resolution did.
        l_mt = local.mtime_ms or 0
        r_mt = remote.mtime_ms or 0
        if l_mt != r_mt:
            applied = "local" if l_mt > r_mt else "remote"
        elif (local.blob_hash or "") >= (remote.blob_hash or ""):
            applied = "local"
        else:
            applied = "remote"
        try:
            cid = self.state.record_manifest_conflict(
                folder_name=folder_name,
                file_path=remote.file_path,
                peer_fp=peer_fp,
                local_blob_hash=local.blob_hash,
                local_size=local.size,
                local_mtime_ms=local.mtime_ms,
                local_vclock=local.vclock.to_dict(),
                remote_blob_hash=remote.blob_hash,
                remote_size=remote.size,
                remote_mtime_ms=remote.mtime_ms,
                remote_vclock=remote.vclock.to_dict(),
                applied_choice=applied,
            )
            log.info(
                "folder %s: divergent-edit conflict logged id=%s path=%s "
                "applied=%s peer=%s",
                folder_name, cid, remote.file_path, applied,
                (peer_fp or "?")[:8],
            )
            # Notify the UI live (best-effort — daemon owns ui_server).
            if self._on_conflict_recorded is not None:
                try:
                    self._on_conflict_recorded(folder_name, cid)
                except Exception as exc:
                    log.warning(
                        "conflict notification callback failed for %s/%s: %s",
                        folder_name,
                        remote.file_path,
                        exc,
                        exc_info=True,
                    )
        except Exception as exc:
            log.warning("conflict record failed for %s/%s: %s",
                        folder_name, remote.file_path, exc)

    def resolve_conflict(
        self, *, conflict_id: int, choice: str,
    ) -> dict:
        """v0.8.9: resolve a divergent-edit conflict via UI choice.

        choice is one of:
          'mine'   — keep our blob_hash, bump vclock past remote.
          'theirs' — adopt remote's blob_hash + materialize.
          'both'   — keep mine; ALSO write a conflict-suffixed file
                     under "<name>.conflict-{peer-shortfp}.<ext>"
                     containing remote's blob.

        After resolution, the manifest CRDT carries the chosen state;
        the next sync round will propagate it. Returns a dict with
        the resolution outcome (manifest entries written, materialize
        flags) so the API layer can echo it to the UI.

        Raises ValueError on bad choice / missing conflict / a 'theirs'
        or 'both' resolution where the remote blob isn't yet local."""
        if choice not in ("mine", "theirs", "both"):
            raise ValueError(
                f"choice must be mine|theirs|both, got {choice!r}"
            )
        conflict = self.state.get_manifest_conflict(conflict_id)
        if conflict is None:
            raise ValueError(f"conflict {conflict_id} not found")
        if conflict.get("resolved_ms") is not None:
            return {
                "ok": False, "already_resolved": True,
                "conflict_id": conflict_id,
                "resolution": conflict.get("resolution"),
            }
        folder_name = conflict["folder_name"]
        file_path = conflict["file_path"]
        local_vc = VectorClock.from_dict(conflict["local_vclock"])
        remote_vc = VectorClock.from_dict(conflict["remote_vclock"])
        # Use the LIVE manifest entry (might've drifted since detection
        # if a third peer's edit landed in between).
        live_row = self.state.get_manifest_entry(folder_name, file_path)
        live = (
            ManifestEntry(
                file_path=live_row["file_path"],
                blob_hash=live_row["blob_hash"],
                size=live_row["size"],
                mtime_ms=live_row["mtime_ms"],
                vclock=VectorClock.from_dict(live_row["vclock"]),
            ) if live_row else None
        )
        # The new vclock for whichever entry we're stamping. Merge of
        # live + both detection-time clocks then bumped on our node so
        # downstream peers strictly observe our resolution.
        merged = (live.vclock if live else VectorClock.empty()).merge(local_vc).merge(remote_vc)
        new_vc = merged.increment(self.me_fp)
        result = {
            "ok": True,
            "conflict_id": conflict_id,
            "resolution": choice,
            "folder_name": folder_name,
            "file_path": file_path,
            "wrote": [],
        }
        if choice == "mine":
            chosen_entry = ManifestEntry(
                file_path=file_path,
                blob_hash=conflict["local_blob_hash"],
                size=conflict["local_size"],
                mtime_ms=conflict["local_mtime_ms"],
                vclock=new_vc,
            )
            self._apply_resolution_entry(folder_name, chosen_entry, materialize=True)
            result["wrote"].append(file_path)
        elif choice == "theirs":
            chosen_entry = ManifestEntry(
                file_path=file_path,
                blob_hash=conflict["remote_blob_hash"],
                size=conflict["remote_size"],
                mtime_ms=conflict["remote_mtime_ms"],
                vclock=new_vc,
            )
            self._apply_resolution_entry(folder_name, chosen_entry, materialize=True)
            result["wrote"].append(file_path)
        else:  # both
            # 1. Keep mine in place under original path.
            mine_entry = ManifestEntry(
                file_path=file_path,
                blob_hash=conflict["local_blob_hash"],
                size=conflict["local_size"],
                mtime_ms=conflict["local_mtime_ms"],
                vclock=new_vc,
            )
            self._apply_resolution_entry(folder_name, mine_entry, materialize=True)
            result["wrote"].append(file_path)
            # 2. Write theirs at a conflict-suffixed path.
            suffix_path = self._conflict_suffixed_path(
                file_path, conflict.get("peer_fp"),
            )
            # Fresh vclock for the new path — it's a new entry.
            suffix_vc = VectorClock.empty().increment(self.me_fp)
            suffix_entry = ManifestEntry(
                file_path=suffix_path,
                blob_hash=conflict["remote_blob_hash"],
                size=conflict["remote_size"],
                mtime_ms=conflict["remote_mtime_ms"],
                vclock=suffix_vc,
            )
            self._apply_resolution_entry(folder_name, suffix_entry, materialize=True)
            result["wrote"].append(suffix_path)
            result["suffixed_path"] = suffix_path
        self.state.mark_manifest_conflict_resolved(
            conflict_id, resolution=choice, resolved_by="ui",
        )
        return result

    def _apply_resolution_entry(
        self,
        folder_name: str,
        entry: ManifestEntry,
        *,
        materialize: bool,
    ) -> None:
        with self._path_lock(folder_name, entry.file_path):
            pending = self.state.get_folder_pending_apply(
                folder_name,
                entry.file_path,
            )
            if pending is not None:
                self._recover_pending_apply_row(pending)
            self.state.upsert_manifest_entry(
                folder_name=folder_name,
                file_path=entry.file_path,
                blob_hash=entry.blob_hash,
                size=entry.size,
                mtime_ms=entry.mtime_ms,
                vclock=entry.vclock.to_dict(),
                clear_pending_apply=True,
            )
            self._pending_apply_guards.pop(
                (folder_name, entry.file_path),
                None,
            )
            if materialize and entry.blob_hash is not None:
                if self.blobs.has(entry.blob_hash):
                    self._materialize_locked(folder_name, entry)
                # Otherwise materialize_after_blob_arrived replays it when
                # the selected conflict generation reaches the CAS.

    @staticmethod
    def _conflict_suffixed_path(
        file_path: str, peer_fp: Optional[str],
    ) -> str:
        """foo.txt + peer aabbcc… → foo.conflict-aabbcc88.txt
        foo (no extension) → foo.conflict-aabbcc88"""
        tag = (peer_fp or "peer")[:8]
        # Find last dot AFTER the last slash (so dotfiles + paths work).
        slash_idx = max(file_path.rfind("/"), file_path.rfind("\\"))
        dot_idx = file_path.rfind(".")
        if dot_idx > slash_idx and dot_idx > 0:
            stem, ext = file_path[:dot_idx], file_path[dot_idx:]
            return f"{stem}.conflict-{tag}{ext}"
        return f"{file_path}.conflict-{tag}"

    def materialize_after_blob_arrived(
        self, *, blob_hash: str
    ) -> int:
        """Materialize only indexed consumers and count proven successes."""
        n = 0
        cursor: tuple[str, str] | None = None
        while True:
            rows = self.state.list_manifest_entries_by_blob(
                blob_hash,
                limit=4096,
                after=cursor,
            )
            if not rows:
                break
            for manifest_row in rows:
                entry = ManifestEntry(
                    file_path=manifest_row["file_path"],
                    blob_hash=manifest_row["blob_hash"],
                    size=manifest_row["size"],
                    mtime_ms=manifest_row["mtime_ms"],
                    vclock=VectorClock.from_dict(manifest_row["vclock"]),
                )
                if self._materialize(manifest_row["folder_name"], entry):
                    n += 1
            cursor = (str(rows[-1]["folder_name"]), str(rows[-1]["file_path"]))
            if len(rows) < 4096:
                break
        return n

    def verify_materialized_paths(
        self,
        *,
        folder_name: str,
        paths: Iterable[str],
        max_paths: int = 4096,
        max_total_bytes: int = 128 * 1024 * 1024 * 1024,
        deadline_monotonic: float | None = None,
    ) -> tuple[bool, str, str]:
        """Prove the current CRDT winners are exact on disk.

        This is the receiver side of the folder commit receipt.  It verifies
        only paths affected by the remote manifest, but verifies each against
        the *current winning* manifest row so legitimate conflict resolution
        is attested rather than mistaken for corruption.  Handles are opened
        without following the final symlink and stable stat evidence is checked
        before/after hashing to detect concurrent replacement.
        """
        folder = self.state.get_folder(folder_name)
        if not folder:
            return False, "folder_missing", ""
        root = Path(folder["local_path"])
        unique_paths = tuple(dict.fromkeys(str(path) for path in paths))
        if len(unique_paths) > max(0, int(max_paths)):
            return False, "path_count_exceeded", ""
        initial_rows = self.state.list_manifest(folder_name)
        initial_by_path = {str(row["file_path"]): row for row in initial_rows}
        if len(initial_by_path) != len(initial_rows):
            return False, "manifest_path_collision", ""
        live_path_evidence: dict[str, tuple[int, int, int, int, int]] = {}
        tombstone_paths: list[Path] = []
        verified_bytes = 0
        for rel_path in unique_paths:
            if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
                return False, "verification_deadline_exceeded", ""
            row = initial_by_path.get(rel_path)
            if row is None:
                return False, "manifest_entry_missing", ""
            dst = _safe_child(root, rel_path)
            if dst is None or _has_symlink_in_chain(dst, root):
                return False, "unsafe_materialized_path", ""
            expected_hash = row.get("blob_hash")
            if expected_hash is None:
                if dst.exists() or dst.is_symlink():
                    return False, "tombstone_not_materialized", ""
                tombstone_paths.append(dst)
                continue
            if not isinstance(expected_hash, str) or not self.blobs.has(expected_hash):
                return False, "cas_blob_missing", ""
            expected_size = int(row.get("size") or 0)
            if not self.state.has_blob(expected_hash):
                try:
                    self.state.record_blob(expected_hash, expected_size)
                except Exception:
                    return False, "blob_index_repair_failed", ""
                if not self.state.has_blob(expected_hash):
                    return False, "blob_index_missing", ""
            cached_evidence = self._materialized_proof_matches(
                folder_name,
                rel_path,
                expected_hash,
                dst,
            )
            if cached_evidence is not None:
                live_path_evidence[rel_path] = cached_evidence
                continue
            verified_bytes += expected_size
            if verified_bytes > max(0, int(max_total_bytes)):
                return False, "verification_byte_budget_exceeded", ""
            flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
            flags |= int(getattr(os, "O_NOFOLLOW", 0))
            try:
                lookup_before = dst.lstat()
                if stat.S_ISLNK(lookup_before.st_mode):
                    return False, "unsafe_materialized_path", ""
                fd = os.open(dst, flags)
                before = os.fstat(fd)
                if (
                    before.st_dev != lookup_before.st_dev
                    or before.st_ino != lookup_before.st_ino
                ):
                    os.close(fd)
                    return False, "materialized_path_changed", ""
                digest = blake3.blake3()
                with os.fdopen(fd, "rb") as materialized:
                    for block in iter(
                        lambda: materialized.read(1024 * 1024), b"",
                    ):
                        if (
                            deadline_monotonic is not None
                            and time.monotonic() >= deadline_monotonic
                        ):
                            return False, "verification_deadline_exceeded", ""
                        digest.update(block)
                    after = os.fstat(materialized.fileno())
                lookup_after = dst.lstat()
                resolved_after = dst.resolve(strict=True)
                resolved_after.relative_to(root.resolve(strict=True))
            except OSError:
                return False, "materialized_file_unavailable", ""
            except (RuntimeError, ValueError):
                return False, "unsafe_materialized_path", ""
            before_evidence = self._disk_evidence(before)
            after_evidence = self._disk_evidence(after)
            path_after_evidence = self._disk_evidence(lookup_after)
            if (
                not stat.S_ISREG(after.st_mode)
                or before_evidence != after_evidence
                or after_evidence != path_after_evidence
                or after.st_size != expected_size
                or digest.hexdigest() != expected_hash
            ):
                return False, "materialized_content_mismatch", ""
            recorded = self._record_materialized_proof(
                folder_name,
                rel_path,
                expected_hash,
                dst,
                expected_evidence=path_after_evidence,
            )
            if recorded is None:
                return False, "materialized_path_changed", ""
            live_path_evidence[rel_path] = recorded

        # Re-check every directory entry after all hashing, then prove the
        # manifest did not advance between the per-path snapshot and root.
        for rel_path, evidence in live_path_evidence.items():
            dst = _safe_child(root, rel_path)
            if dst is None:
                return False, "unsafe_materialized_path", ""
            try:
                current = dst.lstat()
            except OSError:
                return False, "materialized_path_changed", ""
            current_evidence = self._disk_evidence(current)
            if stat.S_ISLNK(current.st_mode) or current_evidence != evidence:
                return False, "materialized_path_changed", ""
        if any(path.exists() or path.is_symlink() for path in tombstone_paths):
            return False, "tombstone_not_materialized", ""
        final_rows = self.state.list_manifest(folder_name)
        final_by_path = {str(row["file_path"]): row for row in final_rows}
        if len(final_by_path) != len(final_rows):
            return False, "manifest_path_collision", ""
        for rel_path in unique_paths:
            if final_by_path.get(rel_path) != initial_by_path.get(rel_path):
                return False, "verified_projection_changed", ""
        return True, "", manifest_root_for_entries(final_rows)

    # ─── filesystem ↔ manifest ────────────────────────────────────────
    def _materialize(self, folder_name: str, entry: ManifestEntry) -> bool:
        with self._path_lock(folder_name, entry.file_path):
            return self._materialize_locked(folder_name, entry)

    def _materialize_locked(
        self,
        folder_name: str,
        entry: ManifestEntry,
    ) -> bool:
        folder = self.state.get_folder(folder_name)
        if not folder:
            return False
        root = Path(folder["local_path"])
        dst = _safe_child(root, entry.file_path)
        if dst is None:
            log.warning("refusing unsafe manifest path: %r", entry.file_path)
            return False
        if not self._pending_guard_allows_target(
            folder_name=folder_name,
            rel_path=entry.file_path,
            target_blob_hash=entry.blob_hash,
            dst=dst,
        ):
            return False
        if entry.blob_hash is None:
            return self._delete_on_disk(folder_name, entry.file_path)
        if not self.blobs.has(entry.blob_hash):
            return False
        if self._materialized_proof_matches(
            folder_name,
            entry.file_path,
            entry.blob_hash,
            dst,
        ) is not None:
            self._retire_pending_apply(
                folder_name=folder_name,
                rel_path=entry.file_path,
            )
            return True

        current_proof = self._stable_path_hash(dst)
        if (
            current_proof is not None
            and current_proof[0] == entry.blob_hash
            and current_proof[2] == int(entry.size or 0)
        ):
            recorded = self._record_materialized_proof(
                folder_name,
                entry.file_path,
                entry.blob_hash,
                dst,
                expected_evidence=current_proof[1],
            )
            if recorded is not None:
                self._retire_pending_apply(
                    folder_name=folder_name,
                    rel_path=entry.file_path,
                )
                return True

        if (
            current_proof is not None
            and self._on_collision_detected is not None
            and entry.size is not None
            and current_proof[2] != entry.size
        ):
            try:
                self._on_collision_detected(
                    folder_name,
                    entry.file_path,
                    current_proof[2],
                    entry.size,
                    entry.blob_hash,
                )
            except Exception as exc:
                log.warning(
                    "collision notification callback failed for %s/%s: %s",
                    folder_name,
                    entry.file_path,
                    exc,
                    exc_info=True,
                )

        dst.parent.mkdir(parents=True, exist_ok=True)
        if _has_symlink_in_chain(dst, root):
            log.warning(
                "refusing materialize for %s: symlinked component in "
                "destination path chain",
                entry.file_path,
            )
            return False

        guard = self._pending_apply_guards.get((folder_name, entry.file_path))
        staging = dst.parent / f".one-link-{secrets.token_hex(12)}.tmp"
        if not self._transition_pending_apply(
            guard=guard,
            phase="staging",
            staging_name=staging.name,
            recovery_name=None,
        ):
            return False
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        flags |= int(getattr(os, "O_BINARY", 0))
        fd = os.open(str(staging), flags, 0o600)
        recovery: Path | None = None
        published = False
        try:
            with self.blobs.open_read(entry.blob_hash) as source, os.fdopen(
                fd,
                "wb",
            ) as output:
                opened_before = os.fstat(output.fileno())
                staged_digest = blake3.blake3()
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    staged_digest.update(block)
                    output.write(block)
                output.flush()
                os.fsync(output.fileno())
                opened_after = os.fstat(output.fileno())
            staged_lookup = staging.lstat()
            staged_evidence = self._disk_evidence(opened_after)
            if (
                not stat.S_ISREG(opened_after.st_mode)
                or opened_before.st_dev != opened_after.st_dev
                or opened_before.st_ino != opened_after.st_ino
                or staged_evidence != self._disk_evidence(staged_lookup)
                or staged_digest.hexdigest() != entry.blob_hash
                or int(opened_after.st_size) != int(entry.size or 0)
            ):
                raise OSError("staged folder content failed address proof")
            if _has_symlink_in_chain(dst, root):
                raise OSError("destination path changed during materialization")
            resolved_parent = dst.parent.resolve(strict=True)
            resolved_parent.relative_to(root.resolve(strict=True))
            if staging.parent.resolve(strict=True) != resolved_parent:
                raise OSError("staging path escaped folder root")
            if not self._pending_guard_allows_target(
                folder_name=folder_name,
                rel_path=entry.file_path,
                target_blob_hash=entry.blob_hash,
                dst=dst,
            ):
                return False

            try:
                live_stat = dst.lstat()
            except FileNotFoundError:
                live_stat = None
            if live_stat is not None:
                if stat.S_ISLNK(live_stat.st_mode) or not stat.S_ISREG(
                    live_stat.st_mode,
                ):
                    raise OSError("non-regular destination blocks materialization")
                recovery = dst.parent / f".one-link-{secrets.token_hex(12)}.tmp"
                if not self._transition_pending_apply(
                    guard=guard,
                    phase="recovery_prepared",
                    staging_name=staging.name,
                    recovery_name=recovery.name,
                ):
                    return False
                replace_path(dst, recovery)
                self._fsync_parent(dst)
                if not self._transition_pending_apply(
                    guard=guard,
                    phase="recovery_moved",
                    staging_name=staging.name,
                    recovery_name=recovery.name,
                ):
                    raise RuntimeError("pending apply disappeared after recovery move")
                if guard is not None:
                    moved = self._stable_path_hash(recovery)
                    if (
                        guard.baseline_blob_hash is None
                        or moved is None
                        or moved[0] != guard.baseline_blob_hash
                    ):
                        if dst.exists() or dst.is_symlink():
                            log.error(
                                "destination reappeared while preserving %s/%s; "
                                "retaining recovery artifact",
                                folder_name,
                                entry.file_path,
                            )
                            return False
                        replace_path(recovery, dst)
                        self._fsync_parent(dst)
                        recovery = None
                        self._preserve_changed_local_generation(
                            folder_name=folder_name,
                            rel_path=entry.file_path,
                        )
                        self._pending_apply_guards.pop(
                            (folder_name, entry.file_path),
                            None,
                        )
                        return False

            # Moving the pre-image creates a short absent-name window. Never
            # overwrite a user generation that appeared in that window.
            try:
                unexpected = dst.lstat()
            except FileNotFoundError:
                unexpected = None
            if unexpected is not None:
                if stat.S_ISLNK(unexpected.st_mode) or not stat.S_ISREG(
                    unexpected.st_mode,
                ):
                    log.error(
                        "non-regular destination appeared during %s/%s publish",
                        folder_name,
                        entry.file_path,
                    )
                    return False
                if recovery is not None:
                    if guard is not None and guard.baseline_blob_hash is not None:
                        if not self.blobs.has(guard.baseline_blob_hash):
                            self._ensure_preimage_in_cas(
                                expected=guard.baseline_blob_hash,
                                recovery=recovery,
                            )
                # Remove every journal-named artifact while the journal still
                # exists.  If we crash before indexing the reappeared file,
                # recovery sees the live mismatch and preserves it on retry;
                # the inverse order could orphan hidden artifacts forever.
                self._unlink_journal_artifact(staging)
                self._unlink_journal_artifact(recovery)
                if recovery is not None:
                    recovery = None
                self._preserve_changed_local_generation(
                    folder_name=folder_name,
                    rel_path=entry.file_path,
                )
                self._pending_apply_guards.pop(
                    (folder_name, entry.file_path),
                    None,
                )
                return False

            if not self._transition_pending_apply(
                guard=guard,
                phase="publish_prepared",
                staging_name=staging.name,
                recovery_name=recovery.name if recovery is not None else None,
            ):
                raise RuntimeError("pending apply disappeared before publication")
            try:
                staging_link_remains = self._publish_staging_noreplace(staging, dst)
            except FileExistsError:
                # A local generation won the final publication race.  Keep it,
                # remove journal artifacts while the intent is still durable,
                # then atomically index that generation and retire the intent.
                appeared = dst.lstat()
                if stat.S_ISLNK(appeared.st_mode) or not stat.S_ISREG(
                    appeared.st_mode,
                ):
                    log.error(
                        "non-regular destination won %s/%s publish race",
                        folder_name,
                        entry.file_path,
                    )
                    return False
                if recovery is not None:
                    if guard is not None and guard.baseline_blob_hash is not None:
                        if not self.blobs.has(guard.baseline_blob_hash):
                            self._ensure_preimage_in_cas(
                                expected=guard.baseline_blob_hash,
                                recovery=recovery,
                            )
                self._unlink_journal_artifact(staging)
                self._unlink_journal_artifact(recovery)
                if recovery is not None:
                    recovery = None
                self._preserve_changed_local_generation(
                    folder_name=folder_name,
                    rel_path=entry.file_path,
                )
                self._pending_apply_guards.pop(
                    (folder_name, entry.file_path),
                    None,
                )
                return False
            published = True
            if staging_link_remains:
                staging.unlink()
            self._fsync_parent(dst)
            if not self._transition_pending_apply(
                guard=guard,
                phase="published",
                staging_name=None,
                recovery_name=recovery.name if recovery is not None else None,
            ):
                raise RuntimeError("pending apply disappeared after publication")
            final_proof = self._stable_path_hash(dst)
            if (
                final_proof is None
                or final_proof[0] != entry.blob_hash
                or final_proof[2] != int(entry.size or 0)
                or self._record_materialized_proof(
                    folder_name,
                    entry.file_path,
                    entry.blob_hash,
                    dst,
                    expected_evidence=final_proof[1],
                )
                is None
            ):
                raise OSError("materialized file changed before proof publication")
            if recovery is not None:
                if guard is not None and guard.baseline_blob_hash is not None:
                    if not self.blobs.has(guard.baseline_blob_hash):
                        self._ensure_preimage_in_cas(
                            expected=guard.baseline_blob_hash,
                            recovery=recovery,
                        )
                recovery.unlink()
                self._fsync_parent(recovery)
                recovery = None
            self._retire_pending_apply(
                folder_name=folder_name,
                rel_path=entry.file_path,
                guard=guard,
            )
            return True
        finally:
            with contextlib.suppress(OSError):
                staging.unlink()
            if recovery is not None and recovery.exists():
                if not published and not dst.exists():
                    with contextlib.suppress(OSError):
                        replace_path(recovery, dst)
                        self._fsync_parent(dst)
                # A published target keeps its journal-named recovery copy
                # until restart can prove the target and retire it.

    def _delete_on_disk(self, folder_name: str, rel_path: str) -> bool:
        with self._path_lock(folder_name, rel_path):
            folder = self.state.get_folder(folder_name)
            if not folder:
                return False
            root = Path(folder["local_path"])
            dst = _safe_child(root, rel_path)
            if dst is None or _has_symlink_in_chain(dst, root):
                log.warning("refusing unsafe tombstone path: %r", rel_path)
                return False
            if not self._pending_guard_allows_target(
                folder_name=folder_name,
                rel_path=rel_path,
                target_blob_hash=None,
                dst=dst,
            ):
                return False
            try:
                live_stat = dst.lstat()
            except FileNotFoundError:
                self._retire_pending_apply(
                    folder_name=folder_name,
                    rel_path=rel_path,
                )
                self._invalidate_materialized_proof(folder_name, rel_path)
                return True
            if stat.S_ISLNK(live_stat.st_mode) or not stat.S_ISREG(live_stat.st_mode):
                log.warning("refusing non-regular tombstone path: %r", rel_path)
                return False

            guard = self._pending_apply_guards.get((folder_name, rel_path))
            quarantine = dst.parent / f".one-link-{secrets.token_hex(12)}.tmp"
            if not self._transition_pending_apply(
                guard=guard,
                phase="recovery_prepared",
                staging_name=None,
                recovery_name=quarantine.name,
            ):
                return False
            try:
                replace_path(dst, quarantine)
                self._fsync_parent(dst)
                if not self._transition_pending_apply(
                    guard=guard,
                    phase="recovery_moved",
                    staging_name=None,
                    recovery_name=quarantine.name,
                ):
                    raise RuntimeError("pending delete disappeared after recovery move")
                if guard is not None and guard.baseline_blob_hash is not None:
                    moved = self._stable_path_hash(quarantine)
                    if moved is None or moved[0] != guard.baseline_blob_hash:
                        if dst.exists() or dst.is_symlink():
                            log.error(
                                "destination reappeared while deleting %s/%s; "
                                "retaining recovery artifact",
                                folder_name,
                                rel_path,
                            )
                            return False
                        replace_path(quarantine, dst)
                        self._fsync_parent(dst)
                        self._preserve_changed_local_generation(
                            folder_name=folder_name,
                            rel_path=rel_path,
                        )
                        self._pending_apply_guards.pop(
                            (folder_name, rel_path),
                            None,
                        )
                        return False
                if not self._transition_pending_apply(
                    guard=guard,
                    phase="unlink_prepared",
                    staging_name=None,
                    recovery_name=quarantine.name,
                ):
                    raise RuntimeError("pending delete disappeared before unlink")
                if guard is not None and guard.baseline_blob_hash is not None:
                    if not self.blobs.has(guard.baseline_blob_hash):
                        self._ensure_preimage_in_cas(
                            expected=guard.baseline_blob_hash,
                            recovery=quarantine,
                        )
                quarantine.unlink()
                self._fsync_parent(quarantine)
                self._retire_pending_apply(
                    folder_name=folder_name,
                    rel_path=rel_path,
                    guard=guard,
                )
                self._invalidate_materialized_proof(folder_name, rel_path)
                return True
            except OSError as exc:
                if quarantine.exists() and not dst.exists():
                    with contextlib.suppress(OSError):
                        replace_path(quarantine, dst)
                        self._fsync_parent(dst)
                log.warning(
                    "could not apply tombstone %s/%s: %s",
                    folder_name,
                    rel_path,
                    exc,
                )
                return False

    def _start_watch(self, name: str, root: Path) -> None:
        if name in self._folders:
            return
        root = root.resolve()
        root.mkdir(parents=True, exist_ok=True)

        def mark_dirty(path: str, action: str):
            rel_path = _safe_relpath(root, Path(path))
            if rel_path is not None and _is_internal_relpath(rel_path):
                return
            if rel_path is not None:
                # Invalidate synchronously in the watchdog thread.  The
                # debounce delays indexing, but it must never leave an old
                # content proof eligible while a local edit is pending.
                self._invalidate_materialized_proof(name, rel_path)
            with self._dirty_lock:
                folder_dirty = self._dirty.setdefault(name, {})
                folder_dirty[path] = action
            self.loop.call_soon_threadsafe(self._wake.set)

        handler = _Handler(mark_dirty)
        observer = Observer()
        observer.schedule(handler, str(root), recursive=True)
        observer.start()
        self._folders[name] = FolderState(
            name=name, root=root, observer=observer, handler=handler,
        )
        log.info("watching %s at %s", name, root)

    def _scan_full(self, name: str, root: Path) -> None:
        """Bring one manifest fully in line with a successful disk walk.

        The seen set is applied only after ``rglob`` reaches EOF.  A partial
        walk caused by an I/O/permission error must never manufacture mass
        tombstones, while an offline delete or dropped watcher event must be
        discovered by the next complete safety scan.
        """
        seen: set[str] = set()
        complete = True

        def on_walk_error(exc: OSError) -> None:
            nonlocal complete
            complete = False
            log.warning("folder scan could not enumerate %s: %s", name, exc)

        for current, directory_names, file_names in os.walk(
            root,
            topdown=True,
            onerror=on_walk_error,
            followlinks=False,
        ):
            current_path = Path(current)
            safe_directories: list[str] = []
            for directory_name in directory_names:
                candidate = current_path / directory_name
                try:
                    directory_stat = candidate.lstat()
                except OSError as exc:
                    on_walk_error(exc)
                    continue
                if stat.S_ISLNK(directory_stat.st_mode):
                    continue
                if not stat.S_ISDIR(directory_stat.st_mode):
                    complete = False
                    continue
                safe_directories.append(directory_name)
            directory_names[:] = safe_directories
            for file_name in file_names:
                path = current_path / file_name
                try:
                    file_stat = path.lstat()
                except OSError as exc:
                    on_walk_error(exc)
                    continue
                if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(
                    file_stat.st_mode,
                ):
                    continue
                rel = _safe_relpath(root, path)
                if rel is None:
                    complete = False
                    continue
                if _is_internal_relpath(rel):
                    continue
                seen.add(rel)
                self._reconcile_file(name, path)
        if not complete:
            log.warning(
                "folder scan for %s was incomplete; suppressing tombstones",
                name,
            )
            return
        for row in self.state.list_manifest(name):
            rel_path = str(row.get("file_path") or "")
            if row.get("blob_hash") is None or rel_path in seen:
                continue
            if (name, rel_path) in self._pending_apply_guards:
                # A new remote file may legitimately have no on-disk name
                # until its journaled CAS target arrives. Do not reinterpret
                # that expected absence as an offline local deletion.
                continue
            self._tombstone_file(name, root, root / Path(rel_path))

    def register_for_one_shot_no_watcher(
        self, name: str, root: Path,
    ) -> None:
        """v0.21.x: register a folder under a NO-OP watcher entry so
        scan + manifest population work, but no Observer thread is
        ever started. Used by ad-hoc one-shot folder send:

          1. state.add_folder + this method   (no watcher overhead)
          2. start_initial_scan(name)         (populates manifest)
          3. push_folder_to_peer(...)         (uses the manifest)
          4. remove_folder(name)              (cleans state row + this entry)

        Saves the ~3-30ms spent spawning a watchdog Observer thread
        for a folder we'll tear down within seconds. Critically:
        avoids leaving an Observer thread leaked on cleanup edge
        cases — there's no thread to stop.
        """
        if name in self._folders:
            return
        root = Path(root).resolve()
        # Use a sentinel observer + handler — both shapes the rest of
        # the code can call into harmlessly. remove_folder unconditionally
        # calls observer.stop() + .join() which work fine on the stub.
        class _NoopObserver:
            def stop(self): pass
            def join(self, timeout=None): pass
        noop_observer = _NoopObserver()
        noop_handler = _Handler(lambda *_a, **_kw: None)
        self._folders[name] = FolderState(
            name=name, root=root,
            observer=noop_observer, handler=noop_handler,
        )

    async def _periodic_scan(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=SCAN_INTERVAL_S)
            except asyncio.TimeoutError:
                pass
            if self._stop.is_set():
                return
            for fname, fs in list(self._folders.items()):
                try:
                    # Hashing and fsync belong on a worker, never on the
                    # daemon heartbeat/event loop.  State is configured for
                    # cross-thread WAL access and per-path stripes serialize
                    # this scan with watcher and materialization work.
                    await asyncio.to_thread(
                        self.recover_pending_applies,
                        folder_name=fname,
                    )
                    await asyncio.to_thread(self._scan_full, fname, fs.root)
                except Exception as e:
                    log.warning("periodic scan failed for %s: %s", fname, e)

    async def _dirty_pump(self) -> None:
        while not self._stop.is_set():
            try:
                await self._wake.wait()
            except asyncio.CancelledError:
                return
            self._wake.clear()
            if self._stop.is_set():
                return
            # Debounce — let bursts settle
            await asyncio.sleep(DEBOUNCE_MS / 1000.0)
            with self._dirty_lock:
                snapshot = self._dirty
                self._dirty = {}
            # Hashing, CAS fsync, and SQLite FULL commits are intentionally
            # off-loop. A single multi-gigabyte watcher event must not freeze
            # encrypted channels, calls, or UI heartbeats.
            await asyncio.to_thread(self._process_dirty_batch, snapshot)

    def _process_dirty_batch(self, snapshot: dict[str, dict[str, str]]) -> None:
        for folder_name, items in snapshot.items():
            fs = self._folders.get(folder_name)
            if not fs:
                continue
            # v0.21.x rename detection: when a delete + create land in the
            # same debounce window and content addresses match, preserve the
            # inherited CRDT history instead of emitting unrelated changes.
            prehashed: dict[
                str,
                tuple[str, tuple[int, int, int, int, int]],
            ] = {}
            renames = self._detect_renames(
                folder_name,
                fs,
                items,
                prehashed=prehashed,
            )
            renamed_handled: set[str] = set()
            for old_rel, new_rel, blob_hex, new_path in renames:
                try:
                    self._reconcile_rename(
                        folder_name,
                        fs,
                        old_rel,
                        new_rel,
                        blob_hex,
                        new_path,
                        expected_evidence=prehashed.get(str(new_path), ("", None))[1],
                    )
                    renamed_handled.add(str(fs.root / old_rel))
                    renamed_handled.add(str(new_path))
                except Exception as exc:
                    log.warning(
                        "rename reconcile failed for %s -> %s: %s",
                        old_rel,
                        new_rel,
                        exc,
                    )
            for path, action in items.items():
                if path in renamed_handled:
                    continue
                candidate = Path(path)
                try:
                    if action == "deleted" or not candidate.exists():
                        self._tombstone_file(folder_name, fs.root, candidate)
                    else:
                        self._reconcile_file(
                            folder_name,
                            candidate,
                            prehashed=prehashed.get(str(candidate)),
                        )
                except Exception as exc:
                    log.warning("dirty handle failed for %s: %s", path, exc)

    def _detect_renames(
        self,
        folder_name: str,
        fs,
        items: dict,
        *,
        prehashed: Optional[
            dict[str, tuple[str, tuple[int, int, int, int, int]]]
        ] = None,
    ) -> list[tuple[str, str, str, Path]]:
        """Pair deleted-path events with new-create events that have
        identical content (same blob_hash). Returns a list of
        (old_rel, new_rel, blob_hex, new_path) tuples for matched
        pairs. Unmatched events fall back to the standard tombstone
        or reconcile path.

        Pairing rules:
          - For each deleted path: look up its blob_hash in the
            manifest BEFORE tombstoning.
          - For each created path: hash the file once.
          - Pair when blob_hash matches AND old_rel != new_rel.
          - 1:1 pairing — the first match wins (handles
            renames cleanly; doesn't false-positive on copies of
            duplicate-content files because the original still
            exists for the copy case).
        """
        deletes: list[tuple[str, str]] = []  # (rel, blob_hash)
        for path, action in items.items():
            p = Path(path)
            rel = _safe_relpath(fs.root, p)
            if rel is None:
                continue
            if action == "deleted" or not p.exists():
                entry = self.state.get_manifest_entry(folder_name, rel)
                if entry and entry.get("blob_hash"):
                    deletes.append((rel, entry["blob_hash"]))
        if not deletes:
            return []

        creates: list[tuple[str, str, Path]] = []  # (rel, blob_hash, path)
        for path, action in items.items():
            candidate = Path(path)
            if action == "deleted" or not candidate.exists():
                continue
            rel = _safe_relpath(fs.root, candidate)
            if rel is None:
                continue
            existing = self.state.get_manifest_entry(folder_name, rel)
            try:
                before = candidate.lstat()
                if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
                    continue
                before_evidence = self._disk_evidence(before)
                blob_hex = self.blobs.put_path(candidate)
                after = candidate.lstat()
                after_evidence = self._disk_evidence(after)
                if (
                    stat.S_ISLNK(after.st_mode)
                    or not stat.S_ISREG(after.st_mode)
                    or before_evidence != after_evidence
                ):
                    continue
            except (OSError, ValueError) as exc:
                log.warning(
                    "rename candidate ingest failed for %s/%s: %s",
                    folder_name,
                    rel,
                    exc,
                )
                continue
            if prehashed is not None:
                prehashed[str(candidate)] = (blob_hex, after_evidence)
            if existing and existing.get("blob_hash") == blob_hex:
                continue
            creates.append((rel, blob_hex, candidate))
        if not creates:
            return []
        renames: list[tuple[str, str, str, Path]] = []
        used_creates: set[str] = set()
        for old_rel, old_hash in deletes:
            for new_rel, new_hash, new_path in creates:
                if new_rel in used_creates:
                    continue
                if old_hash != new_hash:
                    continue
                if old_rel == new_rel:
                    continue
                renames.append((old_rel, new_rel, old_hash, new_path))
                used_creates.add(new_rel)
                break
        return renames

    def _reconcile_rename(
        self, folder_name: str, fs, old_rel: str, new_rel: str,
        blob_hex: str, new_path: Path,
        *,
        expected_evidence: tuple[int, int, int, int, int] | None = None,
    ) -> None:
        """Apply a detected rename: tombstone the old path + create
        the new entry with an INHERITED vclock (bumped by us) so
        peers see continuous history.

        The locked implementation retains the externally audited contract:
        ``record_folder_audit_event(`` records action ``renamed`` with a
        ``renamed from`` note after both manifest rows commit.
        """
        del fs
        with self._manifest_lock, self._locked_paths(
            folder_name,
            (old_rel, new_rel),
        ):
            self._reconcile_rename_locked(
                folder_name,
                old_rel,
                new_rel,
                blob_hex,
                new_path,
                expected_evidence=expected_evidence,
            )

    def _reconcile_rename_locked(
        self,
        folder_name: str,
        old_rel: str,
        new_rel: str,
        blob_hex: str,
        new_path: Path,
        *,
        expected_evidence: tuple[int, int, int, int, int] | None,
    ) -> None:
        if self.state.get_folder(folder_name) is None:
            return
        try:
            file_stat = new_path.lstat()
        except OSError:
            return
        if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
            return
        evidence = self._disk_evidence(file_stat)
        if expected_evidence is not None:
            if evidence != expected_evidence or not self.blobs.has(blob_hex):
                return
        else:
            proof = self._stable_path_hash(new_path)
            if proof is None or proof[0] != blob_hex:
                return
            evidence = proof[1]
            file_stat = new_path.lstat()
            if self._disk_evidence(file_stat) != evidence:
                return
        old_entry = self.state.get_manifest_entry(folder_name, old_rel)
        # Inherit the old vclock so the new path's history is
        # connected to the old path's. Each operation increments
        # our slot once.
        base_clock = (
            VectorClock.from_dict(old_entry["vclock"])
            if old_entry else VectorClock.empty()
        )
        new_entry_clock = base_clock.increment(self.me_fp)
        self.state.record_blob(blob_hex, file_stat.st_size)
        # Tombstone the old path: same shape as _tombstone_file —
        # formerly an upsert_manifest_entry(..., blob_hash=None) plus a
        # separate live upsert. Both rows now share one SQLite transaction so
        # a crash can never publish only half of a rename.
        # Use a separately-bumped clock so
        # the tombstone propagates independently from the new entry.
        tombstone_clock = new_entry_clock.increment(self.me_fp)
        self.state.upsert_manifest_entries_atomic(
            folder_name=folder_name,
            entries=[
                {
                    "file_path": new_rel,
                    "blob_hash": blob_hex,
                    "size": file_stat.st_size,
                    "mtime_ms": int(file_stat.st_mtime * 1000),
                    "vclock": new_entry_clock.to_dict(),
                },
                {
                    "file_path": old_rel,
                    "blob_hash": None,
                    "size": None,
                    "mtime_ms": int(time.time() * 1000),
                    "vclock": tombstone_clock.to_dict(),
                },
            ],
            pending_applies=[],
        )
        self._pending_apply_guards.pop((folder_name, new_rel), None)
        self._pending_apply_guards.pop((folder_name, old_rel), None)
        # Audit log: 'renamed' action with the old path in the note.
        # peer_fp = me_fp since this is a local-origin rename.
        try:
            self.state.record_folder_audit_event(
                folder_name=folder_name,
                peer_fp=self.me_fp,
                action="renamed",
                file_path=new_rel,
                blob_hash=blob_hex,
                size=file_stat.st_size,
                note=f"renamed from {old_rel}",
            )
        except Exception as exc:
            # Audit persistence is non-authoritative to the CRDT mutation, but
            # losing it must be visible to operators.
            log.warning(
                "rename audit event failed for %s/%s: %s",
                folder_name,
                new_rel,
                exc,
                exc_info=True,
            )
        log.info(
            "rename detected: %s/%s -> %s (blob=%s)",
            folder_name, old_rel, new_rel, blob_hex[:12],
        )

    def _reconcile_file(
        self,
        folder_name: str,
        p: Path,
        *,
        prehashed: tuple[str, tuple[int, int, int, int, int]] | None = None,
    ) -> None:
        """Hash file, ingest into blob store, update manifest if changed."""
        fs = self._folders.get(folder_name)
        if not fs:
            return
        rel = _safe_relpath(fs.root, p)
        if rel is None:
            return
        with self._path_lock(folder_name, rel):
            if self.state.get_folder(folder_name) is None:
                return
            existing = self.state.get_manifest_entry(folder_name, rel)
            pending_guard = self._pending_apply_guards.get((folder_name, rel))
            if pending_guard is not None:
                try:
                    pending_stat = p.lstat()
                except OSError:
                    pending_stat = None
                if (
                    pending_stat is not None
                    and pending_guard.baseline_evidence is not None
                    and not stat.S_ISLNK(pending_stat.st_mode)
                    and stat.S_ISREG(pending_stat.st_mode)
                    and self._disk_evidence(pending_stat)
                    == pending_guard.baseline_evidence
                ):
                    # This exact generation is intentionally retained until
                    # the remote target blob arrives; it is not a local edit.
                    return
            existing_hash = (
                existing.get("blob_hash") if isinstance(existing, dict) else None
            )
            if (
                isinstance(existing_hash, str)
                and self._materialized_proof_matches(
                    folder_name,
                    rel,
                    existing_hash,
                    p,
                ) is not None
            ):
                if pending_guard is not None:
                    self._retire_pending_apply(
                        folder_name=folder_name,
                        rel_path=rel,
                        guard=pending_guard,
                    )
                return
            self._invalidate_materialized_proof(folder_name, rel)
            try:
                file_stat = p.lstat()
                if (
                    stat.S_ISLNK(file_stat.st_mode)
                    or not stat.S_ISREG(file_stat.st_mode)
                ):
                    return
                before_evidence = self._disk_evidence(file_stat)
                if (
                    prehashed is not None
                    and prehashed[1] == before_evidence
                    and self.blobs.has(prehashed[0])
                ):
                    blob_hex = prehashed[0]
                    after_stat = file_stat
                    after_evidence = before_evidence
                else:
                    blob_hex = self.blobs.put_path(p)
                    after_stat = p.lstat()
                    after_evidence = self._disk_evidence(after_stat)
                    if (
                        stat.S_ISLNK(after_stat.st_mode)
                        or not stat.S_ISREG(after_stat.st_mode)
                        or before_evidence != after_evidence
                    ):
                        # The watcher/next scan retries the new generation.
                        return
            except (OSError, ValueError):
                return
            self.state.record_blob(blob_hex, after_stat.st_size)

            if existing and existing["blob_hash"] == blob_hex:
                self._record_materialized_proof(
                    folder_name,
                    rel,
                    blob_hex,
                    p,
                    expected_evidence=after_evidence,
                )
                if pending_guard is not None:
                    self._retire_pending_apply(
                        folder_name=folder_name,
                        rel_path=rel,
                        guard=pending_guard,
                    )
                return

            old_clock = (
                VectorClock.from_dict(existing["vclock"])
                if existing else VectorClock.empty()
            )
            new_clock = old_clock.increment(self.me_fp)
            entry = ManifestEntry(
                file_path=rel,
                blob_hash=blob_hex,
                size=after_stat.st_size,
                mtime_ms=int(after_stat.st_mtime * 1000),
                vclock=new_clock,
            )
            self.state.upsert_manifest_entry(
                folder_name=folder_name,
                file_path=entry.file_path,
                blob_hash=entry.blob_hash,
                size=entry.size,
                mtime_ms=entry.mtime_ms,
                vclock=entry.vclock.to_dict(),
                clear_pending_apply=True,
            )
            self._pending_apply_guards.pop((folder_name, rel), None)
            self._record_materialized_proof(
                folder_name,
                rel,
                blob_hex,
                p,
                expected_evidence=after_evidence,
            )
            if self.on_local_change:
                asyncio.run_coroutine_threadsafe(
                    self.on_local_change(folder_name, entry), self.loop,
                )
            log.info(
                "local change %s : %s -> %s",
                folder_name,
                rel,
                blob_hex[:8],
            )

    def _tombstone_file(self, folder_name: str, root: Path, p: Path) -> None:
        rel = _safe_relpath(root, p)
        if rel is None:
            return
        with self._path_lock(folder_name, rel):
            if self.state.get_folder(folder_name) is None:
                return
            self._invalidate_materialized_proof(folder_name, rel)
            existing = self.state.get_manifest_entry(folder_name, rel)
            if not existing or existing["blob_hash"] is None:
                return
            old_clock = VectorClock.from_dict(existing["vclock"])
            new_clock = old_clock.increment(self.me_fp)
            entry = ManifestEntry(
                file_path=rel,
                blob_hash=None,
                size=None,
                mtime_ms=int(time.time() * 1000),
                vclock=new_clock,
            )
            self.state.upsert_manifest_entry(
                folder_name=folder_name,
                file_path=entry.file_path,
                blob_hash=None,
                size=None,
                mtime_ms=entry.mtime_ms,
                vclock=entry.vclock.to_dict(),
                clear_pending_apply=True,
            )
            self._pending_apply_guards.pop((folder_name, rel), None)
            if self.on_local_change:
                asyncio.run_coroutine_threadsafe(
                    self.on_local_change(folder_name, entry), self.loop,
                )
            log.info("local tombstone %s : %s", folder_name, rel)
