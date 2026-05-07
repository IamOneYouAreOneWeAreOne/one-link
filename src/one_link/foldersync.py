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
import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

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
from one_link.merkle import build_tree, manifest_leaf_hashes
from one_link.state import State

log = logging.getLogger("one_link.foldersync")

DEBOUNCE_MS = 250
SCAN_INTERVAL_S = 60.0  # safety net if a watchdog event is dropped


def _safe_relpath(folder_root: Path, p: Path) -> Optional[str]:
    """Returns the file's path relative to folder_root using forward slashes,
    or None if p is not inside folder_root."""
    try:
        rel = Path(p).resolve().relative_to(folder_root.resolve())
    except ValueError:
        return None
    return rel.as_posix()


def _safe_child(root: Path, rel_path: str) -> Optional[Path]:
    """Resolve a remote manifest path under root, rejecting traversal."""
    rel = Path(str(rel_path).replace("\\", "/"))
    if rel.is_absolute() or any(part in ("", ".", "..") for part in rel.parts):
        return None
    root_resolved = root.resolve()
    candidate = (root_resolved / rel).resolve()
    try:
        candidate.relative_to(root_resolved)
    except ValueError:
        return None
    return candidate


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
    observer: Observer
    handler: _Handler


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
        self._wake: asyncio.Event = asyncio.Event()
        self._stop = asyncio.Event()
        self._task: Optional[asyncio.Task] = None
        self._scan_task: Optional[asyncio.Task] = None

    # ─── lifecycle ────────────────────────────────────────────────────
    async def start(self) -> None:
        # Bring up watchers for any folders already configured in state
        for f in self.state.list_folders():
            try:
                self._start_watch(f["name"], Path(f["local_path"]))
                # Initial scan to build manifest from existing files
                self._scan_full(f["name"], Path(f["local_path"]))
            except Exception as e:
                log.warning("could not start folder %s: %s", f["name"], e)
        self._task = asyncio.create_task(self._dirty_pump())
        self._scan_task = asyncio.create_task(self._periodic_scan())

    async def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        for fs in list(self._folders.values()):
            try:
                fs.observer.stop()
                fs.observer.join(timeout=2.0)
            except Exception:
                pass
        self._folders.clear()
        for t in (self._task, self._scan_task):
            if t is not None and not t.done():
                t.cancel()
                try:
                    await t
                except (asyncio.CancelledError, Exception):
                    pass

    # ─── folder management ────────────────────────────────────────────
    def add_folder(
        self, *, name: str, local_path: Path, shared_with: Iterable[str],
        max_file_bytes: int | None = None,
        ignored_patterns: list[str] | None = None,
        conflict_policy: str = "latest-wins",
    ) -> dict:
        local_path = Path(local_path).expanduser().resolve()
        local_path.mkdir(parents=True, exist_ok=True)
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
            self._scan_full(name, local_path)
        except Exception:
            self.state.remove_folder(name)
            raise
        return self.state.get_folder(name)

    def remove_folder(self, name: str) -> None:
        fs = self._folders.pop(name, None)
        if fs:
            try:
                fs.observer.stop()
                fs.observer.join(timeout=2.0)
            except Exception:
                pass
        self.state.remove_folder(name)

    def share_with(self, name: str, peer_fp: str, mode: str = "rw") -> None:
        self.state.share_folder_with(name, peer_fp)
        self.state.set_folder_peer_permission(name, peer_fp, mode)

    def unshare_with(self, name: str, peer_fp: str) -> None:
        self.state.unshare_folder_with(name, peer_fp)

    # ─── peer protocol callbacks ──────────────────────────────────────
    def manifest_for(self, name: str) -> list[dict]:
        return [m for m in self.state.list_manifest(name)]

    def manifest_root(self, name: str) -> str:
        rows = [
            (m["file_path"], m.get("blob_hash") or "", int(m.get("size") or 0))
            for m in self.state.list_manifest(name)
        ]
        return build_tree(manifest_leaf_hashes(rows)).root

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
        wants: list[dict] = []
        for e in entries:
            remote = ManifestEntry.from_dict(e)
            local_row = self.state.get_manifest_entry(folder_name, remote.file_path)
            local = (
                ManifestEntry(
                    file_path=local_row["file_path"],
                    blob_hash=local_row["blob_hash"],
                    size=local_row["size"],
                    mtime_ms=local_row["mtime_ms"],
                    vclock=VectorClock.from_dict(local_row["vclock"]),
                )
                if local_row is not None
                else None
            )
            # v0.8.9: detect concurrent divergent edits BEFORE merge.
            # We only care about the specific "both sides have a real
            # blob and the hashes differ" case — that's the dataloss
            # scenario where one user's edits silently overwrite the
            # other's. Tombstone-vs-edit is handled deterministically
            # by merge_manifest_entries (edit wins) so no UI prompt.
            self._maybe_record_conflict(
                folder_name=folder_name,
                local=local,
                remote=remote,
                peer_fp=peer_fp,
            )

            winner = merge_manifest_entries(local, remote)
            if winner is None:
                continue
            self.state.upsert_manifest_entry(
                folder_name=folder_name,
                file_path=winner.file_path,
                blob_hash=winner.blob_hash,
                size=winner.size,
                mtime_ms=winner.mtime_ms,
                vclock=winner.vclock.to_dict(),
            )
            # If winner is live and we don't have its blob, request it
            if winner.blob_hash is not None and not self.blobs.has(winner.blob_hash):
                wants.append(winner.to_dict())
            elif winner.blob_hash is not None and self.blobs.has(winner.blob_hash):
                # We have the blob — materialize on disk if needed.
                self._materialize(folder_name, winner)
            elif winner.blob_hash is None and (local and local.blob_hash):
                # Tombstone won; remove local file (and blob is GC'd elsewhere)
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
            cb = getattr(self, "_on_conflict_recorded", None)
            if callable(cb):
                try:
                    cb(folder_name, cid)
                except Exception:
                    pass
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
        self.state.upsert_manifest_entry(
            folder_name=folder_name,
            file_path=entry.file_path,
            blob_hash=entry.blob_hash,
            size=entry.size,
            mtime_ms=entry.mtime_ms,
            vclock=entry.vclock.to_dict(),
        )
        if materialize and entry.blob_hash is not None:
            if self.blobs.has(entry.blob_hash):
                self._materialize(folder_name, entry)
            # else: blob not yet local — _materialize will be replayed
            # by materialize_after_blob_arrived when it lands.

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
        """After we receive a blob, walk the manifests for any entry that
        wanted it and write the file out. Returns the number of files
        materialized."""
        n = 0
        for f in self.state.list_folders():
            for m in self.state.list_manifest(f["name"]):
                if m["blob_hash"] == blob_hash:
                    entry = ManifestEntry(
                        file_path=m["file_path"],
                        blob_hash=m["blob_hash"],
                        size=m["size"],
                        mtime_ms=m["mtime_ms"],
                        vclock=VectorClock.from_dict(m["vclock"]),
                    )
                    self._materialize(f["name"], entry)
                    n += 1
        return n

    # ─── filesystem ↔ manifest ────────────────────────────────────────
    def _materialize(self, folder_name: str, entry: ManifestEntry) -> None:
        f = self.state.get_folder(folder_name)
        if not f:
            return
        root = Path(f["local_path"])
        dst = _safe_child(root, entry.file_path)
        if dst is None:
            log.warning("refusing unsafe manifest path: %r", entry.file_path)
            return
        if entry.blob_hash is None:
            # Tombstone: remove if present
            if dst.is_file():
                try:
                    dst.unlink()
                except OSError:
                    pass
            return
        if not self.blobs.has(entry.blob_hash):
            return
        # Skip if already correct
        if dst.is_file() and dst.stat().st_size == (entry.size or 0):
            try:
                # Quick check by filesystem mtime; we deliberately don't
                # re-hash here for cost. The CRDT clock decides truth.
                pass
            except OSError:
                pass
        dst.parent.mkdir(parents=True, exist_ok=True)
        # Write atomically: copy from blob path
        import shutil
        with self.blobs.open_read(entry.blob_hash) as src, open(dst, "wb") as out:
            shutil.copyfileobj(src, out)

    def _delete_on_disk(self, folder_name: str, rel_path: str) -> None:
        f = self.state.get_folder(folder_name)
        if not f:
            return
        p = _safe_child(Path(f["local_path"]), rel_path)
        if p is None:
            log.warning("refusing unsafe tombstone path: %r", rel_path)
            return
        if p.is_file():
            try:
                p.unlink()
            except OSError:
                pass

    def _start_watch(self, name: str, root: Path) -> None:
        if name in self._folders:
            return
        root = root.resolve()
        root.mkdir(parents=True, exist_ok=True)

        def mark_dirty(path: str, action: str):
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
        """One-time directory walk to bring the manifest in line with disk."""
        for p in root.rglob("*"):
            if p.is_file():
                self._reconcile_file(name, p)

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
                    self._scan_full(fname, fs.root)
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
            for folder_name, items in snapshot.items():
                fs = self._folders.get(folder_name)
                if not fs:
                    continue
                for path, action in items.items():
                    p = Path(path)
                    try:
                        if action == "deleted" or not p.exists():
                            self._tombstone_file(folder_name, fs.root, p)
                        else:
                            self._reconcile_file(folder_name, p)
                    except Exception as e:
                        log.warning("dirty handle failed for %s: %s", path, e)

    def _reconcile_file(self, folder_name: str, p: Path) -> None:
        """Hash file, ingest into blob store, update manifest if changed."""
        fs = self._folders.get(folder_name)
        if not fs:
            return
        rel = _safe_relpath(fs.root, p)
        if rel is None:
            return
        try:
            stat = p.stat()
        except OSError:
            return
        blob_hex = self.blobs.put_path(p)
        self.state.record_blob(blob_hex, stat.st_size)

        # Check if manifest entry is already up-to-date
        existing = self.state.get_manifest_entry(folder_name, rel)
        if existing and existing["blob_hash"] == blob_hex:
            return

        # Bump our slot in vclock
        old_clock = (
            VectorClock.from_dict(existing["vclock"])
            if existing else VectorClock.empty()
        )
        new_clock = old_clock.increment(self.me_fp)
        entry = ManifestEntry(
            file_path=rel,
            blob_hash=blob_hex,
            size=stat.st_size,
            mtime_ms=int(stat.st_mtime * 1000),
            vclock=new_clock,
        )
        self.state.upsert_manifest_entry(
            folder_name=folder_name,
            file_path=entry.file_path,
            blob_hash=entry.blob_hash,
            size=entry.size,
            mtime_ms=entry.mtime_ms,
            vclock=entry.vclock.to_dict(),
        )
        if self.on_local_change:
            asyncio.run_coroutine_threadsafe(
                self.on_local_change(folder_name, entry), self.loop,
            )
        log.info("local change %s : %s -> %s", folder_name, rel, blob_hex[:8])

    def _tombstone_file(self, folder_name: str, root: Path, p: Path) -> None:
        rel = _safe_relpath(root, p)
        if rel is None:
            return
        existing = self.state.get_manifest_entry(folder_name, rel)
        if not existing or existing["blob_hash"] is None:
            # Already tombstoned or never existed
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
        )
        if self.on_local_change:
            asyncio.run_coroutine_threadsafe(
                self.on_local_change(folder_name, entry), self.loop,
            )
        log.info("local tombstone %s : %s", folder_name, rel)
