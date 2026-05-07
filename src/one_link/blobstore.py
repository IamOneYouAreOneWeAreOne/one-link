"""Content-addressed blob store.

Files are stored under `<root>/<aa>/<rest>` where `<aa>` is the first two
hex chars of the BLAKE3 hash and `<rest>` is the remaining 62 hex chars.
The two-level layout keeps any single directory bounded.

All writes go through an atomic-rename pattern so partial writes never
present as a valid blob.
"""

from __future__ import annotations

import contextlib
import os
import secrets
import shutil
import time
from pathlib import Path
from typing import Iterable, Iterator

import blake3


def _is_hex(s: str) -> bool:
    if len(s) != 64:
        return False
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


class BlobStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._tmp = self.root / "_tmp"
        self._tmp.mkdir(parents=True, exist_ok=True)

    # ─── path math ────────────────────────────────────────────────────
    def path(self, hash_hex: str) -> Path:
        if not _is_hex(hash_hex):
            raise ValueError(f"not a 64-char lower hex hash: {hash_hex!r}")
        return self.root / hash_hex[:2] / hash_hex[2:]

    def has(self, hash_hex: str) -> bool:
        try:
            return self.path(hash_hex).is_file()
        except ValueError:
            return False

    def size(self, hash_hex: str) -> int:
        return self.path(hash_hex).stat().st_size

    # ─── writes ───────────────────────────────────────────────────────
    def put_bytes(self, data: bytes) -> str:
        h = blake3.blake3(data).hexdigest()
        if self.has(h):
            return h
        dst = self.path(h)
        dst.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._tmp / f"put_{secrets.token_hex(8)}"
        tmp.write_bytes(data)
        os.replace(tmp, dst)
        return h

    def put_path(self, src: Path) -> str:
        """Hash and ingest an existing file. Streams; bounded memory."""
        src = Path(src)
        h = blake3.blake3()
        with open(src, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        hex_ = h.hexdigest()
        if self.has(hex_):
            return hex_
        dst = self.path(hex_)
        dst.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._tmp / f"put_{secrets.token_hex(8)}"
        # Copy then atomic-rename. Don't move (`shutil.move`) because src
        # is the user's file and we never want to move it out of place.
        shutil.copyfile(src, tmp)
        os.replace(tmp, dst)
        return hex_

    @contextlib.contextmanager
    def writer(self) -> Iterator[tuple["BlobWriter", Path]]:
        """Open a streaming writer. On commit, returns the hash; on
        cancellation, the temp file is cleaned up.

        Usage:
            with store.writer() as (w, _):
                w.write(chunk1); w.write(chunk2)
                hash_hex = w.commit()
        """
        tmp = self._tmp / f"put_{secrets.token_hex(8)}"
        bw = BlobWriter(tmp, self)
        try:
            yield bw, tmp
        finally:
            bw.close_if_open()
            if tmp.exists() and not bw.committed:
                with contextlib.suppress(OSError):
                    tmp.unlink()

    # ─── reads ────────────────────────────────────────────────────────
    def open_read(self, hash_hex: str):
        return open(self.path(hash_hex), "rb")

    def read_bytes(self, hash_hex: str) -> bytes:
        return self.path(hash_hex).read_bytes()

    def verify(self, hash_hex: str) -> bool:
        """Re-hash a stored blob and confirm its address still matches."""
        if not self.has(hash_hex):
            return False
        h = blake3.blake3()
        try:
            with self.open_read(hash_hex) as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
        except OSError:
            return False
        return h.hexdigest() == hash_hex

    def audit(self) -> dict:
        """Return an integrity summary for the whole store."""
        ok: list[dict] = []
        corrupt: list[dict] = []
        for hash_hex, size in self.iter_blobs():
            entry = {"hash": hash_hex, "size": size}
            if self.verify(hash_hex):
                ok.append(entry)
            else:
                corrupt.append(entry)
        return {
            "ok": len(corrupt) == 0,
            "blobs": len(ok) + len(corrupt),
            "verified": len(ok),
            "corrupt": corrupt,
        }

    def cleanup_tmp(self, *, older_than_ms: int = 0) -> int:
        """Remove abandoned temp files left by interrupted writes."""
        now = time.time()
        removed = 0
        for p in self._tmp.iterdir():
            if not p.is_file():
                continue
            try:
                age_ms = int((now - p.stat().st_mtime) * 1000)
            except OSError:
                continue
            if age_ms >= older_than_ms:
                with contextlib.suppress(OSError):
                    p.unlink()
                    removed += 1
        return removed

    # ─── enumeration / GC ─────────────────────────────────────────────
    def iter_blobs(self) -> Iterable[tuple[str, int]]:
        for shard in self.root.iterdir():
            if shard.name == "_tmp":
                continue
            if not shard.is_dir() or len(shard.name) != 2:
                continue
            for f in shard.iterdir():
                if f.is_file() and _is_hex(shard.name + f.name):
                    yield (shard.name + f.name, f.stat().st_size)

    def remove(self, hash_hex: str) -> bool:
        p = self.path(hash_hex)
        if p.is_file():
            p.unlink()
            # Try to remove the shard dir if it became empty (best-effort)
            with contextlib.suppress(OSError):
                p.parent.rmdir()
            return True
        return False

    def total_size(self) -> int:
        return sum(sz for _, sz in self.iter_blobs())


class BlobWriter:
    """Streaming write context. Hash computed incrementally."""

    def __init__(self, tmp_path: Path, store: BlobStore):
        self._fh = open(tmp_path, "wb")
        self._h = blake3.blake3()
        self._tmp = tmp_path
        self._store = store
        self.committed = False

    def write(self, data: bytes) -> None:
        if self._fh is None:
            raise RuntimeError("writer is closed")
        self._h.update(data)
        self._fh.write(data)

    def commit(self) -> str:
        if self.committed:
            raise RuntimeError("already committed")
        if self._fh is None:
            raise RuntimeError("writer is closed")
        self._fh.flush()
        os.fsync(self._fh.fileno())
        self._fh.close()
        self._fh = None
        hex_ = self._h.hexdigest()
        dst = self._store.path(hex_)
        dst.parent.mkdir(parents=True, exist_ok=True)
        os.replace(self._tmp, dst)
        self.committed = True
        return hex_

    def close_if_open(self) -> None:
        if self._fh is not None:
            with contextlib.suppress(OSError):
                self._fh.close()
            self._fh = None
