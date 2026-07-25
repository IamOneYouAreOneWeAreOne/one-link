"""Content-addressed blob store.

Files are stored under `<root>/<aa>/<rest>` where `<aa>` is the first two
hex chars of the BLAKE3 hash and `<rest>` is the remaining 62 hex chars.
The two-level layout keeps any single directory bounded.

All writes go through an atomic-rename pattern so partial writes never
present as a valid blob.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Iterable, Iterator, cast

import blake3


PARTIAL_BLOB_VERSION = 1
PARTIAL_BLOB_CHECKPOINT_BYTES = 8 * 1024 * 1024
_PARTIAL_METADATA_DOMAIN = b"one-link-partial-blob-metadata-v1\0"


@dataclass(frozen=True)
class PartialBlobStatus:
    """Durable, verified prefix available for a content-addressed blob."""

    peer_fp: str
    blob_hash: str
    size: int
    received: int
    prefix_digest: str
    updated_ns: int


def _is_hex(s: str) -> bool:
    if len(s) != 64 or s != s.lower():
        return False
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def _is_redirected(st: os.stat_result) -> bool:
    """Return whether a path stat describes a symlink/reparse redirect."""

    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    attributes = int(getattr(st, "st_file_attributes", 0))
    return stat.S_ISLNK(st.st_mode) or bool(attributes & reparse_flag)


class BlobStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        root_stat = self.root.lstat()
        if _is_redirected(root_stat) or not stat.S_ISDIR(root_stat.st_mode):
            raise OSError("blob store root must be a real directory")
        self._tmp = self.root / "_tmp"
        self._tmp.mkdir(parents=True, exist_ok=True)
        tmp_stat = self._tmp.lstat()
        if _is_redirected(tmp_stat) or not stat.S_ISDIR(tmp_stat.st_mode):
            raise OSError("blob store temporary root must be a real directory")
        self._partials = self.root / "_partials"
        self._partials.mkdir(parents=True, exist_ok=True)
        partial_stat = self._partials.lstat()
        if _is_redirected(partial_stat) or not stat.S_ISDIR(partial_stat.st_mode):
            raise OSError("partial blob staging root must be a real directory")
        with contextlib.suppress(OSError):
            self._partials.chmod(0o700)
        self._verified: dict[str, tuple[int, int, int, int]] = {}
        self._verified_lock = threading.RLock()
        self._partial_lock = threading.RLock()
        self._active_partials: set[str] = set()

    @staticmethod
    def _stat_evidence(st: os.stat_result) -> tuple[int, int, int, int]:
        # Windows can report a slightly different st_ctime_ns for an open
        # handle than for the directory lookup of the same unchanged file.
        # File-id + size + mtime remain stable and let us bind the verified
        # path to the opened object. POSIX ctime is stable here and adds a
        # defense against restored-mtime mutations.
        ctime_ns = 0 if os.name == "nt" else int(st.st_ctime_ns)
        return (
            int(st.st_size),
            int(st.st_mtime_ns),
            ctime_ns,
            int(getattr(st, "st_ino", 0)),
        )

    @staticmethod
    def _stream_source_evidence(
        st: os.stat_result,
    ) -> tuple[bool, int, int, int, int, int]:
        """Identity and mutation evidence for one already-open source."""

        return (
            stat.S_ISREG(st.st_mode),
            int(st.st_dev),
            int(st.st_ino),
            int(st.st_size),
            int(st.st_mtime_ns),
            int(st.st_ctime_ns),
        )

    # ─── path math ────────────────────────────────────────────────────
    def path(self, hash_hex: str) -> Path:
        if not _is_hex(hash_hex):
            raise ValueError(f"not a 64-char lower hex hash: {hash_hex!r}")
        return self.root / hash_hex[:2] / hash_hex[2:]

    def has(self, hash_hex: str) -> bool:
        try:
            path = self.path(hash_hex)
        except ValueError:
            return False
        try:
            st = path.stat()
        except OSError:
            return False
        evidence = self._stat_evidence(st)
        with self._verified_lock:
            if self._verified.get(hash_hex) == evidence:
                return True
        if self._verify_path(path, hash_hex):
            with self._verified_lock:
                self._verified[hash_hex] = evidence
            return True
        # Existence is not possession in a CAS.  Keep the failed lookup
        # fail-closed, but never unlink this pathname here: a concurrent
        # writer may atomically publish the correct object after verification
        # fails and before cleanup runs.  The next legitimate ``put_*`` uses
        # ``os.replace`` and therefore heals a poisoned address safely.
        with self._verified_lock:
            self._verified.pop(hash_hex, None)
        return False

    def size(self, hash_hex: str) -> int:
        if not self.has(hash_hex):
            raise FileNotFoundError(f"verified blob is unavailable: {hash_hex}")
        return self.path(hash_hex).stat().st_size

    @staticmethod
    def _fsync_parent(path: Path) -> None:
        if os.name == "nt":
            return
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    # ─── writes ───────────────────────────────────────────────────────
    def put_bytes(self, data: bytes) -> str:
        h = blake3.blake3(data).hexdigest()
        if self.has(h):
            return h
        dst = self.path(h)
        dst.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._tmp / f"put_{secrets.token_hex(8)}"
        try:
            with open(tmp, "xb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, dst)
            self._fsync_parent(dst)
        finally:
            with contextlib.suppress(OSError):
                tmp.unlink()
        with self._verified_lock:
            self._verified.pop(h, None)
        if not self.has(h):
            raise OSError("blob CAS commit failed integrity verification")
        return h

    def put_path(self, src: Path) -> str:
        """Hash and ingest an existing file. Streams; bounded memory."""
        src = Path(src)
        before = src.lstat()
        if _is_redirected(before) or not stat.S_ISREG(before.st_mode):
            raise ValueError("blob source must be a regular non-symlink file")
        tmp = self._tmp / f"put_{secrets.token_hex(8)}"
        flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        fd = os.open(src, flags)
        h = blake3.blake3()
        try:
            opened = os.fstat(fd)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
            ):
                raise OSError("blob source changed while opening")
            with os.fdopen(fd, "rb", closefd=True) as source, open(tmp, "xb") as out:
                fd = -1
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    h.update(chunk)
                    out.write(chunk)
                opened_after = os.fstat(source.fileno())
                if (
                    not stat.S_ISREG(opened_after.st_mode)
                    or self._stream_source_evidence(opened_after)
                    != self._stream_source_evidence(opened)
                ):
                    raise OSError("blob source changed while hashing")
                out.flush()
                os.fsync(out.fileno())
            hex_ = h.hexdigest()
            if self.has(hex_):
                return hex_
            dst = self.path(hex_)
            dst.parent.mkdir(parents=True, exist_ok=True)
            os.replace(tmp, dst)
            self._fsync_parent(dst)
            with self._verified_lock:
                self._verified.pop(hex_, None)
            if not self.has(hex_):
                raise OSError("blob CAS commit failed integrity verification")
            return hex_
        finally:
            if fd >= 0:
                os.close(fd)
            with contextlib.suppress(OSError):
                tmp.unlink()

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

    # ─── durable partial writes ──────────────────────────────────────
    @staticmethod
    def _partial_identity(peer_fp: str, blob_hash: str, size: int) -> str:
        if not _is_hex(peer_fp):
            raise ValueError("peer_fp must be canonical 64-character lower hex")
        if not _is_hex(blob_hash):
            raise ValueError("blob_hash must be canonical 64-character lower hex")
        if type(size) is not int or size < 0 or size > (1 << 63) - 1:
            raise ValueError("partial blob size is invalid")
        material = (
            b"one-link-partial-blob-key-v1\0"
            + bytes.fromhex(peer_fp)
            + bytes.fromhex(blob_hash)
            + size.to_bytes(8, "big")
        )
        return blake3.blake3(material).hexdigest()

    def _partial_paths(
        self,
        peer_fp: str,
        blob_hash: str,
        size: int,
    ) -> tuple[str, Path, Path]:
        key = self._partial_identity(peer_fp, blob_hash, size)
        return (
            key,
            self._partials / f"{key}.part",
            self._partials / f"{key}.json",
        )

    @staticmethod
    def _partial_metadata_checksum(payload: dict[str, object]) -> str:
        encoded = json.dumps(
            payload,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return blake3.blake3(_PARTIAL_METADATA_DOMAIN + encoded).hexdigest()

    @classmethod
    def _decode_partial_metadata(cls, raw: bytes) -> dict[str, object] | None:
        if len(raw) > 4096:
            return None
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            return None
        if not isinstance(decoded, dict) or set(decoded) != {
            "version",
            "peer_fp",
            "blob_hash",
            "size",
            "received",
            "prefix_digest",
            "updated_ns",
            "checksum",
        }:
            return None
        checksum = decoded.pop("checksum", None)
        if (
            not isinstance(checksum, str)
            or not _is_hex(checksum)
            or checksum != cls._partial_metadata_checksum(decoded)
        ):
            return None
        if (
            decoded.get("version") != PARTIAL_BLOB_VERSION
            or not isinstance(decoded.get("peer_fp"), str)
            or not _is_hex(str(decoded.get("peer_fp")))
            or not isinstance(decoded.get("blob_hash"), str)
            or not _is_hex(str(decoded.get("blob_hash")))
            or type(decoded.get("size")) is not int
            or type(decoded.get("received")) is not int
            or type(decoded.get("updated_ns")) is not int
            or not isinstance(decoded.get("prefix_digest"), str)
            or not _is_hex(str(decoded.get("prefix_digest")))
        ):
            return None
        size = int(decoded["size"])
        received = int(decoded["received"])
        updated_ns = int(decoded["updated_ns"])
        if (
            size < 0
            or size > (1 << 63) - 1
            or received < 0
            or received > size
            or updated_ns <= 0
        ):
            return None
        return decoded

    @staticmethod
    def _open_regular(path: Path, *, writable: bool = False) -> int:
        before = path.lstat()
        if _is_redirected(before) or not stat.S_ISREG(before.st_mode):
            raise OSError("partial blob path is not a regular file")
        flags = (os.O_RDWR if writable else os.O_RDONLY) | int(
            getattr(os, "O_BINARY", 0),
        )
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        fd = os.open(path, flags)
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
        ):
            os.close(fd)
            raise OSError("partial blob changed while opening")
        return fd

    @staticmethod
    def _hash_open_prefix(fh: IO[bytes], length: int) -> str:
        digest = blake3.blake3()
        remaining = int(length)
        while remaining:
            chunk = fh.read(min(1024 * 1024, remaining))
            if not chunk:
                raise OSError("partial blob is shorter than durable metadata")
            digest.update(chunk)
            remaining -= len(chunk)
        return digest.hexdigest()

    def _discard_partial_paths(self, key: str, data_path: Path, meta_path: Path) -> None:
        with self._partial_lock:
            if key in self._active_partials:
                raise RuntimeError("cannot discard an active partial blob")
            for path in (data_path, meta_path):
                with contextlib.suppress(OSError):
                    path.unlink()
            self._fsync_parent(data_path)

    def discard_partial(self, peer_fp: str, blob_hash: str, size: int) -> bool:
        key, data_path, meta_path = self._partial_paths(peer_fp, blob_hash, size)
        with self._partial_lock:
            if key in self._active_partials:
                return False
            existed = data_path.exists() or meta_path.exists()
            for path in (data_path, meta_path):
                with contextlib.suppress(OSError):
                    path.unlink()
            if existed:
                self._fsync_parent(data_path)
            return existed

    def partial_status(
        self,
        peer_fp: str,
        blob_hash: str,
        size: int,
    ) -> PartialBlobStatus | None:
        """Return a re-hashed durable prefix, discarding corrupt metadata.

        Data is fsynced before metadata at every checkpoint. If a crash lands
        extra bytes after the last metadata checkpoint, they are truncated to
        the advertised durable offset before a resume claim is returned.
        """

        key, data_path, meta_path = self._partial_paths(peer_fp, blob_hash, size)
        with self._partial_lock:
            if key in self._active_partials:
                return None
            try:
                meta_fd = self._open_regular(meta_path)
                with os.fdopen(meta_fd, "rb") as meta_fh:
                    metadata = self._decode_partial_metadata(meta_fh.read(4097))
                if metadata is None:
                    raise OSError("invalid partial blob metadata")
                if (
                    metadata["peer_fp"] != peer_fp
                    or metadata["blob_hash"] != blob_hash
                    or metadata["size"] != size
                ):
                    raise OSError("partial blob metadata identity mismatch")
                received = cast(int, metadata["received"])
                fd = self._open_regular(data_path, writable=True)
                with os.fdopen(fd, "r+b") as data_fh:
                    opened = os.fstat(data_fh.fileno())
                    if int(opened.st_size) < received:
                        raise OSError("partial blob is shorter than its checkpoint")
                    if int(opened.st_size) > received:
                        data_fh.truncate(received)
                        data_fh.flush()
                        os.fsync(data_fh.fileno())
                    prefix_digest = self._hash_open_prefix(data_fh, received)
                if prefix_digest != metadata["prefix_digest"]:
                    raise OSError("partial blob prefix digest mismatch")
                return PartialBlobStatus(
                    peer_fp=peer_fp,
                    blob_hash=blob_hash,
                    size=size,
                    received=received,
                    prefix_digest=prefix_digest,
                    updated_ns=cast(int, metadata["updated_ns"]),
                )
            except (OSError, ValueError):
                for path in (data_path, meta_path):
                    with contextlib.suppress(OSError):
                        path.unlink()
                self._fsync_parent(data_path)
                return None

    def prefix_digest(self, blob_hash: str, length: int) -> str:
        """Hash exactly one verified CAS prefix for resume-proof validation."""

        if type(length) is not int or length < 0:
            raise ValueError("prefix length must be a non-negative integer")
        with self.open_read(blob_hash) as fh:
            size = os.fstat(fh.fileno()).st_size
            if length > size:
                raise ValueError("prefix length exceeds blob size")
            return self._hash_open_prefix(fh, length)

    @contextlib.contextmanager
    def partial_writer(
        self,
        *,
        peer_fp: str,
        blob_hash: str,
        size: int,
        expected_offset: int,
        expected_prefix_digest: str,
    ) -> Iterator[tuple["PartialBlobWriter", Path]]:
        """Open one exclusive crash-resumable writer at an exact prefix."""

        key, data_path, meta_path = self._partial_paths(peer_fp, blob_hash, size)
        if (
            type(expected_offset) is not int
            or expected_offset < 0
            or expected_offset > size
            or not _is_hex(expected_prefix_digest)
        ):
            raise ValueError("invalid partial resume contract")
        with self._partial_lock:
            if key in self._active_partials:
                raise RuntimeError("partial blob is already active")
            status = self.partial_status(peer_fp, blob_hash, size)
            if expected_offset == 0:
                if expected_prefix_digest != blake3.blake3().hexdigest():
                    raise ValueError("zero-offset partial has a non-empty prefix digest")
                for path in (data_path, meta_path):
                    with contextlib.suppress(OSError):
                        path.unlink()
                status = None
            elif (
                status is None
                or status.received != expected_offset
                or status.prefix_digest != expected_prefix_digest
            ):
                raise ValueError("durable partial does not match resume contract")
            self._active_partials.add(key)
        try:
            writer = PartialBlobWriter(
                store=self,
                key=key,
                data_path=data_path,
                meta_path=meta_path,
                peer_fp=peer_fp,
                blob_hash=blob_hash,
                size=size,
                expected_offset=expected_offset,
            )
        except Exception:
            with self._partial_lock:
                self._active_partials.discard(key)
            raise
        try:
            yield writer, data_path
        finally:
            try:
                writer.close_if_open(preserve=True)
            finally:
                with self._partial_lock:
                    self._active_partials.discard(key)

    def cleanup_partials(
        self,
        *,
        older_than_s: float,
        max_total_bytes: int,
        max_entries: int,
    ) -> dict[str, int]:
        """Prune corrupt, expired, and over-budget durable partials."""

        now_ns = time.time_ns()
        ttl_ns = max(0, int(float(older_than_s) * 1_000_000_000))
        byte_budget = max(0, int(max_total_bytes))
        entry_budget = max(0, int(max_entries))
        removed = 0
        removed_bytes = 0
        candidates: list[tuple[int, int, str, Path, Path]] = []
        with self._partial_lock:
            for meta_path in self._partials.glob("*.json"):
                key = meta_path.stem
                data_path = self._partials / f"{key}.part"
                if len(key) != 64 or key in self._active_partials:
                    continue
                metadata: dict[str, object] | None = None
                try:
                    meta_fd = self._open_regular(meta_path)
                    with os.fdopen(meta_fd, "rb") as meta_fh:
                        metadata = self._decode_partial_metadata(meta_fh.read(4097))
                    if metadata is None:
                        raise OSError("invalid metadata")
                    expected_key = self._partial_identity(
                        str(metadata["peer_fp"]),
                        str(metadata["blob_hash"]),
                        cast(int, metadata["size"]),
                    )
                    if expected_key != key:
                        raise OSError("metadata filename mismatch")
                    data_st = data_path.lstat()
                    if (
                        _is_redirected(data_st)
                        or not stat.S_ISREG(data_st.st_mode)
                        or data_st.st_size < cast(int, metadata["received"])
                    ):
                        raise OSError("invalid partial data")
                except (OSError, ValueError):
                    size_on_disk = 0
                    with contextlib.suppress(OSError):
                        size_on_disk = int(data_path.lstat().st_size)
                    for path in (data_path, meta_path):
                        with contextlib.suppress(OSError):
                            path.unlink()
                    removed += 1
                    removed_bytes += max(0, size_on_disk)
                    continue
                assert metadata is not None
                updated_ns = cast(int, metadata["updated_ns"])
                size_on_disk = int(data_st.st_size)
                candidates.append(
                    (updated_ns, size_on_disk, key, data_path, meta_path),
                )

            def _remove(candidate: tuple[int, int, str, Path, Path]) -> None:
                nonlocal removed, removed_bytes
                _updated, bytes_on_disk, _key, data_path, meta_path = candidate
                for path in (data_path, meta_path):
                    with contextlib.suppress(OSError):
                        path.unlink()
                removed += 1
                removed_bytes += max(0, bytes_on_disk)

            kept: list[tuple[int, int, str, Path, Path]] = []
            for candidate in candidates:
                if ttl_ns == 0 or now_ns - candidate[0] >= ttl_ns:
                    _remove(candidate)
                else:
                    kept.append(candidate)
            kept.sort(key=lambda item: item[0])
            total_bytes = sum(item[1] for item in kept)
            while kept and (
                len(kept) > entry_budget or total_bytes > byte_budget
            ):
                candidate = kept.pop(0)
                total_bytes -= candidate[1]
                _remove(candidate)

            retained_keys = {candidate[2] for candidate in kept}

            # Crash before metadata publication can leave an orphan data file.
            for data_path in self._partials.glob("*.part"):
                key = data_path.stem
                if key in retained_keys or key in self._active_partials:
                    continue
                size_on_disk = 0
                with contextlib.suppress(OSError):
                    size_on_disk = int(data_path.lstat().st_size)
                with contextlib.suppress(OSError):
                    data_path.unlink()
                    removed += 1
                    removed_bytes += max(0, size_on_disk)
            for meta_tmp in self._partials.glob("meta_*.tmp"):
                if not meta_tmp.is_file() or meta_tmp.is_symlink():
                    continue
                with contextlib.suppress(OSError):
                    meta_tmp.unlink()
                    removed += 1
            if removed:
                self._fsync_parent(self._partials / "cleanup")
        return {
            "removed": removed,
            "removed_bytes": removed_bytes,
            "remaining": len(kept),
            "remaining_bytes": max(0, total_bytes),
        }

    # ─── reads ────────────────────────────────────────────────────────
    def open_read(self, hash_hex: str):
        """Open a verified regular CAS object without following symlinks.

        ``has`` establishes content evidence; the subsequent handle's stat is
        compared to that exact evidence so a path swap between verification
        and open cannot silently serve another object.
        """
        path = self.path(hash_hex)
        for _attempt in range(2):
            if not self.has(hash_hex):
                raise FileNotFoundError(f"verified blob is unavailable: {hash_hex}")
            flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
            flags |= int(getattr(os, "O_NOFOLLOW", 0))
            fd = os.open(path, flags)
            opened = os.fstat(fd)
            evidence = self._stat_evidence(opened)
            with self._verified_lock:
                expected = self._verified.get(hash_hex)
            if stat.S_ISREG(opened.st_mode) and evidence == expected:
                return os.fdopen(fd, "rb")
            os.close(fd)
            with self._verified_lock:
                self._verified.pop(hash_hex, None)
        raise OSError("blob changed while opening verified CAS object")

    def read_bytes(self, hash_hex: str) -> bytes:
        with self.open_read(hash_hex) as f:
            return f.read()

    def verify(self, hash_hex: str) -> bool:
        """Re-hash a stored blob and confirm its address still matches."""
        try:
            path = self.path(hash_hex)
        except ValueError:
            return False
        return self._verify_path(path, hash_hex)

    @staticmethod
    def _verify_path(path: Path, hash_hex: str) -> bool:
        h = blake3.blake3()
        flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        try:
            before = path.lstat()
            if _is_redirected(before) or not stat.S_ISREG(before.st_mode):
                return False
            fd = os.open(path, flags)
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode):
                os.close(fd)
                return False
            with os.fdopen(fd, "rb") as f:
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
            with self._verified_lock:
                self._verified.pop(hash_hex, None)
            return True
        return False

    def total_size(self) -> int:
        return sum(sz for _, sz in self.iter_blobs())


class PartialBlobWriter:
    """Append-only writer with fsynced prefix checkpoints across restarts."""

    def __init__(
        self,
        *,
        store: BlobStore,
        key: str,
        data_path: Path,
        meta_path: Path,
        peer_fp: str,
        blob_hash: str,
        size: int,
        expected_offset: int,
    ):
        self._store = store
        self._key = key
        self._data_path = data_path
        self._meta_path = meta_path
        self._peer_fp = peer_fp
        self._blob_hash = blob_hash
        self._size = int(size)
        self._received = int(expected_offset)
        self._durable_received = int(expected_offset)
        self._h = blake3.blake3()
        self._fh: IO[bytes] | None = None
        self.committed = False

        if expected_offset == 0:
            flags = (
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | int(getattr(os, "O_BINARY", 0))
            )
            fd = os.open(data_path, flags, 0o600)
            self._fh = os.fdopen(fd, "r+b")
            self.checkpoint()
            return

        fd = store._open_regular(data_path, writable=True)
        try:
            opened = os.fstat(fd)
            if int(opened.st_size) != expected_offset:
                raise OSError("partial blob length changed before resume")
            fh = os.fdopen(fd, "r+b", closefd=True)
            fd = -1
            remaining = expected_offset
            while remaining:
                chunk = fh.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise OSError("partial blob truncated while reopening")
                self._h.update(chunk)
                remaining -= len(chunk)
            after = os.fstat(fh.fileno())
            if (
                int(after.st_size) != expected_offset
                or after.st_dev != opened.st_dev
                or after.st_ino != opened.st_ino
            ):
                raise OSError("partial blob changed while reopening")
            fh.seek(expected_offset)
            self._fh = fh
        finally:
            if fd >= 0:
                os.close(fd)

    @property
    def received(self) -> int:
        return self._received

    @property
    def prefix_digest(self) -> str:
        return self._h.hexdigest()

    @property
    def checkpoint_due(self) -> bool:
        return (
            self._received - self._durable_received
            >= PARTIAL_BLOB_CHECKPOINT_BYTES
        )

    def _metadata_payload(self) -> dict[str, object]:
        return {
            "version": PARTIAL_BLOB_VERSION,
            "peer_fp": self._peer_fp,
            "blob_hash": self._blob_hash,
            "size": self._size,
            "received": self._received,
            "prefix_digest": self._h.hexdigest(),
            "updated_ns": time.time_ns(),
        }

    def _publish_metadata(self) -> None:
        payload = self._metadata_payload()
        encoded = json.dumps(
            {
                **payload,
                "checksum": self._store._partial_metadata_checksum(payload),
            },
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        tmp = self._store._partials / f"meta_{secrets.token_hex(16)}.tmp"
        fd = -1
        try:
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | int(getattr(os, "O_BINARY", 0))
            )
            fd = os.open(tmp, flags, 0o600)
            with os.fdopen(fd, "wb", closefd=True) as fh:
                fd = -1
                fh.write(encoded)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._meta_path)
            self._store._fsync_parent(self._meta_path)
        finally:
            if fd >= 0:
                os.close(fd)
            with contextlib.suppress(OSError):
                tmp.unlink()

    def checkpoint(self) -> None:
        if self.committed:
            raise RuntimeError("partial blob is already committed")
        if self._fh is None:
            raise RuntimeError("partial blob writer is closed")
        self._fh.flush()
        os.fsync(self._fh.fileno())
        # Data durability precedes the atomic metadata publication. Recovery
        # may therefore see extra data, but can never trust bytes not fsynced.
        self._publish_metadata()
        self._durable_received = self._received

    def write(self, data: bytes) -> None:
        if self._fh is None:
            raise RuntimeError("partial blob writer is closed")
        if not isinstance(data, bytes):
            raise TypeError("partial blob chunks must be bytes")
        if self._received + len(data) > self._size:
            raise ValueError("partial blob exceeds its declared size")
        self._h.update(data)
        self._fh.write(data)
        self._received += len(data)

    def commit(self, *, expected_hash: str) -> str:
        if self.committed:
            raise RuntimeError("partial blob is already committed")
        if self._fh is None:
            raise RuntimeError("partial blob writer is closed")
        if expected_hash != self._blob_hash or not _is_hex(expected_hash):
            raise ValueError("partial commit hash does not match its contract")
        if self._received != self._size:
            raise ValueError("partial blob is incomplete")
        self.checkpoint()
        self._fh.close()
        self._fh = None
        if self._h.hexdigest() != expected_hash:
            self.discard()
            raise ValueError("staged partial content does not match expected hash")
        dst = self._store.path(expected_hash)
        dst.parent.mkdir(parents=True, exist_ok=True)
        os.replace(self._data_path, dst)
        self._store._fsync_parent(dst)
        with contextlib.suppress(OSError):
            self._meta_path.unlink()
        self._store._fsync_parent(self._meta_path)
        with self._store._verified_lock:
            self._store._verified.pop(expected_hash, None)
        if not self._store.has(expected_hash):
            raise OSError("partial blob CAS commit failed integrity verification")
        self.committed = True
        return expected_hash

    def discard(self) -> None:
        if self._fh is not None:
            with contextlib.suppress(OSError):
                self._fh.close()
            self._fh = None
        for path in (self._data_path, self._meta_path):
            with contextlib.suppress(OSError):
                path.unlink()
        self._store._fsync_parent(self._data_path)

    def close_if_open(self, *, preserve: bool) -> None:
        if self._fh is None:
            return
        try:
            if preserve:
                self.checkpoint()
        finally:
            with contextlib.suppress(OSError):
                self._fh.close()
            self._fh = None
        if not preserve:
            self.discard()


class BlobWriter:
    """Streaming write context. Hash computed incrementally."""

    def __init__(self, tmp_path: Path, store: BlobStore):
        self._fh: IO[bytes] | None = open(tmp_path, "wb")
        self._h = blake3.blake3()
        self._tmp = tmp_path
        self._store = store
        self.committed = False

    def write(self, data: bytes) -> None:
        if self._fh is None:
            raise RuntimeError("writer is closed")
        self._h.update(data)
        self._fh.write(data)

    def commit(self, *, expected_hash: str | None = None) -> str:
        """Durably publish the staged object after optional address binding.

        When a wire protocol already knows the expected content address, the
        comparison must happen *before* ``os.replace``.  Publishing first and
        deleting the mismatched computed address afterwards lets an attacker
        replace and then delete an unrelated, legitimate CAS object whose
        bytes they know.
        """

        if self.committed:
            raise RuntimeError("already committed")
        if self._fh is None:
            raise RuntimeError("writer is closed")
        if expected_hash is not None and not _is_hex(expected_hash):
            raise ValueError("expected_hash must be canonical lower hex")
        self._fh.flush()
        os.fsync(self._fh.fileno())
        self._fh.close()
        self._fh = None
        hex_ = self._h.hexdigest()
        if expected_hash is not None and hex_ != expected_hash:
            raise ValueError("staged content does not match expected hash")
        dst = self._store.path(hex_)
        dst.parent.mkdir(parents=True, exist_ok=True)
        os.replace(self._tmp, dst)
        self._store._fsync_parent(dst)
        with self._store._verified_lock:
            self._store._verified.pop(hex_, None)
        if not self._store.has(hex_):
            raise OSError("blob CAS commit failed integrity verification")
        self.committed = True
        return hex_

    def close_if_open(self) -> None:
        if self._fh is not None:
            with contextlib.suppress(OSError):
                self._fh.close()
            self._fh = None
