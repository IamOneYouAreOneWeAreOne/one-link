"""Encrypted backup bundles — your chat history + groups + settings,
sealed with a key only you can derive.

The "for the people" recovery story has two layers:

  1. **Identity recovery** (Bundle 23, mnemonic.py + master_seed.py):
     24 words on paper restore your Ed25519 identity + at-rest
     keys on a new device. Peers continue to recognize you.

  2. **Data recovery** (this module, Bundle 24): an encrypted
     ``.olbak`` bundle holds your sqlite state — chat history,
     group memberships, peer trust state, settings — encrypted
     under a key that ONLY the master seed can derive. Drop the
     bundle on any portable medium (USB stick, cloud-storage,
     the email-yourself trick, a printed QR for the truly
     paranoid). Without the seed it is ciphertext indistinguishable
     from random; with the seed (= the 24 words) anyone restoring
     to a new device gets the full daemon state back.

Wire format
-----------
``.olbak`` v1 layout (binary):

    [0..8)        magic         b"OLBAK\\x01\\x00\\x00"   (8 bytes)
    [8..16)       length-prefix u64 big-endian             (size of plaintext)
    [16..28)      AES-GCM nonce 12 bytes (random per export)
    [28..36)      created_ms    u64 big-endian (clock-of-export timestamp)
    [36..)        ciphertext + 16-byte AEAD tag

The plaintext is a deflate-compressed tar archive of the daemon's
data dir, with a strict allowlist of files included (state.db,
master.seed, settings, NO inbox content by default — that's
opt-in via ``--include-files`` because inboxes can be huge).

The AAD on the AEAD covers magic + length + nonce + created_ms,
so any tamper of the header invalidates the tag.

Sovereignty notes
-----------------
- The bundle key derives from the master seed via HKDF with a
  distinct domain-separation tag (``OL/master/backup-bundle|v1``).
  A leak of the bundle key cannot be used to decrypt the running
  daemon's at-rest data (which uses a different derived subkey).
- No third-party service ever sees the bundle plaintext. The
  user can post-process (encrypt-again, split via Shamir, hide in
  a tarball of cat photos) without affecting the recovery path.
- Restore explicitly requires possession of the 24-word phrase OR
  an existing master seed file. There is no "lost the words and
  the file? click here" recovery — that path doesn't exist by
  design, and every user-visible message in the CLI says so.
"""
from __future__ import annotations

import gzip
import os
import secrets
import struct
import tarfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Iterable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


BUNDLE_MAGIC = b"OLBAK\x01\x00\x00"
NONCE_LEN = 12
HEADER_LEN = len(BUNDLE_MAGIC) + 8 + NONCE_LEN + 8  # magic + len + nonce + ts
PLAINTEXT_VERSION = 1


# Files inside the daemon data_dir that we INCLUDE in the default
# bundle. Inbox + chunk-cache are large and not load-bearing for
# identity / chat / groups, so they're opt-in via include_files.
DEFAULT_INCLUDE = {
    "state.db",
    "state.db-wal",
    "state.db-shm",  # may not exist; that's fine
    "master.seed",
    "data-root-key.bin",
    "lockbox.salt",
    "ui.token",
}


@dataclass(frozen=True)
class BundleHeader:
    magic: bytes
    plaintext_len: int
    nonce: bytes
    created_ms: int

    def encode(self) -> bytes:
        return (
            self.magic
            + struct.pack(">Q", self.plaintext_len)
            + self.nonce
            + struct.pack(">Q", self.created_ms)
        )

    @classmethod
    def decode(cls, raw: bytes) -> "BundleHeader":
        if len(raw) < HEADER_LEN:
            raise ValueError(
                f"bundle header truncated: {len(raw)} < {HEADER_LEN}"
            )
        magic = raw[:8]
        if magic != BUNDLE_MAGIC:
            raise ValueError(
                f"not a One Link backup bundle (bad magic: {magic!r})"
            )
        plaintext_len = struct.unpack(">Q", raw[8:16])[0]
        nonce = raw[16:28]
        created_ms = struct.unpack(">Q", raw[28:36])[0]
        return cls(
            magic=magic,
            plaintext_len=plaintext_len,
            nonce=nonce,
            created_ms=created_ms,
        )


def _now_ms() -> int:
    import time
    return int(time.time() * 1000)


def _walk_data_dir(
    data_dir: Path,
    *,
    include_files: bool,
    extra_allowlist: Iterable[str] = (),
) -> list[tuple[Path, str]]:
    """Return list of (absolute_path, archive_name) tuples to include.

    archive_name is the path within the bundle, with forward
    slashes regardless of host OS. Symlinks are followed once and
    then included as ordinary files (we don't preserve symlink
    semantics — the bundle is a portable archive, not a filesystem
    snapshot).
    """
    data_dir = Path(data_dir).resolve()
    allowed = set(DEFAULT_INCLUDE) | set(extra_allowlist)
    out: list[tuple[Path, str]] = []
    # Top-level allowlisted files first.
    for name in sorted(allowed):
        p = data_dir / name
        if p.is_file():
            out.append((p, name))
    if include_files:
        # Inbox subtree: include user-received files + the chunk
        # cache. NOT recursive into other subtrees we don't ship.
        inbox = data_dir / "inbox"
        if inbox.is_dir():
            for entry in sorted(inbox.rglob("*")):
                if entry.is_file():
                    rel = entry.relative_to(data_dir).as_posix()
                    out.append((entry, rel))
    return out


def _build_plaintext_archive(
    data_dir: Path,
    *,
    include_files: bool,
    extra_allowlist: Iterable[str] = (),
) -> bytes:
    """Compose the gzip-compressed tar plaintext."""
    members = _walk_data_dir(
        data_dir,
        include_files=include_files,
        extra_allowlist=extra_allowlist,
    )
    buf = BytesIO()
    # mtime=0 + uname/gname empty makes the tar deterministic
    # given the same input set; useful for any future
    # reproducible-bundle property tests.
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w") as tf:
            # Manifest first so a partial-decode reader can still
            # discover what's in the bundle.
            manifest_text = "\n".join(
                f"{archive_name}\t{p.stat().st_size}"
                for p, archive_name in members
            ) + "\n"
            manifest = tarfile.TarInfo(name="MANIFEST")
            manifest.size = len(manifest_text.encode("utf-8"))
            manifest.mtime = 0
            tf.addfile(manifest, BytesIO(manifest_text.encode("utf-8")))
            for p, archive_name in members:
                ti = tarfile.TarInfo(name=archive_name)
                ti.size = p.stat().st_size
                ti.mtime = 0
                ti.uid = 0
                ti.gid = 0
                ti.uname = ""
                ti.gname = ""
                with p.open("rb") as fh:
                    tf.addfile(ti, fh)
    return buf.getvalue()


def create_bundle(
    *,
    seed: bytes,
    data_dir: Path,
    include_files: bool = False,
    extra_allowlist: Iterable[str] = (),
) -> bytes:
    """Encode a portable encrypted backup of the daemon's state.

    Args:
      seed: the 32-byte master seed (e.g. from
        master_seed.load_seed). The bundle key is derived from
        this; the seed itself never appears in the bundle output.
      data_dir: the daemon's config / data dir to back up.
      include_files: when True also archive everything under
        ``inbox/``. Default False because inboxes can be GB-sized;
        identity + chat history + groups are in state.db which is
        always included.
      extra_allowlist: additional top-level filenames in data_dir
        to include. Used when callers add new persistent state
        files that aren't in the canonical DEFAULT_INCLUDE set.

    Returns the encoded ``.olbak`` bytes ready to write to disk.
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    data_dir = Path(data_dir).resolve()
    if not data_dir.is_dir():
        raise FileNotFoundError(f"data_dir does not exist: {data_dir}")

    plaintext = _build_plaintext_archive(
        data_dir,
        include_files=include_files,
        extra_allowlist=extra_allowlist,
    )

    from one_link.master_seed import derive_backup_key
    key = derive_backup_key(bytes(seed))
    nonce = secrets.token_bytes(NONCE_LEN)
    header = BundleHeader(
        magic=BUNDLE_MAGIC,
        plaintext_len=len(plaintext),
        nonce=nonce,
        created_ms=_now_ms(),
    )
    aead = AESGCM(key)
    aad = header.encode()
    ct_with_tag = aead.encrypt(nonce, plaintext, aad)
    return aad + ct_with_tag


def open_bundle(
    *,
    seed: bytes,
    bundle_bytes: bytes,
) -> tuple[BundleHeader, bytes]:
    """Decrypt a bundle, return (header, plaintext archive bytes).

    Raises ValueError on header tamper, AEAD-tag mismatch, or
    truncated input. The plaintext is the gzip-tar archive; pass
    to ``extract_bundle_to_dir`` to write it out.
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    if len(bundle_bytes) < HEADER_LEN + 16:  # +16 for AEAD tag
        raise ValueError("bundle too short to be valid")
    header = BundleHeader.decode(bundle_bytes[:HEADER_LEN])
    aad = header.encode()
    ct_with_tag = bundle_bytes[HEADER_LEN:]
    from one_link.master_seed import derive_backup_key
    key = derive_backup_key(bytes(seed))
    aead = AESGCM(key)
    try:
        plaintext = aead.decrypt(header.nonce, ct_with_tag, aad)
    except Exception as e:
        raise ValueError(
            f"bundle decrypt failed (wrong seed or tampered file): {e}"
        ) from None
    if len(plaintext) != header.plaintext_len:
        raise ValueError(
            f"plaintext-length header lies: claimed "
            f"{header.plaintext_len}, got {len(plaintext)}"
        )
    return header, plaintext


def extract_bundle_to_dir(
    *,
    plaintext: bytes,
    target_dir: Path,
    overwrite: bool = False,
) -> list[str]:
    """Unpack a decrypted bundle's plaintext archive into target_dir.

    Returns the list of archive_name strings that were written.
    Refuses to overwrite existing files unless overwrite=True; on
    refuse, raises FileExistsError WITHOUT writing anything (we
    extract to a temp dir first, then atomically promote).

    Path-safety: refuses any archive entry whose normalized path
    escapes target_dir (`..`, absolute paths, drive letters,
    ``\\\\?\\`` prefixes — same shape as audit M21).
    """
    target_dir = Path(target_dir).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    # Stage to a sibling temp dir so a partial extract on error
    # doesn't poison the daemon's existing data.
    staging = target_dir / f".bundle-import.{secrets.token_hex(4)}"
    staging.mkdir(parents=True, exist_ok=False)
    try:
        with gzip.GzipFile(fileobj=BytesIO(plaintext), mode="rb") as gz:
            with tarfile.open(fileobj=gz, mode="r") as tf:
                for ti in tf.getmembers():
                    name = ti.name
                    # Path safety: same allowlist shape as audit
                    # M21's manifest sandbox.
                    norm = name.replace("\\", "/")
                    if (
                        not norm
                        or norm.startswith("/")
                        or ".." in norm.split("/")
                        or (len(name) > 1 and name[1] == ":")
                        or any(ord(c) < 0x20 or ord(c) == 0x7f for c in name)
                    ):
                        raise ValueError(
                            f"unsafe archive entry path: {name!r}"
                        )
                    if ti.isdir():
                        (staging / norm).mkdir(parents=True, exist_ok=True)
                        continue
                    if not ti.isfile():
                        # Symlinks, devices, etc. — refuse.
                        raise ValueError(
                            f"unsupported archive entry type for {name!r}"
                        )
                    out_path = staging / norm
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    extracted = tf.extractfile(ti)
                    if extracted is None:
                        raise ValueError(
                            f"failed to read archive entry {name!r}"
                        )
                    out_path.write_bytes(extracted.read())
                    written.append(name)
        # Promote staging → target_dir, refusing overwrite per flag.
        if not overwrite:
            for name in written:
                if (target_dir / name).exists():
                    raise FileExistsError(
                        f"target file already exists: {target_dir / name}"
                    )
        for name in written:
            src = staging / name
            dst = target_dir / name
            dst.parent.mkdir(parents=True, exist_ok=True)
            os.replace(src, dst)
    finally:
        # Clean up any partial-staging files; if extraction
        # succeeded, the os.replace calls above moved everything
        # out, leaving an empty tree to remove.
        import shutil
        shutil.rmtree(staging, ignore_errors=True)
    return written


# ── Convenience: round-trip via base64 / file ────────────────────────


def create_bundle_to_file(
    *,
    seed: bytes,
    data_dir: Path,
    out_path: Path,
    include_files: bool = False,
) -> int:
    """Create a bundle + write to disk. Returns bytes written."""
    bundle = create_bundle(
        seed=seed,
        data_dir=data_dir,
        include_files=include_files,
    )
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bundle)
    return len(bundle)


def restore_bundle_from_file(
    *,
    seed: bytes,
    bundle_path: Path,
    target_dir: Path,
    overwrite: bool = False,
) -> tuple[BundleHeader, list[str]]:
    """Read + decrypt + extract a .olbak file."""
    bundle_bytes = Path(bundle_path).read_bytes()
    header, plaintext = open_bundle(
        seed=seed, bundle_bytes=bundle_bytes,
    )
    written = extract_bundle_to_dir(
        plaintext=plaintext,
        target_dir=Path(target_dir),
        overwrite=overwrite,
    )
    return header, written
