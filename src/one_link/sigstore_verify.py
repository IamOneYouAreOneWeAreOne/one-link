"""In-process Sigstore verification for the frozen update helper.

The normal source-install updater invokes ``python -m sigstore``.  A
PyInstaller executable is not a general Python interpreter, so that command
would recursively invoke the helper instead of the bundled Sigstore CLI.
This module uses sigstore-python's public verification API and pre-hashes
large artifacts through a stable file descriptor.  Imports are deliberately
lazy: the regular One Link launcher does not ship the Sigstore dependency
graph, while the separately built one-file helper does.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable

from one_link.update_metadata import (
    MAX_STANDALONE_ARTIFACT_BYTES,
    MAX_UPDATE_METADATA_BYTES,
    UPDATE_OIDC_ISSUER,
    UPDATE_REPOSITORY,
    UPDATE_WORKFLOW,
)


_STABLE_TAG = re.compile(
    r"^v(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)$"
)


class SigstoreVerificationUnavailable(RuntimeError):
    """The frozen helper lacks a complete, usable Sigstore runtime."""


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    attributes = int(getattr(metadata, "st_file_attributes", 0) or 0)
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse)


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    left_dev = int(getattr(left, "st_dev", 0) or 0)
    right_dev = int(getattr(right, "st_dev", 0) or 0)
    left_ino = int(getattr(left, "st_ino", 0) or 0)
    right_ino = int(getattr(right, "st_ino", 0) or 0)
    return not (
        (left_dev and right_dev and left_dev != right_dev)
        or (left_ino and right_ino and left_ino != right_ino)
    )


def _stable_sha256(path: Path, *, maximum: int, label: str) -> tuple[bytes, int]:
    candidate = Path(path)
    try:
        before = os.lstat(candidate)
    except OSError as exc:
        raise ValueError(f"{label} is absent or unreadable") from exc
    if (
        _is_link_or_reparse(before)
        or not stat.S_ISREG(before.st_mode)
        or not (0 < before.st_size <= maximum)
    ):
        raise ValueError(f"{label} must be a bounded non-reparse regular file")
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(candidate, flags)
    except OSError as exc:
        raise ValueError(f"{label} cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_file(before, opened):
            raise ValueError(f"{label} changed while opening")
        digest = hashlib.sha256()
        count = 0
        while True:
            block = os.read(descriptor, min(1024 * 1024, maximum + 1 - count))
            if not block:
                break
            digest.update(block)
            count += len(block)
            if count > maximum:
                raise ValueError(f"{label} exceeds its byte budget")
        opened_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        after = os.lstat(candidate)
    except OSError as exc:
        raise ValueError(f"{label} changed while hashing") from exc
    identities = {
        (
            int(value.st_size),
            int(value.st_mtime_ns),
            int(getattr(value, "st_dev", 0) or 0),
            int(getattr(value, "st_ino", 0) or 0),
        )
        for value in (before, opened, opened_after, after)
    }
    if _is_link_or_reparse(after) or len(identities) != 1 or count != before.st_size:
        raise ValueError(f"{label} changed while hashing")
    return digest.digest(), count


def _read_stable_bundle(path: Path) -> bytes:
    candidate = Path(path)
    try:
        before = os.lstat(candidate)
    except OSError as exc:
        raise ValueError("Sigstore bundle is absent or unreadable") from exc
    if (
        _is_link_or_reparse(before)
        or not stat.S_ISREG(before.st_mode)
        or not (0 < before.st_size <= MAX_UPDATE_METADATA_BYTES)
    ):
        raise ValueError("Sigstore bundle must be a bounded regular file")
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
    descriptor = os.open(candidate, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_file(before, opened):
            raise ValueError("Sigstore bundle changed while opening")
        chunks: list[bytes] = []
        remaining = int(before.st_size)
        while remaining:
            block = os.read(descriptor, min(65536, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        payload = b"".join(chunks)
        opened_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        after = os.lstat(candidate)
    except OSError as exc:
        raise ValueError("Sigstore bundle changed while reading") from exc
    identities = {
        (v.st_size, v.st_mtime_ns, v.st_dev, v.st_ino)
        for v in (before, opened, opened_after, after)
    }
    if _is_link_or_reparse(after) or len(payload) != before.st_size or len(identities) != 1:
        raise ValueError("Sigstore bundle changed while reading")
    return payload


def _load_sigstore_api() -> tuple[Any, Any, Any, Any]:
    try:
        from sigstore.hashes import Hashed  # type: ignore[import-not-found]
        from sigstore.models import Bundle  # type: ignore[import-not-found]
        from sigstore.verify.policy import Identity  # type: ignore[import-not-found]
        from sigstore.verify.verifier import Verifier  # type: ignore[import-not-found]
        from sigstore_models.common.v1 import HashAlgorithm  # type: ignore[import-not-found]
    except (ImportError, RuntimeError) as exc:
        raise SigstoreVerificationUnavailable(
            "the standalone update helper lacks its Sigstore dependency graph"
        ) from exc
    return Hashed, Bundle, Identity, (Verifier, HashAlgorithm)


def verify_sigstore_identity(
    *,
    artifact: Path,
    bundle: Path,
    tag: str,
    _loader: Callable[[], tuple[Any, Any, Any, Any]] = _load_sigstore_api,
) -> None:
    """Verify an artifact under the exact release workflow and tag identity.

    The artifact is streamed once into a SHA-256 digest, allowing the helper
    to authenticate multi-gigabyte standalone ZIPs without buffering them.
    ``Verifier.production`` performs the complete Fulcio, Rekor, certificate
    time, inclusion-proof, signed-checkpoint, signature, and identity policy.
    """

    if not isinstance(tag, str) or not _STABLE_TAG.fullmatch(tag):
        raise ValueError("release tag is not canonical stable")
    artifact_path = Path(artifact)
    bundle_path = Path(bundle)
    if artifact_path == bundle_path:
        raise ValueError("artifact and Sigstore bundle must be distinct files")
    artifact_digest, _ = _stable_sha256(
        artifact_path,
        maximum=MAX_STANDALONE_ARTIFACT_BYTES,
        label="Sigstore artifact",
    )
    bundle_payload = _read_stable_bundle(bundle_path)
    expected_identity = (
        f"https://github.com/{UPDATE_REPOSITORY}/{UPDATE_WORKFLOW}"
        f"@refs/tags/{tag}"
    )
    try:
        hashed_type, bundle_type, identity_type, verifier_api = _loader()
        verifier_type, hash_algorithm = verifier_api
        signed_bundle = bundle_type.from_json(bundle_payload)
        hashed = hashed_type(
            digest=artifact_digest,
            algorithm=hash_algorithm.SHA2_256,
        )
        policy = identity_type(
            identity=expected_identity,
            issuer=UPDATE_OIDC_ISSUER,
        )
        verifier_type.production(offline=False).verify_artifact(
            hashed,
            signed_bundle,
            policy,
        )
    except SigstoreVerificationUnavailable:
        raise
    except Exception as exc:
        # Do not serialize unbounded third-party diagnostics into updater state
        # or UI responses. The exception chain remains available to local logs.
        raise RuntimeError("Sigstore identity verification failed") from exc
    final_digest, _ = _stable_sha256(
        artifact_path,
        maximum=MAX_STANDALONE_ARTIFACT_BYTES,
        label="Sigstore artifact",
    )
    if final_digest != artifact_digest:
        raise ValueError("Sigstore artifact changed after verification")


__all__ = [
    "SigstoreVerificationUnavailable",
    "verify_sigstore_identity",
]
