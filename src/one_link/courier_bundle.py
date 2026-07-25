"""Encrypted offline courier bundles for One Link chunks.

Courier bundles are the no-router, no-internet fallback for large transfers:
put encrypted chunks on a USB stick, local share, SD card, or any other
plain file carrier, then pass a short unlock token over a separate channel.

The file is intentionally useless without the token. Every imported chunk is
content-address verified before it enters the normal CDC chunk cache, so the
online and offline paths share the same integrity model.

AES-GCM proves that a bundle holder has the separate unlock token; by itself it
does not identify who created the bundle.  New callers should pass the local
Ed25519 ``signing_key`` on export.  Import verifies every signature it sees and
``expected_sender_fp``/``require_sender_signature`` make unsigned legacy
bundles fail closed when sender authenticity is required.
"""
from __future__ import annotations

import base64
import contextlib
import gzip
import io
import json
import secrets
import struct
import tempfile
import time
import zlib
from dataclasses import dataclass
from typing import BinaryIO, Iterable, Mapping, MutableSet, Sequence, cast

from one_link._coerce import to_int

import blake3
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


COURIER_MAGIC = b"OLCB\x01\x00\x00\x00"
COURIER_TOKEN_PREFIX = "OLC1."
COURIER_VERSION = 1
NONCE_LEN = 12
KEY_LEN = 32
GCM_TAG_LEN = 16
HEADER_LEN = len(COURIER_MAGIC) + 8 + NONCE_LEN + 8 + 8
DEFAULT_TTL_S = 24 * 60 * 60
MAX_TTL_S = 14 * 24 * 60 * 60
DEFAULT_MAX_CHUNKS = 4096
DEFAULT_MAX_PLAINTEXT_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_BUNDLE_BYTES = 768 * 1024 * 1024
DEFAULT_MAX_COMPRESSED_BYTES = 640 * 1024 * 1024
DEFAULT_MAX_CHUNK_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_TOTAL_CHUNK_BYTES = 384 * 1024 * 1024
STREAM_BLOCK_BYTES = 1024 * 1024
SPOOL_MEMORY_BYTES = 8 * 1024 * 1024
COURIER_SIGNATURE_DOMAIN = b"One Link courier bundle manifest v1\x00"


class CourierBundleError(ValueError):
    """Raised when a courier bundle is malformed, unsafe, or undecryptable."""


@dataclass(frozen=True)
class CourierHeader:
    plaintext_len: int
    nonce: bytes
    created_ms: int
    expires_ms: int

    def encode(self) -> bytes:
        return (
            COURIER_MAGIC
            + struct.pack(">Q", self.plaintext_len)
            + self.nonce
            + struct.pack(">Q", self.created_ms)
            + struct.pack(">Q", self.expires_ms)
        )

    @classmethod
    def decode(cls, raw: bytes) -> "CourierHeader":
        if len(raw) < HEADER_LEN:
            raise CourierBundleError("courier bundle header truncated")
        magic = raw[: len(COURIER_MAGIC)]
        if magic != COURIER_MAGIC:
            raise CourierBundleError("not a One Link courier bundle")
        off = len(COURIER_MAGIC)
        plaintext_len = struct.unpack(">Q", raw[off : off + 8])[0]
        off += 8
        nonce = raw[off : off + NONCE_LEN]
        off += NONCE_LEN
        created_ms = struct.unpack(">Q", raw[off : off + 8])[0]
        off += 8
        expires_ms = struct.unpack(">Q", raw[off : off + 8])[0]
        if plaintext_len <= 0:
            raise CourierBundleError("courier bundle has empty plaintext")
        if expires_ms <= created_ms:
            raise CourierBundleError("courier bundle expiry is invalid")
        return cls(
            plaintext_len=plaintext_len,
            nonce=nonce,
            created_ms=created_ms,
            expires_ms=expires_ms,
        )


@dataclass(frozen=True)
class CourierExport:
    bundle: bytes
    key_token: str
    manifest: Mapping[str, object]


@dataclass(frozen=True)
class CourierImport:
    manifest: Mapping[str, object]
    chunks: tuple[tuple[str, bytes], ...]


def encode_key_token(key: bytes) -> str:
    if not isinstance(key, bytes) or len(key) != KEY_LEN:
        raise CourierBundleError("courier key must be 32 bytes")
    payload = _b64u_encode(key)
    return COURIER_TOKEN_PREFIX + payload


def decode_key_token(token: str) -> bytes:
    if not isinstance(token, str):
        raise CourierBundleError("courier key token must be a string")
    token = token.strip()
    if not token.startswith(COURIER_TOKEN_PREFIX):
        raise CourierBundleError("courier key token must start with OLC1.")
    raw = token[len(COURIER_TOKEN_PREFIX) :]
    if not raw:
        raise CourierBundleError("courier key token is empty")
    try:
        return _b64u_decode(raw, expected_len=KEY_LEN, label="courier key token")
    except CourierBundleError as exc:
        raise CourierBundleError("courier key token is not valid base64") from exc


def encode_bundle_b64(bundle: bytes) -> str:
    return base64.b64encode(bundle).decode("ascii")


def decode_bundle_b64(value: str, *, max_bundle_bytes: int = DEFAULT_MAX_BUNDLE_BYTES) -> bytes:
    max_bundle_bytes = _positive_limit(max_bundle_bytes, "max_bundle_bytes")
    if not isinstance(value, str):
        raise CourierBundleError("courier bundle must be a base64 string")
    # Reject an oversized transport value before base64 decoding allocates a
    # second, attacker-sized buffer.  Whitespace is deliberately unsupported
    # (``validate=True`` below) so this encoded-length bound is exact.
    max_encoded = ((max_bundle_bytes + 2) // 3) * 4
    if len(value) > max_encoded:
        raise CourierBundleError("courier bundle exceeds the configured size limit")
    try:
        bundle = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise CourierBundleError("courier bundle is not valid base64") from exc
    if len(bundle) > max_bundle_bytes:
        raise CourierBundleError("courier bundle exceeds the configured size limit")
    return bundle


def export_courier_bundle(
    chunks: Iterable[tuple[str, bytes]],
    *,
    sender_fp: str,
    recipient_fp: str | None = None,
    blob_hash: str | None = None,
    name: str | None = None,
    ttl_s: int = DEFAULT_TTL_S,
    now_ms: int | None = None,
    max_chunks: int = DEFAULT_MAX_CHUNKS,
    max_plaintext_bytes: int = DEFAULT_MAX_PLAINTEXT_BYTES,
    max_compressed_bytes: int = DEFAULT_MAX_COMPRESSED_BYTES,
    max_chunk_bytes: int = DEFAULT_MAX_CHUNK_BYTES,
    max_total_chunk_bytes: int = DEFAULT_MAX_TOTAL_CHUNK_BYTES,
    signing_key: Ed25519PrivateKey | None = None,  # gitleaks:allow - type name
) -> CourierExport:
    max_chunks = _positive_limit(max_chunks, "max_chunks")
    max_plaintext_bytes = _positive_limit(max_plaintext_bytes, "max_plaintext_bytes")
    max_compressed_bytes = _positive_limit(max_compressed_bytes, "max_compressed_bytes")
    max_chunk_bytes = _positive_limit(max_chunk_bytes, "max_chunk_bytes")
    max_total_chunk_bytes = _positive_limit(
        max_total_chunk_bytes,
        "max_total_chunk_bytes",
    )
    now = int(now_ms if now_ms is not None else time.time() * 1000)
    ttl = max(1, min(int(ttl_s), MAX_TTL_S))
    expires_ms = now + ttl * 1000
    entries = _normalize_export_chunks(
        chunks,
        max_chunks=max_chunks,
        max_chunk_bytes=max_chunk_bytes,
        max_total_chunk_bytes=max_total_chunk_bytes,
    )
    bundle_id = secrets.token_hex(16)
    clean_sender_fp = _clean_fp(sender_fp, required=True)
    assert clean_sender_fp is not None
    manifest: dict[str, object] = {
        "version": COURIER_VERSION,
        "bundle_id": bundle_id,
        "created_ms": now,
        "expires_ms": expires_ms,
        "sender_fp": clean_sender_fp,
        "recipient_fp": _clean_fp(recipient_fp, required=False),
        "blob_hash": _clean_hash(blob_hash) if blob_hash else None,
        "name": _clean_name(name),
        "chunk_count": len(entries),
        "total_bytes": sum(to_int(e["size"]) for e in entries),
        "chunks": entries,
    }
    sender_authenticated = False
    if signing_key is not None:
        sender_pub = signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        if blake3.blake3(sender_pub).hexdigest() != clean_sender_fp:
            raise CourierBundleError(
                "courier signing key does not match the sender fingerprint"
            )
        manifest["sender_pub"] = _b64u_encode(sender_pub)
        manifest["sender_signature"] = _b64u_encode(
            signing_key.sign(_signature_payload(manifest))
        )
        sender_authenticated = True
    plaintext = _canonical_json(manifest)
    if len(plaintext) > max_plaintext_bytes:
        raise CourierBundleError("courier bundle manifest exceeds the size limit")
    compressed = gzip.compress(plaintext, compresslevel=6, mtime=0)
    if len(compressed) > max_compressed_bytes:
        raise CourierBundleError("courier bundle compressed payload exceeds the size limit")
    key = secrets.token_bytes(KEY_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    header = CourierHeader(
        plaintext_len=len(compressed),
        nonce=nonce,
        created_ms=now,
        expires_ms=expires_ms,
    )
    aad = header.encode()
    ciphertext = AESGCM(key).encrypt(nonce, compressed, aad)
    public_manifest = _public_manifest(manifest)
    public_manifest["sender_authenticated"] = sender_authenticated
    return CourierExport(
        bundle=aad + ciphertext,
        key_token=encode_key_token(key),
        manifest=public_manifest,
    )


def import_courier_bundle(
    bundle: bytes,
    key_token: str,
    *,
    expected_recipient_fp: str | None = None,
    now_ms: int | None = None,
    replay_seen: MutableSet[str] | None = None,
    max_chunks: int = DEFAULT_MAX_CHUNKS,
    max_plaintext_bytes: int = DEFAULT_MAX_PLAINTEXT_BYTES,
    max_bundle_bytes: int = DEFAULT_MAX_BUNDLE_BYTES,
    max_compressed_bytes: int = DEFAULT_MAX_COMPRESSED_BYTES,
    max_chunk_bytes: int = DEFAULT_MAX_CHUNK_BYTES,
    max_total_chunk_bytes: int = DEFAULT_MAX_TOTAL_CHUNK_BYTES,
    expected_sender_fp: str | None = None,
    require_sender_signature: bool = False,
) -> CourierImport:
    max_chunks = _positive_limit(max_chunks, "max_chunks")
    max_plaintext_bytes = _positive_limit(max_plaintext_bytes, "max_plaintext_bytes")
    max_bundle_bytes = _positive_limit(max_bundle_bytes, "max_bundle_bytes")
    max_compressed_bytes = _positive_limit(max_compressed_bytes, "max_compressed_bytes")
    max_chunk_bytes = _positive_limit(max_chunk_bytes, "max_chunk_bytes")
    max_total_chunk_bytes = _positive_limit(
        max_total_chunk_bytes,
        "max_total_chunk_bytes",
    )
    if not isinstance(bundle, bytes):
        raise CourierBundleError("courier bundle must be bytes")
    if len(bundle) > max_bundle_bytes:
        raise CourierBundleError("courier bundle exceeds the configured size limit")
    header = CourierHeader.decode(bundle)
    if header.plaintext_len > max_compressed_bytes:
        raise CourierBundleError("courier bundle compressed payload exceeds the size limit")
    expected_bundle_len = HEADER_LEN + header.plaintext_len + GCM_TAG_LEN
    if len(bundle) != expected_bundle_len:
        raise CourierBundleError("courier bundle ciphertext length mismatch")
    now = int(now_ms if now_ms is not None else time.time() * 1000)
    if now > header.expires_ms:
        raise CourierBundleError("courier bundle has expired")
    key = decode_key_token(key_token)
    # AES-GCM and gzip are both processed incrementally into bounded spools.
    # This prevents a tiny gzip bomb from materialising a giant bytes object
    # and avoids holding bundle + decrypted gzip + JSON bytes simultaneously.
    with _decrypt_bundle_to_spool(bundle, key, header) as compressed_stream:
        with _decompress_gzip_to_spool(
            compressed_stream,
            max_output_bytes=max_plaintext_bytes,
        ) as plaintext_stream:
            manifest = _load_manifest_stream(plaintext_stream)
    if to_int(manifest["created_ms"]) != header.created_ms:
        raise CourierBundleError("courier bundle created time mismatch")
    if to_int(manifest["expires_ms"]) != header.expires_ms:
        raise CourierBundleError("courier bundle expiry mismatch")
    recipient_fp = manifest.get("recipient_fp") or None
    expected = _clean_fp(expected_recipient_fp, required=False)
    if expected:
        if recipient_fp is None:
            raise CourierBundleError("courier bundle is not bound to a recipient")
        if recipient_fp != expected:
            raise CourierBundleError("courier bundle is for a different recipient")
    sender_authenticated = _verify_sender_signature(
        manifest,
        expected_sender_fp=expected_sender_fp,
        required=require_sender_signature or expected_sender_fp is not None,
    )
    bundle_id = str(manifest["bundle_id"])
    manifest_total = _strict_nonnegative_int(
        manifest.get("total_bytes"),
        "courier bundle byte count",
    )
    if manifest_total > max_total_chunk_bytes:
        raise CourierBundleError("courier bundle exceeds the total chunk size limit")
    chunks = _decode_import_chunks(
        manifest["chunks"],
        max_chunks=max_chunks,
        max_chunk_bytes=max_chunk_bytes,
        max_total_chunk_bytes=max_total_chunk_bytes,
        expected_total_bytes=manifest_total,
    )
    if replay_seen is not None:
        if bundle_id in replay_seen:
            raise CourierBundleError("courier bundle was already imported")
        replay_seen.add(bundle_id)
    public_manifest = _public_manifest(manifest)
    public_manifest["sender_authenticated"] = sender_authenticated
    return CourierImport(manifest=public_manifest, chunks=chunks)


def assemble_courier_chunks(
    chunks: Iterable[tuple[str, bytes]],
    destination: BinaryIO,
    *,
    expected_blob_hash: str | None = None,
    max_chunks: int = DEFAULT_MAX_CHUNKS,
    max_chunk_bytes: int = DEFAULT_MAX_CHUNK_BYTES,
    max_total_chunk_bytes: int = DEFAULT_MAX_TOTAL_CHUNK_BYTES,
) -> int:
    """Verify and stream courier chunks to a seekable destination.

    The function intentionally never builds a ``parts`` list or joins the
    complete blob in memory.  On any validation or write failure it truncates
    the destination back to its original position, making cleanup deterministic
    for a temporary file or an exclusively-created output file.
    """

    max_chunks = _positive_limit(max_chunks, "max_chunks")
    max_chunk_bytes = _positive_limit(max_chunk_bytes, "max_chunk_bytes")
    max_total_chunk_bytes = _positive_limit(
        max_total_chunk_bytes,
        "max_total_chunk_bytes",
    )
    expected = _clean_hash(expected_blob_hash) if expected_blob_hash else None
    if not destination.seekable() or not destination.writable():
        raise CourierBundleError("courier assembly destination must be seekable and writable")
    try:
        start = destination.tell()
    except (OSError, ValueError) as exc:
        raise CourierBundleError("courier assembly destination is unavailable") from exc

    blob_hasher = blake3.blake3()
    seen: set[str] = set()
    total = 0
    count = 0
    try:
        for raw_hash, raw_data in chunks:
            if count >= max_chunks:
                raise CourierBundleError("courier assembly has too many chunks")
            chunk_hash = _clean_hash(raw_hash)
            if chunk_hash in seen:
                raise CourierBundleError("courier assembly contains duplicate chunks")
            if not isinstance(raw_data, (bytes, bytearray, memoryview)):
                raise CourierBundleError("courier assembly chunk data must be bytes")
            data = memoryview(raw_data)
            size = data.nbytes
            if size > max_chunk_bytes:
                raise CourierBundleError("courier chunk exceeds the per-chunk size limit")
            if size > max_total_chunk_bytes - total:
                raise CourierBundleError("courier assembly exceeds the total chunk size limit")
            if blake3.blake3(data).hexdigest() != chunk_hash:
                raise CourierBundleError("courier assembly chunk hash mismatch")
            blob_hasher.update(data)
            _write_all(destination, data)
            seen.add(chunk_hash)
            total += size
            count += 1
        if count == 0:
            raise CourierBundleError("courier assembly must contain at least one chunk")
        if expected and blob_hasher.hexdigest() != expected:
            raise CourierBundleError("courier assembly blob hash mismatch")
        return total
    except Exception:
        with contextlib.suppress(OSError, ValueError):
            destination.seek(start)
            destination.truncate()
        raise


def _positive_limit(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise CourierBundleError(f"{name} must be a positive integer")
    return value


def _strict_nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CourierBundleError(f"{label} is invalid")
    return value


def _decrypt_bundle_to_spool(
    bundle: bytes,
    key: bytes,
    header: CourierHeader,
) -> BinaryIO:
    """Authenticate and decrypt AES-GCM incrementally into a bounded spool."""

    output = tempfile.SpooledTemporaryFile(max_size=SPOOL_MEMORY_BYTES, mode="w+b")
    try:
        ciphertext = memoryview(bundle)[HEADER_LEN:-GCM_TAG_LEN]
        tag = bytes(memoryview(bundle)[-GCM_TAG_LEN:])
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(header.nonce, tag),
        ).decryptor()
        decryptor.authenticate_additional_data(bundle[:HEADER_LEN])
        written = 0
        for offset in range(0, len(ciphertext), STREAM_BLOCK_BYTES):
            block = decryptor.update(ciphertext[offset : offset + STREAM_BLOCK_BYTES])
            if block:
                output.write(block)
                written += len(block)
        tail = decryptor.finalize()
        if tail:
            output.write(tail)
            written += len(tail)
        if written != header.plaintext_len:
            raise CourierBundleError("courier bundle plaintext length mismatch")
        output.seek(0)
        return cast(BinaryIO, output)
    except InvalidTag as exc:
        output.close()
        raise CourierBundleError("courier bundle could not be decrypted") from exc
    except Exception:
        output.close()
        raise


def _decompress_gzip_to_spool(
    compressed: BinaryIO,
    *,
    max_output_bytes: int,
) -> BinaryIO:
    """Stream exactly one gzip member to disk/memory with a hard output cap."""

    output = tempfile.SpooledTemporaryFile(max_size=SPOOL_MEMORY_BYTES, mode="w+b")
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    total = 0
    reached_eof = False
    try:
        compressed.seek(0)
        while not reached_eof:
            source_block = compressed.read(STREAM_BLOCK_BYTES)
            if not source_block:
                break
            pending = source_block
            while pending:
                remaining = max_output_bytes - total
                max_decode = min(STREAM_BLOCK_BYTES, remaining + 1)
                try:
                    decoded = decoder.decompress(pending, max_decode)
                except zlib.error as exc:
                    raise CourierBundleError(
                        "courier bundle payload is not valid gzip"
                    ) from exc
                next_pending = decoder.unconsumed_tail
                if decoded:
                    total += len(decoded)
                    if total > max_output_bytes:
                        raise CourierBundleError(
                            "courier bundle payload exceeds the size limit"
                        )
                    output.write(decoded)
                if decoder.unused_data:
                    raise CourierBundleError(
                        "courier bundle gzip payload has trailing data"
                    )
                if decoder.eof:
                    # A second member or any trailing byte is rejected rather
                    # than silently expanding another attacker-controlled body.
                    if next_pending or compressed.read(1):
                        raise CourierBundleError(
                            "courier bundle gzip payload has trailing data"
                        )
                    reached_eof = True
                    break
                if next_pending == pending and not decoded:
                    raise CourierBundleError("courier bundle payload is not valid gzip")
                pending = next_pending
        if not reached_eof or not decoder.eof:
            raise CourierBundleError("courier bundle gzip payload is truncated")
        output.seek(0)
        return cast(BinaryIO, output)
    except Exception:
        output.close()
        raise


def _write_all(destination: BinaryIO, data: memoryview) -> None:
    offset = 0
    while offset < data.nbytes:
        written = destination.write(data[offset : offset + STREAM_BLOCK_BYTES])
        if not isinstance(written, int) or written <= 0:
            raise CourierBundleError("courier assembly destination write failed")
        offset += written


def _b64u_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64u_decode(value: object, *, expected_len: int, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise CourierBundleError(f"{label} is missing or malformed")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except Exception as exc:
        raise CourierBundleError(f"{label} is malformed") from exc
    if len(decoded) != expected_len or _b64u_encode(decoded) != value:
        raise CourierBundleError(f"{label} is malformed")
    return decoded


def _signature_payload(manifest: Mapping[str, object]) -> bytes:
    raw_chunks = manifest.get("chunks")
    if not isinstance(raw_chunks, list):
        raise CourierBundleError("courier bundle chunk list is missing")
    # Sign the fixed manifest schema plus the ordered content-address list,
    # excluding bulky base64 data.  Each decoded part is independently checked
    # against its signed BLAKE3 address, so this authenticates the exact bytes
    # without re-serialising hundreds of MiB during verification.
    signed: dict[str, object] = {
        "version": manifest.get("version"),
        "bundle_id": manifest.get("bundle_id"),
        "created_ms": manifest.get("created_ms"),
        "expires_ms": manifest.get("expires_ms"),
        "sender_fp": manifest.get("sender_fp"),
        "sender_pub": manifest.get("sender_pub"),
        "recipient_fp": manifest.get("recipient_fp"),
        "blob_hash": manifest.get("blob_hash"),
        "name": manifest.get("name"),
        "chunk_count": manifest.get("chunk_count"),
        "total_bytes": manifest.get("total_bytes"),
        "chunks": [
            {
                "index": item.get("index"),
                "hash": item.get("hash"),
                "size": item.get("size"),
            }
            for item in raw_chunks
            if isinstance(item, Mapping)
        ],
    }
    return COURIER_SIGNATURE_DOMAIN + _canonical_json(signed)


def _verify_sender_signature(
    manifest: Mapping[str, object],
    *,
    expected_sender_fp: str | None,
    required: bool,
) -> bool:
    sender_fp = _clean_fp(manifest.get("sender_fp"), required=True)
    expected = _clean_fp(
        expected_sender_fp,
        required=expected_sender_fp is not None,
    )
    if expected is not None and sender_fp != expected:
        raise CourierBundleError("courier bundle is from a different sender")

    has_pub = "sender_pub" in manifest
    has_signature = "sender_signature" in manifest
    if has_pub != has_signature:
        raise CourierBundleError("courier sender identity proof is incomplete")
    if not has_pub:
        if required:
            raise CourierBundleError("courier sender signature is required")
        return False

    sender_pub = _b64u_decode(
        manifest.get("sender_pub"),
        expected_len=32,
        label="courier sender public key",
    )
    signature = _b64u_decode(
        manifest.get("sender_signature"),
        expected_len=64,
        label="courier sender signature",
    )
    if blake3.blake3(sender_pub).hexdigest() != sender_fp:
        raise CourierBundleError(
            "courier sender public key does not match the sender fingerprint"
        )
    try:
        Ed25519PublicKey.from_public_bytes(sender_pub).verify(
            signature,
            _signature_payload(manifest),
        )
    except (InvalidSignature, ValueError) as exc:
        raise CourierBundleError("courier sender signature is invalid") from exc
    return True


def _normalize_export_chunks(
    chunks: Iterable[tuple[str, bytes]],
    *,
    max_chunks: int,
    max_chunk_bytes: int,
    max_total_chunk_bytes: int,
) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    seen: set[str] = set()
    total = 0
    for chunk_hash, data in chunks:
        if len(out) >= max_chunks:
            raise CourierBundleError("courier bundle has too many chunks")
        h = _clean_hash(chunk_hash)
        if h in seen:
            raise CourierBundleError("courier bundle contains duplicate chunks")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise CourierBundleError("courier chunk data must be bytes")
        data_len = memoryview(data).nbytes
        if data_len > max_chunk_bytes:
            raise CourierBundleError("courier chunk exceeds the per-chunk size limit")
        if data_len > max_total_chunk_bytes - total:
            raise CourierBundleError("courier bundle exceeds the total chunk size limit")
        b = bytes(data)
        if blake3.blake3(b).hexdigest() != h:
            raise CourierBundleError("courier chunk hash mismatch")
        total += len(b)
        seen.add(h)
        out.append({
            "index": len(out),
            "hash": h,
            "size": len(b),
            "data": base64.b64encode(b).decode("ascii"),
        })
    if not out:
        raise CourierBundleError("courier bundle must contain at least one chunk")
    return out


def _decode_import_chunks(
    raw_chunks: object,
    *,
    max_chunks: int,
    max_chunk_bytes: int,
    max_total_chunk_bytes: int,
    expected_total_bytes: int,
) -> tuple[tuple[str, bytes], ...]:
    if not isinstance(raw_chunks, Sequence) or isinstance(raw_chunks, (str, bytes, bytearray)):
        raise CourierBundleError("courier chunk list is malformed")
    if not raw_chunks or len(raw_chunks) > max_chunks:
        raise CourierBundleError("courier chunk count is outside limits")

    # Validate every declared size, encoded length, index, hash, and the
    # aggregate byte budget before decoding even the first base64 payload.
    # That makes failure deterministic and prevents a late oversized part from
    # forcing all earlier decoded parts to remain resident first.
    validated: list[tuple[str, int]] = []
    seen: set[str] = set()
    declared_total = 0
    for item in raw_chunks:
        if not isinstance(item, Mapping):
            raise CourierBundleError("courier chunk entry is malformed")
        if set(item) != {"index", "hash", "size", "data"}:
            raise CourierBundleError("courier chunk entry has unknown or missing fields")
        raw_hash = item.get("hash")
        h = _clean_hash(raw_hash)
        if not isinstance(raw_hash, str) or raw_hash != h:
            raise CourierBundleError("courier chunk hash is not canonical")
        if h in seen:
            raise CourierBundleError("courier bundle contains duplicate chunks")
        index = _strict_nonnegative_int(item.get("index"), "courier chunk index")
        declared_size = _strict_nonnegative_int(item.get("size"), "courier chunk size")
        if index != len(validated):
            raise CourierBundleError("courier chunk index is invalid")
        if declared_size > max_chunk_bytes:
            raise CourierBundleError("courier chunk exceeds the per-chunk size limit")
        if declared_size > max_total_chunk_bytes - declared_total:
            raise CourierBundleError("courier bundle exceeds the total chunk size limit")
        encoded = item.get("data")
        if not isinstance(encoded, str):
            raise CourierBundleError("courier chunk payload is not a base64 string")
        expected_encoded_len = ((declared_size + 2) // 3) * 4
        if len(encoded) != expected_encoded_len:
            raise CourierBundleError("courier chunk encoded size mismatch")
        try:
            encoded.encode("ascii")
        except UnicodeEncodeError as exc:
            raise CourierBundleError("courier chunk payload is not valid base64") from exc
        declared_total += declared_size
        seen.add(h)
        validated.append((h, declared_size))

    if declared_total != expected_total_bytes:
        raise CourierBundleError("courier bundle byte count mismatch")

    out: list[tuple[str, bytes]] = []
    for raw_item, (h, declared_size) in zip(raw_chunks, validated, strict=True):
        assert isinstance(raw_item, Mapping)
        encoded = raw_item.get("data")
        assert isinstance(encoded, str)
        try:
            data = base64.b64decode(encoded, validate=True)
        except Exception as exc:
            raise CourierBundleError("courier chunk payload is not valid base64") from exc
        if len(data) != declared_size:
            raise CourierBundleError("courier chunk size mismatch")
        if base64.b64encode(data).decode("ascii") != encoded:
            raise CourierBundleError("courier chunk payload is not canonical base64")
        if blake3.blake3(data).hexdigest() != h:
            raise CourierBundleError("courier chunk hash mismatch")
        out.append((h, data))
        # ``json.load`` has already materialised the manifest.  Release each
        # bulky base64 string as soon as its verified bytes exist so peak
        # memory tracks the bounded manifest size rather than manifest + all
        # decoded chunks.  JSON objects are concrete dicts in this path.
        if isinstance(raw_item, dict):
            raw_item["data"] = None
    return tuple(out)


def _load_manifest_stream(plaintext: BinaryIO) -> dict[str, object]:
    plaintext.seek(0)
    text_stream = io.TextIOWrapper(plaintext, encoding="utf-8", errors="strict")
    try:
        manifest = json.load(text_stream, object_pairs_hook=_unique_json_object)
    except CourierBundleError:
        raise
    except Exception as exc:
        raise CourierBundleError("courier bundle manifest is not valid JSON") from exc
    finally:
        # The surrounding temporary-file context owns the binary stream.
        # Detach so TextIOWrapper finalisation cannot close it twice.
        with contextlib.suppress(Exception):
            text_stream.detach()
    if not isinstance(manifest, dict):
        raise CourierBundleError("courier bundle manifest is not an object")
    allowed_fields = {
        "version",
        "bundle_id",
        "created_ms",
        "expires_ms",
        "sender_fp",
        "sender_pub",
        "sender_signature",
        "recipient_fp",
        "blob_hash",
        "name",
        "chunk_count",
        "total_bytes",
        "chunks",
    }
    if any(not isinstance(key, str) or key not in allowed_fields for key in manifest):
        raise CourierBundleError("courier bundle manifest has unknown fields")
    version = manifest.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version != COURIER_VERSION:
        raise CourierBundleError("unsupported courier bundle version")
    bundle_id = manifest.get("bundle_id")
    if not isinstance(bundle_id, str) or len(bundle_id) != 32:
        raise CourierBundleError("courier bundle id is invalid")
    try:
        int(bundle_id, 16)
    except ValueError as exc:
        raise CourierBundleError("courier bundle id is invalid") from exc
    if bundle_id != bundle_id.lower():
        raise CourierBundleError("courier bundle id is not canonical")
    sender_fp = _clean_fp(manifest.get("sender_fp"), required=True)
    if sender_fp != manifest.get("sender_fp"):
        raise CourierBundleError("courier sender fingerprint is not canonical")
    recipient_fp = _clean_fp(manifest.get("recipient_fp"), required=False)
    if recipient_fp != manifest.get("recipient_fp"):
        raise CourierBundleError("courier recipient fingerprint is not canonical")
    blob_hash = manifest.get("blob_hash")
    if blob_hash is not None:
        clean_blob_hash = _clean_hash(blob_hash)
        if not isinstance(blob_hash, str) or clean_blob_hash != blob_hash:
            raise CourierBundleError("courier blob hash is not canonical")
    name = manifest.get("name")
    if name is not None:
        if not isinstance(name, str) or _clean_name(name) != name:
            raise CourierBundleError("courier bundle name is not canonical")
    created_ms = _strict_nonnegative_int(
        manifest.get("created_ms"),
        "courier bundle created time",
    )
    expires_ms = _strict_nonnegative_int(
        manifest.get("expires_ms"),
        "courier bundle expiry",
    )
    if expires_ms <= created_ms:
        raise CourierBundleError("courier bundle expiry is invalid")
    chunk_count = _strict_nonnegative_int(
        manifest.get("chunk_count"),
        "courier bundle chunk count",
    )
    _strict_nonnegative_int(manifest.get("total_bytes"), "courier bundle byte count")
    chunks = manifest.get("chunks")
    if not isinstance(chunks, list):
        raise CourierBundleError("courier bundle chunk list is missing")
    if chunk_count != len(chunks):
        raise CourierBundleError("courier bundle chunk count mismatch")
    return manifest


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CourierBundleError("courier bundle manifest has duplicate fields")
        result[key] = value
    return result


def _clean_hash(value: object) -> str:
    h = str(value or "").strip().lower()
    if len(h) != 64:
        raise CourierBundleError("courier chunk hash is invalid")
    try:
        int(h, 16)
    except ValueError as exc:
        raise CourierBundleError("courier chunk hash is invalid") from exc
    return h


def _clean_fp(value: object, *, required: bool) -> str | None:
    text = str(value or "").strip().lower()
    if not text:
        if required:
            raise CourierBundleError("courier peer fingerprint is required")
        return None
    if len(text) != 64:
        raise CourierBundleError("courier peer fingerprint is invalid")
    try:
        int(text, 16)
    except ValueError as exc:
        raise CourierBundleError("courier peer fingerprint is invalid") from exc
    return text


def _clean_name(value: object) -> str | None:
    text = str(value or "").replace("\x00", "").strip()
    if not text:
        return None
    text = text.replace("\\", "/").split("/")[-1].rstrip(". ")
    text = "".join(c for c in text if ord(c) >= 32 and ord(c) != 127)
    if not text:
        return None
    encoded = text.encode("utf-8", errors="ignore")
    if len(encoded) <= 240:
        return text
    return encoded[:240].decode("utf-8", errors="ignore").rstrip() or None


def _canonical_json(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _public_manifest(manifest: Mapping[str, object]) -> dict[str, object]:
    chunks_raw = manifest.get("chunks", [])
    chunks = chunks_raw if isinstance(chunks_raw, list) else []
    return {
        "version": manifest.get("version"),
        "bundle_id": manifest.get("bundle_id"),
        "created_ms": manifest.get("created_ms"),
        "expires_ms": manifest.get("expires_ms"),
        "sender_fp": manifest.get("sender_fp"),
        "recipient_fp": manifest.get("recipient_fp"),
        "blob_hash": manifest.get("blob_hash"),
        "name": manifest.get("name"),
        "chunk_count": manifest.get("chunk_count"),
        "total_bytes": manifest.get("total_bytes"),
        "chunks": [
            {"index": c.get("index"), "hash": c.get("hash"), "size": c.get("size")}
            for c in chunks
            if isinstance(c, Mapping)
        ],
    }
