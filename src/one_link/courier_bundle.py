"""Encrypted offline courier bundles for One Link chunks.

Courier bundles are the no-router, no-internet fallback for large transfers:
put encrypted chunks on a USB stick, local share, SD card, or any other
plain file carrier, then pass a short unlock token over a separate channel.

The file is intentionally useless without the token. Every imported chunk is
content-address verified before it enters the normal CDC chunk cache, so the
online and offline paths share the same integrity model.
"""
from __future__ import annotations

import base64
import gzip
import json
import secrets
import struct
import time
from dataclasses import dataclass
from typing import Iterable, Mapping, MutableSet, Sequence

import blake3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


COURIER_MAGIC = b"OLCB\x01\x00\x00\x00"
COURIER_TOKEN_PREFIX = "OLC1."
COURIER_VERSION = 1
NONCE_LEN = 12
KEY_LEN = 32
HEADER_LEN = len(COURIER_MAGIC) + 8 + NONCE_LEN + 8 + 8
DEFAULT_TTL_S = 24 * 60 * 60
MAX_TTL_S = 14 * 24 * 60 * 60
DEFAULT_MAX_CHUNKS = 4096
DEFAULT_MAX_PLAINTEXT_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_BUNDLE_BYTES = 768 * 1024 * 1024


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
    if len(key) != KEY_LEN:
        raise CourierBundleError("courier key must be 32 bytes")
    payload = base64.urlsafe_b64encode(key).decode("ascii").rstrip("=")
    return COURIER_TOKEN_PREFIX + payload


def decode_key_token(token: str) -> bytes:
    token = str(token or "").strip()
    if not token.startswith(COURIER_TOKEN_PREFIX):
        raise CourierBundleError("courier key token must start with OLC1.")
    raw = token[len(COURIER_TOKEN_PREFIX) :]
    if not raw:
        raise CourierBundleError("courier key token is empty")
    try:
        key = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except Exception as exc:
        raise CourierBundleError("courier key token is not valid base64") from exc
    if len(key) != KEY_LEN:
        raise CourierBundleError("courier key token has the wrong length")
    return key


def encode_bundle_b64(bundle: bytes) -> str:
    return base64.b64encode(bundle).decode("ascii")


def decode_bundle_b64(value: str, *, max_bundle_bytes: int = DEFAULT_MAX_BUNDLE_BYTES) -> bytes:
    try:
        bundle = base64.b64decode(str(value or ""), validate=True)
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
) -> CourierExport:
    now = int(now_ms if now_ms is not None else time.time() * 1000)
    ttl = max(1, min(int(ttl_s), MAX_TTL_S))
    expires_ms = now + ttl * 1000
    entries = _normalize_export_chunks(
        chunks,
        max_chunks=max_chunks,
        max_plaintext_bytes=max_plaintext_bytes,
    )
    bundle_id = secrets.token_hex(16)
    manifest: dict[str, object] = {
        "version": COURIER_VERSION,
        "bundle_id": bundle_id,
        "created_ms": now,
        "expires_ms": expires_ms,
        "sender_fp": _clean_fp(sender_fp, required=True),
        "recipient_fp": _clean_fp(recipient_fp, required=False),
        "blob_hash": _clean_hash(blob_hash) if blob_hash else None,
        "name": _clean_name(name),
        "chunk_count": len(entries),
        "total_bytes": sum(int(e["size"]) for e in entries),
        "chunks": entries,
    }
    plaintext = _canonical_json(manifest)
    if len(plaintext) > max_plaintext_bytes:
        raise CourierBundleError("courier bundle manifest exceeds the size limit")
    compressed = gzip.compress(plaintext, compresslevel=6, mtime=0)
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
    return CourierExport(
        bundle=aad + ciphertext,
        key_token=encode_key_token(key),
        manifest=_public_manifest(manifest),
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
) -> CourierImport:
    if len(bundle) > max_bundle_bytes:
        raise CourierBundleError("courier bundle exceeds the configured size limit")
    header = CourierHeader.decode(bundle)
    now = int(now_ms if now_ms is not None else time.time() * 1000)
    if now > header.expires_ms:
        raise CourierBundleError("courier bundle has expired")
    ciphertext = bundle[HEADER_LEN:]
    if not ciphertext:
        raise CourierBundleError("courier bundle has no ciphertext")
    key = decode_key_token(key_token)
    try:
        compressed = AESGCM(key).decrypt(header.nonce, ciphertext, bundle[:HEADER_LEN])
    except Exception as exc:
        raise CourierBundleError("courier bundle could not be decrypted") from exc
    if len(compressed) != header.plaintext_len:
        raise CourierBundleError("courier bundle plaintext length mismatch")
    try:
        plaintext = gzip.decompress(compressed)
    except Exception as exc:
        raise CourierBundleError("courier bundle payload is not valid gzip") from exc
    if len(plaintext) > max_plaintext_bytes:
        raise CourierBundleError("courier bundle payload exceeds the size limit")
    manifest = _load_manifest(plaintext)
    if int(manifest["created_ms"]) != header.created_ms:
        raise CourierBundleError("courier bundle created time mismatch")
    if int(manifest["expires_ms"]) != header.expires_ms:
        raise CourierBundleError("courier bundle expiry mismatch")
    recipient_fp = manifest.get("recipient_fp") or None
    expected = _clean_fp(expected_recipient_fp, required=False)
    if expected and recipient_fp and recipient_fp != expected:
        raise CourierBundleError("courier bundle is for a different recipient")
    bundle_id = str(manifest["bundle_id"])
    chunks = _decode_import_chunks(
        manifest["chunks"],
        max_chunks=max_chunks,
        max_plaintext_bytes=max_plaintext_bytes,
    )
    if int(manifest["total_bytes"]) != sum(len(data) for _, data in chunks):
        raise CourierBundleError("courier bundle byte count mismatch")
    if replay_seen is not None:
        if bundle_id in replay_seen:
            raise CourierBundleError("courier bundle was already imported")
        replay_seen.add(bundle_id)
    return CourierImport(manifest=_public_manifest(manifest), chunks=chunks)


def _normalize_export_chunks(
    chunks: Iterable[tuple[str, bytes]],
    *,
    max_chunks: int,
    max_plaintext_bytes: int,
) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    seen: set[str] = set()
    total = 0
    for chunk_hash, data in chunks:
        h = _clean_hash(chunk_hash)
        if h in seen:
            raise CourierBundleError("courier bundle contains duplicate chunks")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise CourierBundleError("courier chunk data must be bytes")
        b = bytes(data)
        if blake3.blake3(b).hexdigest() != h:
            raise CourierBundleError("courier chunk hash mismatch")
        total += len(b)
        if total > max_plaintext_bytes:
            raise CourierBundleError("courier bundle exceeds the size limit")
        seen.add(h)
        out.append({
            "index": len(out),
            "hash": h,
            "size": len(b),
            "data": base64.b64encode(b).decode("ascii"),
        })
        if len(out) > max_chunks:
            raise CourierBundleError("courier bundle has too many chunks")
    if not out:
        raise CourierBundleError("courier bundle must contain at least one chunk")
    return out


def _decode_import_chunks(
    raw_chunks: object,
    *,
    max_chunks: int,
    max_plaintext_bytes: int,
) -> tuple[tuple[str, bytes], ...]:
    if not isinstance(raw_chunks, Sequence) or isinstance(raw_chunks, (str, bytes, bytearray)):
        raise CourierBundleError("courier chunk list is malformed")
    if not raw_chunks or len(raw_chunks) > max_chunks:
        raise CourierBundleError("courier chunk count is outside limits")
    out: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    total = 0
    for item in raw_chunks:
        if not isinstance(item, Mapping):
            raise CourierBundleError("courier chunk entry is malformed")
        h = _clean_hash(item.get("hash"))
        if h in seen:
            raise CourierBundleError("courier bundle contains duplicate chunks")
        try:
            index = int(item.get("index", len(out)))
            declared_size = int(item.get("size"))
        except (TypeError, ValueError, OverflowError) as exc:
            raise CourierBundleError("courier chunk size is invalid") from exc
        if index != len(out):
            raise CourierBundleError("courier chunk index is invalid")
        if declared_size < 0:
            raise CourierBundleError("courier chunk size is invalid")
        try:
            data = base64.b64decode(str(item.get("data") or ""), validate=True)
        except Exception as exc:
            raise CourierBundleError("courier chunk payload is not valid base64") from exc
        if len(data) != declared_size:
            raise CourierBundleError("courier chunk size mismatch")
        if blake3.blake3(data).hexdigest() != h:
            raise CourierBundleError("courier chunk hash mismatch")
        total += len(data)
        if total > max_plaintext_bytes:
            raise CourierBundleError("courier bundle exceeds the size limit")
        seen.add(h)
        out.append((h, data))
    return tuple(out)


def _load_manifest(plaintext: bytes) -> dict[str, object]:
    try:
        manifest = json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise CourierBundleError("courier bundle manifest is not valid JSON") from exc
    if not isinstance(manifest, dict):
        raise CourierBundleError("courier bundle manifest is not an object")
    if manifest.get("version") != COURIER_VERSION:
        raise CourierBundleError("unsupported courier bundle version")
    if not isinstance(manifest.get("bundle_id"), str) or len(str(manifest["bundle_id"])) != 32:
        raise CourierBundleError("courier bundle id is invalid")
    _clean_fp(manifest.get("sender_fp"), required=True)
    _clean_fp(manifest.get("recipient_fp"), required=False)
    if manifest.get("blob_hash"):
        _clean_hash(manifest.get("blob_hash"))
    try:
        int(manifest["created_ms"])
        int(manifest["expires_ms"])
        int(manifest["chunk_count"])
        int(manifest["total_bytes"])
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise CourierBundleError("courier bundle manifest counters are invalid") from exc
    chunks = manifest.get("chunks")
    if not isinstance(chunks, list):
        raise CourierBundleError("courier bundle chunk list is missing")
    if int(manifest["chunk_count"]) != len(chunks):
        raise CourierBundleError("courier bundle chunk count mismatch")
    return manifest


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
    chunks = manifest.get("chunks", [])
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
