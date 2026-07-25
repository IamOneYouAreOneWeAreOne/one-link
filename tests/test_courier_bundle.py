from __future__ import annotations

import base64
import gzip
import io
import json
import secrets

import blake3
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from one_link.courier_bundle import (
    COURIER_MAGIC,
    COURIER_TOKEN_PREFIX,
    NONCE_LEN,
    CourierBundleError,
    CourierHeader,
    assemble_courier_chunks,
    decode_bundle_b64,
    decode_key_token,
    encode_bundle_b64,
    encode_key_token,
    export_courier_bundle,
    import_courier_bundle,
)


SENDER_FP = "11" * 32
RECIPIENT_FP = "22" * 32
OTHER_FP = "33" * 32


def _chunk(data: bytes) -> tuple[str, bytes]:
    return blake3.blake3(data).hexdigest(), data


def _seal_compressed(compressed: bytes) -> tuple[bytes, str]:
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(NONCE_LEN)
    header = CourierHeader(
        plaintext_len=len(compressed),
        nonce=nonce,
        created_ms=1_000,
        expires_ms=2_000,
    )
    aad = header.encode()
    return aad + AESGCM(key).encrypt(nonce, compressed, aad), encode_key_token(key)


def test_courier_bundle_round_trips_encrypted_chunks():
    plain = b"people-owned offline data path: We are One" * 32
    chunks = [_chunk(plain), _chunk(b"second chunk" * 100)]

    export = export_courier_bundle(
        chunks,
        sender_fp=SENDER_FP,
        recipient_fp=RECIPIENT_FP,
        blob_hash=blake3.blake3(plain + chunks[1][1]).hexdigest(),
        name="../Report.txt.",
        ttl_s=60,
        now_ms=1_000_000,
    )

    assert export.bundle.startswith(COURIER_MAGIC)
    assert export.key_token.startswith(COURIER_TOKEN_PREFIX)
    assert plain not in export.bundle
    assert b"people-owned" not in export.bundle
    assert export.manifest["chunk_count"] == 2
    assert export.manifest["name"] == "Report.txt"
    assert export.manifest["chunks"][0]["index"] == 0
    assert "data" not in export.manifest["chunks"][0]

    imported = import_courier_bundle(
        export.bundle,
        export.key_token,
        expected_recipient_fp=RECIPIENT_FP,
        now_ms=1_000_100,
    )
    assert imported.manifest["sender_fp"] == SENDER_FP
    assert imported.chunks == tuple(chunks)


def test_courier_bundle_rejects_tampered_ciphertext():
    export = export_courier_bundle([_chunk(b"tamper target")], sender_fp=SENDER_FP)
    tampered = bytearray(export.bundle)
    tampered[-8] ^= 0x55

    with pytest.raises(CourierBundleError, match="could not be decrypted"):
        import_courier_bundle(bytes(tampered), export.key_token)


def test_courier_bundle_rejects_wrong_key():
    export = export_courier_bundle([_chunk(b"secret")], sender_fp=SENDER_FP)
    wrong = export_courier_bundle([_chunk(b"other")], sender_fp=SENDER_FP)

    with pytest.raises(CourierBundleError, match="could not be decrypted"):
        import_courier_bundle(export.bundle, wrong.key_token)


def test_courier_bundle_rejects_expired_bundle():
    export = export_courier_bundle(
        [_chunk(b"expires")],
        sender_fp=SENDER_FP,
        ttl_s=1,
        now_ms=10_000,
    )

    with pytest.raises(CourierBundleError, match="expired"):
        import_courier_bundle(export.bundle, export.key_token, now_ms=12_000)


def test_courier_bundle_rejects_wrong_recipient():
    export = export_courier_bundle(
        [_chunk(b"recipient")],
        sender_fp=SENDER_FP,
        recipient_fp=RECIPIENT_FP,
    )

    with pytest.raises(CourierBundleError, match="different recipient"):
        import_courier_bundle(
            export.bundle,
            export.key_token,
            expected_recipient_fp=OTHER_FP,
        )


def test_courier_bundle_rejects_duplicate_chunks_and_bad_hashes():
    h, data = _chunk(b"duplicate")
    with pytest.raises(CourierBundleError, match="duplicate"):
        export_courier_bundle([(h, data), (h, data)], sender_fp=SENDER_FP)

    with pytest.raises(CourierBundleError, match="hash mismatch"):
        export_courier_bundle([("00" * 32, data)], sender_fp=SENDER_FP)


def test_courier_bundle_rejects_replay_when_seen_set_is_supplied():
    export = export_courier_bundle([_chunk(b"replay")], sender_fp=SENDER_FP)
    seen: set[str] = set()

    import_courier_bundle(export.bundle, export.key_token, replay_seen=seen)
    with pytest.raises(CourierBundleError, match="already imported"):
        import_courier_bundle(export.bundle, export.key_token, replay_seen=seen)


def test_courier_bundle_base64_and_token_validation():
    export = export_courier_bundle([_chunk(b"encoding")], sender_fp=SENDER_FP)
    encoded = encode_bundle_b64(export.bundle)

    assert decode_bundle_b64(encoded) == export.bundle
    assert len(decode_key_token(export.key_token)) == 32

    with pytest.raises(CourierBundleError, match="not valid base64"):
        decode_bundle_b64("%%%")
    with pytest.raises(CourierBundleError, match="start with OLC1"):
        decode_key_token(base64.b64encode(b"x" * 32).decode("ascii"))


def test_courier_bundle_streaming_decompress_rejects_gzip_bomb():
    bundle, token = _seal_compressed(gzip.compress(b"A" * (2 * 1024 * 1024), mtime=0))

    with pytest.raises(CourierBundleError, match="payload exceeds the size limit"):
        import_courier_bundle(
            bundle,
            token,
            now_ms=1_500,
            max_plaintext_bytes=1024,
        )


def test_courier_bundle_streaming_decompress_rejects_truncated_member():
    compressed = gzip.compress(b'{}', mtime=0)
    bundle, token = _seal_compressed(compressed[:-4])

    with pytest.raises(CourierBundleError, match="gzip payload is truncated"):
        import_courier_bundle(bundle, token, now_ms=1_500)


def test_courier_bundle_enforces_part_count_part_size_and_total_before_decode():
    chunks = [_chunk(b"a" * 32), _chunk(b"b" * 48)]
    export = export_courier_bundle(
        chunks,
        sender_fp=SENDER_FP,
        now_ms=1_000,
        ttl_s=60,
    )

    with pytest.raises(CourierBundleError, match="count is outside limits"):
        import_courier_bundle(
            export.bundle,
            export.key_token,
            now_ms=1_100,
            max_chunks=1,
        )
    with pytest.raises(CourierBundleError, match="per-chunk size limit"):
        import_courier_bundle(
            export.bundle,
            export.key_token,
            now_ms=1_100,
            max_chunk_bytes=31,
        )
    with pytest.raises(CourierBundleError, match="total chunk size limit"):
        import_courier_bundle(
            export.bundle,
            export.key_token,
            now_ms=1_100,
            max_total_chunk_bytes=79,
        )


def test_courier_bundle_expected_recipient_requires_manifest_binding():
    export = export_courier_bundle(
        [_chunk(b"recipient binding is mandatory")],
        sender_fp=SENDER_FP,
        now_ms=1_000,
        ttl_s=60,
    )

    with pytest.raises(CourierBundleError, match="not bound to a recipient"):
        import_courier_bundle(
            export.bundle,
            export.key_token,
            expected_recipient_fp=RECIPIENT_FP,
            now_ms=1_100,
        )


def test_courier_bundle_ed25519_authenticates_expected_sender():
    signing_key = Ed25519PrivateKey.generate()
    sender_pub = signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    sender_fp = blake3.blake3(sender_pub).hexdigest()
    signed = export_courier_bundle(
        [_chunk(b"signed offline payload")],
        sender_fp=sender_fp,
        recipient_fp=RECIPIENT_FP,
        signing_key=signing_key,
        now_ms=1_000,
        ttl_s=60,
    )

    imported = import_courier_bundle(
        signed.bundle,
        signed.key_token,
        expected_recipient_fp=RECIPIENT_FP,
        expected_sender_fp=sender_fp,
        now_ms=1_100,
    )
    assert imported.manifest["sender_authenticated"] is True

    unsigned = export_courier_bundle(
        [_chunk(b"legacy unsigned payload")],
        sender_fp=sender_fp,
        recipient_fp=RECIPIENT_FP,
        now_ms=1_000,
        ttl_s=60,
    )
    with pytest.raises(CourierBundleError, match="sender signature is required"):
        import_courier_bundle(
            unsigned.bundle,
            unsigned.key_token,
            expected_sender_fp=sender_fp,
            now_ms=1_100,
        )


def test_courier_bundle_sender_signature_rejects_token_holder_forgery():
    signing_key = Ed25519PrivateKey.generate()
    sender_pub = signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    sender_fp = blake3.blake3(sender_pub).hexdigest()
    export = export_courier_bundle(
        [_chunk(b"authentic signed payload")],
        sender_fp=sender_fp,
        signing_key=signing_key,
        now_ms=1_000,
        ttl_s=60,
    )
    key = decode_key_token(export.key_token)
    header = CourierHeader.decode(export.bundle)
    compressed = AESGCM(key).decrypt(
        header.nonce,
        export.bundle[len(header.encode()) :],
        header.encode(),
    )
    manifest = json.loads(gzip.decompress(compressed))
    manifest["name"] = "forged-name.bin"
    forged_compressed = gzip.compress(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        mtime=0,
    )
    forged_header = CourierHeader(
        plaintext_len=len(forged_compressed),
        nonce=header.nonce,
        created_ms=header.created_ms,
        expires_ms=header.expires_ms,
    )
    forged_aad = forged_header.encode()
    forged_bundle = forged_aad + AESGCM(key).encrypt(
        header.nonce,
        forged_compressed,
        forged_aad,
    )

    with pytest.raises(CourierBundleError, match="sender signature is invalid"):
        import_courier_bundle(forged_bundle, export.key_token, now_ms=1_100)


def test_courier_assembly_streams_and_rolls_back_on_total_limit():
    prefix = b"existing-prefix"
    destination = io.BytesIO(prefix)
    destination.seek(0, io.SEEK_END)
    chunks = [_chunk(b"first" * 8), _chunk(b"second" * 8)]

    with pytest.raises(CourierBundleError, match="total chunk size limit"):
        assemble_courier_chunks(
            iter(chunks),
            destination,
            max_total_chunk_bytes=len(chunks[0][1]) + len(chunks[1][1]) - 1,
        )
    assert destination.getvalue() == prefix

    total = assemble_courier_chunks(
        iter(chunks),
        destination,
        expected_blob_hash=blake3.blake3(chunks[0][1] + chunks[1][1]).hexdigest(),
    )
    assert total == sum(len(data) for _, data in chunks)
    assert destination.getvalue() == prefix + chunks[0][1] + chunks[1][1]


def test_courier_bundle_rejects_declared_compressed_size_before_decryption():
    export = export_courier_bundle(
        [_chunk(b"compressed cap")],
        sender_fp=SENDER_FP,
    )
    length_start = len(COURIER_MAGIC)
    compressed_len = int.from_bytes(export.bundle[length_start : length_start + 8], "big")

    with pytest.raises(CourierBundleError, match="compressed payload exceeds"):
        import_courier_bundle(
            export.bundle,
            export.key_token,
            max_compressed_bytes=compressed_len - 1,
        )
