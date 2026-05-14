from __future__ import annotations

import base64

import blake3
import pytest

from one_link.courier_bundle import (
    COURIER_MAGIC,
    COURIER_TOKEN_PREFIX,
    CourierBundleError,
    decode_bundle_b64,
    decode_key_token,
    encode_bundle_b64,
    export_courier_bundle,
    import_courier_bundle,
)


SENDER_FP = "11" * 32
RECIPIENT_FP = "22" * 32
OTHER_FP = "33" * 32


def _chunk(data: bytes) -> tuple[str, bytes]:
    return blake3.blake3(data).hexdigest(), data


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
