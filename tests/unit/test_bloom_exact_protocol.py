"""Lossless Bloom-init protocol regression coverage.

The Bloom filter compresses a receiver's verified chunk inventory.  Bloom
membership is probabilistic, so the wire response also carries the exact
missing indexes that false-positive in that particular filter.  Together they
must reconstruct the same delta as an explicit ``FILE_WANTS`` list.
"""

from __future__ import annotations

import asyncio
import base64
from pathlib import Path
from types import SimpleNamespace

import blake3
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import bloom_init
from one_link.capabilities import BLOOM_INIT_EXACT_V2, BLOOM_INIT_V1
from one_link.daemon import Daemon, IncomingFile, _bloom_manifest_binding
from one_link.identity import Identity, fingerprint_of
from one_link.wire import decode_msg


pytestmark = pytest.mark.skipif(
    not bloom_init.HAS_NATIVE,
    reason="native Bloom runtime is unavailable",
)


def _identity() -> Identity:
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    public_bytes = public.public_bytes_raw()
    fingerprint = fingerprint_of(public_bytes)
    return Identity(
        private=private,
        public=public,
        public_bytes=public_bytes,
        fingerprint=fingerprint,
        short_id=fingerprint[:8],
        hostname="bloom-test",
    )


class _CaptureChannel:
    def __init__(self) -> None:
        self.sent: list[dict] = []

    async def send(self, payload: bytes) -> None:
        self.sent.append(decode_msg(payload))


def _advertise_bloom(daemon: Daemon, peer_fp: str) -> None:
    daemon._outbound_sessions[peer_fp] = SimpleNamespace(
        channel=SimpleNamespace(
            peer_caps={"features": [BLOOM_INIT_V1, BLOOM_INIT_EXACT_V2]},
        ),
    )


def test_manifest_binding_covers_boundaries_order_and_hashes() -> None:
    chunk_hash = blake3.blake3(b"a").hexdigest()
    manifest = [{
        "index": 0,
        "start": 0,
        "end": 1,
        "size": 1,
        "hash": chunk_hash,
    }]
    binding = _bloom_manifest_binding(manifest)
    assert binding == _bloom_manifest_binding([dict(manifest[0])])
    changed = [dict(manifest[0], start=1, end=2)]
    assert _bloom_manifest_binding(changed) != binding
    with pytest.raises(ValueError, match="invalid CDC manifest"):
        _bloom_manifest_binding([dict(manifest[0], hash="not-a-hash")])


def test_receiver_inventory_and_corrections_reconstruct_exact_delta(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receiver = Daemon(_identity())
    sender = Daemon(_identity())
    _advertise_bloom(receiver, sender.me.fingerprint)
    _advertise_bloom(sender, receiver.me.fingerprint)

    chunks: list[bytes] = [
        blake3.blake3(i.to_bytes(4, "little")).digest()
        for i in range(257)
    ]
    manifest: list[dict] = []
    cursor = 0
    for index, data in enumerate(chunks):
        manifest.append({
            "index": index,
            "start": cursor,
            "end": cursor + len(data),
            "size": len(data),
            "hash": blake3.blake3(data).hexdigest(),
        })
        cursor += len(data)
    blob = blake3.blake3(b"".join(chunks)).hexdigest()
    partial = tmp_path / "partial.bin"
    handle = partial.open("w+b")
    receiver._incoming_files[blob] = IncomingFile(
        name="delta.bin",
        size=cursor,
        blob_hex=blob,
        out_path=partial,
        handle=handle,
        hasher=blake3.blake3(),
        cdc_chunks=manifest,
        cdc_missing=set(range(1, len(manifest))),
        peer_fp=sender.me.fingerprint,
    )
    try:
        receiver._store_chunk_cache(manifest[0]["hash"], chunks[0])
        assert receiver._locally_held_chunk_ids_for_blob(blob) == [
            bytes.fromhex(manifest[0]["hash"]),
        ]

        # A deliberately high rate makes false positives common and proves
        # the correction vector, rather than statistical luck, preserves the
        # exact delta.
        monkeypatch.setenv("ONE_LINK_BLOOM_FP_RATE", "0.5")
        channel = _CaptureChannel()
        sent = asyncio.run(receiver._maybe_send_bloom_init_advisory(
            channel,
            msg_id="offer-123",
            blob=blob,
            peer_fp=sender.me.fingerprint,
        ))
        assert sent is True
        assert len(channel.sent) == 1
        message = channel.sent[0]
        assert message["of"] == "offer-123"
        assert message["manifest_binding"] == _bloom_manifest_binding(manifest)

        wire = base64.b64decode(message["bloom"], validate=True)
        decoded = bloom_init.decode_receiver_bloom(wire)
        corrections = set(message["corrections"])
        reconstructed = {
            int(chunk["index"])
            for chunk in manifest
            if not decoded.contains(bytes.fromhex(chunk["hash"]))
            or int(chunk["index"]) in corrections
        }
        assert reconstructed == set(range(1, len(manifest)))
        assert corrections

        accepted = asyncio.run(sender._handle_bloom_init_advisory(
            SimpleNamespace(),
            message,
            receiver.me.fingerprint,
        ))
        assert accepted is True
        assert sender.bloom_decision_for_chunk(
            receiver.me.fingerprint,
            blob,
            bytes.fromhex(manifest[0]["hash"]),
            manifest_binding="0" * 64,
            manifest_count=len(manifest),
        ) is None
        assert sender.bloom_decision_for_chunk(
            receiver.me.fingerprint,
            blob,
            bytes.fromhex(manifest[0]["hash"]),
            manifest_binding=message["manifest_binding"],
            manifest_count=len(manifest),
        ) is True
        sender_reconstructed = {
            int(chunk["index"])
            for chunk in manifest
            if not sender.bloom_decision_for_chunk(
                receiver.me.fingerprint,
                blob,
                bytes.fromhex(chunk["hash"]),
            )
            or int(chunk["index"]) in corrections
        }
        assert sender_reconstructed == set(range(1, len(manifest)))

        malformed = dict(message, n_known=len(manifest) + 1)
        assert asyncio.run(sender._handle_bloom_init_advisory(
            SimpleNamespace(), malformed, receiver.me.fingerprint,
        )) is False
        malformed = dict(message, corrections=[1, 1])
        assert asyncio.run(sender._handle_bloom_init_advisory(
            SimpleNamespace(), malformed, receiver.me.fingerprint,
        )) is False
    finally:
        handle.close()
