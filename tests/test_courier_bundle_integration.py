from __future__ import annotations

from pathlib import Path

import blake3
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.courier_bundle import export_courier_bundle, import_courier_bundle
from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.state import State


def _identity(hostname: str) -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key()
    pub_bytes = pub.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk,
        public=pub,
        public_bytes=pub_bytes,
        fingerprint=fp,
        short_id=fp[:8],
        hostname=hostname,
    )


@pytest.mark.asyncio
async def test_courier_bundle_moves_chunks_between_separate_daemon_homes(tmp_path: Path, monkeypatch):
    sender_home = tmp_path / "sender"
    receiver_home = tmp_path / "receiver"
    sender_id = _identity("sender")
    receiver_id = _identity("receiver")

    monkeypatch.setenv("ONE_LINK_HOME", str(sender_home))
    (sender_home / "data").mkdir(parents=True)
    sender_state = State(db_path=sender_home / "data" / "state.db")
    sender = Daemon(sender_id)
    sender.state = sender_state
    payloads = [
        b"offline courier first chunk" * 17,
        b"offline courier second chunk" * 23,
    ]
    chunks = []
    blob_hash = blake3.blake3(b"".join(payloads)).hexdigest()
    for index, payload in enumerate(payloads):
        h = blake3.blake3(payload).hexdigest()
        sender._store_chunk_cache(h, payload, blob_hash=blob_hash, chunk_index=index)
        chunks.append((h, payload))
    exported = export_courier_bundle(
        chunks,
        sender_fp=sender.me.fingerprint,
        recipient_fp=receiver_id.fingerprint,
        blob_hash=blob_hash,
        name="offline.bin",
        ttl_s=300,
    )
    sender_state.close()

    monkeypatch.setenv("ONE_LINK_HOME", str(receiver_home))
    (receiver_home / "data").mkdir(parents=True)
    receiver_state = State(db_path=receiver_home / "data" / "state.db")
    receiver = Daemon(receiver_id)
    receiver.state = receiver_state
    for h, _ in chunks:
        assert receiver._read_chunk_cache(h) is None

    imported = import_courier_bundle(
        exported.bundle,
        exported.key_token,
        expected_recipient_fp=receiver.me.fingerprint,
    )
    assert imported.manifest["blob_hash"] == blob_hash
    assert imported.manifest["name"] == "offline.bin"
    for index, (h, payload) in enumerate(imported.chunks):
        receiver._store_chunk_cache(
            h,
            payload,
            blob_hash=imported.manifest["blob_hash"],
            chunk_index=index,
        )

    assert [receiver._read_chunk_cache(h) for h, _ in chunks] == payloads
    rows = receiver_state.list_chunks_for_blob(blob_hash)
    assembled = b"".join(receiver._read_chunk_cache(r["chunk_hash"]) or b"" for r in rows)
    assert blake3.blake3(assembled).hexdigest() == blob_hash
    receiver_state.close()
