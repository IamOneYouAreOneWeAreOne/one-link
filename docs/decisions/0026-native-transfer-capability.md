# ADR-0026: NATIVE_TRANSFER_V1 capability + FILE_NATIVE_CHUNK wire format

**Status:** ACCEPTED (Phase C-3 production cutover)
**Phase:** C-3
**Depends on:** ADR-0017 (PQ KEM), ADR-0020 (per-chunk ratchet), ADR-0024 (Phase C-3 wiring status), ADR-0025 (chunk-store transport pipeline)

---

## Context

[ADR-0025](0025-chunk-store-transport-pipeline.md) shipped the composed `NativeTransferSession` pipeline and the `Channel.establish_native_transfer()` integration helper. The daemon could *construct* a native session, but `send_file()` still emitted legacy `FILE_CHUNK` / `FILE_BIN_CHUNK` messages — the wire-format swap was deferred.

This ADR records the production cutover and its indexed-wire follow-up: `NATIVE_TRANSFER_V1` and `NATIVE_TRANSFER_INDEXED_V1` capabilities, the `FILE_NATIVE_CHUNK` message type, direction-separated session roots, and an explicit rollback switch.

## Decision

**Use `FILE_NATIVE_CHUNK` only when both peers negotiate `NATIVE_TRANSFER_INDEXED_V1`. Native transfer is default-on for that safe indexed format; `ONE_LINK_NATIVE_TRANSFER=0` is an explicit incident rollback. Legacy or unindexed peers keep using `FILE_CHUNK` / `FILE_BIN_CHUNK` transparently — no version bump.**

### Capability negotiation

- `one_link.capabilities.NATIVE_TRANSFER_V1 = "native_transfer_v1"`.
- `one_link.capabilities.NATIVE_TRANSFER_INDEXED_V1 = "native_transfer_indexed_v1"` prevents nonce/ratchet drift with older envelopes that lacked a session-global chunk index.
- Added to `LOCAL_CAPABILITIES` and `TRANSPORT_LAYER_CAPS` (i.e. transport-layer, not user-prompt-required).
- `Channel.note_caps_received()` sets `_peer_native_transfer_capable = "native_transfer_v1" in features` alongside the existing DR capability detection.
- `Channel.peer_native_transfer_capable` exposes the flag as a read-only property.

### Wire message: `FILE_NATIVE_CHUNK`

```
{
  "t": "FILE_NATIVE_CHUNK",
  "id": <uuid>,
  "ts": <unix_ms>,
  "from": <sender_short_id>,
  "blob": <hex blob hash>,
  "seq": <int chunk index>,
  "chunk_index": <monotonic session-global ratchet index>,
  "chunk_id": <hex 32B BLAKE3 content address>,
  "plaintext_len": <int>,
  "data": <base64 of native AEAD ciphertext>,
  "eof": <bool>
}
```

The native AEAD ciphertext authenticates `chunk_id` as AAD. After decryption, the receiver also recomputes the protocol content address (raw or convergent BLAKE3) and rejects a validly encrypted but falsely labeled chunk before persistence. `chunk_index` is replay-window checked and bound to direction-separated traffic roots.

### Sender path

In `daemon.send_file()`'s stream chunk loop:

```python
native_transfer_used = (
    NATIVE_TRANSFER_INDEXED_V1 in peer_feature_set
    and os.environ.get("ONE_LINK_NATIVE_TRANSFER", "1") != "0"
)
native_session = (
    channel.get_or_create_native_transfer_session()
    if native_transfer_used else None
)

# For each chunk:
if native_transfer_used and native_session is not None:
    record = native_session.encrypt_chunk_bytes(data)
    chunk_msg = make_msg(
        "FILE_NATIVE_CHUNK", self.me.short_id,
        blob=blob_hex, seq=seq,
        chunk_index=record.chunk_index,
        chunk_id=record.chunk_id.hex(),
        plaintext_len=record.plaintext_len,
        data=base64.b64encode(record.ciphertext).decode("ascii"),
        eof=eof,
    )
elif binary_stream_used:
    # ... FILE_BIN_CHUNK (legacy fast path)
else:
    # ... FILE_CHUNK (legacy default)
```

Failures to construct the native session fall back to the legacy path with a warning log — no failed transfer.

### Receiver path

`daemon._on_peer_message()` dispatches `FILE_NATIVE_CHUNK` to `_handle_file_native_chunk()`:

1. Lookup incoming file by blob hash.
2. Re-check capability (mid-stream revocation gate).
3. Decode `chunk_id` (32B hex), `plaintext_len`, `ciphertext` (base64).
4. Lazy-build the channel's matched native session via `channel.get_or_create_native_transfer_session()`.
5. Reconstruct a `NativeChunkRecord` and call `session.decrypt_chunk()`.
6. AEAD failure aborts the transfer with `native_chunk_decrypt_failed` ACK.
7. Plaintext goes through the same `f.handle.write(data) + f.hasher.update(data)` path as legacy chunks.

### Default-on cutover and rollback

The original shadow period required `ONE_LINK_NATIVE_TRANSFER=1`. The follow-up cutover is now complete: indexed-capable peers use native transfer by default. Operators retain `ONE_LINK_NATIVE_TRANSFER=0` as a fail-safe rollback during a production incident. Capability negotiation remains the interoperability boundary, and all failures to construct the native session degrade explicitly to the legacy path with diagnostics.

## Verification

- 8 unit tests at `tests/unit/test_native_transfer_cutover.py`:
  - Capability constant in `LOCAL_CAPABILITIES` + `TRANSPORT_LAYER_CAPS`.
  - `Channel.note_caps_received()` flips `peer_native_transfer_capable`.
  - `get_or_create_native_transfer_session()` caches.
  - `FILE_NATIVE_CHUNK` wire envelope round trips through paired sessions.
  - AEAD AAD binding rejects `chunk_id` swap.
  - 8-chunk multi-chunk round trip matches the daemon's send_file loop shape.
  - Default-on indexed negotiation + explicit `=0` rollback semantics.
- **2,952 daemon regression tests pass / 0 failures** after the cutover wiring landed.
- 77 total unit tests pass.

## Migration

Legacy peers continue to interoperate transparently:

- Old peer ↔ new peer: old peer doesn't advertise `NATIVE_TRANSFER_V1`, new peer's `peer_native_transfer_capable` stays False, send_file emits FILE_CHUNK / FILE_BIN_CHUNK as before.
- New indexed peer ↔ new indexed peer: sender emits `FILE_NATIVE_CHUNK` by default; receiver dispatches to `_handle_file_native_chunk`.
- Operator rollback: setting `ONE_LINK_NATIVE_TRANSFER=0` keeps the sender on the legacy path without changing peer state or the wire version.
- Peers advertising only the original unindexed capability remain on the legacy path.

## Follow-up

Retain `FILE_CHUNK` / `FILE_BIN_CHUNK` decoding indefinitely for backwards compatibility. QUIC chunk carriage remains separately gated until its authenticated-receipt path has live multi-daemon evidence; native AEAD does not imply QUIC readiness.

## References

- ADR-0017 (PQ-hybrid KEM)
- ADR-0020 (Per-chunk forward-secret ratchet)
- ADR-0024 (Phase C-3 wiring status)
- ADR-0025 (Chunk-store transport pipeline)
- `capabilities.NATIVE_TRANSFER_V1`
- `Channel.peer_native_transfer_capable`
- `Channel.get_or_create_native_transfer_session()`
- `daemon._handle_file_native_chunk()`
- `daemon.send_file()` stream chunk loop
