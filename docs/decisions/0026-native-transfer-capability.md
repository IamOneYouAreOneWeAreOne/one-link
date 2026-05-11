# ADR-0026: NATIVE_TRANSFER_V1 capability + FILE_NATIVE_CHUNK wire format

**Status:** ACCEPTED (Phase C-3 production cutover)
**Phase:** C-3
**Depends on:** ADR-0017 (PQ KEM), ADR-0020 (per-chunk ratchet), ADR-0024 (Phase C-3 wiring status), ADR-0025 (chunk-store transport pipeline)

---

## Context

[ADR-0025](0025-chunk-store-transport-pipeline.md) shipped the composed `NativeTransferSession` pipeline and the `Channel.establish_native_transfer()` integration helper. The daemon could *construct* a native session, but `send_file()` still emitted legacy `FILE_CHUNK` / `FILE_BIN_CHUNK` messages — the wire-format swap was deferred.

This ADR records the final production cutover: a `NATIVE_TRANSFER_V1` capability advertised in the CAPS frame, a new `FILE_NATIVE_CHUNK` message type, and the sender-side opt-in flag that gates the cutover in production.

## Decision

**Add a `NATIVE_TRANSFER_V1` capability and a `FILE_NATIVE_CHUNK` wire message. Both peers must advertise the capability; the sender additionally opts in via `ONE_LINK_NATIVE_TRANSFER=1`. Legacy peers (no capability) keep using `FILE_CHUNK` / `FILE_BIN_CHUNK` transparently — no version bump.**

### Capability negotiation

- `one_link.capabilities.NATIVE_TRANSFER_V1 = "native_transfer_v1"`.
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
  "chunk_id": <hex 32B BLAKE3 content address>,
  "plaintext_len": <int>,
  "data": <base64 of native AEAD ciphertext>,
  "eof": <bool>
}
```

The native AEAD ciphertext authenticates `chunk_id` as AAD — a swap or tamper raises before plaintext is exposed.

### Sender path

In `daemon.send_file()`'s stream chunk loop:

```python
native_transfer_used = (
    NATIVE_TRANSFER_V1 in peer_feature_set
    and os.environ.get("ONE_LINK_NATIVE_TRANSFER") == "1"
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

### Why env-flag opt-in instead of default-on

Production reliability. The legacy `FILE_CHUNK` / `FILE_BIN_CHUNK` path has 2,952 daemon regression tests covering it. The native path has full unit coverage and the integration tests at `tests/unit/test_native_transfer_cutover.py`, but no live multi-daemon socket coverage yet. `ONE_LINK_NATIVE_TRANSFER=1` is the operator opt-in: production deployments stay on legacy until operators flip the flag to try the new transport. When confidence is high we flip the default in a follow-up commit.

This is the same shadow-→-authoritative posture as [ADR-0024](0024-phase-c3-wiring-status.md): a tested code path lands first, the cutover commit (default flip) is a one-line follow-up.

## Verification

- 8 unit tests at `tests/unit/test_native_transfer_cutover.py`:
  - Capability constant in `LOCAL_CAPABILITIES` + `TRANSPORT_LAYER_CAPS`.
  - `Channel.note_caps_received()` flips `peer_native_transfer_capable`.
  - `get_or_create_native_transfer_session()` caches.
  - `FILE_NATIVE_CHUNK` wire envelope round trips through paired sessions.
  - AEAD AAD binding rejects `chunk_id` swap.
  - 8-chunk multi-chunk round trip matches the daemon's send_file loop shape.
  - Env-flag default-off + explicit opt-in semantics.
- **2,952 daemon regression tests pass / 0 failures** after the cutover wiring landed.
- 77 total unit tests pass.

## Migration

Legacy peers continue to interoperate transparently:

- Old peer ↔ new peer: old peer doesn't advertise `NATIVE_TRANSFER_V1`, new peer's `peer_native_transfer_capable` stays False, send_file emits FILE_CHUNK / FILE_BIN_CHUNK as before.
- New peer ↔ new peer with opt-in: both advertise the capability AND the sender has `ONE_LINK_NATIVE_TRANSFER=1`, sender emits FILE_NATIVE_CHUNK, receiver dispatches to `_handle_file_native_chunk`.
- New peer ↔ new peer without opt-in: capability is advertised but sender's env flag isn't set, sender stays on legacy. Receiver still has the FILE_NATIVE_CHUNK handler ready for whenever the sender flips the flag.

## Follow-up

Once production traffic on `ONE_LINK_NATIVE_TRANSFER=1` reports zero divergence:

1. Flip the sender default: emit `FILE_NATIVE_CHUNK` whenever the peer advertises the capability, without the env-flag gate.
2. Eventually deprecate `FILE_CHUNK` / `FILE_BIN_CHUNK` (after a long deprecation window — those messages must remain decodable for backwards compatibility with legacy peers indefinitely).

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
