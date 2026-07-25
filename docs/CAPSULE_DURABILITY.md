# Async Capsule Durability and Delivery Contract

This document is the implementation contract for the voice capsule created
when a live call converts to asynchronous delivery. The relevant production
modules are `async_capsule.py`, `capsule_transport.py`, `capsule_at_rest.py`,
`capsule_store.py`, and the capsule paths in `daemon.py`.

## Safety invariants

- A finalized capsule is encrypted and durably indexed before the daemon
  reports that it is queued. If the durable commit fails, finalization fails
  closed; plaintext is not used as a fallback.
- The installation capsule root key is random, stable across restarts, and
  wrapped by the daemon `LockBox`. An existing corrupt or wrongly wrapped key
  is an error. The daemon never silently replaces it and strands old data.
- Capsule bodies (audio, provenance, identities, and timing contract) are
  sealed with ChaCha20-Poly1305. Each sealed file uses a fresh nonce and a key
  derived from the installation root plus `call_id` and `finalized_at_ms`.
  Those contextual fields are authenticated as associated data.
- Writes use a create-exclusive private temporary file, file `fsync`, atomic
  replace, and directory `fsync` where the operating system exposes it.
- The SQLite index runs in WAL mode with `synchronous=FULL`. A row first enters
  `staging`; only after its sealed body is durable does it transition to
  `pending` (outbound) or `received` (inbound).
- Startup reconciles every `staging` row. A complete, authentic body advances;
  a missing body removes the incomplete row; invalid bytes are quarantined.
- Capsule ids are idempotency keys, not overwrite keys. An exact replay returns
  the existing record. Any change to peer, direction, call, payload hash, or
  authenticated capsule content raises a conflict.
- The sender transitions `pending` to `delivered` only after an authenticated,
  pinned peer returns a content-bound `CAPSULE_RECEIPT` for the exact capsule
  id, call id, payload hash, and durable-commit flag. An ordinary transport ACK
  never clears the outbox.
- The receiver sends that receipt only after sealed-file and SQLite commit.
  Replaying an identical offer/transfer is harmless and returns another
  receipt; conflicting replays are rejected.
- Delivery attempts survive process restart and use bounded exponential
  backoff. A link loss leaves the row pending. The periodic delivery loop and
  peer capability updates wake the outbox again.
- Capsules are never empty or provenance-free. The pinned sender public key
  must hash to the complete declared sender fingerprint; matching only the
  eight-character display/device prefix is never sufficient identity proof.

## Bounded-resource contract

- Audio payload: at most 16 MiB.
- Serialized sealed plaintext: at most 32 MiB.
- Provenance JSON: at most 12 MiB and a bounded number of entries.
- Wire chunks: at most 256 KiB, decoded with strict base64 and exact schemas.
- Inbound assemblies: at most 16 globally and 4 per peer.
- Declared in-flight bytes: at most 64 MiB globally and 32 MiB per peer.
- Incomplete assemblies expire after 180 seconds. Completed-replay memory is
  capped at 512 entries.
- Delivery drains at most 4 records concurrently. Every transport frame has a
  40-second deadline and only one encoded chunk is materialized at a time.

All lengths, timestamps, ids, enum values, chunk counts, hashes, provenance
signatures, sender identities, recipient identities, and negotiated
capabilities are validated before durable state changes. Every provenance
entry carries a positive segment byte length; cardinality must match the
provenance chain, lengths must sum exactly to the audio size, and each rebuilt
payload slice must hash to its corresponding signed segment. Thus a chain of
valid signatures over unrelated audio cannot be presented as coverage of the
delivered capsule. Boolean values are not accepted where the wire contract
requires integers. Offer scalars and final chunk counts are mandatory rather
than defaulted, and a local chunk size that would exceed the sequence-number
space is rejected before any frame is sent.

## Delivery sequence

1. `CallManager` finalizes an `AsyncCapsule` using the instant the call entered
   async capture as `started_at_ms`.
2. The daemon synchronously commits the encrypted outbound record before
   publishing the finalization tail event.
3. The sender transmits `CAPSULE_OFFER`, ordered `CAPSULE_CHUNK` frames, and
   `CAPSULE_COMPLETE` over the authenticated peer session.
4. The receiver binds the offer to the channel's pinned Ed25519 identity,
   verifies the payload hash and provenance signatures, converts an outgoing
   voice note to the local incoming kind, then commits it.
5. The receiver emits `CAPSULE_RECEIPT`, followed by the ordinary ACK for the
   complete frame. The sender's ACK loop dispatches that out-of-band receipt
   and keeps reading until the complete-frame ACK arrives.
6. The sender verifies the receipt contract, marks the outbox row delivered,
   and emits `capsule_delivered` exactly once.

## On-disk visibility and threat boundary

The sealed capsule body is confidential and authenticated. The SQLite outbox
index intentionally retains operational metadata such as capsule id, peer
fingerprint, call id, payload hash, size, status, retry counters, and
timestamps so recovery and scheduling do not require decrypting every body.
Filesystem compromise can therefore reveal that metadata and can delete or
roll back files; it cannot recover capsule audio or forge an authentic body
without the installation secret. Rollback resistance against an administrator
who can replace both database and key-store state requires a hardware monotonic
counter and is outside this local-store format.

## Verification gates

The focused adversarial coverage is in:

- `tests/test_capsule_at_rest.py`
- `tests/test_capsule_store.py`
- `tests/test_capsule_repository.py`
- `tests/test_capsule_transport.py`
- `tests/test_daemon_capsule_e2e.py`
- `tests/test_call_manager.py`
- `tests/test_daemon_flush_call_api.py`

The daemon integration suite covers encrypted finalization, real ACK/receipt
interleaving, interrupted transfer, process restart, retry, duplicate collapse,
full-wire replay, wrong-peer receipt spoofing, and unnegotiated offers.
