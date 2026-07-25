# One Link Validation Gates

Status: in_progress
Last updated: 2026-05-07

These gates turn the We Are One doctrine into release criteria. A release is
not production-ready for normal people until these behaviors are proven by
automated tests or explicit manual evidence.

## 1. File Transfer Gate

- Zero-byte, one-byte, text, binary, large, and huge-file cases.
- Filenames with spaces and supported Unicode.
- Duplicate file sends transmit no unnecessary bytes when CDC is available.
- Renamed duplicate files are recognized by content.
- Interrupted sends become paused/resumable, not silently failed.
- Daemon/UI restart preserves transfer ledger state.
- Receiver write failure does not create a completed file.
- Corrupt chunks are rejected and retried.
- Final manifest/hash verification is mandatory.

## 2. Compatibility Gate

- Current client to previous compatible minor version.
- Previous compatible minor version to current client.
- Unknown optional fields are ignored safely.
- Unsupported required features return a structured reason.
- File transfer falls back from CDC to baseline mode when needed.
- Chat remains available when advanced transfer features differ.
- Group features degrade cleanly where possible.

## 3. Security Gate

- Bad signature rejected.
- Bad AEAD tag rejected.
- Replay frame rejected.
- Too-old sequence rejected.
- Bad timestamp rejected.
- Key-change warning generated and surfaced.
- Path traversal rejected.
- Local HTTP API requires token.
- Unauthorized peer cannot send files or request folder data.
- Blocked peer remains blocked across reconnect.

## 4. Reliability Gate

- Peer disappears mid-send.
- Peer changes IP/port.
- Peer returns after delay.
- Connection reset.
- Latency spike.
- Frame truncation.
- Multiple concurrent transfers.
- UI reload during transfer.
- Daemon restart during transfer.
- Transfer status never spins forever without watchdog intervention.

## 5. Storage Gate

- Blob writes are atomic.
- Partial temp files are cleaned up.
- Corrupt stored blob is detected.
- Missing blob is reported, not treated as complete.
- Cache audit reports verified and corrupt counts.
- Duplicate blobs are stored once.

## 6. Mesh Gate

- Self peers are suppressed.
- Duplicate endpoints collapse to one device identity.
- Stale peers disappear automatically.
- Paired offline devices remain visible as paired devices, not ghosts.
- Reachability status is structured.
- Chunk availability can be reconciled across multiple trusted devices.

## 7. UX Gate

- First-run user knows how to pair.
- Selected direct conversation or group is obvious.
- File send has an obvious button and drag/drop.
- Group settings include members, rename, invite, and leave.
- Recoverable version drift does not create a giant panic banner.
- Advanced warnings use human language.
- Normal cleanup is automatic.

## 8. Packaged Artifact Parity Gate

- Generated PyInstaller spec includes dynamic imports used by guarded
  routes, including `one_link.sessions` and `one_link.recovery_api`.
- Generated PyInstaller spec includes package data, including
  `one_link/web` and `one_link/data`.
- Packaged binary `--version` matches current `src/one_link/__init__.py`.
- Packaged `/peer` response has `ETag` and `no-cache, must-revalidate`.
- Packaged recovery routes exist and are either auth-gated or return all
  recovery tracks.
- Packaged HTTPS endpoint negotiates ALPN `http/1.1`, not `h2`.
- Packaged HTTPS endpoint serves a two-certificate chain.
- Release command:
  `python scripts/validate_packaged_artifact.py --artifact dist/one-link --spec build/one-link.spec`
  (pass the complete onedir so the gate can reject leaked preview
  models/ONNX Runtime as well as validate the launcher and generated spec)

## Current Phase 1 Focus

- Protocol compatibility negotiation.
- Replay-window primitive.
- Blob-store corruption and temp cleanup.
- Transfer fault classification.
- Peer registry stability.
- Packaged artifact parity before public release.
