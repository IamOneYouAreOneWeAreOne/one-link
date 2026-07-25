# File Engine v2 Migration Guide

> How an existing v0.20.x One Link daemon upgrades to a build that
> includes the file engine v2 substrate (Phase A1–E). Reading order:
> top-to-bottom; each section is self-contained.

## TL;DR

**There is nothing to migrate.** File engine v2 adds new code paths
behind feature gates (presence of the `one_link_native` wheel) and
**preserves every shipped wire format and on-disk format**. Drop in
the new build; everything keeps working; Phase B/D/E features
activate automatically if the native wheel is installed.

If you don't install the wheel, the daemon stays on the pure-Python
v0.20.x path with no behavioral change.

## What changes when the wheel is installed

| Surface | v0.20.x behavior | v0.21+ behavior with wheel |
|---|---|---|
| File chunking | Python CDC ~8 MiB/s | Rust CDC + BLAKE3, ~3 GiB/s |
| Chunk storage | `blobstore.py` JSON files | `ol_chunk_store` LSM + WAL + bloom |
| AEAD | `cryptography` ChaCha20-Poly1305 | `ol_aead` AES-NI / ChaCha20 via ring |
| Routing relay scoring | `loss_penalty = 1/(1−loss)²` heuristic | BE-RAR `nu((1−loss)/loss)` (Phase E) |
| Ratchet rotation | Fixed cadence | Field-driven advisory per-peer |
| Bandit prior | Uniform | Field-score weighted (Phase E) |
| Chunk address scheme | Always raw-BLAKE3 | Raw for docs, convergent for raw media |
| `/api/metrics` | Did not exist | Returns full native + field telemetry |
| `/api/status.native_status` | Did not exist | Lists every Phase A/D/E crate's availability |

Daemons still on v0.20.x interoperate with v0.21+ daemons over the
**wire format** because:
- WebRTC daemon↔daemon transport is unchanged.
- Channel handshake unchanged (Noise / Double Ratchet).
- Folder-sync state CRDT unchanged.
- Capability format unchanged.

## What does NOT change

- **Identity** — your `me.ed25519` keypair is preserved.
- **Paired peers** — `peers` table in sqlite stays as-is.
- **Folders** — folder state, manifest format, sharing model.
- **Capabilities** — Ed25519 grants + macaroons.
- **WebRTC/DTLS-SRTP path** — daemon↔daemon transport unchanged.
- **Browser-as-peer** — still WebRTC (intentional; Phase A2 QUIC
  cutover is daemon↔daemon only).
- **At-rest encryption** — lockbox + DPAPI wrapping unchanged.

## Specifically what the v0.21+ build adds at runtime

1. **`FieldSnapshotManager`** runs on a background thread (5s tick).
   No-op when peers < 3 or native wheel missing.
2. **BE-RAR-driven relay scoring** in `_pick_best_relay` when
   `ol_coherence_field` is installed; falls back to heuristic
   otherwise.
3. **Convergent-vs-raw chunk addressing** in `NativeTransferSession`
   when `ol_chunk_store` is installed; falls back to legacy
   `blobstore.py` raw-BLAKE3 otherwise.
4. **Field telemetry** in `/api/metrics` and the `status` control
   verb's `native_status` block.

Each of these gates on `HAS_NATIVE` being true in the respective
adapter module. **If you don't install the wheel, none of this
activates.**

## Upgrade procedure

**For users (most installations):**

```bash
pip install --upgrade one-link
```

That's it. If the new release ships `one_link_native` as part of the
wheel, every new path activates automatically. If the wheel is
unavailable for your platform (eg, niche arch), the daemon stays on
the v0.20.x pure-Python path with full functionality.

**For from-source installations:**

```bash
git pull
cd native && maturin develop --release
```

Restart the daemon. `/api/status.native_status` will show
`coherence_field.available: true`.

**For operators running supervised installations:**

1. Verify backup of `~/.one_link/` (state.db + chain keys).
2. Stop the daemon.
3. Update the binary.
4. Start the daemon.
5. Check `/api/status` — `app_version` should reflect new version,
   `native_status` block should report all Phase D/E subsystems as
   `available: true`.

Rollback is symmetric: install the previous version, restart. State
and wire format are preserved both directions.

## Wire format compatibility matrix

| v0.21+ daemon ↔ v0.20.x daemon | Status |
|---|---|
| WebRTC pairing | Works (no protocol change) |
| Text messages | Works |
| File transfers | Works (legacy fallback; indexed native pipeline is default-on only when both peers advertise the required capabilities; `ONE_LINK_NATIVE_TRANSFER=0` is the incident rollback switch) |
| Folder sync | Works (CRDT unchanged) |
| Capability grants | Works (Ed25519 format unchanged) |

Two v0.21+ daemons negotiate the native transfer pipeline via the
`NATIVE_TRANSFER_INDEXED_V1` capability. If either side lacks it (e.g.
v0.20.x), or an operator explicitly sets `ONE_LINK_NATIVE_TRANSFER=0`,
the sender falls back to the legacy path.

## On-disk format compatibility

The native `ol_chunk_store` writes to `~/.one_link/chunks/` (new
directory). The legacy `blobstore.py` writes to `~/.one_link/blobs/`
(existing). The two stores **coexist** during the transition.

Reading priority on transfer-send:
1. If `ol_chunk_store` has the chunk → use native ciphertext.
2. Otherwise → use legacy blobstore.
3. Otherwise → re-chunk from source.

No migration is forced. New chunks land in the native store; legacy
chunks stay in the legacy store until referenced (and then aren't
migrated — they stay valid). The legacy store can be drained
manually via `One Link blobstore vacuum` once you're confident the
native store is healthy.

## Rollback procedure

If a v0.21+ build is misbehaving:

1. Stop the daemon.
2. `pip install one-link==0.20.6` (or whatever the prior known-good
   version is).
3. Start the daemon.

State, peers, folders, capabilities all unchanged. The only loss is:
- Any chunks written EXCLUSIVELY to the native store after upgrade
  (they're still on disk in `~/.one_link/chunks/` but the
  v0.20.x daemon can't read them; v0.21+ daemons can).

To force a clean migration:
```bash
rm -rf ~/.one_link/chunks/   # only after confirming all transfers complete
```

The native store will rebuild on next ingest.

## Things to watch in the first 24h after upgrade

1. **`/api/metrics`** — should show `field_solve_count` increasing,
   `field_solve_failures: 0`.
2. **CPU baseline** — should be ≤ pre-upgrade. The Rust paths are
   strictly faster than the Python paths they replace.
3. **Disk growth** — native chunk store has different sizing
   characteristics. Expect ~10% storage overhead vs. legacy
   blobstore during the migration window (chunks land in both).
4. **Routing decisions** — `/api/metrics.per_peer_field_advisories`
   should populate within 30s of having ≥ 3 peers.
5. **Existing transfers** — in-flight transfers complete on the path
   they started. New transfers may pick the native pipeline if the
   peer advertises `NATIVE_TRANSFER_V1`.

If any of these look wrong, see
[PHASE_E_OPERATOR_RUNBOOK.md](PHASE_E_OPERATOR_RUNBOOK.md).
