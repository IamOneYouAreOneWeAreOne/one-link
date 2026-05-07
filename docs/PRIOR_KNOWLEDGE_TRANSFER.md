# Prior Knowledge Transfer

One Link's large-file path should make prior knowledge useful automatically:
if the receiver, another trusted device, or a future model already knows most
of the object, the sender should transmit only the novelty.

## Sources Pulled From OneField Mesh

- `tools/onefield_transport/cdc_dedup.py`
  - Sender streams a content-defined chunk manifest.
  - Receiver answers with the chunks it is missing.
  - Sender transmits only missing chunks.
- `tools/calibration/codec_temporal_delta.py`
  - Video-like streams can send keyframes plus prediction residuals.
  - Both sides maintain deterministic predictor state.
  - Drift-sync packets detect state divergence and force re-keying.
- `tools/calibration/test_temporal_delta_drift_sync.py`
  - A lossy-channel simulation proves predictor drift can be bounded by
    periodic state hashes and forced keyframes.

## Implemented In One Link

One Link already has CDC file manifests, verified BLAKE3 chunk hashes, durable
transfer intents, retry/resume, and swarm chunk assist.

This pass adds local prior assist:

1. The daemon keeps a bounded background index of chunks already present in
   the One Link inbox and configured sync folders.
2. The index is lazy: it stores path + byte range + mtime metadata, not a
   duplicate copy of every chunk.
3. When a trusted peer offers a CDC file, the receiver hydrates only matching
   chunks that are actually needed, verifies each by BLAKE3, and then answers
   `FILE_WANTS`.
4. The receiver asks the sender only for chunks not found locally or through
   trusted swarm assist.
5. When a trusted peer asks `CHUNK_QUERY`, the daemon can hydrate from the
   lazy prior index before answering.

This means a huge video, VM image, dataset, or edited archive can transfer at a
fraction of the bandwidth when the receiver already has a related version.

This pass also upgrades trusted swarm assist from "ask another device if it has
a chunk" into a deterministic transfer scheduler:

1. Rarest chunks are pulled first, so chunks that only one trusted device has
   are secured before common chunks.
2. Sources are scored by trust, reliability, bandwidth, latency, and energy
   cost. Integrity is still enforced by BLAKE3 for every chunk.
3. Equal sources are byte-balanced, so multiple trusted devices act as one
   parallel fabric instead of one source being overloaded.
4. The daemon now records the planned schedule, assigned bytes, missing bytes,
   and per-source byte counts for future UI and retry decisions.

## Safety Boundaries

- Scans are rooted only in the One Link inbox and configured sync folders.
- Scans are bounded by file count and bytes per offer/query.
- Lazy source reads are accepted only if the source file's size and mtime
  still match the indexed metadata.
- A chunk is usable only if its BLAKE3 hash exactly matches the peer manifest.
- No private local filenames or directory listings are sent as part of prior
  assist.
- If no prior chunks are found, the normal CDC transfer path continues.

## Next Upgrade

The next major leap is a true predictive stream mode for video and very large
related media:

1. Negotiate `file_video_delta_v1` only when both peers advertise it.
2. Send a codec/session descriptor and model hash.
3. Send periodic keyframes plus residual chunks.
4. Exchange predictor state hashes.
5. On drift, force a keyframe or fall back to normal CDC.

That mode should be optional and integrity-gated. The default arbitrary-file
path remains exact byte delivery through CDC chunks.
