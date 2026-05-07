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

1. When a trusted peer offers a CDC file, the receiver scans bounded local
   One Link roots before answering `FILE_WANTS`.
2. Matching chunks from existing local files are verified by BLAKE3 and copied
   into the normal chunk cache.
3. The receiver asks the sender only for chunks not found locally or through
   trusted swarm assist.
4. When a trusted peer asks `CHUNK_QUERY`, the daemon also hydrates from local
   prior files before answering.

This means a huge video, VM image, dataset, or edited archive can transfer at a
fraction of the bandwidth when the receiver already has a related version.

## Safety Boundaries

- Scans are rooted only in the One Link inbox and configured sync folders.
- Scans are bounded by file count and bytes per offer/query.
- A chunk is usable only if its BLAKE3 hash exactly matches the peer manifest.
- No private local filenames or directory listings are sent as part of prior
  assist.
- If no prior chunks are found, the normal CDC transfer path continues.

## Next Upgrade

The next major leap is a true predictive stream mode for video:

1. Negotiate `file_video_delta_v1` only when both peers advertise it.
2. Send a codec/session descriptor and model hash.
3. Send periodic keyframes plus residual chunks.
4. Exchange predictor state hashes.
5. On drift, force a keyframe or fall back to normal CDC.

That mode should be optional and integrity-gated. The default arbitrary-file
path remains exact byte delivery through CDC chunks.
