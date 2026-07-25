# Coherence Transfer Brain

Status: in_progress for v0.11.0.

One Link should not blindly use the most advanced transfer protocol every time.
The correct behavior is context-aware:

- if the peer is old, use the fastest shared protocol;
- if the receiver has no prior chunks, avoid slow CDC planning unless it buys
  resilience;
- if the receiver has almost the whole object already, pay the CDC cost when
  the wire savings beat the manifest CPU cost;
- if multiple trusted devices have pieces, split missing chunks across them;
- if a route degrades, automatically refresh route/session and simplify the
  protocol until health recovers.

## Coherence Sources Mined

From `$HOME\Projects\Coherence\coherence_lang\coherence_lang`:

- `npe/strategy/adaptive_cost.py`
  - calibration tiers: cold, warming, warm, hot, verified;
  - confidence from observed runtime behavior;
  - hardware/route-aware cost predictions;
  - multi-objective optimization.
- `npe/coherence/regulator.py`
  - autonomic health loop;
  - healthy, observing, constrained, repair states;
  - graduated response instead of scary user errors.
- `loovm/dataflow_scheduler.py`
  - prove independence, then parallelize;
  - conservative fallback when independence is unknown.
- `npe/strategy/quantum_solver.py`
  - Pareto frontier selection;
  - route/backend switching for hot regions.

## What Landed

`one_link.transfer_brain` adds a deterministic planning core:

- route observations with EMA latency/bandwidth/energy;
- reliability and calibration confidence;
- Pareto-frontier transfer candidate selection;
- health regulator states;
- strategy estimates for:
  - `hash_stream`
  - `fixed_manifest`
  - `cdc_manifest`
  - `swarm_cdc`

This does not require a server or cloud. It is local learning on the user's own
device.

The live daemon now also uses the same conclusion operationally: peers that
support CDC no longer force large first-time sends through Python CDC. For
files above `128 MiB`, One Link automatically uses the fast stream lane unless
the transfer is already resuming an existing CDC send. That directly fixes the
"video never arrived because planning was too slow" class of failure while
keeping CDC for the cases where it is currently worth it.

v0.11.3 adds the next speed layer: the fast stream lane is pipelined. Instead
of sending one chunk and waiting for one ACK, it keeps a bounded window of
encrypted chunks in flight. Chunk size scales with file size up to `4 MiB`.
The normal stream planner is capped at `24 MiB` / `16` chunks. CDC manifests
can publish much smaller cadence chunks, so the live scheduler converts that
limit into a byte budget: it may account for up to 384 small chunks while still
holding the same immutable `24 MiB` memory ceiling. Fresh content starts at a
conservative `4 MiB`; clean RTT observations grow the window in nominal
stream-sized steps, while retries and loss halve it. This avoids collapsing a
healthy high-latency path to a few hundred kilobytes in flight without making
memory usage depend on file size.

v0.11.6 adds the first binary stream lane. Peers that advertise
`file_binary_frame` still use the same authenticated encrypted channel, but
file chunks are carried as `OLB1 + compact-json-header + raw-bytes` instead of
JSON with base64 content. Older peers automatically keep using the JSON stream
fallback. This removes the base64 expansion tax for upgraded peers without
splitting security into a second transport.

## Current Important Result

The 2026-07-21 Windows audit measured the current native-backed pipeline at:

- base-content chunking: about `112.6 MiB/s`;
- changed-content chunking: about `397.1 MiB/s` with `98.1%` deduplication;
- 385 MiB ingest indexing: about `2.08 GiB/s`;
- 385 MiB durable ingest: about `0.29 GiB/s`;
- isolated 385 MiB end-to-end cold transfer: `15.47 s` (`24.9 MiB/s`).

These are reproducible development-machine measurements, not WAN claims. The
reported 596 ms two-device route still requires a fresh physical cross-device
run before a remote throughput number can be published.

That means One Link must be selective:

- old/non-CDC peer -> hash-only stream;
- new video with no prior knowledge -> hash-only or fixed manifest;
- related file/version/video with high prior knowledge -> CDC or swarm CDC
  once CDC indexing is fast enough to beat plain streaming;
- degraded route -> simpler protocol + automatic route/session repair.

## Remaining Production Proof

The daemon now feeds live observations into the adaptive brain, persists route
memory, estimates cache hit rate, negotiates fixed manifests, executes swarm
pulls, and gates performance regressions. Remaining release evidence is:

1. run a 385 MiB transfer between two upgraded physical devices over the
   reported 596 ms route, including forced response loss and restart/resume;
2. retain the authenticated receiver `FILE_COMMIT` receipt and verify exactly
   one receiver path and one sender intent after each fault injection;
3. use that physical result to tune the bounded adaptive window, then repeat
   the signed packaged-build gates on every supported operating system.

## Critical Finding

The transfer brain does not blindly choose CDC. Native CDC is available in the
audited build, but planning, hashing, durable staging, encryption, transport,
and receiver commit are separate costs. A new file on a fast LAN can still be
faster as `hash_stream`; a related file with a high cache-hit estimate can be
far cheaper as CDC/swarm. The planner chooses from measured route and content
evidence rather than treating native availability as proof that CDC always
wins.

The goal is not to look advanced. The goal is to make the advanced path
disappear behind "send anything and it arrives."
