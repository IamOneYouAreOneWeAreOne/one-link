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
encrypted chunks in flight. Chunk size scales with file size up to `4 MiB`, and
the in-flight window is capped at `24 MiB` / `16` chunks so One Link can push
hard on Wi-Fi/Ethernet without unbounded RAM growth.

v0.11.6 adds the first binary stream lane. Peers that advertise
`file_binary_frame` still use the same authenticated encrypted channel, but
file chunks are carried as `OLB1 + compact-json-header + raw-bytes` instead of
JSON with base64 content. Older peers automatically keep using the JSON stream
fallback. This removes the base64 expansion tax for upgraded peers without
splitting security into a second transport.

## Current Important Result

The current Python CDC implementation is about `8 MiB/s` on the local Windows
dev machine. The new fast identity lanes measured:

- hash-only manifest: about `1.6 GiB/s`;
- fixed-size manifest: about `1.2 GiB/s`;
- CDC manifest: about `8 MiB/s`.

That means One Link must be selective:

- old/non-CDC peer -> hash-only stream;
- new video with no prior knowledge -> hash-only or fixed manifest;
- related file/version/video with high prior knowledge -> CDC or swarm CDC
  once CDC indexing is fast enough to beat plain streaming;
- degraded route -> simpler protocol + automatic route/session repair.

## Next Build Steps

1. Feed real transfer observations into `AdaptiveTransferBrain` from the daemon.
2. Persist per-peer route stats in SQLite.
3. Add prior-hit-rate estimates from chunk cache before choosing CDC.
4. Add fixed-manifest wire negotiation for aligned media blocks.
5. Add swarm CDC fetch execution, not just planning.
6. Add perf gates so a change cannot silently make transfer planning slower.
7. Measure binary-frame LAN throughput on two upgraded devices and use the
   result to tune the adaptive stream window.

## Critical Finding

The transfer brain does not blindly choose CDC. With today's Python CDC speed,
a huge file on a fast LAN can still be faster as `hash_stream` even when the
receiver has most of the bytes already. That is not a failure of the planner;
it is evidence that the next breakthrough is a native CDC engine. Once CDC
rises from ~`8 MiB/s` to native-class throughput, the same planner flips
high-prior large files to CDC/swarm and sends only the missing pieces.

The goal is not to look advanced. The goal is to make the advanced path
disappear behind "send anything and it arrives."
