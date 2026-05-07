# Transfer Doctor And Torture Gate

Status: in_progress for v0.10.7.

One Link's promise is not "try to send a file." The promise is "the file gets
there, quietly, even when devices sleep, routes move, sessions desync, versions
differ, and chunks fail."

## Transfer Doctor

`one_link.transfer_doctor` converts raw transfer ledger state into product-safe
diagnosis:

- `Sending`
- `Waiting for device`
- `Resuming`
- `Done`
- `Needs attention`

Each diagnosis includes:

- a stable code;
- a plain user message;
- whether One Link can heal automatically;
- the next automatic action;
- optional retry timing and route action.

The daemon attaches this doctor block to transfer WebSocket events and paused
transfer metadata. The server attaches the same block to `/api/transfers`.

## Auto-Healing Actions

Current action vocabulary:

- `wait_for_peer` - device is offline or asleep; wait quietly.
- `retry_with_backoff` - durable intent stays queued until retry time.
- `reopen_secure_session` - secure session desync; drop and reconnect.
- `refresh_route` - peer moved IP/port; resolve again.
- `retry_missing_chunk` - corrupt or missing piece; retry only that piece.
- `fallback_protocol` - versions differ; use best shared protocol.

## Route Memory

`RouteMemory` scores observed routes by:

- success ratio;
- latency;
- bandwidth;
- failure count.

This is the foundation for making One Link stop hammering weak paths and prefer
the route that actually works for that peer.

## Huge File Torture Simulator

`one_link.transfer_sim` models large transfers without creating large files.
It builds synthetic chunk manifests and injects:

- offline rounds;
- corrupt chunks;
- legacy protocol fallback;
- route scoring;
- automatic retry until verified delivery.

Run:

```powershell
python scripts\torture_transfer_engine.py --size-gib 10 --chunk-mib 16
```

The command exits non-zero if delivery does not complete.

## What This Unlocks Next

The next production leap is to feed live route observations into `RouteMemory`
from the daemon and expose the doctor state in the UI transfer cards:

- speed;
- ETA;
- automatic retry state;
- current route;
- which chunks were recovered from prior knowledge or trusted swarm sources.
