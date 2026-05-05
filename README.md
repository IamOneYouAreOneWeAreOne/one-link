# One_link

Peer-to-peer LAN chat + file sync. No accounts, no servers, no cloud.
Your computers find each other on your network and talk directly.

Built on the Coherence Language ecosystem (CRDT runtime, identity primitives,
effect tracking) with Python as the host harness while LLVM/WASM backends mature.

## Status

v0.0.1 — first slice. Identity, encrypted channel, mDNS discovery, CLI send/tail.
Folder sync and GUI come next.

## Install

```bash
pip install -e .[dev]
```

## Use

On every computer (Win / Mac):

```bash
one-link daemon          # leave running; auto-starts on next session
```

In another terminal:

```bash
one-link peers           # who's on the LAN
one-link send <peer> "hi"
one-link send-file <peer> ./photo.jpg
one-link tail            # stream incoming
```

`<peer>` accepts either the human name (computer hostname) or the first 8 chars of the device fingerprint.

## Architecture

```
one_link/
├── identity.py    Ed25519 keypair, fingerprint, persistence
├── wire.py        length-prefixed frame protocol + signed envelopes
├── channel.py     X25519 handshake + ChaCha20-Poly1305 stream
├── discovery.py   mDNS via zeroconf (_onelink._tcp.local)
├── daemon.py      asyncio TCP server + peer registry
├── cli.py         click-based CLI
└── paths.py       cross-platform config/data dirs
```

Coherence Language integration:
- `coherence_lang.bootstrap.runtime.crdt.VectorClock` for sync ordering (v1)
- `coherence_lang.bootstrap.runtime.effects` for declared-effect boundaries
- `coherence_lang.bootstrap.runtime.linear` for crypto-key linearity (v2)

## License

Copyright (c) 2026 One Link contributor. All rights reserved.
