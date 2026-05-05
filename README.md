# One_link

Peer-to-peer LAN chat + file sync. No accounts, no servers, no cloud.
Your computers find each other on your network and talk directly,
end-to-end encrypted, mutually authenticated.

Built on the Coherence Language ecosystem (CRDT runtime, identity primitives,
effect tracking) with Python as the host harness while LLVM/WASM backends mature.

---

## Status

**v0.2.8** — long-lived encrypted chat sessions, resumable CDC chunk caching, peer capability policies, and stronger rejected-peer enforcement.

- Native-feeling browser app: dark theme, peer sidebar with online dots,
  message bubbles, drag-drop file send, live updates over WebSocket
- 235 passing tests across identity, wire, channel, discovery, paths, CLI,
  integration, raw-protocol attacks, resilience, tail subscription,
  chat REPL, and the new HTTP/WS server
- Full path-traversal defense at both the wire-protocol and HTTP layers
- LAN mDNS discovery, X25519 + ChaCha20-Poly1305 channel, Ed25519 identity

---

## Install

### Windows (single binary)

Download `one-link.exe` from the [latest release](https://github.com/IamOneYouAreOneWeAreOne/one-link/releases) and run:

```cmd
one-link.exe app
```

The first time you launch, Windows Defender / SmartScreen may flag the
unsigned exe — click "More info → Run anyway." (EV code-signing is
on the v0.2 roadmap.)

### Windows / macOS / Linux (from source)

```bash
git clone https://github.com/IamOneYouAreOneWeAreOne/one-link
cd one-link
pip install -e .
one-link app
```

On Windows, you can also drop a Desktop shortcut:

```powershell
PowerShell -ExecutionPolicy Bypass -File scripts\install_desktop_shortcut.ps1
```

Now there's a `One_link` icon on your Desktop. Double-click → app opens.

---

## Use

`one-link app` starts the daemon (if not already running) and opens
the desktop UI in your browser. The window has:

- **Sidebar** — every peer One_link finds on your LAN, with hostname,
  short_id, and an online indicator
- **Conversation pane** — pick a peer; chat with bubbles + timestamps
- **Drag-drop file zone** — drop any file anywhere on the window to send
- **Files panel** — toggle `Files` to see everything you've received
- **Live updates** — incoming messages and files appear instantly via
  WebSocket; no refresh needed

Files of any size, no upload limits, no third party in the middle.

### Lower-level commands (still available)

```bash
one-link daemon            # headless service mode
one-link chat              # terminal REPL alternative to the GUI
one-link whoami            # show this device's identity
one-link peers             # list discovered devices
one-link send <peer> "hi"
one-link send-file <peer> /path/to/file.zip
one-link tail              # stream events as JSON lines
```

---

## How it works

```
                       [ LAN ]
   computer A  <─── mDNS discovery ───>  computer B
   one-link                _onelink._tcp     one-link

   per message:
     1. open TCP to peer (port advertised in mDNS)
     2. exchange Ed25519 pubkeys + sigs (mutual authn)
     3. X25519 handshake → shared secret → HKDF → AEAD keys
     4. ChaCha20-Poly1305 framed messages, both directions
     5. close
```

The local UI is served by the daemon on a token-gated 127.0.0.1 port.
Only your browser, with the cookie set on first GET, can talk to it.
The daemon does not listen on any external interface for HTTP — only
the encrypted peer protocol on TCP for LAN traffic.

- **Identity:** long-term Ed25519 keypair, BLAKE3 fingerprint = device ID
- **Encryption:** per-connection X25519 ephemerals → forward secrecy.
  ChaCha20-Poly1305 with a 64-bit counter nonce, AAD-tagged
- **Discovery:** `_onelink._tcp.local.` mDNS. TXT record carries
  the Ed25519 public-key hex
- **Files:** streamed in 256 KiB chunks, BLAKE3 verified end-to-end

---

## Architecture

```
src/one_link/
├── __main__.py    `python -m one_link` entry
├── identity.py    Ed25519 keypair, BLAKE3 fingerprint, persistence
├── wire.py        length-prefixed frame protocol + JSON envelopes
├── channel.py     X25519 handshake + ChaCha20-Poly1305 stream
├── discovery.py   mDNS via async zeroconf
├── daemon.py      asyncio peer + control + UI servers
├── server.py      aiohttp HTTP + WebSocket UI API
├── web/index.html the desktop UI (single file, ~700 lines, no build step)
├── app.py         `one-link app` launcher
├── chat.py        terminal REPL (legacy, still useful)
├── cli.py         click-based CLI dispatch
├── state.py       (v0.2) sqlite persistent state
├── cdc.py         content-defined chunking + dedup transfer planning
├── merkle.py      Merkle drift detection for manifests/blob indexes
├── capabilities.py per-peer feature/capability names
├── sessions.py    explicit peer session-protocol catalog
├── sovereign.py   mission/principles/capability audit surface
└── paths.py       cross-platform config/data dirs
```

Coherence / OneField ecosystem hooks:
- `coherence_lang.bootstrap.runtime.crdt.VectorClock` inspired the active
  `one_link.crdt.VectorClock` folder-sync primitive
- OneField Mesh `cdc_dedup.cl` inspired live `FILE_WANTS` /
  `FILE_CDC_CHUNK` transfer skipping
- OneField Mesh `merkle_drift_sync.cl` inspired live manifest root checks
- Session-protocol and capability concepts now ship as `one_link.sessions`
  and `one_link.capabilities`

---

## Security notes

- **Loopback-only UI.** The HTTP/WebSocket server binds to 127.0.0.1.
  No remote-attacker surface; only browsers running on this exact machine
  can reach it.
- **Per-process token.** Every daemon restart rotates a 256-bit URL-safe
  token. Required as cookie or Authorization header for every API call.
- **Path-traversal defense in two layers** (verified across 7 wire-level
  vectors and 7 HTTP-level vectors): basename-only writes to inbox, raw
  HTTP requests with `..` in the URL get rejected.
- **AEAD-protected wire protocol.** Tampering with any frame after
  the handshake closes the connection.
- **Trust on first use with pairing upgrade.** New peers start as pending;
  SAS pairing lets you pin or reject devices, and rejected peers are blocked
  in both outbound and inbound directions.
- **Identity key is unencrypted on disk** (file mode 0600 on Unix; user-
  only ACL via `%APPDATA%` on Windows). Passphrase-encrypted keystore
  is on the roadmap.

This is alpha software. Don't use it for anything you wouldn't be okay
losing or having someone else read if your device were compromised.

---

## Development

```bash
pip install -e .[dev]
python -m pytest tests/ --ignore=tests/smoke_loopback.py -v
python scripts/build_binary.py     # produces dist/one-link[.exe]
python scripts/bench_transfer_primitives.py
```

The smoke test (`tests/smoke_loopback.py`) starts two daemons in temp
directories and runs a complete end-to-end round-trip including a
multi-chunk file. The pytest suite covers everything in much greater
depth — see `TESTING.md`.

### Running multiple daemons on one machine

Set `ONE_LINK_HOME` to override config + data dirs:

```bash
ONE_LINK_HOME=/tmp/ol-A one-link app
ONE_LINK_HOME=/tmp/ol-B one-link app    # different port, different identity
```

---

## Roadmap

- **v0.3** — Complete folder sync wire integration, group rooms,
  native window via Tauri (proper app, not a browser tab),
  signed installers (EV cert) for Win + Mac, tray icon, auto-start
- **v0.4** — Internet P2P (NAT traversal via Iroh), persistent peers
  beyond mDNS range, distributed gossip discovery
- **v1.0** — Multi-modal transports from OneField (RF, audio, DSSS sub-noise),
  voice/video, mobile (iOS/Android via React Native)

---

## License

Copyright (c) 2026 One Link contributor (weareone@oneunity.earth).
Released under the MIT License. See [LICENSE](LICENSE).
