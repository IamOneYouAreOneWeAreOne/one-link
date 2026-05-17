# One Link

**Peer-to-peer chat, file sync, and live voice + video.** No accounts.
No servers. No cloud. Your devices find each other and talk directly,
end-to-end encrypted, mutually authenticated.

Built on the Coherence Language ecosystem (CRDT runtime, identity primitives,
effect tracking) with a Python host harness and a Rust native fast path.

---

## Download

Pick the artifact for your platform from the
[latest release](https://github.com/IamOneYouAreOneWeAreOne/one-link/releases/latest).

| Platform | File | What you do |
|---|---|---|
| Windows | `one-link-windows.exe` | Double-click. The first run may need "More info → Run anyway" until code-signing lands. |
| macOS | `one-link-macos` | Double-click. The first run may need a right-click → Open to bypass Gatekeeper. |
| Linux | `one-link-linux-x86_64` | `chmod +x one-link-linux-x86_64 && ./one-link-linux-x86_64` |

The binary opens your browser to a local URL. That's the whole install.
No Python, no Rust, no `pip`. Roughly 120-150 MB after install.

---

## What it does

- **Chat.** Direct messages, group threads. Edit, react, delete.
- **Files & folders.** Drag-drop send. Synced folders that update both ways.
- **Voice & video calls.** Living Presence: a call that survives bad
  networks — when the WiFi drops, it becomes a voice note and resumes
  when you reconnect. Optional Tier ζ semantic codec compresses voice
  to ~640 bps (25× smaller than Opus) using a trained predictor that
  ships in the binary.
- **Identity that's yours.** One private key on your device. No login.
  Pair with people by QR or a five-word safety string.
- **Cryptographic provenance** on every frame and file — you can see
  exactly what came from whom, without surfacing jargon.

---

## Run from source

For developers, or to run the daemon as a service:

```bash
git clone https://github.com/IamOneYouAreOneWeAreOne/one-link
cd one-link
pip install -e .
one-link daemon --open
```

`--open` auto-launches your browser to the local UI when the daemon's
ready. Drop `--open` if you're running on a server. The UI is at
`http://127.0.0.1:8765` by default.

On Windows you can drop a Desktop shortcut:

```powershell
PowerShell -ExecutionPolicy Bypass -File scripts\install_desktop_shortcut.ps1
```

---

## Use

`one-link app` starts the daemon (if not already running) and opens
the desktop UI in your browser. The window has:

- **Sidebar** — every peer One_link finds on your LAN, with hostname,
  short_id, and an online indicator
- **Conversation pane** — pick a peer; chat with bubbles + timestamps
- **Drag-drop file zone** — drop any file anywhere on the window to send
- **Files panel** — toggle `Files` to see everything you've received
- **Folders panel** — add local sync folders and push Merkle/CDC folder
  drift rounds to paired peers
- **Mesh panel** — see recent transfers with durable progress and
  completion/failure state
- **Peer controls** — allow/deny chat, file transfer, or folder sync per
  paired device
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
- **Files:** BLAKE3 verified end-to-end. Related files use
  content-defined chunking so receivers ask only for missing chunks; the
  transfer ledger survives UI refreshes and reports live progress.

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
python scripts/build_native_cdc.py # optional: prebuild the native CDC scanner
python scripts/bench_transfer_primitives.py
python scripts/perf_lab.py --scale quick
```

The smoke test (`tests/smoke_loopback.py`) starts two daemons in temp
directories and runs a complete end-to-end round-trip including a
multi-chunk file. The pytest suite covers everything in much greater
depth — see `TESTING.md`.

### Performance Lab

Use the repeatable local perf lab to see whether transfer work is getting
faster or slower:

```bash
python scripts/perf_lab.py --scale quick
python scripts/perf_lab.py --scale standard
```

Reports are written under `benchmarks/results/` as JSON and ignored by git.
The lab measures hash-only manifests, fixed manifests, CDC indexing,
prior-knowledge bandwidth savings, swarm scheduler throughput, the never-lose
torture simulator, SQLite transfer ledger pressure, compression throughput,
and the adaptive transfer brain. The transfer brain is the local Coherence
planner that decides when a file should use the simple fast lane, CDC, or
swarm CDC based on measured route health and prior knowledge.

One Link can use a bundled native CDC scanner for prior-knowledge transfers.
When present, the perf lab reports `engine=ctypes-c`; otherwise it falls back
to the pure-Python scanner with the same chunk hashes and wire format.

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

Copyright (c) 2026 One Link contributors (weareone@oneunity.earth).
Released under the MIT License. See [LICENSE](LICENSE).
