# One_link

Peer-to-peer LAN chat + file sync. No accounts, no servers, no cloud.
Your computers find each other on your network and talk directly.

Built on the Coherence Language ecosystem (CRDT runtime, identity primitives,
effect tracking) with Python as the host harness while LLVM/WASM backends mature.

---

## Status

**v0.0.1** — first working slice. Two computers find each other on the LAN
via mDNS, mutually authenticate by Ed25519 fingerprint, establish an
X25519 + ChaCha20-Poly1305 channel, and exchange chat messages and files
of any size. CLI only, no GUI yet, no folder-watch sync yet.

---

## Install

### Windows — single-file binary (easiest)

Download `one-link.exe` from the latest [Release](https://github.com/IamOneYouAreOneWeAreOne/one-link/releases) and run it from a terminal:

```cmd
one-link.exe daemon
```

### macOS / Linux — from source

macOS comes with Python 3 already; on Linux install `python3.11+` from your package manager.

```bash
git clone https://github.com/IamOneYouAreOneWeAreOne/one-link
cd one-link
pip install -e .
one-link daemon
```

### Windows — from source (alternate)

Same as above; install Python 3.11+ from python.org first if you don't have it.

---

## Use

On every computer, leave the daemon running in a terminal (or set it to
auto-start — see "Background service" below):

```bash
one-link daemon
```

In another terminal on any of those computers:

```bash
one-link whoami           # show this device's identity
one-link peers            # list discovered devices on the LAN
one-link send <peer> "hi" # send a chat message
one-link send-file <peer> /path/to/file.zip
one-link tail             # stream incoming + outgoing events live
```

`<peer>` accepts either the hostname (e.g. `Alex-MacBook`) or the first 8 chars
of the device fingerprint (shown by `one-link peers`).

Received files land in the recipient's inbox:
- Windows: `%LOCALAPPDATA%\Coherence\One_link\inbox\`
- macOS:   `~/Library/Application Support/One_link/inbox/`
- Linux:   `~/.local/share/One_link/inbox/`

---

## How it works

```
                       [ LAN ]
   computer A  <─── mDNS discovery ───>  computer B
   one-link.exe        _onelink._tcp        one-link.exe

   per message:
     1. open TCP to peer (port advertised in mDNS)
     2. exchange Ed25519 pubkeys + sigs (mutual authn)
     3. X25519 handshake -> shared secret -> HKDF -> AEAD keys
     4. ChaCha20-Poly1305 framed messages, both directions
     5. close
```

- **Identity** is a long-term Ed25519 keypair generated on first run,
  stored in your user config dir. The BLAKE3 fingerprint of your public
  key is your device ID.
- **Encryption** is per-connection. Each new connection generates fresh
  X25519 ephemeral keys for forward secrecy. ChaCha20-Poly1305 with a
  64-bit counter nonce, AAD-tagged.
- **Discovery** is `_onelink._tcp.local.` mDNS. TXT record carries the
  Ed25519 public-key hex so peers can verify identity at first contact.
- **Files** are streamed in 256 KiB chunks, BLAKE3-hashed end-to-end for
  integrity verification on receive.

---

## Architecture

```
src/one_link/
├── __main__.py    `python -m one_link` entry
├── identity.py    Ed25519 keypair, BLAKE3 fingerprint, persistence
├── wire.py        length-prefixed frame protocol + JSON envelopes
├── channel.py     X25519 handshake + ChaCha20-Poly1305 stream
├── discovery.py   mDNS via async zeroconf
├── daemon.py      asyncio TCP server + local control socket
├── cli.py         click-based CLI
└── paths.py       cross-platform config/data dirs
```

Coherence Language ecosystem hooks (planned for v0.1):
- `coherence_lang.bootstrap.runtime.crdt.VectorClock` for sync ordering
- `coherence_lang.bootstrap.runtime.effects` for declared-effect boundaries
- `coherence_lang.bootstrap.runtime.linear` for crypto-key linearity

---

## Development

```bash
pip install -e .[dev]
python tests/smoke_loopback.py     # full two-daemon round-trip on this PC
python scripts/build_binary.py     # build standalone one-link[.exe]
```

The smoke test starts two independent daemons in temporary directories,
waits for mDNS discovery, sends a TEXT message, sends a 750 KB file,
and verifies the bytes arrive identical (BLAKE3-checked).

### Running multiple daemons on one machine

Set `ONE_LINK_HOME` to override config + data dirs:

```bash
ONE_LINK_HOME=/tmp/ol-A one-link daemon
ONE_LINK_HOME=/tmp/ol-B one-link daemon   # in another terminal
```

---

## Background service

Not yet packaged as a system service. Workaround for now:

- **Windows**: drop a shortcut to `one-link.exe daemon` in
  `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`.
- **macOS**: a `launchctl` plist or just leave it running in a tmux/screen.
- **Linux**: a `systemd --user` unit.

A proper tray-icon background service is on the v0.0.2 roadmap.

---

## Roadmap

- **v0.0.2** — tray icon, auto-start, peer trust prompts (TOFU acceptance UI),
  signed macOS .app + Windows installer
- **v0.1** — folder-watch sync engine using CRDT manifests, content-addressed
  blob store, conflict-free merge across peers
- **v0.2** — GUI (Tauri + React or Qt), group chat, voice/video
- **v0.3+** — internet P2P (NAT traversal via Iroh or libp2p), multi-modal
  transports from OneField Mesh (RF, audio fallback) for offline-resilient comms

---

## Security notes

- **Trust on first use.** v0.0.1 silently accepts any new peer's fingerprint.
  A confirmation prompt is on the v0.0.2 list.
- **No replay protection** beyond the per-channel nonce counter. Adequate for
  LAN; will need hardening for any future internet-facing mode.
- **Identity key is unencrypted on disk.** File mode 0600 on Unix; on Windows
  it inherits user-only ACL via `%APPDATA%`. A passphrase-encrypted keystore
  is on the roadmap.

This is alpha software. Don't use it for anything you wouldn't be okay
losing or having someone else read if your device were compromised.

---

## License

Copyright (c) 2026 One Link contributor (weareone@oneunity.earth). All rights reserved.
See [LICENSE](LICENSE).
