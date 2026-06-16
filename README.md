# One Link

**Peer-to-peer chat, file sync, and live voice + video.** No accounts.
No servers. No cloud. Your devices find each other and talk directly,
end-to-end encrypted, mutually authenticated.

Built on the Coherence Language ecosystem (CRDT runtime, identity primitives,
effect tracking) with a Python host harness and a Rust native fast path.

**Project home:** [weareone-link.org](https://weareone-link.org) - live
in-browser demos of every cryptographic primitive in this repo (pair-by-QR,
Sphinx onion, PQ-hybrid sign, Shamir threshold recovery, per-chunk ratchet,
TOFU device recognition, streaming verifying download).

I am One. You are One. We are One.

---

## 60-second start

1. Open the [`auto-latest` release](https://github.com/IamOneYouAreOneWeAreOne/one-link/releases/tag/auto-latest) — rebuilt on every push to `master` by CI.
2. Download the zip for your OS.
3. Unzip into any folder you control.
4. Double-click `one-link` (or `one-link.exe` on Windows).
5. Your browser opens to a local URL. Click **Set up One Link** in the welcome wizard.
6. To pair a second device, open One Link there too, then scan the QR.

That's the install. No Python, no Rust, no `pip`. Roughly 120-150 MB on disk.

## Releases

Two channels:

| Channel | What it is | When to use |
|---|---|---|
| [`auto-latest`](https://github.com/IamOneYouAreOneWeAreOne/one-link/releases/tag/auto-latest) | Rolling continuous build, overwritten on every push to `master` | You want the most recent fixes |
| [tagged `v*` releases](https://github.com/IamOneYouAreOneWeAreOne/one-link/releases) | Versioned releases with Sigstore signatures + SLSA attestation | You want a stable, reproducibly-signed build |

Per-platform install notes:

| Platform | Architecture | File | What you do |
|---|---|---|---|
| Windows | x86_64 (Intel/AMD) | **`one-link-setup-x86_64.exe`** (installer) OR `one-link-windows-x86_64.zip` | Installer is per-user (no UAC), drops a Start Menu shortcut, includes an uninstaller. Zip path is "unzip + double-click `one-link.exe`" for users who prefer portable installs. First run may need "More info → Run anyway" until code-signing lands. |
| Windows | arm64 (Snapdragon X / Surface Pro X) | **`one-link-setup-arm64.exe`** (installer) OR `one-link-windows-arm64.zip` | Same flow as x86_64. Native ARM build — no x86 emulation cost. |
| macOS | arm64 (Apple Silicon — M1/M2/M3/M4) | **`one-link-macos-arm64.dmg`** OR `one-link-macos-arm64.zip` | Double-click the .dmg, drag One Link into Applications — the canonical Mac install gesture. The first run may need a right-click → Open to bypass Gatekeeper until Apple notarization lands. The .zip path is for users who prefer portable installs. |
| macOS | x86_64 (Intel Macs) | **`one-link-macos-x86_64.dmg`** OR `one-link-macos-x86_64.zip` | Same flow as arm64. For pre-Apple-Silicon Macs. |
| Linux | x86_64 | **`one-link-linux-x86_64.AppImage`** OR `one-link-linux-x86_64.zip` | AppImage runs across every modern distro (Ubuntu, Debian, Fedora, Arch, etc.) with no root + no package-manager integration — `chmod +x one-link-linux-x86_64.AppImage && ./one-link-linux-x86_64.AppImage`. The .zip path is for users who prefer extracting a folder. |
| Linux | arm64 (Raspberry Pi 4/5 64-bit, ARM cloud) | **`one-link-linux-arm64.AppImage`** OR `one-link-linux-arm64.zip` | Same flow as x86_64. AppImage runtime supports aarch64 — Raspberry Pi OS 64-bit + Ubuntu/Debian on ARM all work. |

**The Windows installer is opinionated about being lightweight + honest:** no admin prompt, no EULA, no telemetry opt-in, no third-party offers, no newsletter checkboxes, no recommended-software garbage. One screen, install button, done. The "Run at Windows boot" toggle is in the in-app settings — never enabled by the installer.

Each download has a matching `.sha256` next to it; `manifest.txt` collates every artifact's hash. Verify before extracting:

```bash
curl -sLO <release_url>/manifest.txt
sha256sum --check manifest.txt
```

---

## What it does

- **Chat.** Direct messages, group threads. Edit, react, delete.
- **Files & folders.** Drag-drop send. Synced folders that update both ways.
- **Voice & video calls.** Living Presence: a call that survives bad
  networks - when the WiFi drops, it becomes a voice note and resumes
  when you reconnect. Optional Tier ζ semantic codec compresses voice
  to ~640 bps (25× smaller than Opus) using a trained predictor that
  ships in the binary.
- **Identity that's yours.** One private key on your device. No login.
  Pair with people by QR or a five-word safety string.
- **Cryptographic provenance** on every frame and file - you can see
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

- **Sidebar** - every peer One_link finds on your LAN, with hostname,
  short_id, and an online indicator
- **Conversation pane** - pick a peer; chat with bubbles + timestamps
- **Drag-drop file zone** - drop any file anywhere on the window to send
- **Files panel** - toggle `Files` to see everything you've received
- **Folders panel** - add local sync folders and push Merkle/CDC folder
  drift rounds to paired peers
- **Mesh panel** - see recent transfers with durable progress and
  completion/failure state
- **Peer controls** - allow/deny chat, file transfer, or folder sync per
  paired device
- **Live updates** - incoming messages and files appear instantly via
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
The daemon does not listen on any external interface for HTTP - only
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
depth - see `TESTING.md`.

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

## Troubleshooting

If something feels off, open **Settings → Advanced → One Link Doctor**
and click **Run health check**. It runs ~14 checks against the
current state (daemon reachable, peer version compatibility,
browser secure context, WebRTC support, mic + camera permission,
service worker registration, pending outbox depth, etc.) and
renders pass / warn / fail per surface with a one-line fix hint.

Common issues:

| Symptom | Likely cause | What to do |
|---|---|---|
| Messages sit as "Queued" while the peer is online | The other device is on an older build. Wire-version mismatch. | Update the other device to the same `auto-latest` build. |
| Calls connect but no audio / video | Browser blocked mic / camera permission. | Site settings → reset permissions → reload, accept on the next call. |
| Welcome wizard re-appears every launch | localStorage blocked or cleared by privacy mode. | Check browser settings; allow site data for `127.0.0.1`. |
| "Can't reach One Link. Is it running?" | The tray daemon stopped. | Restart by double-clicking the `one-link` binary again. |
| Files arrive but don't open | Daemon doesn't auto-open; this is by design. | Click the file bubble; image / PDF previews open in the lightbox, others open in a new tab. |

To file a bug: **Settings → Advanced → Report a bug on GitHub**
pre-fills an issue with a redacted diagnostic snapshot (no
fingerprints, no message bodies, no paths — only counts +
versions + recent error severities).

---

## Roadmap

Live status: see the **Truth Dashboard** in **Settings → About** — every
major feature is rated across four axes (primitive proven / daemon wired
/ UI exposed / soak proven). Only all-four-green = "shipped".

What's already in master at v0.21.x:
- Chat (1:1 + groups) with edit / react / delete / disappearing messages
- File transfer (native chunk store + AEAD, 10 MiB+ verified in soak)
- Voice + video calls (Living Presence Tier α-pre, signed offers, missed-call entries, audible ringtone)
- Pair-by-QR with Ed25519+ML-DSA hybrid signatures + SAS verification
- Personal device mesh (multi-device on same identity)
- Folder sync with CRDT conflict resolution
- Confidential-compute attestation (software provider; TPM in flight)
- Pinned + archived conversations, slash commands, image markup before send

What's queued:
- Double Ratchet activation in CAPS (closes the headline crypto gap)
- Service Worker pinned-pubkey signature verification (closes the update channel)
- Argon2id-wrapped identity key + OS-keyring passphrase (replaces PBKDF2 + env var)
- `server.py` modularization (12K → many smaller files for review)
- CSP nonce migration + TrustedTypes
- Group calls (3+ participants)
- Code-signed installers (Authenticode + Apple notarization)

See [`docs/UX_AUDIT_2026-05-17.md`](docs/UX_AUDIT_2026-05-17.md) for the
full audit list and recommended ordering.

---

## License

Copyright (c) 2026 One Link contributors (weareone@oneunity.earth).
Released under the **GNU Affero General Public License v3.0 or later**
(AGPL-3.0-or-later). See [LICENSE](LICENSE) and the full text in
[LICENSE.AGPL-3.0](LICENSE.AGPL-3.0).

AGPL is a deliberate, for-the-people choice: it keeps One Link free and
open even when run as a network service — anyone who offers it to others
must share their source, so it can't be quietly taken closed. (Versions
before commit `87d1b98` / v0.20.7 were MIT; this README previously still
said MIT, which was a stale inconsistency with LICENSE and pyproject.)
